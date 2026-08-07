package safepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// tempHome returns a temp directory with no symlinks in its own path: on macOS the
// system temp dir sits under a symlinked /var and the resolver correctly reports the
// real location, so a comparison has to start from the resolved form.
func tempHome(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	return dir
}

// resolverAt builds a Resolver rooted at home with no guard.
func resolverAt(t *testing.T, home string) *Resolver {
	t.Helper()
	return New(home, nil)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
}

func TestRoots_Contains(t *testing.T) {
	home := filepath.Join(string(filepath.Separator)+"tmp", "homes", "bob")
	tests := []struct {
		name string
		root string
		in   []string
		out  []string
	}{
		{
			name: "under the root",
			root: home,
			in:   []string{home, filepath.Join(home, ".aws"), filepath.Join(home, ".aws", "credentials")},
			// A sibling sharing the root's prefix must not pass: the boundary is
			// a separator, not a string prefix.
			out: []string{
				filepath.Join(string(filepath.Separator)+"tmp", "homes", "bobby", ".aws"),
				filepath.Join(string(filepath.Separator) + "tmp/homes"),
				filepath.Join(string(filepath.Separator) + "etc"),
			},
		},
		// An unresolved user leaves the root empty, and an empty root must
		// contain nothing rather than everything.
		{name: "empty root contains nothing", root: "", out: []string{"/", "/etc/passwd", `C:\Windows`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New(tt.root, nil)
			for _, p := range tt.in {
				if !r.Contains(p) {
					t.Errorf("Contains(%q) = false, want true", p)
				}
			}
			for _, p := range tt.out {
				if r.Contains(p) {
					t.Errorf("Contains(%q) = true, want false", p)
				}
			}
		})
	}
}

func TestResolve_RejectsRelativeAndEmpty(t *testing.T) {
	r := resolverAt(t, tempHome(t))
	for _, p := range []string{"", ".aws/credentials", "~/.aws/credentials"} {
		if _, err := r.Resolve(p); ReasonOf(err) != ReasonUnresolved {
			t.Errorf("Resolve(%q) reason = %q, want %q", p, ReasonOf(err), ReasonUnresolved)
		}
	}
}

func TestRead(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		max           int64
		wantLen       int
		wantTruncated bool
	}{
		{name: "under the cap", content: "[default]\n", max: 1 << 20, wantLen: 10},
		// The cap is a read bound, not a rejection: a header-only parse is
		// still valid, so a longer file yields exactly cap bytes and says so.
		{name: "over the cap truncates", content: strings.Repeat("x", 100), max: 10, wantLen: 10, wantTruncated: true},
		{name: "exactly at the cap is complete", content: strings.Repeat("y", 10), max: 10, wantLen: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := tempHome(t)
			path := filepath.Join(home, ".aws", "credentials")
			writeFile(t, path, tt.content)

			data, resolved, info, truncated, err := resolverAt(t, home).Read(path, tt.max)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if len(data) != tt.wantLen || truncated != tt.wantTruncated {
				t.Errorf("len=%d truncated=%v, want %d %v", len(data), truncated, tt.wantLen, tt.wantTruncated)
			}
			if resolved != path {
				t.Errorf("resolved = %q, want %q", resolved, path)
			}
			if info.Size() != int64(len(tt.content)) {
				t.Errorf("size = %d, want %d", info.Size(), len(tt.content))
			}
		})
	}

	// Absence must be distinguishable from a refusal: a machine that lacks a
	// credential file reports nothing, while a refused one is reported.
	t.Run("missing is not a refusal", func(t *testing.T) {
		home := tempHome(t)
		_, _, _, _, err := resolverAt(t, home).Read(filepath.Join(home, "nope"), 1024)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("err = %v, want os.ErrNotExist", err)
		}
		if ReasonOf(err) != "" {
			t.Errorf("missing file produced refusal %q", ReasonOf(err))
		}
	})
}

// TestResolve_SymlinkContainment covers every way a link can redirect a path: those
// staying inside the roots resolve to the real location, those that leave are
// refused. Each case builds its own layout and names the path to probe.
func TestResolve_SymlinkContainment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	tests := []struct {
		name string
		// build returns the containment root, the path to resolve, the resolved
		// path expected on success, and the refusal reason expected instead.
		build func(t *testing.T) (root, probe, wantResolved, wantReason string)
	}{
		{
			name: "leaf link inside the roots reports the real file",
			build: func(t *testing.T) (string, string, string, string) {
				home := tempHome(t)
				target := filepath.Join(home, "dotfiles", "creds")
				writeFile(t, target, "token\n")
				link := filepath.Join(home, ".git-credentials")
				symlink(t, target, link)
				return home, link, target, ""
			},
		},
		{
			// The case a leaf-only Lstat misses: the probed path looks ordinary
			// while the bytes live somewhere else entirely.
			name: "linked parent reports the real location",
			build: func(t *testing.T) (string, string, string, string) {
				home := tempHome(t)
				realDir := filepath.Join(home, "dotfiles", "aws-real")
				writeFile(t, filepath.Join(realDir, "credentials"), "[default]\n")
				symlink(t, realDir, filepath.Join(home, ".aws"))
				return home, filepath.Join(home, ".aws", "credentials"), filepath.Join(realDir, "credentials"), ""
			},
		},
		{
			// A home reachable only through a symlink is an ordinary layout, so
			// containment anchors on the resolved home as well as the written one.
			name: "linked home still contains its own files",
			build: func(t *testing.T) (string, string, string, string) {
				base := tempHome(t)
				realHome := filepath.Join(base, "real", "bob")
				writeFile(t, filepath.Join(realHome, ".npmrc"), "registry=https://example.test\n")
				linkedHome := filepath.Join(base, "home-bob")
				symlink(t, realHome, linkedHome)
				return linkedHome, filepath.Join(linkedHome, ".npmrc"), filepath.Join(realHome, ".npmrc"), ""
			},
		},
		{
			// The layout the two-root containment set exists for: every path under
			// the home redirects on its first component, and refusing those would
			// refuse every file the account owns.
			name: "redirect into the resolved home is allowed",
			build: func(t *testing.T) (string, string, string, string) {
				base := tempHome(t)
				actual := filepath.Join(base, "actual")
				writeFile(t, filepath.Join(actual, ".aws", "credentials"), "[default]\n")
				linked := filepath.Join(base, "linked")
				symlink(t, actual, linked)
				// The root is the home as the account record spells it.
				return linked, filepath.Join(linked, ".aws", "credentials"), filepath.Join(actual, ".aws", "credentials"), ""
			},
		},
		{
			// The redirection containment exists to stop, refused without the
			// target being opened.
			name: "leaf link out of the roots is refused",
			build: func(t *testing.T) (string, string, string, string) {
				outside := tempHome(t)
				secret := filepath.Join(outside, "other-user-secret")
				writeFile(t, secret, "not ours\n")
				home := tempHome(t)
				link := filepath.Join(home, ".netrc")
				symlink(t, secret, link)
				return home, link, "", ReasonOutsideRoots
			},
		},
		{
			// The shape a dotfiles layout produces accidentally.
			name: "linked parent out of the roots is refused",
			build: func(t *testing.T) (string, string, string, string) {
				outside := tempHome(t)
				writeFile(t, filepath.Join(outside, "credentials"), "[default]\n")
				home := tempHome(t)
				symlink(t, outside, filepath.Join(home, ".aws"))
				return home, filepath.Join(home, ".aws", "credentials"), "", ReasonOutsideRoots
			},
		},
		{
			// This resolves in the end to a file inside the home, but only by way of
			// a directory outside it whose components would have to be stat'd to find
			// out — and that stat is the blocking call, so the refusal comes at the
			// hop that leaves.
			name: "out of the roots and back again is refused at the hop",
			build: func(t *testing.T) (string, string, string, string) {
				home := tempHome(t)
				outside := filepath.Join(filepath.Dir(home), "outside")
				real := filepath.Join(home, "real")
				writeFile(t, filepath.Join(real, "credentials"), "[default]\n")
				if err := os.MkdirAll(outside, 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				symlink(t, outside, filepath.Join(home, "away"))
				symlink(t, real, filepath.Join(outside, "back"))
				return home, filepath.Join(home, "away", "back", "credentials"), "", ReasonOutsideRoots
			},
		},
		{
			// A cycle must burn the hop budget and refuse, never loop.
			name: "cycle refuses rather than looping",
			build: func(t *testing.T) (string, string, string, string) {
				home := tempHome(t)
				a, b := filepath.Join(home, "a"), filepath.Join(home, "b")
				symlink(t, b, a)
				symlink(t, a, b)
				return home, a, "", ReasonUnresolved
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, probe, wantResolved, wantReason := tt.build(t)
			r := resolverAt(t, root)

			resolved, err := r.Resolve(probe)
			if wantReason == "" {
				if err != nil {
					t.Fatalf("Resolve: %v", err)
				}
				if resolved != wantResolved {
					t.Errorf("resolved = %q, want %q", resolved, wantResolved)
				}
				return
			}
			if got := ReasonOf(err); got != wantReason {
				t.Fatalf("reason = %q (err %v), want %q", got, err, wantReason)
			}
			// The read path must refuse too, not just the resolve.
			if _, _, _, _, err := r.Read(probe, 1024); ReasonOf(err) != wantReason {
				t.Errorf("Read reason = %q, want %q", ReasonOf(err), wantReason)
			}
		})
	}
}

func TestResolve_Guard(t *testing.T) {
	// A guard that declines an ancestor must be consulted before any syscall reaches
	// it, and its reason must be the one the caller sees: the resolver carries the
	// caller's vocabulary rather than inventing one.
	t.Run("refuses before touching the path", func(t *testing.T) {
		home := tempHome(t)
		gated := filepath.Join(home, "Documents", "project")
		writeFile(t, filepath.Join(gated, ".npmrc"), "x=1\n")

		const refusedByCaller = "refused_by_caller"
		var asked []string
		r := New(home, func(path string) string {
			asked = append(asked, path)
			if path == gated {
				return refusedByCaller
			}
			return ""
		})

		_, err := r.Resolve(filepath.Join(gated, ".npmrc"))
		if ReasonOf(err) != refusedByCaller {
			t.Fatalf("reason = %q, want %q", ReasonOf(err), refusedByCaller)
		}
		// The refused directory is never the last thing asked about: the guard runs
		// on the whole path first, then each component, so the walk stops early.
		if slices.Contains(asked, filepath.Join(gated, ".npmrc")) && asked[len(asked)-1] != gated {
			t.Errorf("guard was asked in the order %v, want the walk to stop at the refused directory", asked)
		}
	})

	// A nil guard refuses nothing, the posture once the customer has granted
	// the access.
	t.Run("nil guard allows every contained path", func(t *testing.T) {
		home := tempHome(t)
		path := filepath.Join(home, "Documents", "project", ".npmrc")
		writeFile(t, path, "x=1\n")
		if _, err := New(home, nil).Resolve(path); err != nil {
			t.Fatalf("Resolve with no guard: %v", err)
		}
	})
}

// A parent component swapped for a symlink between resolution and open must not
// redirect the read — the property O_NOFOLLOW on the leaf alone does not deliver:
// every directory above the leaf was validated by an earlier syscall, so a local
// process that swaps one in that window still gets the kernel to traverse it, and
// on macOS traversal is itself the consent event. The swap is performed
// deliberately, so this asserts the guarantee rather than the odds.
func TestOpenVerified_RefusesAComponentSwappedAfterResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the descriptor chain this covers is the unix implementation")
	}
	home := tempHome(t)
	real := filepath.Join(home, "real")
	writeFile(t, filepath.Join(real, "credentials"), "[default]\n")
	elsewhere := filepath.Join(home, "elsewhere")
	writeFile(t, filepath.Join(elsewhere, "credentials"), "swapped\n")

	// Resolution sees a real directory, and the resolved path is what a caller
	// would then hand to the open.
	resolved, err := resolverAt(t, home).Resolve(filepath.Join(real, "credentials"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// The window: that directory becomes a symlink to another one.
	if err := os.RemoveAll(real); err != nil {
		t.Fatalf("remove: %v", err)
	}
	symlink(t, elsewhere, real)

	f, _, err := openVerified(resolved, false)
	if err == nil {
		_ = f.Close()
		t.Fatal("openVerified followed a component swapped after resolution")
	}
	if got := ReasonOf(err); got != ReasonUnresolved {
		t.Errorf("reason = %q (err %v), want %q", got, err, ReasonUnresolved)
	}
}

func TestReadDirNames(t *testing.T) {
	t.Run("lists the immediate entries", func(t *testing.T) {
		home := tempHome(t)
		ssh := filepath.Join(home, ".ssh")
		writeFile(t, filepath.Join(ssh, "id_ed25519"), "key\n")
		writeFile(t, filepath.Join(ssh, "known_hosts"), "host\n")

		names, resolved, more, err := resolverAt(t, home).ReadDirNames(ssh, 10)
		if err != nil {
			t.Fatalf("ReadDirNames: %v", err)
		}
		if len(names) != 2 || more || resolved != ssh {
			t.Errorf("got %d names (more=%v) at %q, want 2 entries of %q", len(names), more, resolved, ssh)
		}
	})

	// An empty directory is a complete listing of nothing. The short-read signal
	// the bounded form gets at the end of a directory must not read as a failure.
	t.Run("empty directory is not a failure", func(t *testing.T) {
		home := tempHome(t)
		dir := filepath.Join(home, ".ssh")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		names, resolved, more, err := resolverAt(t, home).ReadDirNames(dir, 10)
		if err != nil {
			t.Fatalf("ReadDirNames of an empty directory: %v", err)
		}
		if len(names) != 0 || more || resolved != dir {
			t.Errorf("got %d names (more=%v) at %q, want an empty listing of %q", len(names), more, resolved, dir)
		}
	})

	// The bound is what a caller reports a capped listing from, so it has to be
	// exact: one short must not claim more, one over must not look complete.
	t.Run("bound reports the overrun", func(t *testing.T) {
		home := tempHome(t)
		dir := filepath.Join(home, ".ssh")
		for i := range 5 {
			writeFile(t, filepath.Join(dir, fmt.Sprintf("key%d", i)), "k\n")
		}
		r := resolverAt(t, home)
		for _, tc := range []struct {
			max      int
			wantLen  int
			wantMore bool
		}{
			{max: 2, wantLen: 2, wantMore: true},
			{max: 4, wantLen: 4, wantMore: true},
			{max: 5, wantLen: 5, wantMore: false},
			{max: 6, wantLen: 5, wantMore: false},
		} {
			names, _, more, err := r.ReadDirNames(dir, tc.max)
			if err != nil {
				t.Fatalf("ReadDirNames(max=%d): %v", tc.max, err)
			}
			if len(names) != tc.wantLen || more != tc.wantMore {
				t.Errorf("ReadDirNames(max=%d) = %d names, more=%v; want %d, %v",
					tc.max, len(names), more, tc.wantLen, tc.wantMore)
			}
		}
	})
}

// A wrong-shaped location never yields bytes a parser could misread. Read describes
// a directory rather than refusing it — "that location is a directory" is an answer
// about the machine — but must never return content for one.
func TestOpen_TypeMismatches(t *testing.T) {
	home := tempHome(t)
	dir := filepath.Join(home, ".ssh")
	writeFile(t, filepath.Join(dir, "id_rsa"), "key\n")

	r := resolverAt(t, home)
	data, resolved, info, truncated, err := r.Read(dir, 1024)
	if err != nil {
		t.Fatalf("Read of a directory: %v", err)
	}
	if data != nil || truncated {
		t.Errorf("Read of a directory returned %d bytes (truncated=%v), want none", len(data), truncated)
	}
	if resolved != dir || info == nil || !info.IsDir() {
		t.Errorf("Read of a directory described it as %q/%v, want the directory itself", resolved, info)
	}
	// A listing of something that is not a directory has no honest answer, so
	// it fails closed.
	if _, _, _, err := r.ReadDirNames(filepath.Join(dir, "id_rsa"), 10); err == nil {
		t.Error("ReadDirNames of a file succeeded")
	}
}

func TestStat(t *testing.T) {
	home := tempHome(t)
	path := filepath.Join(home, ".vault-token")
	writeFile(t, path, "hvs.example\n")

	resolved, info, err := resolverAt(t, home).Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if resolved != path {
		t.Errorf("resolved = %q, want %q", resolved, path)
	}
	if info.Size() == 0 {
		t.Error("size = 0")
	}
}

// A refusal must never carry the path or an underlying OS message, because
// enterprise mode ships captured stderr verbatim.
func TestRefusal_CarriesOnlyTheCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	outside := tempHome(t)
	writeFile(t, filepath.Join(outside, "secret-name-here"), "x")
	home := tempHome(t)
	link := filepath.Join(home, ".netrc")
	symlink(t, filepath.Join(outside, "secret-name-here"), link)

	_, err := resolverAt(t, home).Resolve(link)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if got := err.Error(); got != ReasonOutsideRoots {
		t.Errorf("Error() = %q, want exactly %q", got, ReasonOutsideRoots)
	}
	if strings.Contains(err.Error(), "secret-name-here") || strings.Contains(err.Error(), home) {
		t.Errorf("refusal leaked a path: %q", err.Error())
	}
}

func TestReasonOf_NonRefusal(t *testing.T) {
	for _, err := range []error{nil, os.ErrNotExist} {
		if got := ReasonOf(err); got != "" {
			t.Errorf("ReasonOf(%v) = %q, want empty", err, got)
		}
	}
}

func TestSplit(t *testing.T) {
	vol, comps := split(filepath.Join(string(filepath.Separator)+"a", "b", "c"))
	if vol != filepath.VolumeName(string(filepath.Separator)) {
		t.Errorf("volume = %q", vol)
	}
	if strings.Join(comps, "/") != "a/b/c" {
		t.Errorf("comps = %v", comps)
	}
	if _, comps := split(string(filepath.Separator)); len(comps) != 0 {
		t.Errorf("root comps = %v, want none", comps)
	}
}
