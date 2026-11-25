package detector

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// nixFS is a symlink tree: links resolve component by component like the
// guarded reader, and anything not registered is absent. Like the reader, a
// missing path is a path error naming what was missing: the path itself, or
// the rewritten path once a link was followed. The scanner's guard refuses
// like the reader's, but Readlink is unguarded and recorded, as it is outside
// the reader. Every directory entry is a symlink. Starting a process panics,
// so every test also proves the scanner never runs one.
type nixFS struct {
	*executor.Mock
	links    map[string]string
	exists   map[string]bool
	files    map[string][]byte
	dirs     map[string][]string
	denied   map[string]bool
	resolved map[string]int
	after    func(path string, n int) // runs after path's n-th resolution
	guard    func(string) string
	readlink []string
}

func newNixFS(goos string) *nixFS {
	m := executor.NewMock()
	m.SetGOOS(goos)
	return &nixFS{Mock: m, links: map[string]string{}, exists: map[string]bool{"/nix": true}, files: map[string][]byte{},
		dirs: map[string][]string{}, denied: map[string]bool{}, resolved: map[string]int{}}
}

// noNix is a host where /nix is missing, keeping leftover user links.
func noNix() *nixFS {
	f := newNixFS(model.PlatformLinux)
	delete(f.exists, "/nix")
	f.links[nixHome+"/.nix-profile"] = nixXDG + "/profile"
	return f
}

func (f *nixFS) GuardedFiles(_ []string, guard func(string) string, _ int64) executor.Executor {
	f.guard = guard
	return f
}

func (f *nixFS) refused(p string) bool { return f.guard != nil && f.guard(p) != "" }

func (f *nixFS) Run(context.Context, string, ...string) (string, string, int, error) {
	panic("nix scanner started a process")
}

func (f *nixFS) RunWithTimeout(context.Context, time.Duration, string, ...string) (string, string, int, error) {
	panic("nix scanner started a process")
}

func (f *nixFS) RunInDir(context.Context, string, time.Duration, string, ...string) (string, string, int, error) {
	panic("nix scanner started a process")
}

func (f *nixFS) RunAsUser(context.Context, string, string) (string, error) {
	panic("nix scanner started a process")
}

func (f *nixFS) StartDetached(string, ...string) error { panic("nix scanner started a process") }

func (f *nixFS) LookPath(string) (string, error) { panic("nix scanner looked up a binary") }

func (f *nixFS) Getenv(string) string { panic("nix scanner read the environment") }

func (f *nixFS) EvalSymlinks(p string) (string, error) {
	orig := p
	defer func() {
		f.resolved[orig]++
		if f.after != nil {
			f.after(orig, f.resolved[orig])
		}
	}()
	for hop := 0; hop <= 16; hop++ {
		if f.refused(p) {
			return "", fs.ErrPermission
		}
		changed := false
		for link, target := range f.links {
			if p == link || strings.HasPrefix(p, link+"/") {
				if f.denied[link] {
					return "", fs.ErrPermission
				}
				p, changed = target+p[len(link):], true
				break
			}
		}
		if !changed {
			if f.exists[p] || f.files[p] != nil || f.dirs[p] != nil {
				return p, nil
			}
			return "", &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
		}
	}
	return "", fs.ErrInvalid
}

func (f *nixFS) Readlink(p string) (string, error) {
	f.readlink = append(f.readlink, p)
	if t, ok := f.links[p]; ok {
		return t, nil
	}
	if _, err := f.EvalSymlinks(p); err != nil {
		return "", err
	}
	return "", fs.ErrInvalid // exists, not a link
}

func (f *nixFS) ReadFile(p string) ([]byte, error) {
	r, err := f.EvalSymlinks(p)
	if err != nil {
		return nil, err
	}
	if data, ok := f.files[r]; ok {
		return data, nil
	}
	return nil, fs.ErrNotExist
}

func (f *nixFS) ReadDirLimit(dir string, _ int) ([]os.DirEntry, bool, error) {
	if f.denied[dir] || f.refused(dir) {
		return nil, false, fs.ErrPermission
	}
	names, ok := f.dirs[dir]
	if !ok {
		return nil, false, &fs.PathError{Op: "lstat", Path: dir, Err: fs.ErrNotExist}
	}
	var out []os.DirEntry
	for _, n := range names {
		out = append(out, executor.MockSymlinkDirEntry(n))
	}
	return out, false, nil
}

// profile links P to P-1-link to store path G holding the manifest, when given.
func (f *nixFS) profile(p, g, manifestFile string) {
	f.links[p] = p + "-1-link"
	f.links[p+"-1-link"] = g
	f.exists[g] = true
	if manifestFile != "" {
		data, err := os.ReadFile("testdata/nix/" + manifestFile)
		if err != nil {
			panic(err)
		}
		f.files[g+"/"+manifestFile[strings.LastIndex(manifestFile, "-")+1:]] = data // manifest.json or manifest.nix
	}
}

// env makes store path env a buildEnv whose entries link into members.
func (f *nixFS) env(env string, members ...string) {
	f.dirs[env] = []string{}
	for i, m := range members {
		name := fmt.Sprintf("e%d", i)
		f.dirs[env] = append(f.dirs[env], name)
		f.links[env+"/"+name] = m + "/bin/" + name
	}
}

const (
	nixHome       = "/home/alice"
	nixXDG        = nixHome + "/.local/state/nix/profiles"
	nixWhich      = "/nix/store/2izgqqfw4j4qvf93690561840nj1m2d6-which-2.23"
	nixHMGen      = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-home-manager-generation"
	nixHMPath     = "/nix/store/h1crmzbbn7mv1j6x3ki2kc72l1qwvwjs-home-manager-path"
	nixEnvA       = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-profile"
	nixEnvDef     = "/nix/store/cccccccccccccccccccccccccccccccc-user-environment"
	nixEnvB       = "/nix/store/dddddddddddddddddddddddddddddddd-profile"
	nixSystem     = "/nix/store/ffffffffffffffffffffffffffffffff-nixos-system"
	nixSW         = "/nix/store/gggggggggggggggggggggggggggggggg-system-path"
	nixUserEnv    = "/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-user-environment"
	nixEtcStatic  = "/nix/store/iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii-etc"
	nixGoneSystem = "/nix/store/jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj-nixos-system"
)

// nixHost is a Linux host with an XDG profile (zlib), a Home Manager profile
// (hello, which), a legacy default profile (inactive hello) and
// ~/.nix-profile aliasing the XDG profile.
func nixHost(goos string) *nixFS {
	f := newNixFS(goos)
	f.exists[nixHome] = true
	f.dirs[nixXDG] = []string{"home-manager", "home-manager-5-link", "profile", "profile-1-link"}
	f.profile(nixXDG+"/profile", nixEnvA, "multi-manifest.json")
	f.profile(nixXDG+"/home-manager", nixHMGen, "")
	f.links[nixHMGen+"/home-path"] = nixHMPath
	f.env(nixHMPath, nixHello, nixWhich)
	f.profile(nixDefaultProfile, nixEnvDef, "legacy-inactive-manifest.nix")
	f.links[nixHome+"/.nix-profile"] = nixXDG + "/profile"
	return f
}

var nixAlice = &user.User{Uid: "1000", Username: "alice", HomeDir: nixHome}

func sortedNixRecords(inv nixInventory) string { return sortLines(nixRecords(inv.packages)) }

func sortLines(s string) string {
	lines := strings.Split(s, "\n")
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

const nixHostRecords = "hello 2.12.1 " + nixHello + "\n" +
	"hello 2.12.1 " + nixHello + "\n" +
	"which 2.23 " + nixWhich + "\n" +
	"zlib 1.3.1 " + nixZlib

func TestNixScanner_Scan(t *testing.T) {
	tests := []struct {
		name       string
		host       func() *nixFS
		setup      func(f *nixFS)
		want       string
		present    bool
		incomplete bool
	}{
		{name: "profiles, Home Manager and the default profile", want: nixHostRecords, present: true},
		{
			name: "NixOS system and per-user environments",
			setup: func(f *nixFS) {
				f.links["/run/current-system"] = nixSystem
				f.links[nixSystem+"/sw"] = nixSW
				f.env(nixSW, nixNixStore)
				f.links["/etc/profiles/per-user/alice"] = "/etc/static/profiles/per-user/alice"
				f.links["/etc/static"] = nixEtcStatic
				f.links[nixEtcStatic+"/profiles/per-user/alice"] = nixUserEnv
				f.env(nixUserEnv, nixZlibDev)
			},
			want:    nixHostRecords + "\nnix 2.28.5 " + nixNixStore + "\nzlib 1.3.1-dev " + nixZlibDev,
			present: true,
		},
		{
			name: "links into the environment itself are not members",
			setup: func(f *nixFS) {
				f.dirs[nixHMPath] = append(f.dirs[nixHMPath], "self")
				f.links[nixHMPath+"/self"] = nixHMPath + "/bin/e0"
			},
			want: nixHostRecords, present: true,
		},
		{
			name:  "two profiles holding one home-path read it once",
			setup: func(f *nixFS) { f.links[nixEnvA+"/home-path"] = nixHMPath },
			want:  nixHostRecords, present: true,
		},
		{
			name: "direct ~/.nix-profile is a profile of its own",
			setup: func(f *nixFS) {
				delete(f.links, nixHome+"/.nix-profile")
				f.profile(nixHome+"/.nix-profile", nixEnvB, "direct-manifest.json")
			},
			want:    nixHostRecords + "\nnix 2.28.5 " + nixNixStore,
			present: true,
		},
		{
			name: "~/.nix-profile pinned to a generation is a profile",
			setup: func(f *nixFS) {
				f.dirs[nixXDG] = []string{"home-manager", "home-manager-5-link", "profile-1-link"}
				delete(f.links, nixXDG+"/profile")
				f.links[nixHome+"/.nix-profile"] = nixXDG + "/profile-1-link"
			},
			want: nixHostRecords, present: true,
		},
		{
			name: "dangling default profile is incomplete",
			setup: func(f *nixFS) {
				delete(f.exists, nixEnvDef)
				delete(f.files, nixEnvDef+"/manifest.nix")
			},
			want:    "hello 2.12.1 " + nixHello + "\nwhich 2.23 " + nixWhich + "\nzlib 1.3.1 " + nixZlib,
			present: true, incomplete: true,
		},
		{
			name:  "dangling current-system is incomplete, not absent",
			setup: func(f *nixFS) { f.links["/run/current-system"] = nixGoneSystem },
			want:  nixHostRecords, present: true, incomplete: true,
		},
		{
			name:  "dangling home-path is incomplete",
			setup: func(f *nixFS) { delete(f.dirs, nixHMPath) },
			want:  "hello 2.12.1 " + nixHello + "\nzlib 1.3.1 " + nixZlib, present: true, incomplete: true,
		},
		{
			name:  "unreadable environment is incomplete",
			setup: func(f *nixFS) { f.denied[nixHMPath] = true },
			want:  "hello 2.12.1 " + nixHello + "\nzlib 1.3.1 " + nixZlib, present: true, incomplete: true,
		},
		{
			name:  "unreadable profiles directory is incomplete",
			setup: func(f *nixFS) { f.denied[nixXDG] = true },
			want:  "hello 2.12.1 " + nixHello, present: true, incomplete: true,
		},
		{
			name:  "unsupported manifest version is incomplete",
			setup: func(f *nixFS) { f.files[nixEnvA+"/manifest.json"] = []byte(`{"version":9,"elements":{}}`) },
			want:  "hello 2.12.1 " + nixHello + "\nhello 2.12.1 " + nixHello + "\nwhich 2.23 " + nixWhich, present: true, incomplete: true,
		},
		{
			name: "profile changed during the scan keeps its records",
			setup: func(f *nixFS) {
				f.after = func(p string, n int) {
					if p == nixXDG+"/profile" && n == 1 {
						f.links[nixXDG+"/profile-1-link"] = nixEnvB
						f.exists[nixEnvB] = true
					}
				}
			},
			want: nixHostRecords, present: true, incomplete: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := nixHost(model.PlatformLinux)
			if tc.host != nil {
				f = tc.host()
			}
			if tc.setup != nil {
				tc.setup(f)
			}
			inv := NewNixScanner(f, nil).scan(context.Background(), nixAlice, nil)
			if got := sortedNixRecords(inv); got != sortLines(tc.want) || inv.present != tc.present || inv.incomplete != tc.incomplete {
				t.Errorf("records:\n%s\npresent %v incomplete %v\nwant:\n%s\npresent %v incomplete %v",
					got, inv.present, inv.incomplete, sortLines(tc.want), tc.present, tc.incomplete)
			}
		})
	}
}

func TestNixScanner_DarwinReadsCanonicalSystemPaths(t *testing.T) {
	f := nixHost(model.PlatformDarwin)
	f.links["/private/var/run/current-system"] = nixSystem
	f.links[nixSystem+"/sw"] = nixSW
	f.env(nixSW, nixNixStore)
	f.links["/run/current-system"] = nixGoneSystem // a Linux path; never probed on macOS
	inv := NewNixScanner(f, nil).scan(context.Background(), nixAlice, nil)
	if got := sortedNixRecords(inv); got != sortLines(nixHostRecords+"\nnix 2.28.5 "+nixNixStore) || inv.incomplete {
		t.Errorf("records:\n%s\nincomplete %v", got, inv.incomplete)
	}
}

func TestNixScanner_ScanResult(t *testing.T) {
	refused := func() *nixFS {
		f := newNixFS(model.PlatformLinux)
		f.links["/nix"] = "/data/nix"
		f.denied["/nix"] = true
		return f
	}
	tests := []struct {
		name     string
		host     func() *nixFS
		existing map[string]bool
		reported bool
		want     string // "" with wantNil false is a scan with no packages
		wantNil  bool
		wantErr  string
		present  bool
		noUser   bool // the user lookup returned no user
	}{
		{name: "host without /nix sends no scan, despite a leftover ~/.nix-profile", host: noNix, wantNil: true},
		{name: "removal after a reported upload sends a complete empty scan", host: noNix, reported: true},
		{name: "Nix with no profile sends a complete empty scan",
			host: func() *nixFS { return newNixFS(model.PlatformLinux) }, present: true},
		{name: "refused /nix is incomplete, never empty", host: refused, reported: true,
			wantErr: nixIncompleteError, present: true},
		{name: "one row per name, existing names dropped", host: func() *nixFS { return nixHost(model.PlatformLinux) },
			existing: map[string]bool{"zlib": true},
			want:     "hello 2.12.1 " + nixHello + "\nwhich 2.23 " + nixWhich, present: true},
		{name: "macOS with a console user reads every profile", host: func() *nixFS { return nixHost(model.PlatformDarwin) },
			want: "hello 2.12.1 " + nixHello + "\nwhich 2.23 " + nixWhich + "\nzlib 1.3.1 " + nixZlib, present: true},
		{name: "macOS without a console user keeps machine rows and is incomplete",
			host: func() *nixFS { return nixHost(model.PlatformDarwin) }, noUser: true,
			want: "hello 2.12.1 " + nixHello, wantErr: nixIncompleteError, present: true},
		{name: "macOS without /nix or a console user sends no scan", noUser: true, wantNil: true,
			host: func() *nixFS { f := noNix(); f.SetGOOS(model.PlatformDarwin); return f }},
		{name: "Linux with no user keeps machine rows and is incomplete", host: func() *nixFS { return nixHost(model.PlatformLinux) },
			noUser: true, want: "hello 2.12.1 " + nixHello, wantErr: nixIncompleteError, present: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := nixAlice
			if tc.noUser {
				target = nil
			}
			scan, present := NewNixScanner(tc.host(), nil).Scan(context.Background(), target, nil, tc.existing, tc.reported)
			if present != tc.present {
				t.Errorf("present = %v, want %v", present, tc.present)
			}
			if scan == nil || tc.wantNil {
				if (scan == nil) != tc.wantNil {
					t.Fatalf("scan = %+v, want nil %v", scan, tc.wantNil)
				}
				return
			}
			if scan.ScanType != "nix" || scan.PackageManager != nil || scan.Packages == nil ||
				scan.PackagesCount != len(scan.Packages) || scan.Error != tc.wantErr {
				t.Errorf("scan = %+v", scan)
			}
			if got := nixRecords(scan.Packages); got != tc.want {
				t.Errorf("records = %q, want %q", got, tc.want)
			}
		})
	}
}

// A network /nix or home is refused with or without a user, and Readlink never
// runs below a refused path.
func TestNixScanner_GuardRefusal(t *testing.T) {
	tests := []struct {
		name, refused string
		target        *user.User
		want          string
	}{
		{"network /nix without a user", "/nix", nil, ""},
		{"network home", nixHome, nixAlice, "hello 2.12.1 " + nixHello},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := nixHost(model.PlatformLinux)
			s := NewNixScanner(f, nil)
			s.protection = func(string, *bool, []string) (func(string) string, func(string) bool) {
				return func(p string) string {
					if p == tc.refused || strings.HasPrefix(p, tc.refused+"/") {
						return "refused_network_volume"
					}
					return ""
				}, nil
			}
			inv := s.scan(context.Background(), tc.target, nil)
			if got := sortedNixRecords(inv); got != tc.want || !inv.present || !inv.incomplete {
				t.Errorf("records %q present %v incomplete %v", got, inv.present, inv.incomplete)
			}
			for _, p := range f.readlink {
				if p == tc.refused || strings.HasPrefix(p, tc.refused+"/") {
					t.Errorf("Readlink(%q) below a refused path", p)
				}
			}
		})
	}
}

func TestSelectNixPackages_FirstByVersionThenPath(t *testing.T) {
	pkgs := []model.SystemPackage{
		{Name: "hello", Version: "2.9", InstallPath: "/nix/store/a-hello-2.9"},
		{Name: "hello", Version: "2.12.1", InstallPath: "/nix/store/c-hello-2.12.1"},
		{Name: "hello", Version: "2.12.1", InstallPath: "/nix/store/b-hello-2.12.1"},
	}
	if got := nixRecords(selectNixPackages(pkgs, nil)); got != "hello 2.12.1 /nix/store/b-hello-2.12.1" {
		t.Errorf("selected %q", got)
	}
}

func TestNixScanner_Bounds(t *testing.T) {
	t.Run("service identity reads machine sources only", func(t *testing.T) {
		inv := NewNixScanner(nixHost(model.PlatformLinux), nil).scan(context.Background(), &user.User{Uid: "0", Username: "root", HomeDir: "/root"}, nil)
		if got := sortedNixRecords(inv); got != "hello 2.12.1 "+nixHello || inv.incomplete {
			t.Errorf("records %q incomplete %v", got, inv.incomplete)
		}
	})
	t.Run("windows reads nothing", func(t *testing.T) {
		if inv := NewNixScanner(nixHost(model.PlatformWindows), nil).scan(context.Background(), nixAlice, nil); inv.present || len(inv.packages) != 0 {
			t.Errorf("inventory %+v", inv)
		}
	})
	t.Run("cancelled scan is incomplete", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		inv := NewNixScanner(nixHost(model.PlatformLinux), nil).scan(ctx, nixAlice, nil)
		if len(inv.packages) != 0 || !inv.incomplete {
			t.Errorf("inventory %+v", inv)
		}
	})
	t.Run("sources past the bound are incomplete", func(t *testing.T) {
		f := nixHost(model.PlatformLinux)
		f.dirs[nixXDG] = nil
		for i := range maxNixSources + 1 {
			f.dirs[nixXDG] = append(f.dirs[nixXDG], fmt.Sprintf("p%04d", i))
		}
		if inv := NewNixScanner(f, nil).scan(context.Background(), nixAlice, nil); !inv.incomplete || !inv.present {
			t.Errorf("present %v incomplete %v", inv.present, inv.incomplete)
		}
	})
}

// The guarded reader names the missing component in a path error. nixAbsent
// relies on that shape, so it is checked against the real reader.
func TestNixAbsent_GuardedReader(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("creating symlinks needs privileges on Windows")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"profiles/dangling": "store/gone", "current-system": "store/gone-system"} {
		if err := os.Symlink(filepath.Join(root, target), filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	refused := filepath.Join(root, "refused")
	files := executor.NewReal().GuardedFiles([]string{root, filepath.Join(root, "nix")}, func(p string) string {
		if p == refused {
			return "refused"
		}
		return ""
	}, 1<<20)
	tests := []struct {
		name, path string
		want       bool
	}{
		{"missing leaf", "profiles/default", true},
		{"missing ancestor", "none/profiles/default", true},
		{"missing root", "nix", true},
		{"dangling leaf", "profiles/dangling", false},
		{"dangling parent", "current-system/sw", false},
		{"refused", "refused/sw", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, tc.path)
			_, err := files.EvalSymlinks(path)
			if got := nixAbsent(path, err); got != tc.want {
				t.Errorf("nixAbsent(%s, %v) = %v, want %v", tc.path, err, got, tc.want)
			}
		})
	}
}

// walkEnv on a real symlink forest through the real guarded reader. Link
// targets are store paths that need not exist: only the link text is read.
func TestNixWalkEnv_GuardedReader(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("creating symlinks needs privileges on Windows")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const leak = "/nix/store/kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk-leak-1"
	env, outside := filepath.Join(root, "env"), filepath.Join(root, "outside")
	for _, d := range []string{"env/bin", "env/share/doc", "env/etc", "outside"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"env/bin/hello":     nixHello + "/bin/hello",
		"env/bin/hi":        nixHello + "/bin/hi", // a second link into one member
		"env/bin/which":     nixWhich + "/bin/which",
		"env/share/man":     "/nix/store/z2ib15rv88rh01ga3krx1qif3w7gz2v0-man-db-2.13.0/share/man",
		"env/share/doc/rel": "../../bin/hello", // inside the environment itself
		"env/lib":           outside,           // a symlinked directory is not entered
		"env/etc/host":      "/etc/hosts",      // outside the store
		"outside/x":         leak + "/bin/x",
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(env, "etc", "generated"), []byte(nixZlib), 0o600); err != nil {
		t.Fatal(err)
	}

	walk := func(guard func(string) string) nixInventory {
		r := executor.NewReal()
		n := &nixScan{log: progress.NewNoop(), ctx: context.Background(), walked: map[string]bool{},
			files: r.GuardedFiles([]string{root}, guard, 1<<20)}
		n.walkEnv(env)
		return n.inv
	}
	inv := walk(nil)
	want := "hello 2.12.1 " + nixHello + "\nman-db 2.13.0 /nix/store/z2ib15rv88rh01ga3krx1qif3w7gz2v0-man-db-2.13.0\nwhich 2.23 " + nixWhich
	if got := sortedNixRecords(inv); got != want || inv.incomplete {
		t.Errorf("records:\n%s\nincomplete %v\nwant:\n%s", got, inv.incomplete, want)
	}

	inv = walk(func(p string) string {
		if p == filepath.Join(env, "share") {
			return "refused"
		}
		return ""
	})
	if !inv.incomplete {
		t.Error("a refused directory left the walk complete")
	}
}
