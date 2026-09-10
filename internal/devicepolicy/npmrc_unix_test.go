//go:build unix

package devicepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// fakeOwner is an injectable ownerReader for exercising ownership branches
// without root: it reports whatever uid/gid the test sets, while the file's
// real mode is still read from disk.
type fakeOwner struct {
	uid, gid uint32
	enforced bool
	err      error
}

func (f fakeOwner) ownerUIDGID(_ *os.File) (uint32, uint32, bool, error) {
	return f.uid, f.gid, f.enforced, f.err
}

// newDiskWriter builds a writer anchored at a real tempdir home. Files created
// there are owned by the test process, so the real ownership reader is used by
// default; tests needing a foreign owner swap w.owners.
func newDiskWriter(t *testing.T, home string) *NPMRCWriter {
	t.Helper()
	root, err := os.OpenRoot(home)
	if err != nil {
		t.Fatalf("OpenRoot(%q): %v", home, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return &NPMRCWriter{
		home:   home,
		root:   root,
		owners: newOwnerReader(),
		uid:    os.Getuid(),
		gid:    os.Getgid(),
	}
}

func npmrcPath(home string) string { return filepath.Join(home, ".npmrc") }

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return string(b)
}

// TestWrite_CreatesFile covers edge 1 and doubles as the os.Root.OpenRoot(".")
// canary for the common direct-.npmrc case.
func TestWrite_CreatesFile(t *testing.T) {
	home := t.TempDir()
	w := newDiskWriter(t, home)

	body, err := w.Write(stdBody)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if body != stdBody {
		t.Fatalf("readback body = %q, want %q", body, stdBody)
	}
	got := readFile(t, npmrcPath(home))
	if got != block(stdBody) {
		t.Fatalf("file content = %q, want %q", got, block(stdBody))
	}
	fi, err := os.Stat(npmrcPath(home))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestWrite_ThenConvergedTrue(t *testing.T) { // edge 15 on disk
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdSettingsBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	first := readFile(t, npmrcPath(home))

	conv, err := w.Converged(stdSettingsBody)
	if err != nil {
		t.Fatalf("Converged: %v", err)
	}
	if !conv {
		t.Fatal("expected Converged=true after a fresh write")
	}
	// A second write is byte-identical.
	if _, err := w.Write(stdSettingsBody); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if second := readFile(t, npmrcPath(home)); second != first {
		t.Fatalf("second write not idempotent:\n%q\n%q", first, second)
	}
}

func TestWrite_SettingsConvergesAndClearsExactly(t *testing.T) {
	home := t.TempDir()
	path := npmrcPath(home)
	original := []byte("save-exact=false\r\n@example:registry=https://old.example/\r\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdSettingsBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	converged, err := w.Converged(stdSettingsBody)
	if err != nil {
		t.Fatalf("Converged: %v", err)
	}
	if !converged {
		t.Fatal("settings block did not converge")
	}
	if _, err := w.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("cleared bytes = %q, want %q", got, original)
	}
}

func TestWrite_RejectsStaleMDMBlocksWithoutMutation(t *testing.T) {
	tests := []struct {
		name    string
		content string
		body    string
	}{
		{name: "fixed block", content: mdmBlock(), body: stdBody},
		{name: "bounded block", content: boundedMDMBlock(stdSettingsBody), body: stdSettingsBody},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := npmrcPath(home)
			before := []byte(tc.content)
			if err := os.WriteFile(path, before, 0o600); err != nil {
				t.Fatal(err)
			}
			beforeInfo, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			w := newDiskWriter(t, home)
			if _, err := w.Write(tc.body); !isTargetUnusable(err) {
				t.Fatalf("Write error = %v, want target unusable", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("content changed: %q != %q", after, before)
			}
			afterInfo, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(beforeInfo, afterInfo) {
				t.Fatal("file identity changed")
			}
			if afterInfo.Mode() != beforeInfo.Mode() {
				t.Fatalf("mode = %v, want %v", afterInfo.Mode(), beforeInfo.Mode())
			}
			if !afterInfo.ModTime().Equal(beforeInfo.ModTime()) {
				t.Fatalf("mtime = %v, want %v", afterInfo.ModTime(), beforeInfo.ModTime())
			}
			backups, err := filepath.Glob(path + ".dmg-*.bak")
			if err != nil {
				t.Fatal(err)
			}
			if len(backups) != 0 {
				t.Fatalf("backup residue = %v, want none", backups)
			}
		})
	}
}

func TestConverged_FalseOnLooseMode(t *testing.T) { // edge 18
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := os.Chmod(npmrcPath(home), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	conv, err := w.Converged(stdBody)
	if err != nil {
		t.Fatalf("Converged: %v", err)
	}
	if conv {
		t.Fatal("expected Converged=false when mode is 0644")
	}
}

func TestConverged_RootOwnedRejected(t *testing.T) { // edge 19 (root-owned refused)
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// A root-owned direct .npmrc is never one this writer left behind — it always
	// chowns its output to the target user. Reading it would disclose potentially
	// root-only content into a user-owned backup, so the read fails closed
	// (ErrTargetUnusable → write_failed) rather than quietly reporting "not
	// converged".
	w.owners = fakeOwner{uid: 0, enforced: true}
	if _, err := w.Converged(stdBody); !isTargetUnusable(err) {
		t.Fatalf("root-owned leaf: want ErrTargetUnusable, got %v", err)
	}
}

func TestConverged_FalseWhenActiveRegistryBelowBlock(t *testing.T) { // edge 27
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// `aws codeartifact login`-style append below the block leaves the body
	// equal but defeats precedence.
	f, err := os.OpenFile(npmrcPath(home), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	if _, err := f.WriteString("registry=https://evil/\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	conv, err := w.Converged(stdBody)
	if err != nil {
		t.Fatalf("Converged: %v", err)
	}
	if conv {
		t.Fatal("expected Converged=false when an active registry follows the block")
	}
}

func TestForeignOwner_ReadRejected(t *testing.T) { // edge 36
	home := t.TempDir()
	if err := os.WriteFile(npmrcPath(home), []byte("registry=x\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := newDiskWriter(t, home)
	w.owners = fakeOwner{uid: 99999, enforced: true}

	if _, _, err := w.Read(); !isTargetUnusable(err) {
		t.Fatalf("Read of foreign-owned file: want ErrTargetUnusable, got %v", err)
	}
}

func TestClear_RemovesBlockKeepsFile(t *testing.T) { // edge 9 / 24 on disk
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if err := os.WriteFile(npmrcPath(home), []byte("registry=https://registry.npmjs.org/\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := w.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	got := readFile(t, npmrcPath(home))
	if strings.Contains(got, npmrcBeginMarker) {
		t.Fatalf("block not removed by Clear: %q", got)
	}
	if !strings.Contains(got, "registry=https://registry.npmjs.org/\n") {
		t.Fatalf("Clear did not restore the commented registry line: %q", got)
	}
}

func TestClear_AbsentFileIsNoOp(t *testing.T) {
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if _, err := w.Clear(); err != nil {
		t.Fatalf("Clear on absent file: %v", err)
	}
	if _, err := os.Stat(npmrcPath(home)); !os.IsNotExist(err) {
		t.Fatal("Clear must not create the file")
	}
}

func TestClear_RestoresCreatedFileToAbsent(t *testing.T) {
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); err != nil {
		t.Fatal(err)
	}
	state := AppliedTargetState{}
	if err := w.CompleteState(AppliedTargetState{}, false, &state); err != nil {
		t.Fatal(err)
	}
	if !state.FileCreated {
		t.Fatal("first write to an absent .npmrc must record file creation")
	}
	if err := w.PrepareClear(state, true); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(npmrcPath(home)); !os.IsNotExist(err) {
		t.Fatalf("created .npmrc survived clear: %v", err)
	}
}

func TestClear_PreservesPreexistingEmptyFile(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(npmrcPath(home), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); err != nil {
		t.Fatal(err)
	}
	state := AppliedTargetState{}
	if err := w.CompleteState(AppliedTargetState{}, false, &state); err != nil {
		t.Fatal(err)
	}
	if state.FileCreated {
		t.Fatal("pre-existing empty .npmrc recorded as agent-created")
	}
	if err := w.PrepareClear(state, true); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Clear(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(npmrcPath(home)); err != nil || info.Size() != 0 {
		t.Fatalf("pre-existing empty .npmrc was not preserved: info=%v err=%v", info, err)
	}
}

// Clear's bool is what lets a caller describe what happened without weakening the
// unconditional call: the clear must still run when no block is present (a lost
// ownership record must never strand a live one), so "did anything change" cannot
// be inferred from whether it was invoked. All three outcomes are pinned because
// only the true case may be reported as a removal.
func TestClear_ReportsWhetherAnythingChanged(t *testing.T) {
	const seed = "registry=https://registry.npmjs.org/\n"

	t.Run("absent file changes nothing", func(t *testing.T) {
		home := t.TempDir()
		changed, err := newDiskWriter(t, home).Clear()
		if err != nil {
			t.Fatalf("Clear: %v", err)
		}
		if changed {
			t.Fatal("Clear on an absent file must report changed=false")
		}
	})

	t.Run("no managed block changes nothing", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(npmrcPath(home), []byte(seed), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		changed, err := newDiskWriter(t, home).Clear()
		if err != nil {
			t.Fatalf("Clear: %v", err)
		}
		if changed {
			t.Fatal("Clear over a file with no managed block must report changed=false")
		}
		if got := readFile(t, npmrcPath(home)); got != seed {
			t.Fatalf("a no-op clear must leave the file byte-identical, got %q", got)
		}
	})

	t.Run("live block changes the file", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(npmrcPath(home), []byte(seed), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		w := newDiskWriter(t, home)
		if _, err := w.Write(stdBody); err != nil {
			t.Fatalf("Write: %v", err)
		}
		changed, err := w.Clear()
		if err != nil {
			t.Fatalf("Clear: %v", err)
		}
		if !changed {
			t.Fatal("Clear that removed a live block must report changed=true")
		}
		if got := readFile(t, npmrcPath(home)); strings.Contains(got, npmrcBeginMarker) {
			t.Fatalf("block not removed: %q", got)
		}
	})
}

func TestRestoreSnapshot(t *testing.T) {
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if err := os.WriteFile(npmrcPath(home), []byte("registry=original\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := w.Write(stdSettingsBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.RestoreSnapshot(); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	if got := readFile(t, npmrcPath(home)); got != "registry=original\n" {
		t.Fatalf("restore did not revert file: %q", got)
	}
}

func TestRestoreSnapshot_RemovesCreatedFile(t *testing.T) {
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); err != nil { // file did not exist before
		t.Fatalf("Write: %v", err)
	}
	if err := w.RestoreSnapshot(); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	if _, err := os.Stat(npmrcPath(home)); !os.IsNotExist(err) {
		t.Fatal("restore of a created file should remove it")
	}
}

func TestRestoreSnapshot_NoPending(t *testing.T) {
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if err := w.RestoreSnapshot(); err == nil {
		t.Fatal("RestoreSnapshot with no pending snapshot must error")
	}
}

func TestSymlink_RelativeInHomeResolved(t *testing.T) { // edge 22
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "dotfiles"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "dotfiles", "npmrc"), []byte("registry=orig\n"), 0o600); err != nil {
		t.Fatalf("seed leaf: %v", err)
	}
	if err := os.Symlink(filepath.Join("dotfiles", "npmrc"), npmrcPath(home)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("Write via symlink: %v", err)
	}
	// The chain is preserved: .npmrc is still a symlink.
	li, err := os.Lstat(npmrcPath(home))
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if li.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
	// The block landed at the resolved leaf, and a backup sits beside it.
	leaf := readFile(t, filepath.Join(home, "dotfiles", "npmrc"))
	if !strings.Contains(leaf, npmrcBeginMarker) {
		t.Fatalf("resolved leaf missing block: %q", leaf)
	}
	entries, _ := os.ReadDir(filepath.Join(home, "dotfiles"))
	backups := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "npmrc.dmg-") && strings.HasSuffix(e.Name(), ".bak") {
			backups++
		}
	}
	if backups == 0 {
		t.Fatal("expected a backup beside the resolved leaf")
	}
}

func TestSymlink_AbsoluteRejected(t *testing.T) { // edge 30
	home := t.TempDir()
	if err := os.Symlink("/etc/hosts", npmrcPath(home)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); !isTargetUnusable(err) {
		t.Fatalf("absolute symlink: want ErrTargetUnusable, got %v", err)
	}
}

func TestSymlink_EscapesHomeRejected(t *testing.T) { // edge 25
	home := t.TempDir()
	if err := os.Symlink(filepath.Join("..", "outside"), npmrcPath(home)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); !isTargetUnusable(err) {
		t.Fatalf("escaping symlink: want ErrTargetUnusable, got %v", err)
	}
}

func TestSymlink_SlashTerminatedRejected(t *testing.T) { // GO-2026-4970 regression
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "file"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Symlink("file/", npmrcPath(home)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); !isTargetUnusable(err) {
		t.Fatalf("slash-terminated symlink: want ErrTargetUnusable, got %v", err)
	}
}

func TestSymlink_DanglingRejected(t *testing.T) {
	home := t.TempDir()
	if err := os.Symlink("nonexistent-target", npmrcPath(home)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); !isTargetUnusable(err) {
		t.Fatalf("dangling symlink: want ErrTargetUnusable, got %v", err)
	}
}

func TestNonRegular_FIFORejected(t *testing.T) { // edge 31 (FIFO)
	home := t.TempDir()
	if err := syscall.Mkfifo(npmrcPath(home), 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); !isTargetUnusable(err) {
		t.Fatalf("FIFO leaf: want ErrTargetUnusable, got %v", err)
	}
}

func TestOversizeRejected(t *testing.T) { // edge 31 (size)
	home := t.TempDir()
	big := make([]byte, npmrcMaxBytes+10)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(npmrcPath(home), big, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); !isTargetUnusable(err) {
		t.Fatalf("oversize file: want ErrTargetUnusable, got %v", err)
	}
}

func TestProbeExpected_OnDisk(t *testing.T) { // edge 8 + metadata gate
	home := t.TempDir()
	if err := os.WriteFile(npmrcPath(home), []byte(mdmBlock()), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := newDiskWriter(t, home)
	if managed, _ := w.ProbeExpected(stdBody); !managed {
		t.Fatal("expected ProbeExpected=true for an effective 0600 MDM block")
	}
	// Loose metadata must not freeze the file as managed.
	if err := os.Chmod(npmrcPath(home), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if managed, _ := w.ProbeExpected(stdBody); managed {
		t.Fatal("ProbeExpected must reject an MDM block with loose (0644) metadata")
	}
}

func TestBackup_ModeAndRotation(t *testing.T) { // edge 28 + rotation cap
	home := t.TempDir()
	if err := os.WriteFile(npmrcPath(home), []byte("registry=seed\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := newDiskWriter(t, home)
	for i := 0; i < 5; i++ {
		if _, err := w.Write(stdBody); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	entries, _ := os.ReadDir(home)
	var backups []os.DirEntry
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".npmrc.dmg-") && strings.HasSuffix(e.Name(), ".bak") {
			backups = append(backups, e)
		}
	}
	if len(backups) == 0 || len(backups) > npmrcMaxBackups {
		t.Fatalf("expected 1..%d backups, got %d", npmrcMaxBackups, len(backups))
	}
	for _, b := range backups {
		fi, err := b.Info()
		if err != nil {
			t.Fatalf("info: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("backup %q mode = %v, want 0600", b.Name(), fi.Mode().Perm())
		}
	}
}

func TestConverged_SectionFailsClosed(t *testing.T) {
	// A [section] header above the block scopes npm's registry key so the block is
	// inert. Converged must fail closed (ErrTargetUnusable → write_failed) instead
	// of reporting a false 'compliant' on a body-equal but ineffective block.
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	orig := readFile(t, npmrcPath(home))
	if err := os.WriteFile(npmrcPath(home), []byte("[global]\n"+orig), 0o600); err != nil {
		t.Fatalf("prepend section: %v", err)
	}
	if _, err := w.Converged(stdBody); !isTargetUnusable(err) {
		t.Fatalf("sectioned file: want ErrTargetUnusable from Converged, got %v", err)
	}
}

func TestConverged_LoneCRFailsClosed(t *testing.T) {
	// A bare CR is a line break to npm but not to our '\n' split, so a section or
	// override could hide behind it. Converged must fail closed (ErrTargetUnusable
	// → write_failed), never report a false 'compliant'.
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	orig := readFile(t, npmrcPath(home))
	// Prepend a bare-CR line npm reads as `[global]` + `x=1` (a section) but our
	// '\n' split sees as one opaque line.
	if err := os.WriteFile(npmrcPath(home), []byte("[global]\rx=1\n"+orig), 0o600); err != nil {
		t.Fatalf("prepend lone CR: %v", err)
	}
	if _, err := w.Converged(stdBody); !isTargetUnusable(err) {
		t.Fatalf("lone-CR file: want ErrTargetUnusable from Converged, got %v", err)
	}
}

func TestConverged_CoercibleQuotedKeyFailsClosed(t *testing.T) {
	// A single-quoted non-string JSON key npm coerces to `registry` (e.g.
	// '["registry"]') appended below the block could override it invisibly to a
	// line-based check. Converged must fail closed (ErrTargetUnusable), never report
	// a false 'compliant'.
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	f, err := os.OpenFile(npmrcPath(home), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	if _, err := f.WriteString(`'["registry"]'=https://evil/` + "\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()
	if _, err := w.Converged(stdBody); !isTargetUnusable(err) {
		t.Fatalf("coercible quoted key: want ErrTargetUnusable from Converged, got %v", err)
	}
}

func TestClear_RemovesDuplicateBlocks(t *testing.T) {
	// Offboarding must revoke EVERY token: a file carrying two managed blocks must
	// clear to zero blocks and zero token bytes, not leave the second one live.
	home := t.TempDir()
	if err := os.WriteFile(npmrcPath(home), []byte(block(stdBody)+block(stdBody)), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	got := readFile(t, npmrcPath(home))
	if strings.Contains(got, npmrcBeginMarker) || strings.Contains(got, stdTokenVal) {
		t.Fatalf("clear left a duplicate block or live token behind: %q", got)
	}
}

func TestReadCurrent_LeafSwappedToSymlinkRejected(t *testing.T) { // edge 35
	// The leaf resolves as a regular file, then is swapped for a symlink before the
	// bounded read. readCurrent's Lstat pre-screen must reject it as
	// ErrTargetUnusable rather than follow the swap to another file.
	home := t.TempDir()
	if err := os.WriteFile(npmrcPath(home), []byte("registry=x\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "elsewhere"), []byte("registry=evil\n"), 0o600); err != nil {
		t.Fatalf("seed elsewhere: %v", err)
	}
	w := newDiskWriter(t, home)
	rt, err := w.resolveLeaf()
	if err != nil {
		t.Fatalf("resolveLeaf: %v", err)
	}
	defer rt.close()
	if err := os.Remove(npmrcPath(home)); err != nil {
		t.Fatalf("remove leaf: %v", err)
	}
	if err := os.Symlink("elsewhere", npmrcPath(home)); err != nil {
		t.Fatalf("symlink swap: %v", err)
	}
	if _, _, _, err := w.readCurrent(rt); !isTargetUnusable(err) {
		t.Fatalf("swapped-to-symlink leaf: want ErrTargetUnusable, got %v", err)
	}
}

func TestRestoreSnapshot_ConsumedAfterUse(t *testing.T) {
	// A snapshot is restored at most once: after a successful restore it is
	// consumed, so a second call has nothing to revert and errors.
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if err := os.WriteFile(npmrcPath(home), []byte("registry=original\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.RestoreSnapshot(); err != nil {
		t.Fatalf("first RestoreSnapshot: %v", err)
	}
	if err := w.RestoreSnapshot(); err == nil {
		t.Fatal("second RestoreSnapshot must error — the snapshot is consumed after one use")
	}
}

func TestProbeContentNPM_OnDisk(t *testing.T) {
	home := t.TempDir()
	w := newDiskWriter(t, home)

	// An absent file is the clean "nothing is managing this" signal, NOT an error:
	// the reconciler must report policy_not_applied, not verification_failed.
	present, observed, err := w.ProbeContentNPM(stdBody)
	if err != nil || present || observed != nil {
		t.Fatalf("absent ~/.npmrc = (%v, %v, %v), want (false, nil, nil)", present, observed, err)
	}

	if err := os.WriteFile(npmrcPath(home), []byte(mdmBlock()), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := os.ReadFile(npmrcPath(home))
	if err != nil {
		t.Fatal(err)
	}
	present, observed, err = w.ProbeContentNPM(stdBody)
	if err != nil || !present {
		t.Fatalf("an effective MDM block = (%v, %v), want present with no error", present, err)
	}
	if len(observed) != 3 {
		t.Fatalf("observed = %v, want exactly 3 keys", observed)
	}
	// Verify-only means verify-only: the file is never opened for writing, so not
	// one byte moves — no write, no clear, no rollback, no backup.
	after, err := os.ReadFile(npmrcPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("ProbeContentNPM mutated the file:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if entries, err := os.ReadDir(home); err != nil {
		t.Fatal(err)
	} else if len(entries) != 1 {
		t.Fatalf("ProbeContentNPM left extra files behind: %v", entries)
	}

	settingsBefore := []byte(boundedMDMBlock(stdSettingsBody))
	if err := os.WriteFile(npmrcPath(home), settingsBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	present, observed, err = w.ProbeContentNPM(stdSettingsBody)
	if err != nil {
		t.Fatalf("settings MDM block: %v", err)
	}
	if !present {
		t.Fatal("settings MDM block was not recognized")
	}
	if len(observed) != 4 {
		t.Fatalf("settings observed = %v, want exactly 4 keys", observed)
	}
	settingsAfter, err := os.ReadFile(npmrcPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if string(settingsAfter) != string(settingsBefore) {
		t.Fatalf("settings probe mutated the file: %q != %q", settingsAfter, settingsBefore)
	}
}

func TestProbeContentNPM_LooseModeObserved(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(npmrcPath(home), []byte(mdmBlock()), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := newDiskWriter(t, home)
	present, observed, err := w.ProbeContentNPM(stdBody)
	if err != nil {
		t.Fatalf("base-only probe: %v", err)
	}
	if !present {
		t.Fatal("base-only MDM block was not observed")
	}
	if len(observed) != 3 {
		t.Fatalf("base-only observed keys = %d, want 3", len(observed))
	}

	if err := os.WriteFile(npmrcPath(home), []byte(boundedMDMBlock(stdSettingsBody)), 0o644); err != nil {
		t.Fatal(err)
	}
	present, observed, err = w.ProbeContentNPM(stdSettingsBody)
	if err != nil {
		t.Fatalf("settings-aware probe: %v", err)
	}
	if !present {
		t.Fatal("settings-aware MDM block was not observed")
	}
	if len(observed) != 4 {
		t.Fatalf("settings-aware observed keys = %d, want 4", len(observed))
	}
}

func TestProbeContentNPM_UnreadableIsAnError(t *testing.T) {
	// A file we cannot trust as the target user's own effective config must NOT read
	// as the clean policy_not_applied: we could not establish what npm resolves, so
	// the honest answer is verification_failed.
	home := t.TempDir()
	if err := os.WriteFile(npmrcPath(home), []byte(mdmBlock()), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := newDiskWriter(t, home)
	w.owners = fakeOwner{uid: uint32(os.Getuid() + 1), enforced: true}
	present, observed, err := w.ProbeContentNPM(stdBody)
	if !isTargetUnusable(err) {
		t.Fatalf("a foreign-owned leaf must error with ErrTargetUnusable, got %v", err)
	}
	if present || observed != nil {
		t.Fatalf("a failed read must report nothing, got present=%v observed=%v", present, observed)
	}
}

func TestClear_PurgesTokenBearingBackups(t *testing.T) {
	// Offboarding must leave no readable copy of the token. Every backup after the
	// first holds a previous managed block, and the one Clear itself takes holds the
	// very block being revoked — so removing the block from the live file while
	// leaving those siblings on disk would revoke nothing recoverable. Clear purges
	// its own backups once the new bytes are committed.
	home := t.TempDir()
	if err := os.WriteFile(npmrcPath(home), []byte("registry=https://registry.npmjs.org/\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := newDiskWriter(t, home)
	for i := 0; i < 3; i++ {
		if _, err := w.Write(stdBody); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if backups := dmgBackups(t, home); len(backups) == 0 {
		t.Fatal("expected the writes to leave backups to purge")
	}
	if _, err := w.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if backups := dmgBackups(t, home); len(backups) != 0 {
		t.Fatalf("clear must purge our backups, got %v", backups)
	}
	// Nothing anywhere beside the leaf may still carry the token.
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.Contains(readFile(t, filepath.Join(home, e.Name())), stdTokenVal) {
			t.Fatalf("%q still contains the token after clear", e.Name())
		}
	}
	// The user's own pre-policy line is restored in the live file — the purge
	// removes our backups, not the user's content.
	if got := readFile(t, npmrcPath(home)); !strings.Contains(got, "registry=https://registry.npmjs.org/") {
		t.Fatalf("the user's original registry must be restored, got %q", got)
	}
}

func TestClear_NoOpClearRetriesTheBackupPurge(t *testing.T) {
	// The purge is best-effort, so an unlink that failed once must be retried rather
	// than stranded: nothing else ever revisits a token-bearing sibling. Both paths
	// that clear nothing — a file with no block of ours, and no file at all — reach
	// the same residue, so both retry. Unassignment calls Clear on every cycle, which
	// is what makes the retry fire.
	cases := []struct {
		name string
		seed func(home string)
	}{
		{"a file we do not manage", func(home string) {
			if err := os.WriteFile(npmrcPath(home), []byte("registry=https://registry.npmjs.org/\n"), 0o600); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}},
		{"no live file at all", func(string) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			tc.seed(home)
			// A backup an earlier purge could not remove, still holding the block.
			stale := filepath.Join(home, ".npmrc.dmg-deadbeef.bak")
			if err := os.WriteFile(stale, []byte(block(stdBody)), 0o600); err != nil {
				t.Fatal(err)
			}
			w := newDiskWriter(t, home)
			if _, err := w.Clear(); err != nil {
				t.Fatalf("Clear: %v", err)
			}
			if _, err := os.Stat(stale); !os.IsNotExist(err) {
				t.Fatalf("a later clear must retry the purge, stat err = %v", err)
			}
		})
	}
}

func TestClear_LoneCRIsAnErrorAndKeepsTheBlock(t *testing.T) {
	// On disk: a CR-delimited managed block cannot be located, so Clear reports an
	// error instead of a false success. The reconciler maps that to a failure and
	// keeps the ownership record, so a later run retries rather than forgetting a
	// token that is still on disk.
	home := t.TempDir()
	crFile := strings.ReplaceAll("cache=x\n"+block(stdBody), "\n", "\r")
	if err := os.WriteFile(npmrcPath(home), []byte(crFile), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A refused clear leaves the block live, so the backup is still the recovery aid
	// for it and must survive: only a clear that left nothing of ours purges.
	stale := filepath.Join(home, ".npmrc.dmg-deadbeef.bak")
	if err := os.WriteFile(stale, []byte(block(stdBody)), 0o600); err != nil {
		t.Fatal(err)
	}
	w := newDiskWriter(t, home)
	_, err := w.Clear()
	if !isTargetUnusable(err) {
		t.Fatalf("Clear must fail closed with ErrTargetUnusable, got %v", err)
	}
	if got := readFile(t, npmrcPath(home)); got != crFile {
		t.Fatalf("a refused clear must leave the file byte-identical, got %q", got)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("a refused clear must keep the backup as a recovery aid, stat err = %v", err)
	}
}

// dmgBackups lists the committed backups the writer maintains beside the leaf.
func dmgBackups(t *testing.T, home string) []string {
	t.Helper()
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".npmrc.dmg-") && strings.HasSuffix(e.Name(), ".bak") {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestWrite_SettingsOnlyTransitionsAndClearsExactly(t *testing.T) {
	home := t.TempDir()
	path := npmrcPath(home)
	original := []byte("registry=https://old.example/\nsave-exact=false\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.Write(stdSettingsBody); err != nil {
		t.Fatalf("StepSecurity write: %v", err)
	}
	if _, err := w.Write(stdSettingsOnlyBody); err != nil {
		t.Fatalf("settings-only write: %v", err)
	}
	if got := readFile(t, path); got != string(original)+block(stdSettingsOnlyBody) {
		t.Fatalf("settings-only file = %q, want restored registry line then block", got)
	}
	converged, err := w.Converged(stdSettingsOnlyBody)
	if err != nil {
		t.Fatalf("Converged: %v", err)
	}
	if !converged {
		t.Fatal("settings-only block did not converge")
	}
	if converged, _ := w.Converged(stdBody); converged {
		t.Fatal("settings-only block must not satisfy a StepSecurity-only body")
	}
	if _, err := w.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got := readFile(t, path); got != string(original) {
		t.Fatalf("cleared bytes = %q, want %q", got, original)
	}
}

func TestProbeContentNPM_SettingsOnlyOnDiskIsReadOnly(t *testing.T) {
	home := t.TempDir()
	w := newDiskWriter(t, home)
	content := "engine-strict=true\n" + boundedMDMBlock(stdSettingsOnlyBody)
	if err := os.WriteFile(npmrcPath(home), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	present, observed, err := w.ProbeContentNPM(stdSettingsOnlyBody)
	if err != nil || !present {
		t.Fatalf("settings-only MDM block = (%v, %v), want present with no error", present, err)
	}
	got := observedStrings(t, observed)
	if len(got) != 2 || got[observedKeySettingsStatus] != settingsMatch {
		t.Fatalf("observed = %v, want ecosystem and matching settings_status only", got)
	}
	if managed, _ := w.ProbeExpected(stdSettingsOnlyBody); !managed {
		t.Fatal("ProbeExpected did not recognize the settings-only MDM block")
	}
	if after := readFile(t, npmrcPath(home)); after != content {
		t.Fatalf("MDM probe mutated the file: %q", after)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 1 {
		t.Fatalf("MDM probe left extra files: %v", entries)
	}
}
