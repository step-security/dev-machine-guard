//go:build unix

package devicepolicy

import (
	"errors"
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
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("Write: %v", err)
	}
	first := readFile(t, npmrcPath(home))

	conv, err := w.Converged(stdBody)
	if err != nil {
		t.Fatalf("Converged: %v", err)
	}
	if !conv {
		t.Fatal("expected Converged=true after a fresh write")
	}
	// A second write is byte-identical.
	if _, err := w.Write(stdBody); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if second := readFile(t, npmrcPath(home)); second != first {
		t.Fatalf("second write not idempotent:\n%q\n%q", first, second)
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
	if err := w.Clear(); err != nil {
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
	if err := w.Clear(); err != nil {
		t.Fatalf("Clear on absent file: %v", err)
	}
	if _, err := os.Stat(npmrcPath(home)); !os.IsNotExist(err) {
		t.Fatal("Clear must not create the file")
	}
}

func TestRestoreSnapshot(t *testing.T) {
	home := t.TempDir()
	w := newDiskWriter(t, home)
	if err := os.WriteFile(npmrcPath(home), []byte("registry=original\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := w.Write(stdBody); err != nil {
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

func TestAcquireReconcileLock_LifecycleAndContention(t *testing.T) {
	home := t.TempDir()
	w1 := newDiskWriter(t, home)

	lock, err := w1.AcquireReconcileLock()
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// The lock file and its directory chain now exist, 0600 file under a 0700 dir.
	lockDir := filepath.Join(home, ".stepsecurity", "locks")
	lockPath := filepath.Join(lockDir, "package_config-npm.lock")
	if fi, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file not created: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("lock file mode = %v, want 0600", fi.Mode().Perm())
	}
	if di, err := os.Stat(lockDir); err != nil {
		t.Fatalf("lock dir not created: %v", err)
	} else if di.Mode().Perm() != 0o700 {
		t.Fatalf("lock dir mode = %v, want 0700", di.Mode().Perm())
	}

	// A second, independent open of the same file observes contention (flock
	// treats the two file descriptions independently even within one process).
	w2 := newDiskWriter(t, home)
	if _, err := w2.AcquireReconcileLock(); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("second acquire while held: want ErrLockHeld, got %v", err)
	}

	// Releasing closes the fd but must NEVER unlink the file — a recreate would
	// let two processes lock different inodes under one path and both proceed.
	if err := lock.Close(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file must survive release (never unlinked): %v", err)
	}

	// After release the lock is re-acquirable on the same inode.
	lock2, err := w2.AcquireReconcileLock()
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	if err := lock2.Close(); err != nil {
		t.Fatalf("release 2: %v", err)
	}
}

func TestAcquireReconcileLock_PreexistingStepsecurityDir(t *testing.T) {
	// The common case: ~/.stepsecurity already exists (config.json lives there).
	// Mkdir returns ErrExist and the lock still acquires; the pre-existing dir is
	// left untouched.
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".stepsecurity"), 0o700); err != nil {
		t.Fatalf("seed .stepsecurity: %v", err)
	}
	w := newDiskWriter(t, home)
	lock, err := w.AcquireReconcileLock()
	if err != nil {
		t.Fatalf("acquire with pre-existing .stepsecurity: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("release: %v", err)
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
	if err := w.Clear(); err != nil {
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

func TestAcquireReconcileLock_SymlinkedLockPathRejected(t *testing.T) {
	// A user who pre-plants the lock path as an in-home symlink must not get the
	// (possibly root) daemon to open-and-chown the pointed-at file. openLockFile
	// Lstat-rejects a symlink at the lock path rather than following it.
	home := t.TempDir()
	locks := filepath.Join(home, ".stepsecurity", "locks")
	if err := os.MkdirAll(locks, 0o700); err != nil {
		t.Fatalf("mkdir locks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "target"), []byte("secret\n"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	// Relative, in-home target so os.Root would otherwise follow it.
	if err := os.Symlink(filepath.Join("..", "..", "target"), filepath.Join(locks, "package_config-npm.lock")); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}
	w := newDiskWriter(t, home)
	if _, err := w.AcquireReconcileLock(); !isTargetUnusable(err) {
		t.Fatalf("symlinked lock path: want ErrTargetUnusable, got %v", err)
	}
}

func TestAcquireReconcileLock_FreshDirNotCreatorOwnedRejected(t *testing.T) {
	// The dir-chown path binds the created inode by requiring it be owned by our own
	// euid — proof the daemon created it, and that an attacker did not rmdir+swap in
	// their own directory after the Mkdir (they cannot forge a root-owned one). A
	// handle reporting a foreign owner is refused rather than chowned to the user.
	home := t.TempDir()
	w := newDiskWriter(t, home)
	w.owners = fakeOwner{uid: uint32(os.Geteuid()) + 1, enforced: true} // never our euid
	if _, err := w.AcquireReconcileLock(); !isTargetUnusable(err) {
		t.Fatalf("fresh dir with a foreign owner: want ErrTargetUnusable, got %v", err)
	}
}
