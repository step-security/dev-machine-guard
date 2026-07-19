package devicepolicy

import (
	"errors"
	"fmt"
	"os"
)

// This file adds the cross-process reconciliation lock for the package_config
// #npm category on top of NPMRCWriter. Package-config enforcement runs OUTSIDE
// the telemetry singleton lock (which lives inside telemetry.Run and is released
// when it returns), so a scheduled cycle and a manual run — or a root-daemon
// cycle and a user-mode manual run — could otherwise converge the same ~/.npmrc
// concurrently. This lock serializes them on ONE identity per guarded file.

// Lock placement, relative to the target user's home. The lock guards exactly
// one file (~/.npmrc), so its identity is a function of that FILE, not of the
// process's privilege: a root-daemon cycle and a user-mode manual run converge
// the same file and therefore must contend on the same lock. The lock lives in
// the target user's own tree in BOTH modes (root can write there; a per-mode
// location would let the two modes interleave freely).
const (
	npmrcStateDirRel = ".stepsecurity"
	npmrcLockDirRel  = ".stepsecurity/locks"
	npmrcLockPathRel = ".stepsecurity/locks/package_config-npm.lock"
)

// npmrcLockDirMode is the lock directory's mode on POSIX. It holds a coordination
// primitive, not shared data, so it is not group/other-accessible.
const npmrcLockDirMode os.FileMode = 0o700

// ErrLockHeld signals another agent process already holds the package-config
// reconciliation lock for this file. The current cycle must skip silently and
// retry next tick — it never reports compliance, because the holder is already
// converging and will report.
var ErrLockHeld = errors.New("npmrc: reconciliation lock held by another process")

// npmrcLock is a held cross-process lock. Release closes the fd (which drops the
// OS advisory lock); the lock FILE is deliberately never unlinked — unlink then
// recreate would let two processes lock different inodes under one path and both
// "win".
type npmrcLock struct {
	f *os.File
}

// Close releases the lock by closing its fd. The lock file is intentionally left
// on disk for the next cycle to re-lock.
func (l *npmrcLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// AcquireReconcileLock takes the cross-process reconciliation lock that
// serializes package-config convergence of THIS user's ~/.npmrc across every
// agent process and privilege mode:
//
//   - The lock file lives at <home>/.stepsecurity/locks/package_config-npm.lock,
//     created through the SAME home os.Root the writer uses, so no path component
//     is ever resolved through a symlink out of the home — the primitive the
//     writer already defends against for .npmrc itself.
//   - On POSIX the lock directory and file are chowned to the target user via
//     open handles, so a root-daemon cycle creates a lock the later user-mode
//     agent can still open — without it the two modes could never share one inode.
//   - The lock is advisory and non-blocking. Held by another process → ErrLockHeld
//     (the caller skips this cycle). It is held on a persistent fd and is NEVER
//     unlinked on release.
//
// Any error other than ErrLockHeld is an infrastructure failure (cannot create
// the directory/file, EPERM); the caller classifies it like an unavailable
// writer — surfaced on enforce, silent on clear/absent.
func (w *NPMRCWriter) AcquireReconcileLock() (*npmrcLock, error) {
	if w == nil || w.root == nil {
		return nil, errors.New("npmrc: writer is closed")
	}
	// Create the lock directory chain if absent. Only a directory THIS call freshly
	// creates is chowned to the target user; a pre-existing one (the user's own
	// ~/.stepsecurity, possibly an in-home symlink to their dotfiles) is left as
	// found. os.Root confines every component to the home tree.
	for _, dir := range []string{npmrcStateDirRel, npmrcLockDirRel} {
		if err := w.ensureOwnedDir(dir); err != nil {
			return nil, err
		}
	}

	f, created, err := w.openLockFile()
	if err != nil {
		return nil, err
	}
	// Chown ONLY a lock file this call just created (O_EXCL guarantees it is a
	// fresh regular file). An already-present lock is never chowned: it could be an
	// in-home symlink or a file the user planted, and transferring ownership of a
	// file we did not create is exactly the root-to-user escalation this guards
	// against. Chown-on-create is still enough for the two modes to share one inode
	// (a root cycle creates it user-owned; a later user cycle opens it).
	if created && enforcePOSIXMetadata {
		if err := chownHandle(f, w.uid, w.gid); err != nil {
			f.Close()
			return nil, fmt.Errorf("npmrc: chown lock file: %w", err)
		}
	}

	acquired, err := tryExclusiveLock(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("npmrc: lock: %w", err)
	}
	if !acquired {
		f.Close()
		return nil, ErrLockHeld
	}
	return &npmrcLock{f: f}, nil
}

// openLockFile creates the lock file if absent, or opens the existing one — in
// both cases without ever following a symlink at the final component, the same
// discipline readCurrent applies to .npmrc. It returns created=true only when this
// call made a fresh regular file via O_CREATE|O_EXCL (the one open mode os.Root
// never resolves through a final symlink). If the file already exists it is opened
// O_RDWR after an Lstat pre-screen (reject a symlink or non-regular file) plus a
// post-open SameFile re-check, so an in-home symlink swapped in at the path cannot
// redirect the open. Only a freshly created file is safe for the caller to chown.
func (w *NPMRCWriter) openLockFile() (f *os.File, created bool, err error) {
	f, err = w.root.OpenFile(npmrcLockPathRel, os.O_CREATE|os.O_EXCL|os.O_RDWR, npmrcFileMode)
	if err == nil {
		return f, true, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, false, fmt.Errorf("npmrc: create lock file: %w", err)
	}

	li, err := w.root.Lstat(npmrcLockPathRel)
	if err != nil {
		return nil, false, fmt.Errorf("npmrc: lstat lock file: %w", err)
	}
	if li.Mode()&os.ModeSymlink != 0 || !li.Mode().IsRegular() {
		return nil, false, fmt.Errorf("npmrc: lock path is not a regular file: %w", ErrTargetUnusable)
	}
	f, err = w.root.OpenFile(npmrcLockPathRel, os.O_RDWR|nonblockOpenFlag(), 0)
	if err != nil {
		return nil, false, fmt.Errorf("npmrc: open lock file: %w", err)
	}
	hi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, false, fmt.Errorf("npmrc: stat lock handle: %w", err)
	}
	li2, err := w.root.Lstat(npmrcLockPathRel)
	if err != nil {
		f.Close()
		return nil, false, fmt.Errorf("npmrc: re-lstat lock file: %w", err)
	}
	if li2.Mode()&os.ModeSymlink != 0 || !hi.Mode().IsRegular() || !os.SameFile(li2, hi) {
		f.Close()
		return nil, false, fmt.Errorf("npmrc: lock file changed during open: %w", ErrTargetUnusable)
	}
	return f, false, nil
}

// ensureOwnedDir creates one directory relative to the home root if it does not
// exist and, on POSIX, chowns a freshly created one to the target user. An
// already-present directory is left exactly as found (the config layer owns
// ~/.stepsecurity, which may legitimately be an in-home symlink). It goes through
// the home os.Root so no path component is ever resolved out of the home. Before
// the chown it BINDS the created inode two ways so a create→open swap cannot
// redirect ownership onto another file: the opened handle's identity is
// re-verified (Lstat not-a-symlink + SameFile), AND the handle must be owned by
// our own effective uid — proof it is the directory we just made, since the user
// who controls this tree cannot fabricate a root-owned directory to swap in. The
// path re-Lstat alone cannot provide that anchor: it would happily bind an
// attacker's stable swap. Only after both checks is ownership transferred.
func (w *NPMRCWriter) ensureOwnedDir(rel string) error {
	err := w.root.Mkdir(rel, npmrcLockDirMode)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("npmrc: mkdir %q: %w", rel, err)
	}
	if !enforcePOSIXMetadata {
		return nil
	}
	li, lerr := w.root.Lstat(rel)
	if lerr != nil {
		return fmt.Errorf("npmrc: lstat dir %q: %w", rel, lerr)
	}
	if li.Mode()&os.ModeSymlink != 0 || !li.IsDir() {
		return fmt.Errorf("npmrc: lock dir %q is not a directory: %w", rel, ErrTargetUnusable)
	}
	d, oerr := w.root.Open(rel)
	if oerr != nil {
		return fmt.Errorf("npmrc: open dir %q for chown: %w", rel, oerr)
	}
	defer d.Close()
	di, serr := d.Stat()
	if serr != nil {
		return fmt.Errorf("npmrc: stat dir handle %q: %w", rel, serr)
	}
	li2, lerr := w.root.Lstat(rel)
	if lerr != nil {
		return fmt.Errorf("npmrc: re-lstat dir %q: %w", rel, lerr)
	}
	if li2.Mode()&os.ModeSymlink != 0 || !di.IsDir() || !os.SameFile(li2, di) {
		return fmt.Errorf("npmrc: lock dir %q changed during creation: %w", rel, ErrTargetUnusable)
	}
	// Creator-identity anchor: a directory we just created is owned by our own
	// effective uid (root under the daemon). The target user could rmdir+swap rel
	// between the Mkdir and this open, but cannot fabricate a root-owned directory,
	// so an owner==euid handle proves this is the inode we created and not a
	// substitution — the guarantee SameFile above cannot make on its own.
	duid, _, downed, oerr := w.owners.ownerUIDGID(d)
	if oerr != nil {
		return fmt.Errorf("npmrc: read new dir owner %q: %w", rel, oerr)
	}
	if downed && duid != uint32(os.Geteuid()) {
		return fmt.Errorf("npmrc: lock dir %q not owned by its creator; refusing chown: %w", rel, ErrTargetUnusable)
	}
	if cerr := chownHandle(d, w.uid, w.gid); cerr != nil {
		return fmt.Errorf("npmrc: chown dir %q: %w", rel, cerr)
	}
	return nil
}
