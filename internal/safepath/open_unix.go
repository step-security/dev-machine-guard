//go:build !windows

package safepath

import (
	"os"

	"golang.org/x/sys/unix"
)

// openVerified opens an already-resolved path by walking it as descriptors:
// each directory component is opened relative to the previous one with
// O_NOFOLLOW|O_DIRECTORY, and the leaf relative to the last verified directory.
// Nothing is ever addressed by its full path string, so a component replaced
// with a symlink after resolution cannot redirect the open — the kernel rejects
// it with ELOOP and this fails closed.
//
// wantDir opens the leaf as a directory; otherwise as a regular file. The
// metadata comes back with the handle because it is read from the handle: a
// caller that stat'd the path instead would be describing whatever is at that
// name now, not what it is holding open.
func openVerified(resolved string, wantDir bool) (*os.File, os.FileInfo, error) {
	_, comps := split(resolved)
	if len(comps) == 0 {
		return nil, nil, refuse(ReasonUnresolved)
	}

	const dirFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_DIRECTORY | unix.O_CLOEXEC

	// Start at the filesystem root, which is the one component no local process
	// can swap.
	dirfd, err := unix.Openat(unix.AT_FDCWD, "/", dirFlags, 0)
	if err != nil {
		return nil, nil, refuse(ReasonDenied)
	}
	defer func() {
		if dirfd >= 0 {
			_ = unix.Close(dirfd)
		}
	}()

	for _, comp := range comps[:len(comps)-1] {
		next, oerr := unix.Openat(dirfd, comp, dirFlags, 0)
		if oerr != nil {
			return nil, nil, openErr(oerr)
		}
		_ = unix.Close(dirfd)
		dirfd = next
	}

	leafFlags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if wantDir {
		leafFlags |= unix.O_DIRECTORY
	}
	// O_NONBLOCK so a leaf that turns out to be a FIFO cannot block the phase
	// on open. A credential store is never a FIFO, and the read that follows
	// would return nothing useful either way.
	fd, err := unix.Openat(dirfd, comps[len(comps)-1], leafFlags|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, openErr(err)
	}
	// #nosec G115 -- fd is the descriptor openat just returned on success: a small
	// non-negative int, which is what uintptr carries for the rest of its life. A
	// failure returns above rather than reaching this line.
	f := os.NewFile(uintptr(fd), resolved)
	info, serr := f.Stat()
	if serr != nil {
		_ = f.Close()
		return nil, nil, refuse(ReasonDenied)
	}
	return f, info, nil
}

// openErr maps an openat failure to a refusal. ELOOP means O_NOFOLLOW hit a
// symlink where resolution had seen a real directory or file — the component
// changed underneath us, so the read is abandoned rather than retried.
func openErr(err error) error {
	switch err {
	case unix.ELOOP, unix.EMLINK, unix.ENOTDIR:
		return refuse(ReasonUnresolved)
	case unix.ENOENT:
		return os.ErrNotExist
	case unix.EACCES, unix.EPERM:
		return refuse(ReasonDenied)
	default:
		return refuse(ReasonDenied)
	}
}
