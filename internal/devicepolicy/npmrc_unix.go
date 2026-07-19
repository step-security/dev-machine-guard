//go:build unix

package devicepolicy

import (
	"errors"
	"os"
	"syscall"
)

// enforcePOSIXMetadata gates every mode/owner decision in the writer. On Unix
// the writer asserts mode 0600 and chowns the file to the target user; the
// Windows counterpart leaves both to the platform's ACL model.
const enforcePOSIXMetadata = true

// nonblockOpenFlag adds O_NONBLOCK to the leaf open so that if the entry was
// swapped for a FIFO between the pre-screen Lstat and the open, the open returns
// immediately instead of blocking the daemon before the regular-file check can
// run. It is harmless on a regular file.
func nonblockOpenFlag() int { return syscall.O_NONBLOCK }

// chownHandle sets ownership on an already-open handle (fchown), never by path,
// so the operation cannot be redirected through a swapped symlink.
func chownHandle(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }

// tryExclusiveLock attempts a non-blocking exclusive advisory lock (flock) on an
// open file. acquired=true when this fd now holds it; acquired=false with a nil
// error means another process holds it (contention); a non-nil error is an
// infrastructure failure. The lock releases when the fd is closed.
func tryExclusiveLock(f *os.File) (acquired bool, err error) {
	e := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if e == nil {
		return true, nil
	}
	if errors.Is(e, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return false, e
}

// interactiveSessionOK is the Windows-only session guard. On Unix the console
// user was already resolved by the executor, so there is nothing further to
// gate here.
func interactiveSessionOK() bool { return true }

func newOwnerReader() ownerReader { return unixOwnerReader{} }

// unixOwnerReader reads the owning uid/gid from an open handle's stat.
type unixOwnerReader struct{}

func (unixOwnerReader) ownerUIDGID(f *os.File) (uid, gid uint32, enforced bool, err error) {
	fi, serr := f.Stat()
	if serr != nil {
		return 0, 0, true, serr
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, true, errors.New("npmrc: file handle has no unix owner metadata")
	}
	return st.Uid, st.Gid, true, nil
}
