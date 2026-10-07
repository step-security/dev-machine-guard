//go:build unix

package secureuserfile

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const enforcePOSIXMetadata = true

func nonblockOpenFlag() int { return syscall.O_NONBLOCK }

func interactiveSessionOK(executor.Executor) bool { return true }

func secureUserIDs(u *user.User) (int, int, error) {
	uid, uidErr := strconv.Atoi(u.Uid)
	gid, gidErr := strconv.Atoi(u.Gid)
	if uidErr != nil || gidErr != nil {
		return 0, 0, fmt.Errorf("secure user file: target user %q has non-numeric uid/gid", u.Username)
	}
	return uid, gid, nil
}

func applySecureMetadata(h *Home, f *os.File, mode os.FileMode, _ bool) error {
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("secure user file: fchmod: %w", err)
	}
	if err := f.Chown(h.uid, h.gid); err != nil {
		return fmt.Errorf("secure user file: fchown: %w", err)
	}
	return nil
}

// repairSecureMetadata is applySecureMetadata on POSIX: fchown to the already
// verified owner is a no-op, so no extra privilege is requested.
func repairSecureMetadata(h *Home, f *os.File, mode os.FileMode, directory bool) error {
	return applySecureMetadata(h, f, mode, directory)
}

func checkSecurePlatformOwner(_ *Home, _ *os.File) error { return nil }

func newOwnerReader() ownerReader { return unixOwnerReader{} }

type unixOwnerReader struct{}

func (unixOwnerReader) secure(f *os.File, _ *Home, want os.FileMode) (bool, error) {
	info, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("secure user file: stat metadata: %w", err)
	}
	return info.Mode().Perm() == want.Perm(), nil
}

func (unixOwnerReader) ownerUIDGID(f *os.File) (uid, gid uint32, enforced bool, err error) {
	info, err := f.Stat()
	if err != nil {
		return 0, 0, true, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, true, errors.New("secure user file: handle has no unix owner metadata")
	}
	return stat.Uid, stat.Gid, true, nil
}
