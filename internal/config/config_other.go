//go:build !windows

package config

import (
	"os"
	"syscall"
)

// machineConfigDir has no equivalent on non-Windows hosts — community/dev
// flows use per-user paths everywhere. Returning "" signals "no machine
// path; always read/write under the user's home."
func machineConfigDir() string { return "" }

// isElevated mirrors the Windows admin/SYSTEM check using POSIX euid==0
// so non-Windows test runs of save() / RunConfigureNonInteractive() can
// exercise the elevated branch deterministically when relevant.
func isElevated() bool { return os.Geteuid() == 0 }

// hardenMachineConfigACL is a no-op on non-Windows: file-mode bits we set
// in save() are the actual access control on POSIX hosts, so there is no
// equivalent ACL step. machineConfigDir() returns "" off-Windows, so the
// caller in save() only invokes this from the Windows code path in practice.
func hardenMachineConfigACL(path string) error { return nil }

// preserveOwner restores the replaced file's owner: a root run rewriting a
// user's config.json must not leave it root-owned and unreadable to the user.
func preserveOwner(path string, prev os.FileInfo) {
	if st, ok := prev.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		_ = os.Lchown(path, int(st.Uid), int(st.Gid))
	}
}

// openNoFollow opens path for reading without following a symlink at the
// last component, so the file checked is the file read.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- derived from the running binary's own location.
}

// installTreeLookupAllowed: a root run may read a config.json from its
// install tree, subject to installTreeFileTrusted; everyone else always may.
func installTreeLookupAllowed() bool { return true }

// installTreeFileTrusted guards the root case: a root-run agent whose binary
// sits in a user-writable directory must not adopt a config.json planted
// there (its install_dir would send root's logs and state wherever that
// user chose). Root only trusts a root-owned file nobody else can write.
func installTreeFileTrusted(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return installTreeFileTrustedFor(os.Geteuid(), st.Uid, info.Mode().Perm())
}

func installTreeFileTrustedFor(euid int, ownerUID uint32, perm os.FileMode) bool {
	if euid != 0 {
		return true
	}
	return ownerUID == 0 && perm&0o022 == 0
}
