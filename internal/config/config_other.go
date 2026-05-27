//go:build !windows

package config

import "os"

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
