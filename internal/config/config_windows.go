//go:build windows

package config

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"

	"github.com/step-security/dev-machine-guard/internal/winproc"
	"golang.org/x/sys/windows"
)

// machineConfigDir is the machine-wide config location on Windows. The
// path is hardcoded (not derived from %PROGRAMDATA%) so it matches what
// the MSI WiX manifest hardcodes — keeping installer and binary in sync.
func machineConfigDir() string {
	return `C:\ProgramData\StepSecurity`
}

// isElevated reports whether the current process holds an elevated token
// (admin rights / UAC-elevated). MSI custom actions running deferred with
// Impersonate=no execute under LocalSystem, which is elevated.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// hardenMachineConfigACL locks down the machine-wide config.json with an
// explicit ACL: SYSTEM + Administrators get Full; BUILTIN\Users gets Read
// (so the scheduled task running as the logged-in user can still load it),
// inheritance is disabled, and the file is not writable by non-admins.
// POSIX file-mode bits we set in save() don't actually enforce anything on
// Windows; this is what does. Mirrors the icacls pattern used in
// internal/schtasks/schtasks.go for the agent.log directory.
//
// Best-effort: on failure we emit a warning to stderr (which the MSI's
// WixQuietExec custom action captures into the install log, making it
// visible to SCCM admins during troubleshooting) AND return the error so
// callers MAY surface it further if they choose. The install does not
// abort — the config is still functional with default inherited
// ProgramData ACLs (which are also Administrators/SYSTEM full + Users
// read-and-execute on existing files, just not as tightly scoped).
func hardenMachineConfigACL(path string) error {
	args := []string{
		path,
		"/inheritance:r",          // remove inherited ACEs
		"/grant:r", "*S-1-5-18:F", // NT AUTHORITY\SYSTEM = Full
		"/grant:r", "*S-1-5-32-544:F", // BUILTIN\Administrators = Full
		"/grant:r", "*S-1-5-32-545:R", // BUILTIN\Users = Read
		"/Q",
	}
	cmd := exec.Command("icacls", args...)
	winproc.HideWindow(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: icacls hardening of %q failed: %v\nicacls output:\n%s\n",
			path, err, output)
	}
	return err
}

// preserveOwner is a no-op on Windows: access is ACL-based (see
// hardenMachineConfigACL), not owner-based.
func preserveOwner(path string, prev os.FileInfo) {}

// openNoFollow opens path for reading after checking that it is not a
// symlink or other reparse point. Windows has no O_NOFOLLOW; the lookup is
// never used by an elevated run (installTreeLookupAllowed), so a swap in the
// gap only affects the user who could already read and edit the file.
func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fs.ErrInvalid
	}
	return os.Open(path) // #nosec G304 -- derived from the running binary's own location.
}

// installTreeLookupAllowed: never for an elevated or SYSTEM run. The SYSTEM
// self-updater trusts config.json only because users cannot write the
// machine-wide copy; a file next to the binary carries no such guarantee,
// and the machine-wide lookup must keep outranking everything there.
func installTreeLookupAllowed() bool { return !isElevated() }

// installTreeFileTrusted: an unelevated user reading a file it can already
// read gains nothing it did not have; ACLs are the control on Windows.
func installTreeFileTrusted(os.FileInfo) bool { return true }
