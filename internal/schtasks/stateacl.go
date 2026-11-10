package schtasks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Well-known SIDs the grants are written against: SYSTEM, BUILTIN\Administrators,
// BUILTIN\Users and CREATOR OWNER.
const (
	sidSystem       = "*S-1-5-18"
	sidAdmins       = "*S-1-5-32-544"
	sidUsers        = "*S-1-5-32-545"
	sidCreatorOwner = "*S-1-3-0"
)

// sharedAppendFiles are the files in the machine-wide state directory that a
// signed-in user's scan appends to: the error log every run writes and the
// seen-users visit file. They are created at install so SYSTEM owns them and
// users get write and append on the file alone, never delete or replace.
var sharedAppendFiles = []string{"agent.error.log", "seen-users.txt"}

// protectedStateFiles are the files in the machine-wide state directory that
// only SYSTEM and administrators may change: the tenant configuration and
// the bootstrap it came from, the machine identity, the markers the SYSTEM
// tasks trust, and the machine-level run records. Users read them.
var protectedStateFiles = []string{"config.json", "bootstrap.json", "device-id", "image-builder.json", "multi-user.json", "last-run.json", "scan-state.json", "node-scan-cache.json"}

// hardenStateDirACLs puts the least-privilege ACLs on the machine-wide state
// directory (C:\ProgramData\StepSecurity on an admin install). The directory
// holds the tenant config, the machine identity, the markers and the
// updater's state the SYSTEM tasks trust, next to every session's own state;
// the earlier blanket Users:Modify grant let any signed-in user replace them
// and redirect what SYSTEM runs. Users may list and read the tree, create
// files there and their own subdirectory under users\ (what they create is
// theirs through CREATOR OWNER), and append to the shared log and visit
// files; the protected files and state\ stay SYSTEM and Administrators only.
// Idempotent, so the updater re-applies it on existing installs. The first
// icacls failure is returned; the caller logs it and the install goes on.
func hardenStateDirACLs(ctx context.Context, exec executor.Executor, root string) error {
	if err := os.MkdirAll(filepath.Join(root, "users"), 0o755); err != nil { // #nosec G301 -- shared install dir
		return fmt.Errorf("creating %s: %w", filepath.Join(root, "users"), err)
	}
	for _, name := range sharedAppendFiles {
		f, err := os.OpenFile(filepath.Join(root, name), os.O_CREATE|os.O_WRONLY, 0o644) // #nosec G302,G304 -- shared log and visit files under the install dir
		if err != nil {
			return fmt.Errorf("creating %s: %w", filepath.Join(root, name), err)
		}
		_ = f.Close()
	}
	steps := [][]string{
		{root, "/inheritance:r", "/grant:r", sidSystem + ":(OI)(CI)F", "/grant:r", sidAdmins + ":(OI)(CI)F", "/grant:r", sidUsers + ":(RX,WD,AD)", "/grant:r", sidCreatorOwner + ":(OI)(CI)(IO)F", "/Q"},
		{filepath.Join(root, "users"), "/inheritance:r", "/grant:r", sidSystem + ":(OI)(CI)F", "/grant:r", sidAdmins + ":(OI)(CI)F", "/grant:r", sidUsers + ":(CI)(RX,WD,AD)", "/grant:r", sidCreatorOwner + ":(OI)(CI)(IO)F", "/Q"},
	}
	for _, name := range sharedAppendFiles {
		steps = append(steps, []string{filepath.Join(root, name), "/inheritance:r", "/grant:r", sidSystem + ":F", "/grant:r", sidAdmins + ":F", "/grant:r", sidUsers + ":(RD,WD,AD)", "/Q"})
	}
	for _, name := range protectedStateFiles {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			continue
		}
		steps = append(steps, []string{filepath.Join(root, name), "/inheritance:r", "/grant:r", sidSystem + ":F", "/grant:r", sidAdmins + ":F", "/grant:r", sidUsers + ":R", "/Q"})
	}
	if info, err := os.Stat(filepath.Join(root, "state")); err == nil && info.IsDir() {
		steps = append(steps, []string{filepath.Join(root, "state"), "/inheritance:r", "/grant:r", sidSystem + ":(OI)(CI)F", "/grant:r", sidAdmins + ":(OI)(CI)F", "/grant:r", sidUsers + ":(OI)(CI)RX", "/Q"})
	}
	for _, step := range steps {
		if _, stderr, code, err := exec.Run(ctx, "icacls", step...); err != nil || code != 0 {
			return fmt.Errorf("icacls %s (exit code %d, %v): %s", step[0], code, err, stderr)
		}
	}
	return nil
}
