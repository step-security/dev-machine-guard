package schtasks

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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

// sharedWritableFiles are the machine-wide files every signed-in user's scan
// writes: the error log and the stdout log the task redirects to (appended
// to, and rotated by copying into .prev and truncating in place), and the
// seen-users visit file (rewritten in place under its lock). They are
// created at install so SYSTEM owns them, and users get Modify on the file
// alone: they can write, rotate and rewrite these, never the configuration,
// the identity or the updater state next to them. None of them is ever
// replaced by a rename: a file renamed into place belongs to the session
// that did it and is unwritable to every other.
var sharedWritableFiles = []string{"agent.error.log", "agent.error.log.prev", "agent.log", "agent.log.prev", "seen-users.txt"}

// scanStateFiles are the per-run state files an unscoped scan (a single-user
// host, or multi-user detection switched off) writes under the root itself.
// The scheduled task runs as the signed-in user, who must be able to replace
// them, so users get Modify on the ones that exist. They are not created
// here (absent means no run yet); on a per-session host each session's copies
// live under users\<token>\ and are the session's own.
var scanStateFiles = []string{"last-run.json", "scan-state.json", "node-scan-cache.json", "run-metrics.jsonl"}

// protectedStateFiles are the files only SYSTEM and administrators may
// change: the tenant configuration and the bootstrap it came from, the
// machine identity and the markers the SYSTEM tasks trust. Users read them.
var protectedStateFiles = []string{"config.json", "bootstrap.json", "device-id", "image-builder.json", "multi-user.json"}

// precreatedProtectedFiles are the protected files created empty when absent
// (an empty one reads as absent). The root lets users create files, so an
// absent trusted file is one a signed-in user could plant: image-builder.json
// bound to this machine would switch every scan off.
var precreatedProtectedFiles = []string{"device-id", "image-builder.json", "multi-user.json"}

// hardenStateDirACLs puts the least-privilege ACLs on the machine-wide state
// directory (C:\ProgramData\StepSecurity on an admin install). The directory
// holds the tenant config, the machine identity, the markers and the
// updater's state the SYSTEM tasks trust, next to every session's own state;
// the earlier blanket Users:Modify grant let any signed-in user replace them
// and redirect what SYSTEM runs. Users may list and read the tree, create
// files there, their own subdirectory under users\ and their own run files
// under runs\ (what they create is theirs through CREATOR OWNER), read what
// SYSTEM creates there later (through an inherit-only grant on the root, so
// a marker written after this ran is readable at once), and Modify the
// shared logs, the visit file and the unscoped per-run state; the protected
// files and state\ stay SYSTEM and Administrators only.
//
// Nothing here follows a link. On an install made before these grants every
// user could write the directory, so a junction or symbolic link planted at
// any of these paths would turn an icacls run as SYSTEM into a grant on the
// link's target. Every path is checked (Lstat) before it is created, opened
// or granted, the root included; a link anywhere fails the operation before
// any change, and icacls is told (/L) never to follow one either.
//
// Idempotent, so the updater re-applies it on existing installs. Each path's
// ACL is reset first (/grant:r only replaces a grant with the same inheritance
// flags, so the blanket (OI)(CI)M of an earlier install, and the explicit
// full-control entry a user got on a file they created, would survive a plain
// re-grant) and the owner of the directories, the shared files and the
// protected files becomes SYSTEM, so no file a user created before the grants
// can be reopened through ownership. The first failure is returned; the
// caller logs it and the install goes on.
func hardenStateDirACLs(ctx context.Context, exec executor.Executor, root string) error {
	if _, exists, err := lstatNoLink(root); err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("securing %s: the directory does not exist", root)
	}
	usersDir := filepath.Join(root, "users")
	if err := ensureDir(usersDir); err != nil {
		return err
	}
	runsDir := filepath.Join(root, "runs")
	if err := ensureDir(runsDir); err != nil {
		return err
	}
	for _, name := range sharedWritableFiles {
		if err := ensureFile(filepath.Join(root, name)); err != nil {
			return err
		}
	}
	for _, name := range precreatedProtectedFiles {
		if err := ensureFile(filepath.Join(root, name)); err != nil {
			return err
		}
	}

	type aclStep struct {
		path string
		args []string
	}
	var steps []aclStep
	// icacls takes /setowner only on its own (not with grants), so an owned
	// path gets three calls: reset, grant, own.
	own := aclStep{"", []string{"/setowner", sidSystem, "/L", "/Q"}}
	dir := func(path string, usersGrants ...string) {
		args := []string{"/inheritance:r", "/grant", sidSystem + ":(OI)(CI)F", "/grant", sidAdmins + ":(OI)(CI)F"}
		for _, g := range usersGrants {
			args = append(args, "/grant", sidUsers+":"+g)
		}
		args = append(args, "/grant", sidCreatorOwner+":(OI)(CI)(IO)F", "/L", "/Q")
		steps = append(steps, aclStep{path, []string{"/reset", "/L", "/Q"}}, aclStep{path, args}, aclStep{path, own.args})
	}
	file := func(path, usersGrant string, ownedBySystem bool) {
		args := []string{"/inheritance:r", "/grant", sidSystem + ":F", "/grant", sidAdmins + ":F", "/grant", sidUsers + ":" + usersGrant, "/L", "/Q"}
		steps = append(steps, aclStep{path, []string{"/reset", "/L", "/Q"}}, aclStep{path, args})
		if ownedBySystem {
			steps = append(steps, aclStep{path, own.args})
		}
	}
	// The root: list, read and create on the directory itself; read, through
	// the inherit-only entry, on the files SYSTEM creates in it later.
	dir(root, "(RX,WD,AD)", "(OI)(IO)R")
	// users\: create their own session directory; read the others' (no
	// session writes another's state, so peers get no more than that).
	dir(usersDir, "(RX,WD,AD)", "(OI)(CI)(IO)RX")
	// runs\: create their own run file (runs\<v>.<sid>.json, its lock and
	// temp files), theirs through CREATOR OWNER; the SYSTEM updater reads
	// every user's. No user reads or writes another's.
	dir(runsDir, "(RX,WD)")
	for _, name := range sharedWritableFiles {
		file(filepath.Join(root, name), "M", true)
	}
	for _, name := range scanStateFiles {
		if _, exists, err := lstatNoLink(filepath.Join(root, name)); err != nil {
			return err
		} else if exists {
			file(filepath.Join(root, name), "M", false)
		}
	}
	for _, name := range protectedStateFiles {
		if _, exists, err := lstatNoLink(filepath.Join(root, name)); err != nil {
			return err
		} else if exists {
			file(filepath.Join(root, name), "R", true)
		}
	}
	if info, exists, err := lstatNoLink(filepath.Join(root, "state")); err != nil {
		return err
	} else if exists && info.IsDir() {
		dir(filepath.Join(root, "state"), "(OI)(CI)RX")
	}
	for _, step := range steps {
		// Checked again right before the grant: the window between the
		// checks above and this call is the only one a planted link has.
		if _, exists, err := lstatNoLink(step.path); err != nil {
			return err
		} else if !exists {
			continue
		}
		if _, stderr, code, err := exec.Run(ctx, "icacls", append([]string{step.path}, step.args...)...); err != nil || code != 0 {
			return fmt.Errorf("icacls %s (exit code %d, %v): %s", step.path, code, err, stderr)
		}
	}
	return nil
}

// lstatNoLink reports whether path exists without following it, and fails
// when it is a symbolic link, junction or other reparse point: nothing in
// the state directory is reached through one.
func lstatNoLink(path string) (info os.FileInfo, exists bool, err error) {
	info, err = os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspecting %s: %w", path, err)
	}
	if isReparsePoint(info) {
		return nil, true, fmt.Errorf("refusing to secure %s: it is a link, which a signed-in user could have planted to redirect the grant to its target", path)
	}
	return info, true, nil
}

// ensureDir creates the directory when absent and fails when the path is
// a link or not a directory.
func ensureDir(path string) error {
	info, exists, err := lstatNoLink(path)
	if err != nil {
		return err
	}
	if exists {
		if !info.IsDir() {
			return fmt.Errorf("securing %s: not a directory", path)
		}
		return nil
	}
	if err := os.Mkdir(path, 0o755); err != nil { // #nosec G301 -- shared install dir
		return fmt.Errorf("creating %s: %w", path, err)
	}
	return nil
}

// ensureFile creates the file empty when absent, never opening an existing
// one (a planted link is refused, an existing file is left as it is).
func ensureFile(path string) error {
	info, exists, err := lstatNoLink(path)
	if err != nil {
		return err
	}
	if exists {
		if info.IsDir() {
			return fmt.Errorf("securing %s: a directory stands where a file is expected", path)
		}
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) // #nosec G302,G304 -- shared files under the install dir
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	return f.Close()
}
