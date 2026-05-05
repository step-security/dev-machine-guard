package cli

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// TargetUser identifies the user whose home `hooks install` should
// target. UID/GID are split out so `ChownToTarget` doesn't have to
// re-parse them on each path.
type TargetUser struct {
	User    *user.User
	UID     int
	GID     int
	HomeDir string
}

// ResolveTargetUser determines whose home directory the install should
// modify. It's the only sanctioned way for install handlers to obtain a
// user — in particular, callers must NOT walk /etc/passwd or read
// $SUDO_USER directly.
//
// Behavior:
//   - non-root caller: returns the calling user; ok=true.
//   - root caller, console user resolved: returns the console user; ok=true.
//   - root caller, no console user resolved: writes a one-line note to
//     stderr, appends an entry to the errors log, and returns ok=false.
//     The caller MUST exit 0 in this case — multi-user machines without
//     an active console session aren't a hook-install error, just a
//     no-op.
func ResolveTargetUser(exec executor.Executor, stderr io.Writer) (TargetUser, bool) {
	u, err := exec.LoggedInUser()
	if err != nil || u == nil {
		if exec.IsRoot() {
			noConsoleUser(stderr, fmt.Sprintf("LoggedInUser returned err=%v", err))
		}
		return TargetUser{}, false
	}

	// Under root, executor.LoggedInUser falls back to the current user
	// (root) when it can't resolve the console user. Treat root-as-target
	// as "no console user found" — installing hooks into root's home
	// would write into a profile no human uses interactively.
	if exec.IsRoot() && (u.Username == "" || u.Username == "root") {
		noConsoleUser(stderr, "executor.LoggedInUser returned root under root caller")
		return TargetUser{}, false
	}

	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return TargetUser{
		User:    u,
		UID:     uid,
		GID:     gid,
		HomeDir: u.HomeDir,
	}, true
}

func noConsoleUser(stderr io.Writer, detail string) {
	const note = "stepsecurity-dev-machine-guard: running as root with no console user; nothing to install."
	fmt.Fprintln(stderr, note)
	AppendError("install", "no_console_user", detail, "")
}

// ChownToTarget chowns each path to the target user's UID/GID. It's a
// best-effort helper: any individual chown failure is logged to the
// errors file and the loop continues — an unchown'd file is still a
// working install, just one the target user can't tidy up themselves.
//
// No-op on Windows (chown is a Unix concept) and when the caller is not
// root (chown to a different UID requires CAP_CHOWN). Empty paths in
// the slice are skipped silently so callers can pass `WriteResult.BackupPath`
// without first checking for "".
func ChownToTarget(exec executor.Executor, paths []string, target TargetUser) {
	if !exec.IsRoot() {
		return
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if err := os.Chown(p, target.UID, target.GID); err != nil {
			AppendError("install", "chown_failed", fmt.Sprintf("chown %s to %d:%d: %v", p, target.UID, target.GID, err), "")
		}
	}
}
