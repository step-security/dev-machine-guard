package executor

// ResolveHome returns the home directory of the console (GUI) user when
// present, falling back to the process's current user. Returns an empty
// string when neither resolves — callers degrade gracefully.
//
// On macOS the LoggedInUser path uses `stat /dev/console` to find the
// real GUI user even when the agent runs as root via launchd (issue #63),
// so this is the correct anchor for per-user paths like the TCC skip
// list. Shared by both community-mode scan and enterprise telemetry to
// keep them in lock-step.
func ResolveHome(exec Executor) string {
	if u, err := exec.LoggedInUser(); err == nil {
		return u.HomeDir
	}
	if u, err := exec.CurrentUser(); err == nil {
		return u.HomeDir
	}
	return ""
}
