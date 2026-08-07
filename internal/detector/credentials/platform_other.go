//go:build !windows

package credentials

// readUserEnvironment has no non-Windows implementation: elsewhere these values
// live in a login session rather than a stored per-account record. It reports a
// failed read rather than an empty one — a caller that reaches it has asked for
// a mechanism this platform does not have.
func readUserEnvironment(_ string, _ []string) (userEnv, bool) {
	return userEnv{}, false
}

// broadReadAllowACE has nothing to report outside Windows, where access is
// described by the permission bits already on the finding. Nil leaves the field
// omitted rather than asserting no broad grant exists.
func broadReadAllowACE(_ string) *bool { return nil }
