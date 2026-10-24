//go:build !windows

package updatestate

import "os"

// EnsureProtectedDir creates path if missing. Off Windows there is no
// protected-DACL model to enforce, so it never reports drift.
func EnsureProtectedDir(path string) (fixed bool, err error) {
	exists, err := checkDirNotReparse(path)
	if err != nil || exists {
		return false, err
	}
	// #nosec G301 -- versions\ and state\ are world-readable by design (Users RX).
	if err := os.Mkdir(path, 0o755); err != nil && !os.IsExist(err) {
		return false, err
	}
	return false, nil
}
