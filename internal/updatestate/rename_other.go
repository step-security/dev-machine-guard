//go:build !windows

package updatestate

// renameBlocked is Windows-only: elsewhere an open file never blocks a
// directory rename.
func renameBlocked(error) bool { return false }
