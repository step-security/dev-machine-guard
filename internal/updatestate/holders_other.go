//go:build !windows

package updatestate

// fileHolders is Windows-only (Restart Manager).
func fileHolders([]string) []string { return nil }
