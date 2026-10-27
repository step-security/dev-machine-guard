//go:build !windows

package launcher

// SetRunningVersion is a no-op off Windows (no registry inventory).
func SetRunningVersion(string) error { return nil }
