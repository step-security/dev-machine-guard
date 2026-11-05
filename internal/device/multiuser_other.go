//go:build !windows

package device

// readWindowsEdition has no registry to read off Windows. Tests simulate a
// Windows host by stubbing probeWindowsEdition.
func readWindowsEdition() (edition string, tsAppCompat bool) { return "", false }
