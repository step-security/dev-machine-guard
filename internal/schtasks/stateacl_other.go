//go:build !windows

package schtasks

import "os"

// isReparsePoint reports whether info describes a symbolic link; there are
// no junctions off Windows.
func isReparsePoint(info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}
