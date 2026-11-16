//go:build windows

package schtasks

import (
	"os"
	"syscall"
)

// isReparsePoint reports whether info describes a symbolic link, a junction
// (mount point) or any other reparse point. Go reports junctions as irregular
// files rather than symlinks since 1.23, so the attribute is checked directly.
func isReparsePoint(info os.FileInfo) bool {
	if sys, ok := info.Sys().(*syscall.Win32FileAttributeData); ok && sys.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return true
	}
	return info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0
}
