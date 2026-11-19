//go:build windows

package tcc

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const skipRemoteByDefault = true

// networkVolumeMounts lists drive letters mapped to network shares.
func networkVolumeMounts() []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var mounts []string
	for i := range 26 {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		if windows.GetDriveType(p) == driveRemote {
			mounts = append(mounts, root)
		}
	}
	return mounts
}

// CloudPlaceholder checks the directory entry without opening the target.
// RECALL_ON_OPEN is available only in directory enumeration data.
func CloudPlaceholder(path string) bool {
	// FindFirstFile uses Win32 search syntax and does not automatically extend
	// long paths the way the Go os package does.
	path = filepath.Clean(path)
	if len(path) >= 248 && !strings.HasPrefix(path, `\\?\`) {
		if abs, err := filepath.Abs(path); err == nil {
			if unc, ok := strings.CutPrefix(abs, `\\`); ok {
				path = `\\?\UNC\` + unc
			} else {
				path = `\\?\` + abs
			}
		}
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	var data windows.Win32finddata
	h, err := windows.FindFirstFile(p, &data)
	if err != nil {
		return false
	}
	_ = windows.FindClose(h)
	return isCloudPlaceholderAttrs(data.FileAttributes)
}
