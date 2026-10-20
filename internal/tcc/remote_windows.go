//go:build windows

package tcc

import (
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

// cloudPlaceholder reports whether path is a cloud-sync placeholder whose
// listing would hydrate it from the network. Reading attributes does not.
func cloudPlaceholder(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return false
	}
	return isCloudPlaceholderAttrs(attrs)
}
