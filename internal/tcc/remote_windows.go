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
	data, err := findCloudEntry(path)
	return err == nil && isCloudPlaceholderAttrs(data.FileAttributes)
}

// FindFirstFile returns the link's own attributes and reparse tag without
// opening or following it. A hydrated cloud file can have a reparse tag
// without redirecting through the namespace.
func findCloudEntry(path string) (windows.Win32finddata, error) {
	var data windows.Win32finddata
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
		return data, err
	}
	h, err := windows.FindFirstFile(p, &data)
	if err != nil {
		return data, err
	}
	_ = windows.FindClose(h)
	return data, nil
}

func isNameSurrogate(data windows.Win32finddata) bool {
	const nameSurrogate = 0x20000000 // IsReparseTagNameSurrogate
	return data.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && data.Reserved0&nameSurrogate != 0
}

func cloudEntry(path string) (placeholder, link bool, err error) {
	data, err := findCloudEntry(path)
	return isCloudPlaceholderAttrs(data.FileAttributes), isNameSurrogate(data), err
}
