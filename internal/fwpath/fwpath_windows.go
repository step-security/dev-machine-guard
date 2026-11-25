//go:build windows

package fwpath

import (
	"os"

	"golang.org/x/sys/windows"
)

// programFiles is the native Program Files folder (the loader's
// $env:ProgramFiles), from the known folder.
func programFiles() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil && p != "" {
		return p
	}
	return os.Getenv("ProgramFiles") // the known folder can't fail on a working system
}

func programData() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil && p != "" {
		return p
	}
	return os.Getenv("ProgramData")
}
