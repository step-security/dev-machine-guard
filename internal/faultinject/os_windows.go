//go:build selfupdate_faults && windows

package faultinject

import "golang.org/x/sys/windows"

var errDiskFull error = windows.ERROR_DISK_FULL

func runningAsSystem() bool {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	return u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
