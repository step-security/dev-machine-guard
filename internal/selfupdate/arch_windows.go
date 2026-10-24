//go:build windows

package selfupdate

import (
	"runtime"

	"golang.org/x/sys/windows"
)

const (
	imageFileMachineAMD64 = 0x8664
	imageFileMachineARM64 = 0xAA64
)

func nativeArch() string {
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err == nil {
		if a := archForMachine(native); a != "" {
			return a
		}
	}
	return runtime.GOARCH
}

func archForMachine(m uint16) string {
	switch m {
	case imageFileMachineAMD64:
		return "amd64"
	case imageFileMachineARM64:
		return "arm64"
	}
	return ""
}
