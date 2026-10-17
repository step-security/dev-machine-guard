//go:build windows

package wslagent

import "golang.org/x/sys/windows"

// nativeArch asks Windows for the machine type. IsWow64Process2 reports the
// native machine even for an emulated x64 process, which is not WOW64.
func nativeArch() string {
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err != nil {
		return machineArch(0)
	}
	return machineArch(native)
}
