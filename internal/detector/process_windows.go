//go:build windows

package detector

import (
	"context"
	"strings"
	"unsafe"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"golang.org/x/sys/windows"
)

// processMatchExact enumerates running processes using the Windows API
// and checks if any process name matches exactly.
func processMatchExact(_ context.Context, _ executor.Executor, name string) bool {
	exeName := strings.ToLower(name + ".exe")

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snap, &entry)
	for err == nil {
		proc := windows.UTF16ToString(entry.ExeFile[:])
		if strings.ToLower(proc) == exeName {
			return true
		}
		err = windows.Process32Next(snap, &entry)
	}
	return false
}

// processMatchFuzzy enumerates running processes using the Windows API
// and checks if any process name contains the pattern.
func processMatchFuzzy(_ context.Context, _ executor.Executor, pattern string) bool {
	lowerPattern := strings.ToLower(pattern)

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snap, &entry)
	for err == nil {
		proc := windows.UTF16ToString(entry.ExeFile[:])
		if strings.Contains(strings.ToLower(proc), lowerPattern) {
			return true
		}
		err = windows.Process32Next(snap, &entry)
	}
	return false
}
