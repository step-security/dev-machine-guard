//go:build windows

package procusage

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// processMemoryCounters mirrors PROCESS_MEMORY_COUNTERS. SIZE_T is
// pointer-width, so uintptr keeps the layout right on 386 and amd64.
type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// readUsage reads this process's own CPU and peak working set.
//
// Windows has no getrusage(RUSAGE_CHILDREN) equivalent, so subprocess
// cost is not counted and childrenAttributed stays false. Closing that
// gap needs a Job Object the agent assigns itself to at startup, then
// JobObjectBasicAccountingInformation for descendant CPU.
func readUsage() rusage {
	var out rusage

	handle := windows.CurrentProcess()

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err == nil {
		out.userMs = filetimeDurationMs(user)
		out.sysMs = filetimeDurationMs(kernel)
	}

	psapi := windows.NewLazySystemDLL("psapi.dll")
	proc := psapi.NewProc("GetProcessMemoryInfo")
	var counters processMemoryCounters
	counters.CB = uint32(unsafe.Sizeof(counters))
	r1, _, _ := proc.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&counters)),
		uintptr(counters.CB),
	)
	if r1 != 0 {
		out.peakRSSBytes = uint64(counters.PeakWorkingSetSize)
	}

	return out
}

// filetimeDurationMs converts a FILETIME holding an elapsed duration to
// milliseconds.
//
// Filetime.Nanoseconds() is deliberately not used: it subtracts the
// 1601->1970 epoch offset, which is right for a wall-clock FILETIME and
// badly wrong for the duration ones GetProcessTimes returns for kernel
// and user time.
func filetimeDurationMs(ft windows.Filetime) int64 {
	ticks := int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
	if ticks <= 0 {
		return 0
	}
	return ticks / 10000 // 100ns ticks -> ms
}
