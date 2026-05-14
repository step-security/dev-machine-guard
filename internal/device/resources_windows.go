//go:build windows

package device

import (
	"context"
	"strconv"
	"strings"
	"unsafe"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// getCPUInfoWindows reads CPU model from the registry (no subprocess) and
// counts cores via GetLogicalProcessorInformation. Falls back to a
// PowerShell Get-CimInstance call when either step fails — VMs and
// stripped Server Core images occasionally lack one or the other. wmic
// was removed in Windows 11 / Server 2025 and is intentionally not used.
func getCPUInfoWindows(ctx context.Context, exec executor.Executor) (cpuModel string, physical, logical int) {
	cpuModel = readCPUNameRegistry()
	physical, logical = countCoresFromAPI()

	if cpuModel != "" && physical > 0 && logical > 0 {
		return cpuModel, physical, logical
	}

	// Fill any blanks via PowerShell CIM. wmic was removed in Windows 11 /
	// Server 2025, so PowerShell is the only viable fallback going forward.
	// Format-List output ("Key : Value", one field per line) is parsed by the
	// same helper we use for the non-Windows test stub.
	stdout, _, _, err := exec.Run(ctx, "powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | Format-List")
	if err == nil {
		fbModel, fbPhysical, fbLogical := parseCIMProcessorList(stdout)
		if cpuModel == "" {
			cpuModel = fbModel
		}
		if physical == 0 {
			physical = fbPhysical
		}
		if logical == 0 {
			logical = fbLogical
		}
	}
	return cpuModel, physical, logical
}

func readCPUNameRegistry() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer func() { _ = k.Close() }()
	name, _, err := k.GetStringValue("ProcessorNameString")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(name)
}

// countCoresFromAPI uses GetLogicalProcessorInformation to derive both the
// physical core count (entries with Relationship == RelationProcessorCore)
// and the logical-processor count (popcount of each ProcessorMask). The
// kernel32 export is resolved via windows.NewLazySystemDLL + NewProc so we
// don't need a build-time binding for it.
func countCoresFromAPI() (physical, logical int) {
	const relationProcessorCore = 0

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("GetLogicalProcessorInformation")

	var buf []byte
	var returnedLen uint32

	// First call with nil to discover required size.
	r1, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&returnedLen)))
	if r1 == 0 && returnedLen == 0 {
		return 0, 0
	}
	buf = make([]byte, returnedLen)
	r1, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&returnedLen)))
	if r1 == 0 {
		return 0, 0
	}

	// SYSTEM_LOGICAL_PROCESSOR_INFORMATION layout:
	//   ProcessorMask  uintptr
	//   Relationship   uint32  (followed by 4 bytes padding on amd64)
	//   union[16]byte  (cache/numa/etc — we only inspect the mask)
	type sysLogicalProcInfo struct {
		ProcessorMask uintptr
		Relationship  uint32
		_             [4]byte
		_             [16]byte
	}

	stride := int(unsafe.Sizeof(sysLogicalProcInfo{}))
	count := int(returnedLen) / stride
	for i := 0; i < count; i++ {
		entry := (*sysLogicalProcInfo)(unsafe.Pointer(&buf[i*stride]))
		if entry.Relationship == relationProcessorCore {
			physical++
			logical += popcount(uint64(entry.ProcessorMask))
		}
	}
	return physical, logical
}

func popcount(x uint64) int {
	n := 0
	for x != 0 {
		n += int(x & 1)
		x >>= 1
	}
	return n
}

// memoryStatusEx mirrors the Windows MEMORYSTATUSEX struct. Field order and
// sizes are load-bearing — GlobalMemoryStatusEx fills the buffer by offset.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func getMemoryBytesWindows(ctx context.Context, exec executor.Executor) uint64 {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("GlobalMemoryStatusEx")
	var statex memoryStatusEx
	statex.Length = uint32(unsafe.Sizeof(statex))
	r1, _, _ := proc.Call(uintptr(unsafe.Pointer(&statex)))
	if r1 != 0 && statex.TotalPhys > 0 {
		return statex.TotalPhys
	}

	// Fallback: PowerShell CIM if the syscall failed (extremely rare).
	// wmic is unavailable on Windows 11 / Server 2025.
	stdout, _, _, err := exec.Run(ctx, "powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory")
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(stdout), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func getDiskTotalBytesWindows(exec executor.Executor) uint64 {
	return exec.DiskCapacityBytes(windowsSystemDrive(exec))
}

func windowsSystemDrive(exec executor.Executor) string {
	drive := strings.TrimSpace(exec.Getenv("SystemDrive"))
	if drive == "" {
		drive = "C:"
	}
	return drive + `\`
}
