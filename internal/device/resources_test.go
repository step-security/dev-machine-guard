package device

import (
	"context"
	"runtime"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestParseProcCPUInfo_X86(t *testing.T) {
	// Two-physical-core x86 cpuinfo with hyperthreading (4 logical processors).
	// Both physical cores share physical id 0; core ids are 0 and 1.
	cpuinfo := []byte(`processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
physical id	: 0
core id		: 0
cpu cores	: 2

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
physical id	: 0
core id		: 1
cpu cores	: 2

processor	: 2
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
physical id	: 0
core id		: 0
cpu cores	: 2

processor	: 3
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
physical id	: 0
core id		: 1
cpu cores	: 2
`)

	model, physical := parseProcCPUInfo(cpuinfo)
	if model != "Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz" {
		t.Errorf("model: got %q", model)
	}
	if physical != 2 {
		t.Errorf("physical cores: expected 2, got %d", physical)
	}
}

func TestParseProcCPUInfo_FallbackToCPUCores(t *testing.T) {
	// Single-socket cpuinfo with no "physical id"/"core id" but with "cpu cores".
	// We fall back to that count.
	cpuinfo := []byte(`processor	: 0
model name	: AMD Ryzen 5 3600 6-Core Processor
cpu cores	: 6
`)
	model, physical := parseProcCPUInfo(cpuinfo)
	if model != "AMD Ryzen 5 3600 6-Core Processor" {
		t.Errorf("model: got %q", model)
	}
	if physical != 6 {
		t.Errorf("physical cores: expected 6, got %d", physical)
	}
}

func TestParseProcCPUInfo_ARM(t *testing.T) {
	// ARM /proc/cpuinfo has no "model name". Hardware/Model lines are best-effort.
	cpuinfo := []byte(`processor	: 0
BogoMIPS	: 50.00
Features	: fp asimd
CPU implementer	: 0x41
CPU architecture: 8
CPU variant	: 0x0
CPU part	: 0xd03

Hardware	: BCM2835
Model		: Raspberry Pi 4 Model B Rev 1.4
`)
	model, physical := parseProcCPUInfo(cpuinfo)
	// Expect Hardware or Model picked up; physical cores = 0 since there's no
	// "cpu cores" or distinct (physical id, core id) pairs.
	if model != "BCM2835" {
		t.Errorf("model: expected BCM2835 (first Hardware line), got %q", model)
	}
	if physical != 0 {
		t.Errorf("physical cores: expected 0 (unknown), got %d", physical)
	}
}

func TestParseProcCPUInfo_Empty(t *testing.T) {
	model, physical := parseProcCPUInfo(nil)
	if model != "" || physical != 0 {
		t.Errorf("empty input: got %q, %d", model, physical)
	}
}

func TestParseProcMemInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{
			name:     "typical",
			input:    []byte("MemTotal:       16277124 kB\nMemFree:        12000000 kB\n"),
			expected: 16277124 * 1024,
		},
		{
			name:     "missing",
			input:    []byte("MemFree:        12000000 kB\n"),
			expected: 0,
		},
		{
			name:     "empty",
			input:    nil,
			expected: 0,
		},
		{
			name:     "garbage",
			input:    []byte("MemTotal:       not-a-number kB\n"),
			expected: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseProcMemInfo(tt.input)
			if got != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, got)
			}
		})
	}
}

func TestParseCIMProcessorList_PowerShellFormatList(t *testing.T) {
	// PowerShell Format-List uses "Key : Value" with spaces.
	psOut := `

Name                      : AMD EPYC 7763 64-Core Processor
NumberOfCores             : 64
NumberOfLogicalProcessors : 128

`
	model, physical, logical := parseCIMProcessorList(psOut)
	if model != "AMD EPYC 7763 64-Core Processor" {
		t.Errorf("model: got %q", model)
	}
	if physical != 64 || logical != 128 {
		t.Errorf("cores: expected 64/128, got %d/%d", physical, logical)
	}
}

func TestParseCIMProcessorList_LegacyWmic(t *testing.T) {
	// Older Windows hosts that still ship wmic emit "Key=Value" lines.
	wmic := "\r\n\r\nName=Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz\r\nNumberOfCores=8\r\nNumberOfLogicalProcessors=16\r\n\r\n"
	model, physical, logical := parseCIMProcessorList(wmic)
	if model != "Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz" {
		t.Errorf("model: got %q", model)
	}
	if physical != 8 || logical != 16 {
		t.Errorf("cores: expected 8/16, got %d/%d", physical, logical)
	}
}

func TestGather_LinuxResources(t *testing.T) {
	mock := executor.NewMock()
	t.Cleanup(ResetIDCache)
	mock.SetGOOS("linux")
	mock.SetHostname("linux-dev")
	mock.SetUsername("dev")
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("SERIAL\n"))
	mock.SetFile("/etc/os-release", []byte(`PRETTY_NAME="Fedora Linux 42 (Cloud Edition)"`+"\n"))
	mock.SetFile("/proc/sys/kernel/osrelease", []byte("6.19.12-100.fc42.x86_64\n"))
	mock.SetFile("/proc/cpuinfo", []byte(`processor	: 0
model name	: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
physical id	: 0
core id		: 0
cpu cores	: 4

processor	: 1
model name	: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
physical id	: 0
core id		: 1
cpu cores	: 4

processor	: 2
model name	: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
physical id	: 0
core id		: 2
cpu cores	: 4

processor	: 3
model name	: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
physical id	: 0
core id		: 3
cpu cores	: 4
`))
	mock.SetFile("/proc/meminfo", []byte("MemTotal:       16277124 kB\n"))
	mock.SetDiskCapacityBytes("/", 500*1024*1024*1024) // 500 GiB

	dev := Gather(context.Background(), mock)

	if dev.Resources.CPUModel != "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz" {
		t.Errorf("cpu_model: got %q", dev.Resources.CPUModel)
	}
	if dev.Resources.PhysicalCores != 4 {
		t.Errorf("physical_cores: expected 4, got %d", dev.Resources.PhysicalCores)
	}
	// LogicalCores defaults to runtime.NumCPU(); just verify it's populated.
	if dev.Resources.LogicalCores != runtime.NumCPU() {
		t.Errorf("logical_cores: expected runtime.NumCPU()=%d, got %d", runtime.NumCPU(), dev.Resources.LogicalCores)
	}
	if dev.Resources.MemoryBytes != 16277124*1024 {
		t.Errorf("memory_bytes: expected %d, got %d", uint64(16277124)*1024, dev.Resources.MemoryBytes)
	}
	if dev.Resources.DiskTotalBytes != 500*1024*1024*1024 {
		t.Errorf("disk_total_bytes: expected 500GiB, got %d", dev.Resources.DiskTotalBytes)
	}
	if dev.Resources.CPUArchitecture != runtime.GOARCH {
		t.Errorf("cpu_architecture: expected %s, got %q", runtime.GOARCH, dev.Resources.CPUArchitecture)
	}
}

func TestGather_DarwinResources(t *testing.T) {
	mock := executor.NewMock()
	t.Cleanup(ResetIDCache)
	mock.SetGOOS("darwin")
	mock.SetHostname("mbp")
	mock.SetUsername("dev")
	// device.Gather() also calls ioreg/system_profiler/sw_vers — stub them out
	// minimally so the existing path completes without error.
	mock.SetCommand(`    "IOPlatformSerialNumber" = "ABCD1234"`+"\n", "", 0, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	mock.SetCommand("15.1\n", "", 0, "sw_vers", "-productVersion")

	// Resource sysctls
	mock.SetCommand("Apple M3 Pro\n", "", 0, "sysctl", "-n", "machdep.cpu.brand_string")
	mock.SetCommand("12\n", "", 0, "sysctl", "-n", "hw.physicalcpu")
	mock.SetCommand("16\n", "", 0, "sysctl", "-n", "hw.logicalcpu")
	mock.SetCommand("38654705664\n", "", 0, "sysctl", "-n", "hw.memsize") // 36 GB
	mock.SetDiskCapacityBytes("/", 994*1000*1000*1000)

	dev := Gather(context.Background(), mock)

	if dev.Resources.CPUModel != "Apple M3 Pro" {
		t.Errorf("cpu_model: got %q", dev.Resources.CPUModel)
	}
	if dev.Resources.PhysicalCores != 12 {
		t.Errorf("physical_cores: expected 12, got %d", dev.Resources.PhysicalCores)
	}
	if dev.Resources.LogicalCores != 16 {
		t.Errorf("logical_cores: expected 16, got %d", dev.Resources.LogicalCores)
	}
	if dev.Resources.MemoryBytes != 38654705664 {
		t.Errorf("memory_bytes: got %d", dev.Resources.MemoryBytes)
	}
	if dev.Resources.DiskTotalBytes == 0 {
		t.Errorf("disk_total_bytes: expected non-zero")
	}
}

func TestGather_WindowsResources(t *testing.T) {
	mock := executor.NewMock()
	t.Cleanup(ResetIDCache)
	mock.SetGOOS("windows")
	mock.SetHostname("WIN-DESKTOP")
	mock.SetUsername("dev")

	// device.Gather() calls these for Windows serial/OS version.
	mock.SetCommand("SerialNumber\nWIN-SERIAL-1\n", "", 0, "wmic", "bios", "get", "serialnumber")
	mock.SetCommand("10.0.22631.0\n", "", 0,
		"powershell", "-NoProfile", "-Command",
		"[System.Environment]::OSVersion.Version.ToString()")

	// Resource queries on the non-Windows test path use PowerShell CIM —
	// wmic was removed in Windows 11 / Server 2025, so the agent only ships
	// PowerShell fallbacks.
	mock.SetCommand(
		"\r\nName                      : Intel(R) Core(TM) i9-13900K CPU @ 3.00GHz\r\nNumberOfCores             : 24\r\nNumberOfLogicalProcessors : 32\r\n\r\n",
		"", 0,
		"powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | Format-List")
	mock.SetCommand("68719476736\n", "", 0,
		"powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory")
	mock.SetEnv("SystemDrive", "C:")
	mock.SetDiskCapacityBytes(`C:\`, 953*1000*1000*1000)

	dev := Gather(context.Background(), mock)

	if dev.Resources.CPUModel != "Intel(R) Core(TM) i9-13900K CPU @ 3.00GHz" {
		t.Errorf("cpu_model: got %q", dev.Resources.CPUModel)
	}
	if dev.Resources.PhysicalCores != 24 {
		t.Errorf("physical_cores: expected 24, got %d", dev.Resources.PhysicalCores)
	}
	if dev.Resources.LogicalCores != 32 {
		t.Errorf("logical_cores: expected 32, got %d", dev.Resources.LogicalCores)
	}
	if dev.Resources.MemoryBytes != 68719476736 {
		t.Errorf("memory_bytes: got %d", dev.Resources.MemoryBytes)
	}
	if dev.Resources.DiskTotalBytes == 0 {
		t.Errorf("disk_total_bytes: expected non-zero")
	}
}

func TestGather_LinuxResourcesMissingFiles(t *testing.T) {
	// When /proc/cpuinfo and /proc/meminfo are unavailable, Gather should not
	// fail — Resources just degrades to zero/empty fields except runtime-derived
	// ones (LogicalCores, CPUArchitecture).
	mock := executor.NewMock()
	t.Cleanup(ResetIDCache)
	mock.SetGOOS("linux")
	mock.SetHostname("minimal")
	mock.SetUsername("user")
	mock.SetFile("/etc/machine-id", []byte("abc\n"))
	mock.SetFile("/proc/sys/kernel/osrelease", []byte("6.0.0\n"))

	dev := Gather(context.Background(), mock)

	if dev.Resources.CPUModel != "" {
		t.Errorf("cpu_model: expected empty, got %q", dev.Resources.CPUModel)
	}
	if dev.Resources.MemoryBytes != 0 {
		t.Errorf("memory_bytes: expected 0, got %d", dev.Resources.MemoryBytes)
	}
	if dev.Resources.LogicalCores == 0 {
		t.Errorf("logical_cores: expected runtime.NumCPU() > 0, got 0")
	}
	if dev.Resources.CPUArchitecture == "" {
		t.Errorf("cpu_architecture: expected runtime.GOARCH, got empty")
	}
}
