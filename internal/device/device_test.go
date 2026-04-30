package device

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestGather_BasicFields(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHostname("test-mac.local")
	mock.SetCommand("SERIAL123\n    \"IOPlatformSerialNumber\" = \"SERIAL123\"\n", "", 0, "ioreg", "-l")
	mock.SetCommand("15.1\n", "", 0, "sw_vers", "-productVersion")
	mock.SetUsername("devuser")

	dev := Gather(context.Background(), mock)

	if dev.Hostname != "test-mac.local" {
		t.Errorf("hostname: expected test-mac.local, got %s", dev.Hostname)
	}
	if dev.OSVersion != "15.1" {
		t.Errorf("os_version: expected 15.1, got %s", dev.OSVersion)
	}
	if dev.Platform != "darwin" {
		t.Errorf("platform: expected darwin, got %s", dev.Platform)
	}
	if dev.UserIdentity != "devuser" {
		t.Errorf("user_identity: expected devuser, got %s", dev.UserIdentity)
	}
}

func TestGather_FallbackSerial(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHostname("test")
	// ioreg fails, system_profiler returns serial
	mock.SetCommand("", "", 1, "ioreg", "-l")
	mock.SetCommand("Hardware:\n    Serial Number (system): FB123\n", "", 0, "system_profiler", "SPHardwareDataType")
	mock.SetCommand("14.0\n", "", 0, "sw_vers", "-productVersion")

	dev := Gather(context.Background(), mock)
	if dev.SerialNumber != "FB123" {
		t.Errorf("serial: expected FB123, got %s", dev.SerialNumber)
	}
}

func TestGather_EmailIdentity(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHostname("test")
	mock.SetCommand("", "", 1, "ioreg", "-l")
	mock.SetCommand("", "", 1, "system_profiler", "SPHardwareDataType")
	mock.SetCommand("", "", 1, "sw_vers", "-productVersion")
	mock.SetEnv("USER_EMAIL", "dev@example.com")

	dev := Gather(context.Background(), mock)
	if dev.UserIdentity != "dev@example.com" {
		t.Errorf("identity: expected dev@example.com, got %s", dev.UserIdentity)
	}
}

func TestGather_Linux(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHostname("ubuntu-dev")
	mock.SetHomeDir("/home/testuser")
	mock.SetUsername("testuser")

	// /sys/class/dmi/id/product_serial for serial
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("LINUX-SERIAL-456\n"))

	// /etc/os-release for distro name
	mock.SetFile("/etc/os-release", []byte("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"))
	// /proc/sys/kernel/osrelease for kernel version
	mock.SetFile("/proc/sys/kernel/osrelease", []byte("6.8.0-45-generic\n"))

	dev := Gather(context.Background(), mock)

	if dev.Hostname != "ubuntu-dev" {
		t.Errorf("hostname: expected ubuntu-dev, got %s", dev.Hostname)
	}
	if dev.Platform != "linux" {
		t.Errorf("platform: expected linux, got %s", dev.Platform)
	}
	if dev.SerialNumber != "LINUX-SERIAL-456" {
		t.Errorf("serial: expected LINUX-SERIAL-456, got %s", dev.SerialNumber)
	}
	expected := "Ubuntu 24.04.1 LTS - 6.8.0-45-generic"
	if dev.OSVersion != expected {
		t.Errorf("os_version: expected %q, got %q", expected, dev.OSVersion)
	}
	if dev.UserIdentity != "testuser" {
		t.Errorf("user_identity: expected testuser, got %s", dev.UserIdentity)
	}
}

func TestGather_LinuxFallbackDmidecode(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHostname("linux-vm")
	mock.SetUsername("user")

	// /sys file not available, dmidecode works
	mock.SetCommand("VM-SERIAL-789\n", "", 0, "dmidecode", "-s", "system-serial-number")

	// /etc/os-release not available, lsb_release works
	mock.SetCommand("Ubuntu 22.04.3 LTS\n", "", 0, "lsb_release", "-d", "-s")
	// /proc/sys/kernel/osrelease for kernel
	mock.SetFile("/proc/sys/kernel/osrelease", []byte("5.15.0-91-generic\n"))

	dev := Gather(context.Background(), mock)

	if dev.SerialNumber != "VM-SERIAL-789" {
		t.Errorf("serial: expected VM-SERIAL-789, got %s", dev.SerialNumber)
	}
	expected := "Ubuntu 22.04.3 LTS - 5.15.0-91-generic"
	if dev.OSVersion != expected {
		t.Errorf("os_version: expected %q, got %q", expected, dev.OSVersion)
	}
}

func TestGather_LinuxFallbackMachineID(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHostname("container")
	mock.SetUsername("root")

	// /sys returns OEM placeholder
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("To Be Filled By O.E.M.\n"))
	// dmidecode also returns placeholder
	mock.SetCommand("To Be Filled By O.E.M.\n", "", 0, "dmidecode", "-s", "system-serial-number")
	// machine-id fallback
	mock.SetFile("/etc/machine-id", []byte("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\n"))

	// OS version: only /proc/sys/kernel/osrelease available
	mock.SetFile("/proc/sys/kernel/osrelease", []byte("6.5.0-44-generic\n"))

	dev := Gather(context.Background(), mock)

	if dev.SerialNumber != "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" {
		t.Errorf("serial: expected machine-id, got %s", dev.SerialNumber)
	}
	if dev.OSVersion != "6.5.0-44-generic" {
		t.Errorf("os_version: expected kernel version, got %s", dev.OSVersion)
	}
}

func TestGather_LinuxDistroOnly(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHostname("minimal")
	mock.SetUsername("user")

	mock.SetFile("/etc/machine-id", []byte("abc123\n"))
	mock.SetFile("/etc/os-release", []byte("NAME=\"Alpine Linux\"\nVERSION_ID=3.19\n"))
	// uname not available

	dev := Gather(context.Background(), mock)

	if dev.OSVersion != "3.19" {
		t.Errorf("os_version: expected '3.19', got %q", dev.OSVersion)
	}
}

func TestGather_Windows(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetHostname("WIN-DESKTOP")
	mock.SetHomeDir(`C:\Users\testuser`)
	mock.SetUsername("testuser")

	// wmic for serial number
	mock.SetCommand("SerialNumber\nWIN-SERIAL-123\n", "", 0,
		"wmic", "bios", "get", "serialnumber")

	// PowerShell for OS version
	mock.SetCommand("10.0.22631.0\n", "", 0,
		"powershell", "-NoProfile", "-Command",
		"[System.Environment]::OSVersion.Version.ToString()")

	dev := Gather(context.Background(), mock)

	if dev.Hostname != "WIN-DESKTOP" {
		t.Errorf("hostname: expected WIN-DESKTOP, got %s", dev.Hostname)
	}
	if dev.Platform != "windows" {
		t.Errorf("platform: expected windows, got %s", dev.Platform)
	}
	if dev.SerialNumber != "WIN-SERIAL-123" {
		t.Errorf("serial: expected WIN-SERIAL-123, got %s", dev.SerialNumber)
	}
	if dev.OSVersion != "10.0.22631.0" {
		t.Errorf("os_version: expected 10.0.22631.0, got %s", dev.OSVersion)
	}
	if dev.UserIdentity != "testuser" {
		t.Errorf("user_identity: expected testuser, got %s", dev.UserIdentity)
	}
}
