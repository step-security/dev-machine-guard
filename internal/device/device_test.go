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
