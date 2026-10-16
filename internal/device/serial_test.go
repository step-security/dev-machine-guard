package device

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestUsableSerial(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"C02XL0GHJGH5", true},
		{"VMware-56 4d 1a", true},
		{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", true},
		{"10", true},
		{"", false},
		{"   ", false},
		{"unknown", false},
		{"None", false},
		{"Default string", false},
		{" DEFAULT STRING \n", false},
		{"Not Specified", false},
		{"System Serial Number", false},
		{"To Be Filled By O.E.M.", false},
		{"To be filled by OEM", false},
		{"O.E.M.", false},
		{"Chassis Serial Number", false},
		{"0", false},
		{"0000000000", false},
		{"00000000-0000-0000-0000-000000000000", false},
		{"123456789", false},
	} {
		if got := usableSerial(tc.in); got != tc.want {
			t.Errorf("usableSerial(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSerialProbesSkipPlaceholders(t *testing.T) {
	linux := executor.NewMock()
	linux.SetGOOS("linux")
	linux.SetFile("/sys/class/dmi/id/product_serial", []byte("Default string\n"))
	linux.SetCommand("Not Specified\n", "", 0, "dmidecode", "-s", "system-serial-number")
	linux.SetFile("/etc/machine-id", []byte("a1b2c3d4e5f6\n"))
	if got, hw := getSerialNumberLinux(context.Background(), linux); got != "a1b2c3d4e5f6" || hw {
		t.Errorf("linux = %q (hardware=%v), want machine-id fallback", got, hw)
	}

	darwin := executor.NewMock()
	darwin.SetGOOS("darwin")
	darwin.SetCommand(`"IOPlatformSerialNumber" = "0"`, "", 0, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	darwin.SetCommand("Serial Number (system): MAC123\n", "", 0, "system_profiler", "SPHardwareDataType")
	if got := getSerialNumber(context.Background(), darwin); got != "MAC123" {
		t.Errorf("darwin = %q, want system_profiler serial", got)
	}
}
