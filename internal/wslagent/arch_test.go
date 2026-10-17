package wslagent

import (
	"debug/pe"
	"runtime"
	"testing"
)

// The native machine decides the Linux binary, whatever this executable was
// built for: an amd64 agent emulated on Windows on Arm still gets arm64.
func TestMachineArch(t *testing.T) {
	cases := []struct {
		name    string
		machine uint16
		want    string
	}{
		{name: "x64 host", machine: pe.IMAGE_FILE_MACHINE_AMD64, want: "amd64"},
		{name: "arm64 host (also for an emulated amd64 agent)", machine: pe.IMAGE_FILE_MACHINE_ARM64, want: "arm64"},
		{name: "unknown falls back to build arch", machine: pe.IMAGE_FILE_MACHINE_UNKNOWN, want: runtime.GOARCH},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := machineArch(tc.machine); got != tc.want {
				t.Errorf("machineArch(%#x) = %q, want %q", tc.machine, got, tc.want)
			}
		})
	}
}
