package wslagent

import (
	"debug/pe"
	"runtime"
)

// NativeArch returns the architecture the Linux agent must be built for on
// this host: the machine's own, not this executable's. An amd64 agent can run
// under x64 emulation on Windows on Arm, where WSL distros are arm64 and
// cannot run a linux_amd64 binary. A variable so tests can stand in for the
// host.
var NativeArch = nativeArch

// machineArch maps a PE machine type to a release arch, falling back to the
// build arch when Windows reports nothing usable.
func machineArch(machine uint16) string {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	}
	return runtime.GOARCH
}
