//go:build darwin

package bgpriority

import (
	"fmt"
	"syscall"
)

// Darwin-specific setpriority(2) selectors, spelled out because
// golang.org/x/sys/unix doesn't define them (see sys/resource.h).
const (
	// prioDarwinProcess scopes the call to a whole process (PRIO_DARWIN_PROCESS).
	prioDarwinProcess = 4
	// prioDarwinBG places the process in the Darwin background band
	// (PRIO_DARWIN_BG): throttled CPU, disk IO, and network — the tier Time
	// Machine and Spotlight indexing run at. Throttled means a reduced
	// proportional share under contention, never starvation, and effectively
	// full speed on an otherwise idle machine.
	prioDarwinBG = 0x1000
)

func apply() (string, error) {
	if err := syscall.Setpriority(prioDarwinProcess, 0, prioDarwinBG); err != nil {
		return "", fmt.Errorf("setpriority(PRIO_DARWIN_PROCESS, PRIO_DARWIN_BG): %w", err)
	}
	return "macOS background task policy (throttled CPU/IO/network, inherited by child processes)", nil
}
