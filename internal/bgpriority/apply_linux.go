//go:build linux

package bgpriority

import (
	"fmt"
	"strings"
	"syscall"
)

// ioprio_set(2) encoding (linux/ioprio.h), spelled out because neither the
// stdlib nor golang.org/x/sys/unix wraps the call itself.
const (
	ioprioWhoProcess = 1 // IOPRIO_WHO_PROCESS: target a single process
	ioprioClassShift = 13
	// ioprioClassBE / ioprioBELowest: best-effort class, lowest slot.
	// Deliberately NOT the idle class (3): idle IO is only serviced when the
	// disk is otherwise quiet and can be starved indefinitely under a
	// sustained workload (a running build), whereas best-effort prio 7 is the
	// last slot in the round-robin and always makes progress.
	ioprioClassBE  = 2
	ioprioBELowest = 7
)

func apply() (string, error) {
	var parts []string

	niceErr := syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19)
	if niceErr == nil {
		parts = append(parts, "nice 19")
	}

	ioprio := uintptr(ioprioClassBE<<ioprioClassShift | ioprioBELowest)
	_, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, 0, ioprio)
	if errno == 0 {
		parts = append(parts, "ionice best-effort 7")
	}

	// Partial success still helps; report only what actually applied.
	if len(parts) == 0 {
		return "", fmt.Errorf("setpriority: %v; ioprio_set: %v", niceErr, errno)
	}
	return strings.Join(parts, ", ") + " (inherited by child processes)", nil
}
