//go:build linux

package bgpriority

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ioprio_set(2) encoding (linux/ioprio.h), spelled out because neither the
// stdlib nor golang.org/x/sys/unix wraps the call itself.
const (
	ioprioWhoProcess = 1 // IOPRIO_WHO_PROCESS: with a tid, targets that thread
	ioprioClassShift = 13
	// ioprioClassBE / ioprioBELowest: best-effort class, lowest slot.
	// Deliberately NOT the idle class (3): idle IO is only serviced when the
	// disk is otherwise quiet and can be starved indefinitely under a
	// sustained workload (a running build), whereas best-effort prio 7 is the
	// last slot in the round-robin and always makes progress.
	ioprioClassBE  = 2
	ioprioBELowest = 7
)

// apply lowers CPU and IO priority for EVERY current OS thread. On Linux both
// setpriority(PRIO_PROCESS, 0, …) and ioprio_set(IOPRIO_WHO_PROCESS, 0, …)
// act on the CALLING THREAD only (nice is per-task under NPTL), and the Go
// runtime multiplexes goroutines across many threads — a single self-targeted
// call would leave most scan work, and any child forked from another thread,
// at normal priority. Walking /proc/self/task covers every live thread;
// threads and child processes created afterwards inherit from their (covered)
// creator, so the whole process stays in the background band.
func apply() (string, error) {
	tids, err := os.ReadDir("/proc/self/task")
	if err != nil {
		// Fall back to the calling thread — degraded but not useless.
		return applyToThread(0)
	}

	niceCovered, ioCovered := 0, 0
	for _, ent := range tids {
		tid, convErr := strconv.Atoi(ent.Name())
		if convErr != nil {
			continue
		}
		// A thread can exit between the ReadDir and the calls (ESRCH) —
		// count only what actually applied.
		if syscall.Setpriority(syscall.PRIO_PROCESS, tid, 19) == nil {
			niceCovered++
		}
		ioprio := uintptr(ioprioClassBE<<ioprioClassShift | ioprioBELowest)
		// #nosec G115 -- tid parses from a /proc/self/task entry name: a
		// positive kernel thread id, always far below uintptr's range.
		if _, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprio); errno == 0 {
			ioCovered++
		}
	}

	var parts []string
	if niceCovered > 0 {
		parts = append(parts, fmt.Sprintf("nice 19 on %d/%d threads", niceCovered, len(tids)))
	}
	if ioCovered > 0 {
		parts = append(parts, fmt.Sprintf("ionice best-effort 7 on %d/%d threads", ioCovered, len(tids)))
	}
	// Partial success still helps; report only what actually applied.
	if len(parts) == 0 {
		return "", fmt.Errorf("setpriority/ioprio_set applied to no thread")
	}
	return strings.Join(parts, ", ") + " (inherited by new threads and child processes)", nil
}

// applyToThread is the single-target fallback when /proc is unavailable.
func applyToThread(tid int) (string, error) {
	var parts []string
	niceErr := syscall.Setpriority(syscall.PRIO_PROCESS, tid, 19)
	if niceErr == nil {
		parts = append(parts, "nice 19")
	}
	ioprio := uintptr(ioprioClassBE<<ioprioClassShift | ioprioBELowest)
	// #nosec G115 -- tid is 0 (calling thread) on this fallback path.
	_, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprio)
	if errno == 0 {
		parts = append(parts, "ionice best-effort 7")
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("setpriority: %v; ioprio_set: %v", niceErr, errno)
	}
	return strings.Join(parts, ", ") + " (calling thread only; /proc/self/task unavailable)", nil
}
