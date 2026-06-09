//go:build !windows

package main

import (
	"os"
	"syscall"
	"time"

	"github.com/step-security/dev-machine-guard/internal/progress"
)

// armExecutionWatchdog spawns a single-shot goroutine that, after d
// elapses, signals the process to exit. Graceful first (SIGTERM so the
// signal handler at telemetry.go:259 posts the failure row, releases the
// lock, and flushes the log tail), then a 5s hard-out via os.Exit(2) if
// SIGTERM didn't take.
//
// The watchdog defends against goroutine wedges that the scan-deadline
// context cancel can't reach: a hung HTTP upload bound to a stuck TCP
// socket; an unreaped grandchild that slipped past the PR-122
// process-group fix; a future leak we haven't anticipated. The scan
// deadline (STEPSEC_MAX_SCAN_DURATION, 60min default) bounds the scan
// body; this bounds the whole process.
//
// Goroutine lives in main rather than telemetry.Run so it survives any
// panic/recover and any code path that doesn't return. No cancellation
// path: the watchdog must fire even when the rest of the process is
// wedged.
//
// d <= 0 disables the watchdog (caller passes the result of
// telemetry.ExecutionDeadlineFromEnv which already returns 0 for the
// "off"/"0" env settings).
func armExecutionWatchdog(d time.Duration, log *progress.Logger) {
	if d <= 0 {
		return
	}
	go func() {
		time.Sleep(d)
		log.Warn("execution-watchdog: max duration %s exceeded — initiating shutdown", d)
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		time.Sleep(5 * time.Second)
		log.Error("execution-watchdog: SIGTERM did not exit in 5s — hard kill")
		os.Exit(2)
	}()
}
