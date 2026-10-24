//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/step-security/dev-machine-guard/internal/awakeclock"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
)

// armExecutionWatchdog (Windows): same intent as the Unix version but
// skips the SIGTERM step. Windows console-signal mechanics (CTRL_C_EVENT
// via os.Process.Signal(os.Interrupt)) only reach console-attached
// processes, and the scheduled-task path under
// stepsecurity-dev-machine-guard-task.exe runs without a console. os.Exit(2)
// skips deferred cleanup, but the instance mutex is released by the OS on
// process exit. With no signal to route through telemetry.Run's handler, the
// failed run-status is posted directly.
func armExecutionWatchdog(d time.Duration, log *progress.Logger) {
	if d <= 0 {
		return
	}
	start := awakeclock.Begin(awakeclock.System)
	go func() {
		// Awake time: Go's monotonic clock on Windows includes sleep, so a
		// laptop closed mid-scan would otherwise trip this on resume.
		start.Wait(d, nil, time.Minute)
		log.Warn("execution-watchdog: max duration %s exceeded — exiting", d)
		telemetry.ReportFatal(fmt.Sprintf("execution-watchdog: max duration %s exceeded", d), 10*time.Second)
		os.Exit(2) // a real hang: d of awake time (sleep excluded)
	}()
}
