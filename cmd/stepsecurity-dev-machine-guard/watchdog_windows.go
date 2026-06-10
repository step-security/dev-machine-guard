//go:build windows

package main

import (
	"os"
	"time"

	"github.com/step-security/dev-machine-guard/internal/progress"
)

// armExecutionWatchdog (Windows): same intent as the Unix version but
// skips the SIGTERM step. Windows console-signal mechanics (CTRL_C_EVENT
// via os.Process.Signal(os.Interrupt)) only reach console-attached
// processes, and the scheduled-task path under
// stepsecurity-dev-machine-guard-task.exe runs without a console. Calling
// os.Exit(2) directly skips the deferred lock release; the next launch's
// loader-side stale-process killer (scripts/windows-device-agent/
// stepsecurity-loader.ps1 Stop-StaleDmgProcesses) plus lock.Acquire's
// own dead-PID handling clean up any stale state.
func armExecutionWatchdog(d time.Duration, log *progress.Logger) {
	if d <= 0 {
		return
	}
	go func() {
		time.Sleep(d)
		log.Warn("execution-watchdog: max duration %s exceeded — exiting", d)
		os.Exit(2)
	}()
}
