package telemetry

import (
	"errors"

	"github.com/step-security/dev-machine-guard/internal/faultinject"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// ErrPanic wraps a panic Run recovered from. The process must still end as
// a crash (exit 2), or the self-update health check would count a crashing
// version as healthy (panic after run-status "started") or neutral.
var ErrPanic = errors.New("panic in telemetry.Run")

// ExitCode is the process exit code for Run's error: 2 for a recovered
// panic (the Go runtime's own panic code), 1 for any other failure.
func ExitCode(err error) int {
	if errors.Is(err, ErrPanic) {
		return 2
	}
	return 1
}

// scanCheckpoint is a fault checkpoint inside the scan (selfupdate_faults
// builds only): a harness can make a version crash before or after it
// reports "started". An injected error is only logged.
func scanCheckpoint(log *progress.Logger, name string) {
	if err := faultinject.Point(name); err != nil {
		log.Debug("fault checkpoint %s: %v", name, err)
	}
}
