package telemetry

import (
	"os"
	"time"
)

// defaultExecutionDeadline is the hard wall on whole-process runtime.
// Sits ABOVE the scan deadline (STEPSEC_MAX_SCAN_DURATION, 60min default):
// scan-deadline cancels the scan body but leaves heartbeat, phase-post,
// and final upload running on runCtx. If any of those goroutines wedges
// — a hung S3 PUT, an HTTP socket stuck in close-wait, an unreaped
// grandchild that slipped past the PR-122 process-group fix — the
// process can otherwise run indefinitely. Four hours gives normal scans
// (which finish in under an hour) plus retry budget room, while still
// bounding pathological cases to a single daily launchd/schtasks tick.
const defaultExecutionDeadline = 4 * time.Hour

// EnvMaxExecutionDuration is an optional environment-variable override for the
// execution watchdog, honored ahead of config.json for ad-hoc/manual runs
// (e.g. `STEPSEC_MAX_EXECUTION_DURATION=3s ./binary send-telemetry`). The
// loader no longer exports it: the configured value is delivered through
// config.json (config.MaxExecutionDuration), which the binary reads on every
// invocation — including scheduler-fired runs (launchd/systemd/schtasks) that
// bypass the loader.
const EnvMaxExecutionDuration = "STEPSEC_MAX_EXECUTION_DURATION"

// ExecutionDeadlineFromEnv resolves the execution deadline from the environment
// only. Equivalent to ExecutionDeadline(""); kept for callers (and tests) that
// have no config fallback to supply.
func ExecutionDeadlineFromEnv() time.Duration {
	return ExecutionDeadline("")
}

// ExecutionDeadline resolves the whole-process execution deadline with
// env > config > default precedence. The env var (EnvMaxExecutionDuration) is
// an optional ad-hoc override; configValue is the value the loader/installer
// persists into config.json (config.MaxExecutionDuration), the primary channel
// — it covers every invocation, including scheduler-fired runs
// (launchd/systemd/schtasks) that invoke the binary directly. Each source uses
// the same contract as scanDeadlineFromEnv (scan_deadline.go):
//   - "0" / "off": 0 (watchdog disabled; main.go skips arming)
//   - any positive Go time.ParseDuration string ("2h", "30m", "45m30s"): that
//     duration
//   - empty or unparseable: fall through to the next source, then to
//     defaultExecutionDeadline (a typo in an unattended launchd/schtasks/systemd
//     context must not be fatal to the scan)
func ExecutionDeadline(configValue string) time.Duration {
	if d, ok := parseExecutionDeadline(os.Getenv(EnvMaxExecutionDuration)); ok {
		return d
	}
	if d, ok := parseExecutionDeadline(configValue); ok {
		return d
	}
	return defaultExecutionDeadline
}

// parseExecutionDeadline applies the shared parse contract to a single raw
// value. ok is false when the value is absent or unparseable — signalling the
// caller to fall through to the next source; true (with a possibly-zero
// duration) when the value explicitly resolved, including the "0"/"off" disable
// case.
func parseExecutionDeadline(v string) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if v == "0" || v == "off" {
		return 0, true
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}
