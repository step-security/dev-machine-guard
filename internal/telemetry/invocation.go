package telemetry

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/launchd"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/schtasks"
	"github.com/step-security/dev-machine-guard/internal/systemd"
)

// Wire-format values for the invocation_method field. Kept stable —
// console and backend match on these literal strings.
const (
	InvocationInstall = "install"
	InvocationOneTime = "one_time"
)

// jobStateProbeTimeout bounds the per-platform "is the scheduler job running"
// probe so a slow launchctl/systemctl/powershell can't delay run start.
const jobStateProbeTimeout = 3 * time.Second

// DetectInvocationMethod reports whether THIS run was triggered by the installed
// scheduler ("install") or started manually ("one_time").
//
// A scheduler footprint on disk is necessary but not sufficient — a developer
// can run `send-telemetry` by hand on a machine that also has the scheduler
// installed, and the field/UI mean per-invocation (scheduled vs manual), not
// "is a scheduler installed." So when a footprint exists we consult the live
// job state: only when the scheduler job is CONFIRMED idle do we report a manual
// run; if it's running, or the probe is inconclusive, we keep "install" so a
// genuine scheduled run is never mislabeled. Best-effort and never errors.
func DetectInvocationMethod(exec executor.Executor, log *progress.Logger) string {
	if !isSchedulerInstalled(exec) {
		return InvocationOneTime
	}
	if idle, known := schedulerJobIdle(exec, log); known && idle {
		return InvocationOneTime
	}
	return InvocationInstall
}

func isSchedulerInstalled(exec executor.Executor) bool {
	switch exec.GOOS() {
	case model.PlatformDarwin:
		return fileExists(launchd.DaemonPlistPath) || fileExists(launchd.UserPlistPath())
	case model.PlatformLinux:
		return fileExists(systemd.TimerUnitPath())
	case model.PlatformWindows:
		return schtasks.IsTaskRegistered(context.Background(), exec)
	default:
		return false
	}
}

// schedulerJobIdle reports whether the scheduler job/task is CONFIRMED not
// currently running. The second return is false when the state can't be
// determined (probe failed / unsupported), so callers fail safe to "install".
// The signals are locale-independent: launchctl's "PID" key, systemctl's fixed
// active/activating states, and Get-ScheduledTask's State enum (NOT schtasks
// /query's localized Status field). The exact probe command is logged at debug
// so a misbehaving machine can be reproduced by hand.
func schedulerJobIdle(exec executor.Executor, log *progress.Logger) (idle, known bool) {
	switch exec.GOOS() {
	case model.PlatformDarwin:
		// `launchctl list <label>` prints a "PID" key only while the job runs.
		out, code, err := runStateProbe(exec, log, "launchctl", "list", launchd.Label)
		if err != nil || code != 0 {
			return false, false
		}
		return !strings.Contains(out, `"PID"`), true
	case model.PlatformLinux:
		// is-active prints active/activating while the oneshot service runs;
		// inactive/failed when idle. Fixed strings, not localized. (A non-zero
		// exit is the normal "inactive" answer, so we key off the text.)
		out, _, err := runStateProbe(exec, log, "systemctl", "--user", "is-active", systemd.ServiceUnitName())
		if err != nil {
			return false, false
		}
		state := strings.TrimSpace(out)
		if state == "" {
			return false, false
		}
		running := state == "active" || state == "activating"
		return !running, true
	case model.PlatformWindows:
		// Get-ScheduledTask's State enum (Ready/Running/...) is locale-independent,
		// unlike schtasks /query's localized Status. Absent on Server Core minimal
		// (no ScheduledTasks module) → probe fails → inconclusive → keep "install".
		out, code, err := runStateProbe(exec, log, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			"(Get-ScheduledTask -TaskName '"+schtasks.TaskName+"').State")
		if err != nil || code != 0 {
			return false, false
		}
		state := strings.TrimSpace(out)
		if state == "" {
			return false, false
		}
		return !strings.EqualFold(state, "Running"), true
	default:
		return false, false
	}
}

// runStateProbe runs a scheduler state-probe command and logs the exact
// invocation + result at debug level, so a support engineer can copy the
// command verbatim and re-run it on the affected machine.
func runStateProbe(exec executor.Executor, log *progress.Logger, name string, args ...string) (stdout string, code int, err error) {
	stdout, stderr, code, err := exec.RunWithTimeout(context.Background(), jobStateProbeTimeout, name, args...)
	log.Debug("invocation state probe: %s %s -> exit=%d err=%v out=%q stderr=%q",
		name, strings.Join(args, " "), code, err, strings.TrimSpace(stdout), strings.TrimSpace(stderr))
	return stdout, code, err
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
