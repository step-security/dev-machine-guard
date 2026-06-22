//go:build linux

package schedinfo

import (
	"context"
	"fmt"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/systemd"
)

// gather is best-effort on Linux: it confirms the systemd user timer footprint
// and captures `systemctl --user list-timers` output (logged at Debug) for the
// NEXT/LAST columns. Detailed per-field parsing is intentionally skipped — the
// table is locale/width-dependent; the agent.log mtime serves as the last-run
// proxy. macOS and Windows are the richly-parsed targets.
func gather(ctx context.Context, exec executor.Executor) Info {
	info := Info{
		Platform:        "linux",
		Manager:         "systemd",
		Label:           "stepsecurity-dev-machine-guard.timer",
		ConfiguredHours: configuredHours(),
		Management:      ManagementUnknown,
		LogMtime:        logMtime(),
	}
	if info.ConfiguredHours > 0 {
		info.IntervalSeconds = info.ConfiguredHours * 3600
	}

	unitPath := systemd.TimerUnitPath()
	info.UnitPath = unitPath
	info.Scheduled = exec.FileExists(unitPath)

	out, stderr, code, err := exec.RunWithTimeout(ctx, queryTimeout,
		"systemctl", "--user", "list-timers", "--all", "--no-pager")
	switch {
	case err != nil:
		info.Warnings = append(info.Warnings, fmt.Sprintf("systemctl list-timers: %v", err))
	case code != 0:
		info.Warnings = append(info.Warnings, fmt.Sprintf("systemctl list-timers exited %d: %s", code, firstLine(stderr)))
	default:
		info.Raw = out
		if strings.Contains(out, "stepsecurity-dev-machine-guard") {
			info.Loaded = true
		}
	}
	return info
}
