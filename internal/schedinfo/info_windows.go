//go:build windows

package schedinfo

import (
	"context"
	"fmt"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/schtasks"
)

func gather(ctx context.Context, exec executor.Executor) Info {
	info := Info{
		Platform:        "windows",
		Manager:         "schtasks",
		Label:           schtasks.TaskName,
		ConfiguredHours: configuredHours(),
		Management:      ManagementUnknown,
		LogMtime:        logMtime(),
	}
	// schtasks /v doesn't reliably surface the repetition interval for
	// /sc HOURLY, so derive it from config (the value baked at install time).
	if info.ConfiguredHours > 0 {
		info.IntervalSeconds = info.ConfiguredHours * 3600
	}

	info.Scheduled = schtasks.IsTaskRegistered()

	stdout, stderr, code, err := exec.RunWithTimeout(ctx, queryTimeout,
		"schtasks", "/query", "/tn", schtasks.TaskName, "/v", "/fo", "LIST")
	switch {
	case err != nil:
		info.Warnings = append(info.Warnings, fmt.Sprintf("schtasks query: %v", err))
	case code != 0:
		info.Warnings = append(info.Warnings, fmt.Sprintf("schtasks query exited %d: %s", code, firstLine(stderr)))
	default:
		info.Loaded = true
		info.Raw = stdout
		applySchtasksList(&info, stdout)
	}
	return info
}
