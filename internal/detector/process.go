package detector

import (
	"context"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// isProcessRunning checks if a process with the given name is running.
// On Unix, uses pgrep -x; on Windows, uses tasklist with IMAGENAME filter.
func isProcessRunning(ctx context.Context, exec executor.Executor, name string) bool {
	if exec.GOOS() == "windows" {
		stdout, _, exitCode, _ := exec.Run(ctx, "tasklist", "/FI",
			"IMAGENAME eq "+name+".exe", "/NH")
		return exitCode == 0 && !strings.Contains(stdout, "INFO: No tasks")
	}
	_, _, exitCode, _ := exec.Run(ctx, "pgrep", "-x", name)
	return exitCode == 0
}

// isProcessRunningFuzzy checks if any process matches a substring pattern.
// On Unix, uses pgrep -f; on Windows, scans tasklist output.
func isProcessRunningFuzzy(ctx context.Context, exec executor.Executor, pattern string) bool {
	if exec.GOOS() == "windows" {
		stdout, _, _, _ := exec.Run(ctx, "tasklist", "/NH")
		return strings.Contains(strings.ToLower(stdout), strings.ToLower(pattern))
	}
	_, _, exitCode, _ := exec.Run(ctx, "pgrep", "-f", pattern)
	return exitCode == 0
}
