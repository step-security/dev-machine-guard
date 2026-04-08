package detector

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// runShellCmd runs a shell command string using the platform-appropriate shell.
// On Unix: bash -c "command"
// On Windows: cmd /c "command"
func runShellCmd(ctx context.Context, exec executor.Executor, timeout time.Duration, command string) (string, string, int, error) {
	if exec.GOOS() == "windows" {
		return exec.RunWithTimeout(ctx, timeout, "cmd", "/c", command)
	}
	return exec.RunWithTimeout(ctx, timeout, "bash", "-c", command)
}

// platformShellQuote quotes a string for use in a shell command.
// On Unix: single quotes with escaping.
// On Windows: double quotes with escaping.
func platformShellQuote(exec executor.Executor, s string) string {
	if exec.GOOS() == "windows" {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
