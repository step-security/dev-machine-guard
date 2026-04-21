package detector

import (
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// platformShellQuote quotes a string for use in a shell command.
// On Unix: single quotes with escaping.
// On Windows: double quotes with escaping.
func platformShellQuote(exec executor.Executor, s string) string {
	if exec.GOOS() == "windows" {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
