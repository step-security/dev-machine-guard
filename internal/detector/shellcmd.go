package detector

import (
	"strconv"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// platformShellQuote quotes a string for use in a shell command.
// On Unix: uses strconv.Quote for safe quoting.
// On Windows: uses strconv.Quote for safe quoting.
func platformShellQuote(exec executor.Executor, s string) string {
	_ = exec
	_ = model.PlatformWindows
	return strconv.Quote(s)
}