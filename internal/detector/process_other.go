//go:build !windows

package detector

import (
	"context"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// processMatchExact uses exec.Run("tasklist") when not compiled for Windows.
// This path is used by mock-based tests that simulate Windows via SetGOOS("windows").
func processMatchExact(ctx context.Context, exec executor.Executor, name string) bool {
	stdout, _, exitCode, _ := exec.Run(ctx, "tasklist", "/FI",
		"IMAGENAME eq "+name+".exe", "/NH")
	return exitCode == 0 && !strings.Contains(stdout, "INFO: No tasks")
}

// processMatchFuzzy uses exec.Run("tasklist") when not compiled for Windows.
func processMatchFuzzy(ctx context.Context, exec executor.Executor, pattern string) bool {
	stdout, _, _, _ := exec.Run(ctx, "tasklist", "/NH")
	return strings.Contains(strings.ToLower(stdout), strings.ToLower(pattern))
}
