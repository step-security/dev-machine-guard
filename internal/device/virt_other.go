//go:build !windows

package device

import (
	"context"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// windowsSMBIOS has no registry off Windows; mock-based tests that simulate a
// Windows host answer the CIM commands instead.
func windowsSMBIOS(ctx context.Context, exec executor.Executor) smbiosInfo {
	return windowsSMBIOSFromCIM(ctx, exec)
}
