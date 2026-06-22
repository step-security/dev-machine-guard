//go:build !darwin && !windows && !linux

package schedinfo

import (
	"context"
	"runtime"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// gather is a no-op on platforms without a supported scheduler integration.
func gather(_ context.Context, _ executor.Executor) Info {
	return Info{Platform: runtime.GOOS, Management: ManagementUnknown}
}
