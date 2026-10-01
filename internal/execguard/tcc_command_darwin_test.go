//go:build darwin

package execguard

import (
	"context"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"testing"
)

func TestTCCPreservesSafeCommandFallback(t *testing.T) {
	e := executor.NewMock()
	e.SetGOOS("darwin")
	e.SetCommand("", "", 1, "/usr/bin/xattr", "-p", "com.apple.quarantine", "/usr/local/bin/widgets")
	e.SetCommand("", "", 1, "/usr/bin/xattr", "-p", "com.apple.quarantine", "/usr/local/bin")
	guarded := tcc.GuardedFiles(e, tcc.New(t.TempDir()), 1024)
	if safe, reason := SafeToExec(context.Background(), guarded, "/usr/local/bin/widgets"); !safe {
		t.Fatalf("ordinary CLI fallback suppressed: %s", reason)
	}
}
