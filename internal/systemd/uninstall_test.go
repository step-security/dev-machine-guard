package systemd

import (
	"context"
	"errors"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func TestDoUninstall_ReportsServiceStillActive(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ex := executor.NewMock()
	ex.SetCommand("", "Failed to stop "+unitName+".service", 1, "systemctl", "--user", "stop", unitName+".service")
	ex.SetCommand("active\n", "", 0, "systemctl", "--user", "is-active", unitName+".service")

	err := doUninstall(context.Background(), ex, progress.NewLogger(progress.LevelError))
	if !errors.Is(err, errStillRunning) {
		t.Fatalf("doUninstall with an active service after a failed stop: err=%v, want errStillRunning", err)
	}
}

func TestDoUninstall_StoppedServiceIsClean(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ex := executor.NewMock()
	ex.SetCommand("", "", 0, "systemctl", "--user", "stop", unitName+".service")
	ex.SetCommand("inactive\n", "", 3, "systemctl", "--user", "is-active", unitName+".service")

	if err := doUninstall(context.Background(), ex, progress.NewLogger(progress.LevelError)); err != nil {
		t.Fatalf("doUninstall with a stopped service: %v", err)
	}
}
