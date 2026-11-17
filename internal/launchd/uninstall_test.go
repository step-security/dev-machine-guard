package launchd

import (
	"context"
	"errors"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func TestDoUninstall_ReportsServiceStillLoadedAfterFailedBootout(t *testing.T) {
	noSleep(t)
	ex := executor.NewMock()
	_, target := DomainTarget(ex)
	ex.SetCommand("-\t0\t"+label+"\n", "", 0, "launchctl", "list")
	ex.SetCommand("", "Boot-out failed: 5: Input/output error", 5, "launchctl", "bootout", target)
	ex.SetCommand(target+" = {\n\tstate = running\n}\n", "", 0, "launchctl", "print", target)

	err := doUninstall(context.Background(), ex, progress.NewLogger(progress.LevelError))
	if !errors.Is(err, errStillRunning) {
		t.Fatalf("doUninstall with a loaded service after a failed bootout: err=%v, want errStillRunning", err)
	}
}

func TestDoUninstall_FailedBootoutOfAGoneServiceIsClean(t *testing.T) {
	noSleep(t)
	ex := executor.NewMock()
	_, target := DomainTarget(ex)
	ex.SetCommand("-\t0\t"+label+"\n", "", 0, "launchctl", "list")
	ex.SetCommand("", "Boot-out failed: 3: No such process", 3, "launchctl", "bootout", target)
	ex.SetCommand("", "Could not find service", 113, "launchctl", "print", target)

	if err := doUninstall(context.Background(), ex, progress.NewLogger(progress.LevelError)); err != nil {
		t.Fatalf("doUninstall when the service is already gone: %v", err)
	}
}
