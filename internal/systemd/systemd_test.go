package systemd

import (
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// TestStartTimer_IssuesPlainStart asserts the timer-activation command does
// not carry --now (which would be redundant for `start`) and targets the
// expected unit name. Deliberately separate from Install so the install-time
// race fix (issue #62) — enable without --now, then StartTimer after the
// inline scan — stays locked in.
func TestStartTimer_IssuesPlainStart(t *testing.T) {
	mock := executor.NewMock()
	mock.SetCommand("", "", 0, "systemctl", "--user", "start", unitName+".timer")

	if err := StartTimer(mock, progress.NewLogger(progress.LevelInfo)); err != nil {
		t.Fatalf("StartTimer returned error: %v", err)
	}
}

// TestStartTimer_PropagatesFailure asserts the function surfaces a non-zero
// systemctl exit so the install command can warn the operator.
func TestStartTimer_PropagatesFailure(t *testing.T) {
	mock := executor.NewMock()
	mock.SetCommand("", "Failed to start: Unit not found", 1,
		"systemctl", "--user", "start", unitName+".timer")

	err := StartTimer(mock, progress.NewLogger(progress.LevelInfo))
	if err == nil {
		t.Fatal("expected error from non-zero systemctl exit, got nil")
	}
	if !strings.Contains(err.Error(), "exit code 1") {
		t.Errorf("error should reference the exit code: %v", err)
	}
}
