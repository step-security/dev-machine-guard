package updatestate

import (
	"errors"
	"testing"
	"time"
)

var errBlocked = errors.New("blocked by an open handle")

func stubRename(t *testing.T, fails int, failErr error) *int {
	t.Helper()
	calls := 0
	oldRename, oldBlocked, oldSleep, oldBudget := osRename, isRenameBlocked, renameSleep, renameRetryBudget
	t.Cleanup(func() {
		osRename, isRenameBlocked, renameSleep, renameRetryBudget = oldRename, oldBlocked, oldSleep, oldBudget
	})
	osRename = func(string, string) error {
		calls++
		if calls <= fails {
			return failErr
		}
		return nil
	}
	isRenameBlocked = func(err error) bool { return errors.Is(err, errBlocked) }
	renameSleep = func(time.Duration) {}
	return &calls
}

func TestRenameDirRetriesWhileBlocked(t *testing.T) {
	calls := stubRename(t, 3, errBlocked)
	if err := RenameDir("a", "b"); err != nil {
		t.Fatalf("RenameDir = %v", err)
	}
	if *calls != 4 {
		t.Fatalf("calls = %d, want 4", *calls)
	}
}

func TestRenameDirReturnsOtherErrorsAtOnce(t *testing.T) {
	other := errors.New("not found")
	calls := stubRename(t, 1, other)
	if err := RenameDir("a", "b"); !errors.Is(err, other) {
		t.Fatalf("RenameDir = %v, want %v", err, other)
	}
	if *calls != 1 {
		t.Fatalf("calls = %d, want 1", *calls)
	}
}

func TestRenameDirGivesUpAfterBudget(t *testing.T) {
	stubRename(t, 1<<30, errBlocked)
	renameRetryBudget = 0
	if err := RenameDir("a", "b"); !errors.Is(err, errBlocked) {
		t.Fatalf("RenameDir = %v, want %v", err, errBlocked)
	}
}
