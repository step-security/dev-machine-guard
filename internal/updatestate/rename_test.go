package updatestate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestRenameDirNamesHoldersOnGiveUp(t *testing.T) {
	stubRename(t, 1<<30, errBlocked)
	renameRetryBudget = 0
	old := blockedBy
	t.Cleanup(func() { blockedBy = old })
	var asked []string
	blockedBy = func(paths []string) []string {
		asked = paths
		return []string{"MsMpEng.exe pid 4120 (Microsoft Defender Antivirus Service)"}
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, AgentFile), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RenameDir(src, src+"-dst")
	if !errors.Is(err, errBlocked) || !RenameBlocked(err) {
		t.Fatalf("RenameDir = %v, want a wrapped blocked error", err)
	}
	if !strings.Contains(err.Error(), "held by MsMpEng.exe pid 4120") || len(asked) != 1 {
		t.Fatalf("err = %q, asked %v", err, asked)
	}
	blockedBy = func([]string) []string { return nil }
	if err := RenameDir(src, src+"-dst"); !strings.Contains(err.Error(), "holder not identified") {
		t.Fatalf("err = %q, want holder not identified", err)
	}
}
