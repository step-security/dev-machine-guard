//go:build windows

package updatestate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// holdOpen opens path the way an AV scanner does: read access, sharing
// read and write but not delete.
func holdOpen(t *testing.T, path string) windows.Handle {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func stagedDir(t *testing.T) (src, dst string) {
	t.Helper()
	root := t.TempDir()
	src, dst = filepath.Join(root, ".staging-1.0.0-x"), filepath.Join(root, "1.0.0")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, AgentFile), []byte("agent"), 0o644); err != nil {
		t.Fatal(err)
	}
	return src, dst
}

func TestRenameDirWaitsForScannerHandle(t *testing.T) {
	src, dst := stagedDir(t)
	h := holdOpen(t, filepath.Join(src, AgentFile))
	if err := os.Rename(src, dst); !renameBlocked(err) {
		windows.CloseHandle(h)
		t.Fatalf("plain rename with an open handle = %v, want a blocked error", err)
	}
	go func() { time.Sleep(time.Second); windows.CloseHandle(h) }()
	if err := RenameDir(src, dst); err != nil {
		t.Fatalf("RenameDir = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, AgentFile)); err != nil {
		t.Fatal(err)
	}
}

func TestRenameDirGivesUpOnAHeldHandle(t *testing.T) {
	src, dst := stagedDir(t)
	h := holdOpen(t, filepath.Join(src, AgentFile))
	defer windows.CloseHandle(h)
	old := renameRetryBudget
	renameRetryBudget = 2 * time.Second
	defer func() { renameRetryBudget = old }()
	err := RenameDir(src, dst)
	if !renameBlocked(err) {
		t.Fatalf("RenameDir = %v, want a blocked error", err)
	}
	// Restart Manager names this test process as the holder.
	if want := fmt.Sprintf("pid %d", os.Getpid()); !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %q, want the holder %q", err, want)
	}
}
