//go:build windows

package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// D15/R-C2-7: a hung self-check and everything it spawned die with the
// smoke's job.
func TestSmokeKillsGrandchildren(t *testing.T) {
	t.Setenv(envHelper, "1")
	t.Setenv("DMG_SU_SMOKE_HANG", "1")
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	t.Setenv("DMG_SU_SMOKE_GRANDCHILD", pidFile)
	knobOverrides = map[knob]time.Duration{knobSmokeTimeout: 3 * time.Second}
	defer func() { knobOverrides = map[knob]time.Duration{} }()
	exe := filepath.Join(t.TempDir(), "1.20.0", "agent.exe")
	copySelf(t, exe)
	if err := RunSmoke(context.Background(), exe, mustV("1.20.0")); err == nil {
		t.Fatal("hung smoke passed")
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("grandchild never started: %v", err)
	}
	pid, _ := strconv.Atoi(string(b))
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return // already gone
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if ev, _ := windows.WaitForSingleObject(h, 10_000); ev != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(h, 1)
		t.Fatal("the self-check's child outlived the smoke")
	}
}
