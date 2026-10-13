//go:build windows

package updateinstall

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestReplacePair_WindowsSharingViolationRestoresLauncher(t *testing.T) {
	dir, l, a := pairFixture(t)
	lk, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	path, err := windows.UTF16PtrFromString(filepath.Join(dir, Agent))
	if err != nil {
		t.Fatal(err)
	}
	// Permit reads for backup, but deny renaming the agent, as an endpoint
	// scanner can do. Launcher replacement succeeds before this fails.
	h, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
	}()
	if err = ReplacePair(dir, l, a); err == nil {
		t.Fatal("expected sharing violation")
	}
	// Recovery may also be blocked until the foreign handle closes. The journal
	// must survive, and the next bootstrap must restore the complete old pair.
	if err = windows.CloseHandle(h); err != nil {
		t.Fatal(err)
	}
	h = 0
	if err = Recover(dir); err != nil {
		t.Fatal(err)
	}
	assertPair(t, dir, "old-")
}

func TestAcquire_InteroperatesWithPowerShellInstaller(t *testing.T) {
	dir := t.TempDir()
	lk, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	for _, locked := range []bool{true, false} {
		if !locked {
			lk.Release()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; $f=[IO.File]::Open($env:DMG_INSTALL_LOCK, 'OpenOrCreate', 'ReadWrite', 'ReadWrite'); try { $f.Lock(0,1) } catch { $f.Dispose(); exit 38 }; $f.Dispose(); exit 0`)
		cmd.Env = append(os.Environ(), "DMG_INSTALL_LOCK="+filepath.Join(dir, ".selfupdate.lock"))
		out, runErr := cmd.CombinedOutput()
		cancel()
		want := 0
		if locked {
			want = 38
		}
		if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != want {
			t.Fatalf("PowerShell locked=%v: %v, %s", locked, runErr, out)
		}
	}
}
