//go:build windows

package winproc

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

// D29: a file is "released" only once nothing holds it: an open handle or
// a running image keeps it held, and StopUnder + WaitReleased clears both.
func TestStopUnderThenWaitReleased(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "seed", "1.0.0", "held.exe")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	in, _ := os.Open(self)
	out, _ := os.Create(exe)
	_, _ = io.Copy(out, in)
	_ = in.Close()
	_ = out.Close()

	// A running image holds its file.
	cmd := proctest.Command(t, exe, "-test.run=^TestHelperSleep$")
	cmd.Env = append(cmd.Env, "WINPROC_HELPER_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	time.Sleep(500 * time.Millisecond)
	if held := WaitReleased([]string{exe}, 300*time.Millisecond, 50*time.Millisecond); len(held) != 1 {
		t.Fatalf("running image not reported held: %v", held)
	}
	stopped, err := StopUnder(root)
	if err != nil || len(stopped) != 1 {
		t.Fatalf("StopUnder = %v, %v", stopped, err)
	}
	if held := WaitReleased([]string{exe}, 30*time.Second, 10*time.Millisecond); len(held) != 0 {
		t.Fatalf("still held after StopUnder: %v", held)
	}

	// An open exclusive handle holds it too.
	p, _ := windows.UTF16PtrFromString(exe)
	h, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if held := WaitReleased([]string{exe}, 200*time.Millisecond, 50*time.Millisecond); len(held) != 1 {
		t.Fatal("open handle not reported held")
	}
	_ = windows.CloseHandle(h)
	if held := WaitReleased([]string{exe}, 5*time.Second, 10*time.Millisecond); len(held) != 0 {
		t.Fatal("not released after the handle closed")
	}
	// A missing file is not held.
	if held := WaitReleased([]string{filepath.Join(root, "gone.exe")}, 100*time.Millisecond, 10*time.Millisecond); len(held) != 0 {
		t.Fatal("missing file reported held")
	}
}

func TestHelperSleep(t *testing.T) {
	if os.Getenv("WINPROC_HELPER_SLEEP") != "1" {
		t.Skip("helper")
	}
	proctest.Guard()
	time.Sleep(time.Minute)
}
