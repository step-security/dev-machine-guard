//go:build windows

package winproc

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// The MSI's stop-for-msi spares the on-device firewall's folder inside the
// install root: a process there keeps running, one elsewhere under the root
// is stopped, and ImageRunning sees each by its image path.
func TestStopUnderExceptSparesKeptDir(t *testing.T) {
	root := t.TempDir()
	self, _ := os.Executable()
	copyTo := func(dst string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		in, _ := os.Open(self)
		out, _ := os.Create(dst)
		_, _ = io.Copy(out, in)
		_ = in.Close()
		_ = out.Close()
	}
	kept := filepath.Join(root, "OnDeviceFirewall", "fw.exe")
	dmg := filepath.Join(root, "versions", "1.0.0", "dmg.exe")
	copyTo(kept)
	copyTo(dmg)
	var cmds []*exec.Cmd
	for _, exe := range []string{kept, dmg} {
		cmd := proctest.Command(t, exe, "-test.run=^TestHelperSleep$")
		cmd.Env = append(cmd.Env, "WINPROC_HELPER_SLEEP=1")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, cmd)
	}
	defer func() {
		for _, c := range cmds {
			_ = c.Process.Kill()
		}
	}()
	time.Sleep(500 * time.Millisecond)
	if !ImageRunning(kept) || !ImageRunning(dmg) {
		t.Fatalf("ImageRunning: kept %v, dmg %v", ImageRunning(kept), ImageRunning(dmg))
	}
	stopped, err := StopUnderExcept(root, []string{filepath.Join(root, "OnDeviceFirewall")})
	if err != nil || len(stopped) != 1 || !strings.EqualFold(stopped[0], dmg) {
		t.Fatalf("StopUnderExcept = %v, %v", stopped, err)
	}
	if !ImageRunning(kept) {
		t.Fatal("the kept folder's process was stopped")
	}
}

func TestHelperSleep(t *testing.T) {
	if os.Getenv("WINPROC_HELPER_SLEEP") != "1" {
		t.Skip("helper")
	}
	proctest.Guard()
	time.Sleep(time.Minute)
}
