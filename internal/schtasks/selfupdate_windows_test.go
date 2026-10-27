//go:build windows

package schtasks

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

const envSleep = "DMG_TEST_SLEEP"

// TestHelperSleep is a subprocess body that sleeps; skipped otherwise.
func TestHelperSleep(t *testing.T) {
	if os.Getenv(envSleep) == "" {
		t.Skip("subprocess helper")
	}
	proctest.Guard()
	time.Sleep(time.Minute)
}

func startSleeper(t *testing.T, exe string) *exec.Cmd {
	t.Helper()
	cmd := proctest.Command(t, exe, "-test.run=^TestHelperSleep$")
	cmd.Env = append(cmd.Env, envSleep+"=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func copyExe(t *testing.T, dst string) {
	t.Helper()
	in, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	_ = out.Close()
}

// R-B-5: terminateUnder stops processes whose image is under the root and
// leaves everything else (including itself) running.
func TestTerminateUnder(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "versions", "1.2.3", "stepsecurity-dev-machine-guard.exe")
	copyExe(t, inside)
	in := startSleeper(t, inside)
	out := startSleeper(t, os.Args[0])
	defer func() { _ = out.Process.Kill(); _, _ = out.Process.Wait() }()
	time.Sleep(500 * time.Millisecond)

	if err := terminateUnder(root, newTestLogger()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- in.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = in.Process.Kill()
		t.Fatal("process under the root still running")
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(out.Process.Pid)) // #nosec G115 -- test pid
	if err != nil {
		t.Fatalf("process outside the root is gone: %v", err)
	}
	defer windows.CloseHandle(h)
	if ev, _ := windows.WaitForSingleObject(h, 0); ev == windows.WAIT_OBJECT_0 {
		t.Fatal("process outside the root was terminated")
	}
}

// holdMutex owns name on a locked thread until release is closed.
func holdMutex(t *testing.T, name string, release <-chan struct{}) {
	t.Helper()
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		p, _ := windows.UTF16PtrFromString(name)
		h, err := windows.CreateMutex(nil, true, p)
		if err != nil {
			ready <- err
			return
		}
		ready <- nil
		<-release
		_ = windows.ReleaseMutex(h)
		_ = windows.CloseHandle(h)
	}()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
}

// R-B-5: uninstall waits for a running scan's instance mutex, bounded.
func TestWaitForInstanceMutex(t *testing.T) {
	old := instanceMutex
	t.Cleanup(func() { instanceMutex = old })
	instanceMutex = fmt.Sprintf(`Local\DMGUninstallTest-%d`, time.Now().UnixNano())

	start := time.Now()
	if !waitForInstanceMutex(time.Second) || time.Since(start) > 500*time.Millisecond {
		t.Fatal("absent mutex should report free at once")
	}

	release := make(chan struct{})
	holdMutex(t, instanceMutex, release)
	go func() { time.Sleep(400 * time.Millisecond); close(release) }()
	start = time.Now()
	if !waitForInstanceMutex(10 * time.Second) {
		t.Fatal("mutex released by the scan was not acquired")
	}
	if el := time.Since(start); el < 300*time.Millisecond {
		t.Fatalf("returned after %s, before the scan released the mutex", el)
	}

	release2 := make(chan struct{})
	defer close(release2)
	holdMutex(t, instanceMutex, release2)
	start = time.Now()
	if waitForInstanceMutex(300 * time.Millisecond) {
		t.Fatal("held mutex reported free")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("wait not bounded: %s", el)
	}
}

// A process that is already exiting (here: exited, handle still open) makes
// TerminateProcess fail with ACCESS_DENIED. That happens in uninstall when
// killing the bootstrap first makes its job kill the launcher and agent;
// stopProcess must count it as stopped, not as an error.
func TestStopProcess_AlreadyExitingIsStopped(t *testing.T) {
	cmd := startSleeper(t, os.Args[0])
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid)) // #nosec G115 -- test pid
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	if err := stopProcess(h); err != nil {
		t.Fatalf("stopProcess on an exited process: %v", err)
	}
}
