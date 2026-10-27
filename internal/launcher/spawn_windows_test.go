//go:build windows

package launcher

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

const envTree = "DMG_TEST_TREE"

// TestHelperTree is a subprocess body: "parent" starts a "child" copy of
// this binary (inheriting the job), writes the child's pid and sleeps; the
// child just sleeps. It does nothing in a normal test run.
func TestHelperTree(t *testing.T) {
	switch os.Getenv(envTree) {
	case "parent", "child":
		proctest.GuardDeadline() // the job must kill the tree
	}
	switch os.Getenv(envTree) {
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestHelperTree$")
		child.Env = append(os.Environ(), envTree+"=child")
		if err := child.Start(); err != nil {
			os.Exit(3)
		}
		_ = os.WriteFile(os.Getenv(envTree+"_PIDFILE"), []byte(strconv.Itoa(child.Process.Pid)), 0o600)
		time.Sleep(time.Minute)
	case "child":
		time.Sleep(time.Minute)
	default:
		t.Skip("subprocess helper")
	}
}

// R-B-5: the bootstrap deadline terminates the whole job tree (the child's
// own children included) with exit code 124.
func TestSpawnHidden_DeadlineKillsWholeTree(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	env := append(os.Environ(), envTree+"=parent", envTree+"_PIDFILE="+pidFile)
	start := time.Now()
	res := SpawnHidden(os.Args[0], []string{"-test.run=^TestHelperTree$"}, env, 4*time.Second, nil)
	if !res.Started || !res.Killed || res.ExitCode != ExitKilled {
		t.Fatalf("result = %+v, want started, killed, exit %d", res, ExitKilled)
	}
	if el := time.Since(start); el > 30*time.Second {
		t.Fatalf("took %s", el)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("child never started: %v", err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid)) // #nosec G115 -- test pid
	if err != nil {
		return // already gone
	}
	defer windows.CloseHandle(h)
	if ev, _ := windows.WaitForSingleObject(h, 5000); ev != windows.WAIT_OBJECT_0 {
		t.Fatalf("grandchild %d survived the deadline kill", pid)
	}
}

// waitGone reports whether pid exits within d (an unopenable pid is gone).
func waitGone(t *testing.T, pid int, d time.Duration) bool {
	t.Helper()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid)) // #nosec G115 -- test pid
	if err != nil {
		return true
	}
	defer windows.CloseHandle(h)
	if ev, _ := windows.WaitForSingleObject(h, uint32(d.Milliseconds())); ev == windows.WAIT_OBJECT_0 {
		return true
	}
	_ = windows.TerminateProcess(h, 1)
	return false
}

// Copilot 4356483255: the child must be in the job before it runs, so a
// grandchild it spawns at once can't escape. A slow job setup used to
// leave the child running outside the job meanwhile.
func TestSpawnHidden_GrandchildSpawnedAtOnceDiesWithJob(t *testing.T) {
	newJob = func() (windows.Handle, error) {
		time.Sleep(3 * time.Second)
		return NewKillOnCloseJob()
	}
	t.Cleanup(func() { newJob = NewKillOnCloseJob })
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	env := append(os.Environ(), envTree+"=parent", envTree+"_PIDFILE="+pidFile)
	res := SpawnHidden(os.Args[0], []string{"-test.run=^TestHelperTree$"}, env, 6*time.Second, nil)
	if !res.Started || !res.Killed {
		t.Fatalf("result = %+v, want started and killed", res)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("grandchild never started: %v", err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if !waitGone(t, pid, 5*time.Second) {
		t.Fatalf("grandchild %d escaped the job", pid)
	}
}

// Copilot 4356483255: a job setup failure must not leave the child
// running uncontained: nothing runs and the spawn reports the error.
func TestSpawnHidden_JobSetupFailureRunsNothing(t *testing.T) {
	for name, mk := range map[string]func() (windows.Handle, error){
		"create fails": func() (windows.Handle, error) { return 0, windows.ERROR_ACCESS_DENIED },
		"assign fails": func() (windows.Handle, error) { return windows.CreateEvent(nil, 0, 0, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			newJob = mk
			t.Cleanup(func() { newJob = NewKillOnCloseJob })
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			env := append(os.Environ(), envTree+"=parent", envTree+"_PIDFILE="+pidFile)
			started := false
			res := SpawnHidden(os.Args[0], []string{"-test.run=^TestHelperTree$"}, env, 4*time.Second, func() { started = true })
			if data, err := os.ReadFile(pidFile); err == nil {
				pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
				waitGone(t, pid, 0)
			}
			if res.Started || started || res.Err == nil {
				t.Fatalf("result = %+v (onStart called: %v), want not started with an error", res, started)
			}
			time.Sleep(time.Second)
			if _, err := os.Stat(pidFile); err == nil {
				t.Fatal("the child ran uncontained")
			}
		})
	}
}
