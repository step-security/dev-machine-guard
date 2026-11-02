//go:build windows

package consoleguard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/launcher"
	"github.com/step-security/dev-machine-guard/internal/proctest"
)

// probeArg, as os.Args[1], turns the test binary into the probe.
const probeArg = "consoleguard-probe"

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procAllocConsole     = kernel32.NewProc("AllocConsole")
)

// probeResult is what the probe saw of its console.
type probeResult struct {
	Window    uintptr `json:"window"`
	Allocated bool    `json:"allocated"`
	Visible   bool    `json:"visible"`
}

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == probeArg {
		os.Exit(runProbe(os.Args[2]))
	}
	os.Exit(proctest.Main(m))
}

// runProbe does what wsl.exe does when it has no console: allocate one. A
// child started with CREATE_NO_WINDOW already has a (hidden) console, so the
// allocation fails and nothing appears. A successful allocation is a new
// console window on the user's desktop.
//
// Allocated is the verdict, not Visible: in a non-interactive session (CI
// runners, SSH) the allocated window exists but IsWindowVisible reports
// false, so Visible alone passes vacuously there.
func runProbe(out string) int {
	proctest.GuardDeadline()
	var res probeResult
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		if ok, _, _ := procAllocConsole.Call(); ok != 0 {
			res.Allocated = true
			hwnd, _, _ = procGetConsoleWindow.Call()
		}
	}
	res.Window = hwnd
	res.Visible = hwnd != 0 && windows.IsWindowVisible(windows.HWND(hwnd))
	data, _ := json.Marshal(res)
	if err := os.WriteFile(out+".tmp", data, 0o600); err != nil {
		return 1
	}
	if err := os.Rename(out+".tmp", out); err != nil {
		return 1
	}
	return 0
}

func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// waitResult reads the probe's report, waiting for spawns that do not block.
func waitResult(t *testing.T, out string) probeResult {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		data, err := os.ReadFile(out)
		if err == nil {
			var res probeResult
			if err := json.Unmarshal(data, &res); err != nil {
				t.Fatalf("probe report %q: %v", data, err)
			}
			return res
		}
		if !errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
			t.Fatalf("probe never reported: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func assertHidden(t *testing.T, res probeResult) {
	t.Helper()
	t.Logf("probe: %+v", res)
	if res.Allocated || res.Visible {
		t.Fatalf("spawned process opened a console window (%+v)", res)
	}
}

// The control: a spawn known to open a window (the pre-#271 WSL relay) must
// be seen to. If this fails, the probe is blind in this session and every
// other test here would pass vacuously.
func TestProbeDetectsVisibleConsole(t *testing.T) {
	out := filepath.Join(t.TempDir(), "probe.json")
	cmd := proctest.Command(t, self(t), probeArg, out)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if res := waitResult(t, out); !res.Allocated && !res.Visible {
		t.Fatalf("probe under DETACHED_PROCESS opened no console (%+v); the probe is blind here", res)
	}
}

func TestExecutorRunHidesConsole(t *testing.T) {
	out := filepath.Join(t.TempDir(), "probe.json")
	if _, stderr, code, err := executor.NewReal().Run(context.Background(), self(t), probeArg, out); err != nil || code != 0 {
		t.Fatalf("Run: code=%d err=%v stderr=%s", code, err, stderr)
	}
	assertHidden(t, waitResult(t, out))
}

func TestExecutorRunInDirHidesConsole(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "probe.json")
	if _, stderr, code, err := executor.NewReal().RunInDir(context.Background(), dir, time.Minute, self(t), probeArg, out); err != nil || code != 0 {
		t.Fatalf("RunInDir: code=%d err=%v stderr=%s", code, err, stderr)
	}
	assertHidden(t, waitResult(t, out))
}

// The WSL scan relay path (#271).
func TestExecutorStartDetachedHidesConsole(t *testing.T) {
	out := filepath.Join(t.TempDir(), "probe.json")
	if err := executor.NewReal().StartDetached(self(t), probeArg, out); err != nil {
		t.Fatal(err)
	}
	assertHidden(t, waitResult(t, out))
}

func TestHardenCommandHidesConsole(t *testing.T) {
	out := filepath.Join(t.TempDir(), "probe.json")
	cmd := exec.Command(self(t), probeArg, out) // #nosec G204 -- test probe
	executor.HardenCommand(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	assertHidden(t, waitResult(t, out))
}

// The bootstrap's run/update path.
func TestSpawnHiddenHidesConsole(t *testing.T) {
	out := filepath.Join(t.TempDir(), "probe.json")
	res := launcher.SpawnHidden(self(t), []string{probeArg, out}, os.Environ(), time.Minute, nil)
	if !res.Started || res.ExitCode != 0 {
		t.Fatalf("SpawnHidden: %+v", res)
	}
	assertHidden(t, waitResult(t, out))
}

// envTaskExe points TestTaskLauncherHidesConsole at a prebuilt launcher (a
// release asset, say) instead of building one.
const envTaskExe = "DMG_CONSOLEGUARD_TASK_EXE"

// The scheduled-task path: Task Scheduler starts the GUI-subsystem launcher
// with no console, and the launcher starts the agent.
func TestTaskLauncherHidesConsole(t *testing.T) {
	dir := t.TempDir()
	task := os.Getenv(envTaskExe)
	if task == "" {
		if testing.Short() {
			t.Skip("builds the task launcher; set " + envTaskExe + " to use a prebuilt one")
		}
		task = filepath.Join(dir, "stepsecurity-dev-machine-guard-task.exe")
		build := proctest.Command(t, "go", "build", "-ldflags", "-H windowsgui", "-o", task,
			"github.com/step-security/dev-machine-guard/cmd/stepsecurity-dev-machine-guard-task")
		if b, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build launcher: %v\n%s", err, b)
		}
	}
	out := filepath.Join(dir, "probe.json")
	cmd := proctest.Command(t, task, launcher.ExecFlag, self(t), probeArg, out)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	assertHidden(t, waitResult(t, out))
}
