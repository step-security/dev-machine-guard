package schtasks

import (
	"context"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func newTestLogger() *progress.Logger {
	return progress.NewLogger(progress.LevelInfo)
}

func TestIsConfigured_True(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("", "", 0, "schtasks", "/query", "/tn", taskName)

	got := isConfigured(context.Background(), mock)
	if !got {
		t.Error("expected isConfigured to return true when task exists")
	}
}

func TestIsConfigured_False(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("", "ERROR: The system cannot find the path specified.", 1, "schtasks", "/query", "/tn", taskName)

	got := isConfigured(context.Background(), mock)
	if got {
		t.Error("expected isConfigured to return false when task does not exist")
	}
}

func TestUninstall_Configured(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("", "", 0, "schtasks", "/query", "/tn", taskName)
	mock.SetCommand("SUCCESS: The scheduled task was successfully deleted.", "", 0, "schtasks", "/delete", "/tn", taskName, "/f")

	err := Uninstall(mock, newTestLogger())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestUninstall_NotConfigured(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("", "ERROR: The system cannot find the path specified.", 1, "schtasks", "/query", "/tn", taskName)

	err := Uninstall(mock, newTestLogger())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestInstall_CreateFails(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetHomeDir(`C:\Users\testuser`)
	// Task doesn't exist
	mock.SetCommand("", "ERROR: The system cannot find the path specified.", 1, "schtasks", "/query", "/tn", taskName)

	// Note: Install calls os.Executable() and os.MkdirAll() which we can't mock,
	// but the schtasks /create will fail because we haven't stubbed it.
	err := Install(mock, newTestLogger())
	if err == nil {
		t.Fatal("expected error when schtasks /create is not stubbed")
	}
}

func TestResolveLogDir_NonAdmin(t *testing.T) {
	// paths.Home() is the primary source post-refactor. Drive it via
	// STEPSECURITY_HOME so the test exercises the same code path that
	// the launchd/systemd installers feed.
	t.Setenv("STEPSECURITY_HOME", `C:\Users\testuser\.stepsecurity`)

	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetIsRoot(false)
	mock.SetHomeDir(`C:\Users\testuser`)

	dir := resolveLogDir(mock)
	expected := `C:\Users\testuser\.stepsecurity`
	if dir != expected {
		t.Errorf("expected %s, got %s", expected, dir)
	}
}

func TestResolveLogDir_Admin(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetIsRoot(true)

	dir := resolveLogDir(mock)
	expected := `C:\ProgramData\StepSecurity`
	if dir != expected {
		t.Errorf("expected %s, got %s", expected, dir)
	}
}

func TestBuildCreateArgs_CustomFrequency(t *testing.T) {
	args := buildCreateArgs(`C:\agent.exe`, `C:\logs`, 6, false)

	// Find the /mo argument and check its value
	foundMo := false
	for i, a := range args {
		if a == "/mo" && i+1 < len(args) {
			foundMo = true
			if args[i+1] != "6" {
				t.Errorf("expected /mo 6, got /mo %s", args[i+1])
			}
		}
	}
	if !foundMo {
		t.Error("expected /mo argument in schtasks create args")
	}
}

func TestBuildCreateArgs_Admin(t *testing.T) {
	args := buildCreateArgs(`C:\agent.exe`, `C:\ProgramData\StepSecurity`, 4, true)

	foundRU := false
	for i, a := range args {
		if a == "/ru" && i+1 < len(args) {
			foundRU = true
			if args[i+1] != "INTERACTIVE" {
				t.Errorf("expected /ru INTERACTIVE, got /ru %s", args[i+1])
			}
		}
	}
	if !foundRU {
		t.Error("expected /ru INTERACTIVE for admin install")
	}
}

func TestBuildCreateArgs_NonAdmin(t *testing.T) {
	args := buildCreateArgs(`C:\agent.exe`, `C:\logs`, 4, false)

	for _, a := range args {
		if a == "/ru" {
			t.Error("expected no /ru argument for non-admin install")
		}
	}
}

// When the launcher binary is co-installed (MSI layout) it must be
// preferred over the agent so the scheduled task fires through the
// GUI-subsystem wrapper.
//
// Paths use forward slashes so the test is portable: filepath.{Dir,Join}
// in resolveTaskBinary follow the host OS separator. The Windows
// production path looks like C:\Program Files\StepSecurity\... — same
// logic, just darwin-incompatible to assert against directly.
func TestResolveTaskBinary_LauncherPresent(t *testing.T) {
	mock := executor.NewMock()
	agent := "/install/dir/stepsecurity-dev-machine-guard.exe"
	launcher := "/install/dir/stepsecurity-dev-machine-guard-task.exe"
	mock.SetFile(launcher, []byte{})

	if got := resolveTaskBinary(mock, agent); got != launcher {
		t.Errorf("want launcher %q, got %q", launcher, got)
	}
}

// Ad-hoc deploys may ship only the agent .exe. The task must still
// register correctly against the agent in that case.
func TestResolveTaskBinary_NoLauncher(t *testing.T) {
	mock := executor.NewMock()
	agent := "/install/dir/stepsecurity-dev-machine-guard.exe"

	if got := resolveTaskBinary(mock, agent); got != agent {
		t.Errorf("want agent fallback %q, got %q", agent, got)
	}
}

func TestRunNow_Success(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("SUCCESS: Attempted to run the scheduled task.", "", 0, "schtasks", "/run", "/tn", taskName)

	if err := RunNow(mock, newTestLogger()); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestRunNow_NonZeroExit(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("", "ERROR: The system cannot find the path specified.", 1, "schtasks", "/run", "/tn", taskName)

	err := RunNow(mock, newTestLogger())
	if err == nil {
		t.Fatal("expected error when schtasks /run exits non-zero")
	}
	if !strings.Contains(err.Error(), "exit code 1") {
		t.Errorf("expected exit code in error, got %v", err)
	}
}

// The task action must invoke the binary directly. A `cmd /c` wrapper
// (the pre-fix form) spawns a console window every time Task Scheduler
// fires the task under an interactive user session.
func TestBuildCreateArgs_TaskCommandFormat(t *testing.T) {
	args := buildCreateArgs(`C:\agent.exe`, `C:\ProgramData\StepSecurity`, 4, true)

	taskCmd := ""
	for i, a := range args {
		if a == "/tr" && i+1 < len(args) {
			taskCmd = args[i+1]
			break
		}
	}
	if taskCmd == "" {
		t.Fatal("no /tr argument found")
	}

	if strings.Contains(strings.ToLower(taskCmd), "cmd /c") || strings.Contains(strings.ToLower(taskCmd), "cmd.exe") {
		t.Errorf("task command must not wrap binary in cmd: %q", taskCmd)
	}
	if !strings.Contains(taskCmd, "send-telemetry") {
		t.Errorf("task command missing send-telemetry: %q", taskCmd)
	}
	if !strings.Contains(taskCmd, `--install-dir="C:\ProgramData\StepSecurity"`) {
		t.Errorf("task command missing --install-dir flag: %q", taskCmd)
	}
	if !strings.HasPrefix(taskCmd, `"C:\agent.exe"`) {
		t.Errorf("task command must start with quoted binary path: %q", taskCmd)
	}
	if strings.Contains(taskCmd, ">>") || strings.Contains(taskCmd, "STEPSECURITY_HOME=") {
		t.Errorf("task command must not redirect output or set env vars: %q", taskCmd)
	}
}
