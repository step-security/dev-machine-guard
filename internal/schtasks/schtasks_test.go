package schtasks

import (
	"context"
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
	args := buildCreateArgs(`C:\agent.exe`, `C:\logs`, 4, true)

	foundRU := false
	for i, a := range args {
		if a == "/ru" && i+1 < len(args) {
			foundRU = true
			if args[i+1] != "SYSTEM" {
				t.Errorf("expected /ru SYSTEM, got /ru %s", args[i+1])
			}
		}
	}
	if !foundRU {
		t.Error("expected /ru SYSTEM for admin install")
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
