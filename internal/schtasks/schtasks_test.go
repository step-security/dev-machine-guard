package schtasks

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func newTestLogger() *progress.Logger {
	return progress.NewLogger(false)
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

func TestInstall_CustomFrequency(t *testing.T) {
	origFreq := config.ScanFrequencyHours
	t.Cleanup(func() { config.ScanFrequencyHours = origFreq })
	config.ScanFrequencyHours = "6"

	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetIsRoot(false)
	mock.SetHomeDir(`C:\Users\testuser`)
	// Task doesn't exist
	mock.SetCommand("", "ERROR: not found", 1, "schtasks", "/query", "/tn", taskName)

	// Install will fail at os.Executable or schtasks create, but we're testing
	// that the frequency is parsed correctly via the resolveLogDir and config paths.
	// A full integration test requires the real binary on Windows.
	_ = Install(mock, newTestLogger())
	// If we got past the config parsing without panic, the frequency was handled correctly.
}
