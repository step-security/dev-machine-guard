package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// On a Mac without CLT installed, /usr/bin/pip3 is an Apple shim that pops a
// GUI dialog when invoked. ScanGlobalPackages must skip it; otherwise every
// fleet endpoint without CLT triggers the prompt on first run.
func TestPythonScanner_SkipsAppleStubWithoutCLT(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetAppleCLTInstalled(false)
	mock.SetPath("pip3", "/usr/bin/pip3")
	// No SetCommand for pip3 list — if the guard fails the test surfaces it
	// via a non-empty results slice (mock would return -1 exit with the
	// "no command stub" error captured).

	scanner := NewPythonScanner(mock, progress.NewLogger(progress.LevelError))
	results := scanner.ScanGlobalPackages(context.Background())
	if len(results) != 0 {
		t.Errorf("expected Apple pip3 stub to be skipped, got %d results: %+v", len(results), results)
	}
}

// When CLT is installed, /usr/bin/pip3 is a real binary and must be scanned.
func TestPythonScanner_ScansUsrBinWhenCLTInstalled(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetAppleCLTInstalled(true)
	mock.SetPath("pip3", "/usr/bin/pip3")
	mock.SetCommand("pip 24.0\n", "", 0, "pip3", "--version")
	mock.SetCommand(`[{"name":"requests","version":"2.32.0"}]`, "", 0, "pip3", "list", "--format", "json")

	scanner := NewPythonScanner(mock, progress.NewLogger(progress.LevelError))
	results := scanner.ScanGlobalPackages(context.Background())
	if len(results) != 1 || results[0].PackageManager != "pip" {
		t.Fatalf("expected one pip result with CLT installed, got %+v", results)
	}
	if results[0].ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", results[0].ExitCode)
	}
}

func TestPythonProjectDetector_PipEmptyAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		exit         int
		failed       bool
	}{
		{"empty", "[]", 0, false},
		{"command failure", "[]", 1, true},
		{"malformed output", "invalid", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetCommand(tc.output, "", tc.exit, "pip", "list", "--format", "json")
			got := NewPythonProjectDetector(mock).listVenvPackages(context.Background(), "/venv", "pip")
			if (got == nil) != tc.failed || len(got) != 0 {
				t.Fatalf("packages=%v nil=%v, want failure=%v", got, got == nil, tc.failed)
			}
		})
	}
}
