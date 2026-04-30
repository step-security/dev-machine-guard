package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func newTestLogger() *progress.Logger {
	return progress.NewNoop()
}

func TestBrewDetector_Found(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")
	mock.SetCommand("Homebrew 4.3.5\nHomebrew/homebrew-core (git revision abc123)\n", "", 0, "brew", "--version")

	det := NewBrewDetector(mock)
	result := det.DetectBrew(context.Background())

	if result == nil {
		t.Fatal("expected brew to be detected")
	}
	if result.Name != "homebrew" {
		t.Errorf("expected name homebrew, got %s", result.Name)
	}
	if result.Version != "4.3.5" {
		t.Errorf("expected version 4.3.5, got %s", result.Version)
	}
	if result.Path != "/opt/homebrew/bin/brew" {
		t.Errorf("expected path /opt/homebrew/bin/brew, got %s", result.Path)
	}
}

func TestBrewDetector_NotFound(t *testing.T) {
	mock := executor.NewMock()
	det := NewBrewDetector(mock)
	result := det.DetectBrew(context.Background())

	if result != nil {
		t.Error("expected nil when brew is not installed")
	}
}

func TestBrewDetector_ListFormulae(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")
	mock.SetCommand("ca-certificates 2024.2.2\ncurl 8.4.0\ngit 2.43.0\nopenssl@3 3.2.0\n", "", 0, "brew", "list", "--formula", "--versions")

	det := NewBrewDetector(mock)
	formulae := det.ListFormulae(context.Background())

	if len(formulae) != 4 {
		t.Fatalf("expected 4 formulae, got %d", len(formulae))
	}
	if formulae[0].Name != "ca-certificates" || formulae[0].Version != "2024.2.2" {
		t.Errorf("unexpected first formula: %+v", formulae[0])
	}
}

func TestBrewDetector_ListCasks(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")
	mock.SetCommand("firefox 120.0\ngoogle-chrome 120.0.6099.109\nvisual-studio-code 1.85.0\n", "", 0, "brew", "list", "--cask", "--versions")

	det := NewBrewDetector(mock)
	casks := det.ListCasks(context.Background())

	if len(casks) != 3 {
		t.Fatalf("expected 3 casks, got %d", len(casks))
	}
	if casks[0].Name != "firefox" || casks[0].Version != "120.0" {
		t.Errorf("unexpected first cask: %+v", casks[0])
	}
}

func TestBrewScanner_Formulae(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")
	mock.SetCommand("curl 8.4.0\ngit 2.43.0\n", "", 0, "brew", "list", "--formula", "--versions")

	log := newTestLogger()
	scanner := NewBrewScanner(mock, log)
	result, ok := scanner.ScanFormulae(context.Background())

	if !ok {
		t.Fatal("expected scan to succeed")
	}
	if result.ScanType != "formulae" {
		t.Errorf("expected scan type formulae, got %s", result.ScanType)
	}
	if result.RawStdoutBase64 == "" {
		t.Error("expected non-empty base64 stdout")
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}

func TestBrewScanner_Casks(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")
	mock.SetCommand("firefox 120.0\ngoogle-chrome 120.0.6099.109\n", "", 0, "brew", "list", "--cask", "--versions")

	log := newTestLogger()
	scanner := NewBrewScanner(mock, log)
	result, ok := scanner.ScanCasks(context.Background())

	if !ok {
		t.Fatal("expected scan to succeed")
	}
	if result.ScanType != "casks" {
		t.Errorf("expected scan type casks, got %s", result.ScanType)
	}
	if result.RawStdoutBase64 == "" {
		t.Error("expected non-empty base64 stdout")
	}
}

func TestBrewScanner_NotInstalled(t *testing.T) {
	mock := executor.NewMock()
	log := newTestLogger()
	scanner := NewBrewScanner(mock, log)

	_, ok := scanner.ScanFormulae(context.Background())
	if ok {
		t.Error("expected scan to fail when brew is not installed")
	}
}
