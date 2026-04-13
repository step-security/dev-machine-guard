package detector

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// BrewScanner performs enterprise-mode Homebrew scanning (raw output, base64 encoded).
type BrewScanner struct {
	exec executor.Executor
	log  *progress.Logger
}

func NewBrewScanner(exec executor.Executor, log *progress.Logger) *BrewScanner {
	return &BrewScanner{exec: exec, log: log}
}

// ScanFormulae runs `brew list --formula --versions` and returns raw base64-encoded output.
func (s *BrewScanner) ScanFormulae(ctx context.Context) (model.BrewScanResult, bool) {
	if _, err := s.exec.LookPath("brew"); err != nil {
		return model.BrewScanResult{}, false
	}

	s.log.Progress("  Scanning Homebrew formulae...")
	start := time.Now()
	stdout, stderr, exitCode, _ := s.exec.RunWithTimeout(ctx, 60*time.Second, "brew", "list", "--formula", "--versions")
	duration := time.Since(start).Milliseconds()

	errMsg := ""
	if exitCode != 0 {
		errMsg = "brew list --formula --versions failed"
	}

	return model.BrewScanResult{
		ScanType:        "formulae",
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		RawStderrBase64: base64.StdEncoding.EncodeToString([]byte(stderr)),
		Error:           errMsg,
		ExitCode:        exitCode,
		ScanDurationMs:  duration,
	}, true
}

// ScanCasks runs `brew list --cask --versions` and returns raw base64-encoded output.
func (s *BrewScanner) ScanCasks(ctx context.Context) (model.BrewScanResult, bool) {
	if _, err := s.exec.LookPath("brew"); err != nil {
		return model.BrewScanResult{}, false
	}

	s.log.Progress("  Scanning Homebrew casks...")
	start := time.Now()
	stdout, stderr, exitCode, _ := s.exec.RunWithTimeout(ctx, 60*time.Second, "brew", "list", "--cask", "--versions")
	duration := time.Since(start).Milliseconds()

	errMsg := ""
	if exitCode != 0 {
		errMsg = "brew list --cask --versions failed"
	}

	return model.BrewScanResult{
		ScanType:        "casks",
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		RawStderrBase64: base64.StdEncoding.EncodeToString([]byte(stderr)),
		Error:           errMsg,
		ExitCode:        exitCode,
		ScanDurationMs:  duration,
	}, true
}
