package detector

import (
	"context"
	"encoding/base64"
	"strings"
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
		s.log.Progress("  brew not found in PATH for formulae scan")
		return model.BrewScanResult{}, false
	}

	s.log.Progress("  Scanning Homebrew formulae...")
	start := time.Now()
	stdout, stderr, exitCode, _ := s.exec.RunWithTimeout(ctx, 60*time.Second, "brew", "list", "--formula", "--versions")
	duration := time.Since(start).Milliseconds()

	errMsg := ""
	if exitCode != 0 {
		errMsg = "brew list --formula --versions failed"
		s.log.Warn("brew formulae scan failed (exit_code=%d): %s — results may be incomplete", exitCode, strings.TrimSpace(stderr))
	}

	lineCount := len(strings.Split(strings.TrimSpace(stdout), "\n"))
	if strings.TrimSpace(stdout) == "" {
		lineCount = 0
	}
	s.log.Progress("  Brew formulae scan complete: %d lines, exit_code=%d, duration=%dms", lineCount, exitCode, duration)
	s.log.Debug("brew formulae scan: line_count=%d exit_code=%d duration=%dms stdout_bytes=%d", lineCount, exitCode, duration, len(stdout))

	return model.BrewScanResult{
		ScanType:        "formulae",
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		RawStderrBase64: base64.StdEncoding.EncodeToString([]byte(stderr)),
		Error:           errMsg,
		ExitCode:        exitCode,
		ScanDurationMs:  duration,
		LineCount:       lineCount,
	}, true
}

// ScanCasks runs `brew list --cask --versions` and returns raw base64-encoded output.
func (s *BrewScanner) ScanCasks(ctx context.Context) (model.BrewScanResult, bool) {
	if _, err := s.exec.LookPath("brew"); err != nil {
		s.log.Progress("  brew not found in PATH for casks scan")
		return model.BrewScanResult{}, false
	}

	s.log.Progress("  Scanning Homebrew casks...")
	start := time.Now()
	stdout, stderr, exitCode, _ := s.exec.RunWithTimeout(ctx, 60*time.Second, "brew", "list", "--cask", "--versions")
	duration := time.Since(start).Milliseconds()

	errMsg := ""
	if exitCode != 0 {
		errMsg = "brew list --cask --versions failed"
		s.log.Warn("brew casks scan failed (exit_code=%d): %s — results may be incomplete", exitCode, strings.TrimSpace(stderr))
	}

	lineCount := len(strings.Split(strings.TrimSpace(stdout), "\n"))
	if strings.TrimSpace(stdout) == "" {
		lineCount = 0
	}
	s.log.Progress("  Brew casks scan complete: %d lines, exit_code=%d, duration=%dms", lineCount, exitCode, duration)
	s.log.Debug("brew casks scan: line_count=%d exit_code=%d duration=%dms stdout_bytes=%d", lineCount, exitCode, duration, len(stdout))

	return model.BrewScanResult{
		ScanType:        "casks",
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		RawStderrBase64: base64.StdEncoding.EncodeToString([]byte(stderr)),
		Error:           errMsg,
		ExitCode:        exitCode,
		ScanDurationMs:  duration,
		LineCount:       lineCount,
	}, true
}
