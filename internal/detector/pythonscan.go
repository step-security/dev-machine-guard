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

// PythonScanner performs enterprise-mode Python scanning (raw output, base64 encoded).
type PythonScanner struct {
	exec executor.Executor
	log  *progress.Logger
}

func NewPythonScanner(exec executor.Executor, log *progress.Logger) *PythonScanner {
	return &PythonScanner{exec: exec, log: log}
}

type pythonScanSpec struct {
	binary     string
	name       string
	versionCmd string
	listArgs   []string
}

var pythonScanSpecs = []pythonScanSpec{
	{"pip3", "pip", "--version", []string{"list", "--format", "json"}},
	{"conda", "conda", "--version", []string{"list", "--json"}},
	{"uv", "uv", "--version", []string{"pip", "list", "--format", "json"}},
}

// ScanGlobalPackages runs pip3/conda/uv list and returns raw base64-encoded results.
func (s *PythonScanner) ScanGlobalPackages(ctx context.Context) []model.PythonScanResult {
	var results []model.PythonScanResult

	for _, spec := range pythonScanSpecs {
		binPath, err := s.exec.LookPath(spec.binary)
		if err != nil {
			continue
		}

		s.log.Progress("  Checking %s global packages...", spec.name)
		version := s.getVersion(ctx, spec.binary, spec.versionCmd)

		start := time.Now()
		args := spec.listArgs
		stdout, stderr, exitCode, _ := s.exec.RunWithTimeout(ctx, 60*time.Second, spec.binary, args...)
		duration := time.Since(start).Milliseconds()

		errMsg := ""
		if exitCode != 0 {
			errMsg = spec.binary + " list command failed"
			s.log.Warn("%s list failed (exit_code=%d, %dms) — results may be incomplete", spec.binary, exitCode, duration)
		}
		s.log.Debug("%s global scan: version=%s binary=%s exit_code=%d stdout_bytes=%d duration=%dms", spec.name, version, binPath, exitCode, len(stdout), duration)

		results = append(results, model.PythonScanResult{
			PackageManager:  spec.name,
			PMVersion:       version,
			BinaryPath:      binPath,
			RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(stdout)),
			RawStderrBase64: base64.StdEncoding.EncodeToString([]byte(stderr)),
			Error:           errMsg,
			ExitCode:        exitCode,
			ScanDurationMs:  duration,
		})
	}

	return results
}

func (s *PythonScanner) getVersion(ctx context.Context, binary, versionCmd string) string {
	stdout, _, _, err := s.exec.RunWithTimeout(ctx, 10*time.Second, binary, versionCmd)
	if err != nil {
		return "unknown"
	}
	v := strings.TrimSpace(stdout)
	if v == "" {
		return "unknown"
	}
	return parsePythonVersion(binary, v)
}
