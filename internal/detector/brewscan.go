package detector

import (
	"encoding/base64"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// BrewScanner produces a BrewScanResult for enterprise telemetry by synthesizing
// the raw `brew list --versions` format from the rich package data we already have.
//
// We used to shell out to `brew list --formula|--cask --versions`, but on some hosts
// `brew list --cask --versions` crashes inside Homebrew itself (e.g. nil in a cask's
// depends_on triggers `undefined method 'to_sym' for nil` in cask_struct_generator.rb).
// The rich path (`brew info --json=v2`) is unaffected, so we reuse its data here.
type BrewScanner struct {
	log *progress.Logger
}

// NewBrewScanner keeps the (exec, log) signature for caller compatibility; exec is unused.
func NewBrewScanner(_ executor.Executor, log *progress.Logger) *BrewScanner {
	return &BrewScanner{log: log}
}

// FormulaeResult builds a formulae scan result from rich package data.
func (s *BrewScanner) FormulaeResult(pkgs []model.BrewPackage) model.BrewScanResult {
	return s.synthesize("formulae", pkgs)
}

// CasksResult builds a casks scan result from rich package data.
func (s *BrewScanner) CasksResult(pkgs []model.BrewPackage) model.BrewScanResult {
	return s.synthesize("casks", pkgs)
}

func (s *BrewScanner) synthesize(scanType string, pkgs []model.BrewPackage) model.BrewScanResult {
	var b strings.Builder
	for _, p := range pkgs {
		b.WriteString(p.Name)
		b.WriteByte(' ')
		b.WriteString(p.Version)
		b.WriteByte('\n')
	}
	stdout := b.String()
	s.log.Debug("brew %s scan synthesized from rich data: %d packages", scanType, len(pkgs))
	return model.BrewScanResult{
		ScanType:        scanType,
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		RawStderrBase64: "",
		Error:           "",
		ExitCode:        0,
		ScanDurationMs:  0,
		LineCount:       len(pkgs),
	}
}
