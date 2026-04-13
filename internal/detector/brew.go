package detector

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// BrewDetector detects Homebrew installation and packages.
type BrewDetector struct {
	exec executor.Executor
}

func NewBrewDetector(exec executor.Executor) *BrewDetector {
	return &BrewDetector{exec: exec}
}

// DetectBrew checks if Homebrew is installed and returns its version info.
// Returns nil if Homebrew is not found.
func (d *BrewDetector) DetectBrew(ctx context.Context) *model.PkgManager {
	path, err := d.exec.LookPath("brew")
	if err != nil {
		return nil
	}

	version := "unknown"
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, "brew", "--version")
	if err == nil {
		// "brew --version" outputs "Homebrew 4.3.5\n..."
		if line := firstLine(stdout); line != "" {
			version = strings.TrimPrefix(line, "Homebrew ")
		}
	}

	return &model.PkgManager{
		Name:    "homebrew",
		Version: version,
		Path:    path,
	}
}

// ListFormulae returns installed Homebrew formulae with versions.
func (d *BrewDetector) ListFormulae(ctx context.Context) []model.BrewPackage {
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 30*time.Second, "brew", "list", "--formula", "--versions")
	if err != nil {
		return nil
	}
	return parseBrewList(stdout)
}

// ListCasks returns installed Homebrew casks with versions.
func (d *BrewDetector) ListCasks(ctx context.Context) []model.BrewPackage {
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 30*time.Second, "brew", "list", "--cask", "--versions")
	if err != nil {
		return nil
	}
	return parseBrewList(stdout)
}

// parseBrewList parses "name version" lines from `brew list --versions` output.
func parseBrewList(stdout string) []model.BrewPackage {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil
	}
	var packages []model.BrewPackage
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "name version [version2 ...]"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			packages = append(packages, model.BrewPackage{
				Name:    parts[0],
				Version: parts[1],
			})
		} else if len(parts) == 1 {
			packages = append(packages, model.BrewPackage{
				Name:    parts[0],
				Version: "unknown",
			})
		}
	}
	return packages
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
