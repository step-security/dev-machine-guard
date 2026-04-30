package detector

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

var pythonPackageManagers = []pmSpec{
	{"python3", "python3", "--version"},
	{"pip", "pip3", "--version"},
	{"poetry", "poetry", "--version"},
	{"pipenv", "pipenv", "--version"},
	{"uv", "uv", "--version"},
	{"conda", "conda", "--version"},
	{"rye", "rye", "--version"},
}

// PythonPMDetector detects installed Python package managers.
type PythonPMDetector struct {
	exec executor.Executor
}

func NewPythonPMDetector(exec executor.Executor) *PythonPMDetector {
	return &PythonPMDetector{exec: exec}
}

func (d *PythonPMDetector) DetectManagers(ctx context.Context) []model.PkgManager {
	var results []model.PkgManager

	for _, pm := range pythonPackageManagers {
		path, err := d.exec.LookPath(pm.Binary)
		if err != nil {
			continue
		}

		version := "unknown"
		stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, pm.Binary, pm.VersionCmd)
		if err == nil {
			v := parsePythonVersion(pm.Name, stdout)
			if v != "" {
				version = v
			}
		}

		results = append(results, model.PkgManager{
			Name:    pm.Name,
			Version: version,
			Path:    path,
		})
	}

	return results
}

// ListPackages returns installed Python packages using pip3.
func (d *PythonPMDetector) ListPackages(ctx context.Context) []model.PythonPackage {
	if _, err := d.exec.LookPath("pip3"); err != nil {
		return nil
	}
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 30*time.Second, "pip3", "list", "--format", "json")
	if err != nil {
		return nil
	}
	return parsePipListJSON(stdout)
}

// parsePipListJSON parses `pip list --format json` output: [{"name":"pkg","version":"1.0"},...]
func parsePipListJSON(stdout string) []model.PythonPackage {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil
	}
	type pipEntry struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var entries []pipEntry
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		return nil
	}
	packages := make([]model.PythonPackage, len(entries))
	for i, e := range entries {
		packages[i] = model.PythonPackage{Name: e.Name, Version: e.Version}
	}
	return packages
}

// versionRegex matches a semver-like version number (e.g., 3.12.0, 24.0, 1.8.0).
var versionRegex = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)

// parsePythonVersion extracts the version number from various Python tool output formats:
//   - python3 --version  → "Python 3.12.0"
//   - pip3 --version     → "pip 24.0 from /usr/lib/... (python 3.12)"
//   - poetry --version   → "Poetry (version 1.8.0)"
//   - uv --version       → "uv 0.4.0"
//   - conda --version    → "conda 24.1.2"
//   - rye --version      → "rye 0.35.0"
//   - pipenv --version   → "pipenv, version 2024.0.1"
func parsePythonVersion(name, stdout string) string {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return ""
	}
	// Take first line only
	line := firstLine(stdout)
	if match := versionRegex.FindString(line); match != "" {
		return match
	}
	return strings.TrimSpace(line)
}
