package detector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

const maxPythonProjects = 1000

// PythonProjectDetector scans for Python projects with virtual environments.
type PythonProjectDetector struct {
	exec executor.Executor
}

func NewPythonProjectDetector(exec executor.Executor) *PythonProjectDetector {
	return &PythonProjectDetector{exec: exec}
}

// CountProjects counts Python projects with virtual environments.
func (d *PythonProjectDetector) CountProjects(_ context.Context, searchDirs []string) int {
	return len(d.ListProjects(searchDirs))
}

// ListProjects returns Python projects that have a virtual environment,
// along with the packages installed in each venv.
func (d *PythonProjectDetector) ListProjects(searchDirs []string) []model.ProjectInfo {
	var projects []model.ProjectInfo
	for _, dir := range searchDirs {
		projects = append(projects, d.listInDir(dir)...)
		if len(projects) >= maxPythonProjects {
			return projects[:maxPythonProjects]
		}
	}
	return projects
}

// findPipInVenv returns the path to pip inside a venv-shaped dir, or "".
// Handles POSIX layout (bin/pip) and Windows layout (Scripts/pip.exe).
func (d *PythonProjectDetector) findPipInVenv(venvPath string) string {
	if p := filepath.Join(venvPath, "bin", "pip"); d.exec.FileExists(p) {
		return p
	}
	if p := filepath.Join(venvPath, "Scripts", "pip.exe"); d.exec.FileExists(p) {
		return p
	}
	return ""
}

// isVenvDir reports whether path is a Python virtual environment, returning
// the pip path inside it (or "" if not a venv).
//
// Detection priority:
//  1. pyvenv.cfg at the venv root (PEP 405 — covers `python -m venv` and
//     virtualenv >= 20, regardless of folder name).
//  2. bin/pip (or Scripts/pip.exe) plus an activate script — covers older
//     virtualenvs that predate pyvenv.cfg. The activate-script check guards
//     against false positives like /usr/local/bin/pip.
func (d *PythonProjectDetector) isVenvDir(path string) string {
	if d.exec.FileExists(filepath.Join(path, "pyvenv.cfg")) {
		return d.findPipInVenv(path)
	}
	pip := d.findPipInVenv(path)
	if pip == "" {
		return ""
	}
	if d.exec.FileExists(filepath.Join(path, "bin", "activate")) ||
		d.exec.FileExists(filepath.Join(path, "Scripts", "activate")) {
		return pip
	}
	return ""
}

// listVenvPackages runs pip list inside the venv and returns the packages.
func (d *PythonProjectDetector) listVenvPackages(ctx context.Context, pipPath string) []model.PackageDetail {
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 15*time.Second, pipPath, "list", "--format", "json")
	if err != nil {
		return nil
	}
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
	pkgs := make([]model.PackageDetail, 0, len(entries))
	for _, e := range entries {
		pkgs = append(pkgs, model.PackageDetail{Name: e.Name, Version: e.Version})
	}
	return pkgs
}

// pythonPMFromMarker maps a marker file to its package manager name.
var pythonPMFromMarker = map[string]string{
	"Pipfile":          "pipenv",
	"pyproject.toml":   "pip",
	"setup.py":         "pip",
	"requirements.txt": "pip",
}

func (d *PythonProjectDetector) listInDir(dir string) []model.ProjectInfo {
	ctx := context.Background()
	seen := make(map[string]bool)
	var projects []model.ProjectInfo
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if name == "node_modules" || name == ".git" || name == ".cache" ||
			name == "__pycache__" || name == ".tox" || name == "site-packages" ||
			(strings.HasPrefix(name, ".") && name != ".venv") {
			return filepath.SkipDir
		}

		pipPath := d.isVenvDir(path)
		if pipPath == "" {
			return nil
		}

		// Report each venv as its own entry (Path = venv folder), so multiple
		// venvs sharing a parent directory are all surfaced. Marker-based
		// package_manager detection still runs against the parent dir.
		if !seen[path] {
			seen[path] = true
			pm := d.detectPM(filepath.Dir(path))
			pkgs := d.listVenvPackages(ctx, pipPath)
			projects = append(projects, model.ProjectInfo{
				Path:           path,
				PackageManager: pm,
				Packages:       pkgs,
			})
			if len(projects) >= maxPythonProjects {
				return filepath.SkipAll
			}
		}
		return filepath.SkipDir
	})
	return projects
}

// detectPM determines the package manager for a project directory based on lock/marker files.
func (d *PythonProjectDetector) detectPM(projectDir string) string {
	if d.exec.FileExists(filepath.Join(projectDir, "poetry.lock")) {
		return "poetry"
	}
	if d.exec.FileExists(filepath.Join(projectDir, "Pipfile.lock")) {
		return "pipenv"
	}
	if d.exec.FileExists(filepath.Join(projectDir, "uv.lock")) {
		return "uv"
	}
	for marker, pm := range pythonPMFromMarker {
		if d.exec.FileExists(filepath.Join(projectDir, marker)) {
			return pm
		}
	}
	return "pip"
}
