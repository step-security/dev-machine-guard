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

// pythonMarkerFiles are files that indicate a Python project directory.
var pythonMarkerFiles = map[string]bool{
	"pyproject.toml":   true,
	"setup.py":         true,
	"requirements.txt": true,
	"Pipfile":          true,
}

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

// venvDirNames are directory names that indicate a Python virtual environment.
var venvDirNames = []string{".venv", "venv"}

// findVenvPip returns the path to pip inside a venv, or "" if not found.
func (d *PythonProjectDetector) findVenvPip(projectDir string) string {
	for _, vdir := range venvDirNames {
		pip := filepath.Join(projectDir, vdir, "bin", "pip")
		if d.exec.FileExists(pip) {
			return pip
		}
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
		if entry.IsDir() {
			name := entry.Name()
			if name == "node_modules" || name == ".git" || name == ".cache" ||
				name == "__pycache__" || name == ".tox" || name == "site-packages" ||
				(strings.HasPrefix(name, ".") && name != ".venv") {
				return filepath.SkipDir
			}

			// Detect directories that contain a venv even without a marker file.
			// A venv/ or .venv/ subdirectory is itself evidence of a Python project.
			if !seen[path] {
				if pipPath := d.findVenvPip(path); pipPath != "" {
					seen[path] = true
					pm := d.detectPM(path)
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
			}

			return nil
		}
		if pythonMarkerFiles[entry.Name()] {
			projectDir := filepath.Dir(path)
			if seen[projectDir] {
				return nil
			}
			seen[projectDir] = true

			// Only include marker-based projects that have a virtual environment
			pipPath := d.findVenvPip(projectDir)
			if pipPath == "" {
				return nil
			}

			pm := d.detectPM(projectDir)

			pkgs := d.listVenvPackages(ctx, pipPath)

			projects = append(projects, model.ProjectInfo{
				Path:           projectDir,
				PackageManager: pm,
				Packages:       pkgs,
			})
			if len(projects) >= maxPythonProjects {
				return filepath.SkipAll
			}
		}
		return nil
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
