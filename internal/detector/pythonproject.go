package detector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

const maxPythonProjects = 1000

// PythonProjectDetector scans for Python projects with virtual environments.
type PythonProjectDetector struct {
	exec    executor.Executor
	log     *progress.Logger
	skipper *tcc.Skipper
	// dist, when non-nil, makes per-venv package listing read install
	// metadata from disk instead of running `pip list`.
	dist *PythonDistDetector
}

func NewPythonProjectDetector(exec executor.Executor) *PythonProjectDetector {
	return &PythonProjectDetector{exec: exec, log: progress.NewNoop()}
}

// WithSkipper attaches a TCC skipper so the walk skips macOS-protected
// directories. A nil skipper is a no-op. Returns the detector for chaining.
func (d *PythonProjectDetector) WithSkipper(s *tcc.Skipper) *PythonProjectDetector {
	d.skipper = s
	return d
}

// WithLogger attaches a progress logger so venv discovery and per-venv scans
// surface in the agent log, on par with the Node project scanner. A nil logger
// falls back to the no-op default. Returns the detector for chaining.
func (d *PythonProjectDetector) WithLogger(log *progress.Logger) *PythonProjectDetector {
	if log != nil {
		d.log = log
	}
	return d
}

// WithDiskScan switches per-venv package listing to read on-disk install
// metadata (via the supplied PythonDistDetector) instead of running
// `pip list`. A nil detector leaves the legacy pip path in place. Returns
// the detector for chaining.
func (d *PythonProjectDetector) WithDiskScan(dist *PythonDistDetector) *PythonProjectDetector {
	d.dist = dist
	return d
}

// CountProjects counts Python projects with virtual environments.
func (d *PythonProjectDetector) CountProjects(_ context.Context, searchDirs []string) int {
	projects, _ := d.ListProjects(searchDirs, nil)
	return len(projects)
}

// venvCandidate is one discovered virtual environment, captured before any
// per-venv pip list is run so the discovered set can be reordered by state.
type venvCandidate struct {
	path    string
	pipPath string
	pm      string
	modTime int64
}

// ListProjects returns Python projects that have a virtual environment,
// along with the packages installed in each venv.
//
// Ordering: paths absent from knownLastVerified come first by mtime
// descending; known paths follow by LastVerifiedAt ascending. Pass nil for
// discovery-order behavior.
//
// ProjectInfo.Path is the venv directory itself (not the project root, unlike
// node detection). Multiple venvs sharing a parent each surface as their own
// entry. PackageManager is derived from marker files in the parent.
//
// The second return is every venv path discovered on disk (before the cap),
// so callers can distinguish "missing from disk" from "dropped by the cap"
// when comparing against prior state.
func (d *PythonProjectDetector) ListProjects(searchDirs []string, knownLastVerified map[string]time.Time) (projects []model.ProjectInfo, discovered []string) {
	var candidates []venvCandidate
	for _, dir := range searchDirs {
		d.log.Progress("  Searching in: %s", dir)
		candidates = append(candidates, d.discoverInDir(dir)...)
	}

	d.log.Debug("python venv discovery: found %d venv(s) across %d search dir(s)", len(candidates), len(searchDirs))

	discovered = make([]string, 0, len(candidates))
	for _, c := range candidates {
		discovered = append(discovered, c.path)
	}

	candidates = orderVenvs(candidates, knownLastVerified)

	if len(candidates) > maxPythonProjects {
		d.log.Warn("Python project scan truncated at %d venvs (total discovered: %d) — lowest-priority venvs were skipped", maxPythonProjects, len(candidates))
		candidates = candidates[:maxPythonProjects]
	}

	ctx := context.Background()
	projects = make([]model.ProjectInfo, 0, len(candidates))
	for _, c := range candidates {
		var pkgs []model.PackageDetail
		switch {
		case d.dist != nil:
			// Disk mode: read install metadata from the venv's
			// site-packages — works even for --without-pip venvs.
			d.log.Progress("  Scanning: %s (%s)", c.path, c.pm)
			pkgs = d.dist.ScanVenv(c.path)
		case c.pipPath != "":
			d.log.Progress("  Scanning: %s (%s)", c.path, c.pm)
			pkgs = d.listVenvPackages(ctx, c.path, c.pipPath)
		default:
			// A valid venv (pyvenv.cfg present) created with --without-pip:
			// there's nothing to list, but record that we saw it so the
			// absence of packages is explained rather than silent.
			d.log.Debug("python venv has no pip — skipping package list: %s (%s)", c.path, c.pm)
		}
		projects = append(projects, model.ProjectInfo{
			Path:           c.path,
			PackageManager: c.pm,
			Packages:       pkgs,
		})
	}

	d.log.Progress("  Scanned %d venvs", len(candidates))
	return projects, discovered
}

// orderVenvs prioritises never-seen venvs (mtime desc) before known venvs
// (LastVerifiedAt asc). A nil map (no state at all) preserves discovery order;
// an empty map means state exists but has no Python entries yet, so every
// candidate is unknown and still gets sorted by mtime desc.
func orderVenvs(candidates []venvCandidate, knownLastVerified map[string]time.Time) []venvCandidate {
	if knownLastVerified == nil {
		return candidates
	}
	unknown := make([]venvCandidate, 0, len(candidates))
	known := make([]venvCandidate, 0, len(candidates))
	for _, c := range candidates {
		if _, ok := knownLastVerified[c.path]; ok {
			known = append(known, c)
		} else {
			unknown = append(unknown, c)
		}
	}
	sort.Slice(unknown, func(i, j int) bool {
		return unknown[i].modTime > unknown[j].modTime
	})
	sort.Slice(known, func(i, j int) bool {
		return knownLastVerified[known[i].path].Before(knownLastVerified[known[j].path])
	})
	return append(unknown, known...)
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
// the pip path inside it (which may be empty for valid venvs created with
// --without-pip) and a flag indicating venv shape.
//
// Detection priority:
//  1. pyvenv.cfg at the venv root (PEP 405 — covers `python -m venv` and
//     virtualenv >= 20, regardless of folder name).
//  2. bin/pip (or Scripts/pip.exe) plus an activate script — covers older
//     virtualenvs that predate pyvenv.cfg. The activate-script check guards
//     against false positives like /usr/local/bin/pip.
//
// Returning isVenv=true even when pip is missing lets callers SkipDir the
// venv tree (which can hold thousands of files in site-packages).
func (d *PythonProjectDetector) isVenvDir(path string) (pipPath string, isVenv bool) {
	if d.exec.FileExists(filepath.Join(path, "pyvenv.cfg")) {
		return d.findPipInVenv(path), true
	}
	pip := d.findPipInVenv(path)
	if pip == "" {
		return "", false
	}
	if d.exec.FileExists(filepath.Join(path, "bin", "activate")) ||
		d.exec.FileExists(filepath.Join(path, "Scripts", "activate")) {
		return pip, true
	}
	return "", false
}

// listVenvPackages runs pip list inside the venv and returns the packages.
// venvPath is used only for log context; pipPath is the binary actually run.
func (d *PythonProjectDetector) listVenvPackages(ctx context.Context, venvPath, pipPath string) []model.PackageDetail {
	start := time.Now()
	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 15*time.Second, pipPath, "list", "--format", "json")
	duration := time.Since(start).Milliseconds()
	if errMsg := pmRunError("pip list", exitCode, err); errMsg != "" {
		d.log.Warn("python venv scan failed: %s (venv=%s, exit=%d, %dms) — results may be incomplete", errMsg, venvPath, exitCode, duration)
		return nil
	}
	d.log.Debug("python venv scan: venv=%s exit_code=%d stdout_bytes=%d duration=%dms", venvPath, exitCode, len(stdout), duration)
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
		d.log.Warn("python venv scan: failed to parse pip list JSON (venv=%s): %v", venvPath, err)
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

// discoverInDir walks `dir` and returns every venv it finds, without running
// pip list. The two-phase split (discover → order → scan) lets the caller
// reorder via state before any pip list is run.
func (d *PythonProjectDetector) discoverInDir(dir string) []venvCandidate {
	var found []venvCandidate
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		if d.skipper.ShouldSkip(path, dir) {
			return filepath.SkipDir
		}
		name := entry.Name()
		if name == "node_modules" || name == ".git" || name == ".cache" ||
			name == "__pycache__" || name == ".tox" || name == "site-packages" ||
			(strings.HasPrefix(name, ".") && name != ".venv") {
			return filepath.SkipDir
		}

		pipPath, isVenv := d.isVenvDir(path)
		if !isVenv {
			return nil
		}

		modTime := int64(0)
		if info, infoErr := entry.Info(); infoErr == nil {
			modTime = info.ModTime().Unix()
		}
		found = append(found, venvCandidate{
			path:    path,
			pipPath: pipPath,
			pm:      d.detectPM(filepath.Dir(path)),
			modTime: modTime,
		})
		return filepath.SkipDir
	})
	return found
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
