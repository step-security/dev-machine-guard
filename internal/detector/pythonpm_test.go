package detector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestPythonPMDetector_FindsPip(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("pip3", "/usr/local/bin/pip3")
	mock.SetCommand("pip 24.0 from /usr/lib/python3.12/site-packages/pip (python 3.12)\n", "", 0, "pip3", "--version")

	det := NewPythonPMDetector(mock)
	results := det.DetectManagers(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "pip" {
			found = true
			if r.Version != "24.0" {
				t.Errorf("expected pip version 24.0, got %s", r.Version)
			}
		}
	}
	if !found {
		t.Error("expected pip to be detected")
	}
}

func TestPythonPMDetector_FindsMultiple(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("python3", "/usr/local/bin/python3")
	mock.SetCommand("Python 3.12.0\n", "", 0, "python3", "--version")
	mock.SetPath("pip3", "/usr/local/bin/pip3")
	mock.SetCommand("pip 24.0 from /usr/lib/python3.12/site-packages/pip (python 3.12)\n", "", 0, "pip3", "--version")
	mock.SetPath("uv", "/usr/local/bin/uv")
	mock.SetCommand("uv 0.4.0\n", "", 0, "uv", "--version")

	det := NewPythonPMDetector(mock)
	results := det.DetectManagers(context.Background())

	if len(results) != 3 {
		t.Fatalf("expected 3 package managers, got %d", len(results))
	}
}

func TestPythonPMDetector_NoneFound(t *testing.T) {
	mock := executor.NewMock()
	det := NewPythonPMDetector(mock)
	results := det.DetectManagers(context.Background())

	if len(results) != 0 {
		t.Errorf("expected 0 package managers, got %d", len(results))
	}
}

func TestParsePythonVersion(t *testing.T) {
	tests := []struct {
		name     string
		stdout   string
		expected string
	}{
		{"python3", "Python 3.12.0\n", "3.12.0"},
		{"pip", "pip 24.0 from /usr/lib/python3.12/site-packages/pip (python 3.12)\n", "24.0"},
		{"poetry", "Poetry (version 1.8.0)\n", "1.8.0"},
		{"uv", "uv 0.4.0\n", "0.4.0"},
		{"conda", "conda 24.1.2\n", "24.1.2"},
		{"rye", "rye 0.35.0\n", "0.35.0"},
		{"pipenv", "pipenv, version 2024.0.1\n", "2024.0.1"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePythonVersion(tt.name, tt.stdout)
			if got != tt.expected {
				t.Errorf("parsePythonVersion(%q, %q) = %q, want %q", tt.name, tt.stdout, got, tt.expected)
			}
		})
	}
}

func TestPythonProjectDetector_CountProjects(t *testing.T) {
	dir := t.TempDir()

	// project1: pyproject.toml + .venv with pyvenv.cfg — detected
	mustCreateFile(t, filepath.Join(dir, "project1", "pyproject.toml"))
	mustCreateFile(t, filepath.Join(dir, "project1", ".venv", "pyvenv.cfg"))
	mustCreateFile(t, filepath.Join(dir, "project1", ".venv", "bin", "pip"))

	// project2: setup.py + venv with pyvenv.cfg — detected
	mustCreateFile(t, filepath.Join(dir, "project2", "setup.py"))
	mustCreateFile(t, filepath.Join(dir, "project2", "venv", "pyvenv.cfg"))
	mustCreateFile(t, filepath.Join(dir, "project2", "venv", "bin", "pip"))

	// project3: no venv — skipped
	mustCreateFile(t, filepath.Join(dir, "project3", "Pipfile"))

	mock := executor.NewMock()
	mock.SetFile(filepath.Join(dir, "project1", ".venv", "pyvenv.cfg"), []byte(""))
	mock.SetFile(filepath.Join(dir, "project1", ".venv", "bin", "pip"), []byte(""))
	mock.SetFile(filepath.Join(dir, "project2", "venv", "pyvenv.cfg"), []byte(""))
	mock.SetFile(filepath.Join(dir, "project2", "venv", "bin", "pip"), []byte(""))
	mock.SetCommand(`[{"name":"flask","version":"3.0.0"}]`, "", 0,
		filepath.Join(dir, "project1", ".venv", "bin", "pip"), "list", "--format", "json")
	mock.SetCommand(`[{"name":"django","version":"5.0"}]`, "", 0,
		filepath.Join(dir, "project2", "venv", "bin", "pip"), "list", "--format", "json")

	det := NewPythonProjectDetector(mock)
	projects := det.ListProjects([]string{dir})

	if len(projects) != 2 {
		t.Fatalf("expected 2 venv projects, got %d", len(projects))
	}
	if len(projects[0].Packages) == 0 {
		t.Error("expected packages in first project")
	}
}

// Venvs created by `python -m venv myenv` (or virtualenv >= 20) carry a
// pyvenv.cfg regardless of folder name. Folder names other than venv/.venv
// must be detected via that marker.
func TestPythonProjectDetector_ArbitraryVenvName(t *testing.T) {
	dir := t.TempDir()

	mustCreateFile(t, filepath.Join(dir, "proj", "myenv", "pyvenv.cfg"))
	mustCreateFile(t, filepath.Join(dir, "proj", "myenv", "bin", "pip"))

	mock := executor.NewMock()
	mock.SetFile(filepath.Join(dir, "proj", "myenv", "pyvenv.cfg"), []byte(""))
	mock.SetFile(filepath.Join(dir, "proj", "myenv", "bin", "pip"), []byte(""))
	mock.SetCommand(`[{"name":"requests","version":"2.32.0"}]`, "", 0,
		filepath.Join(dir, "proj", "myenv", "bin", "pip"), "list", "--format", "json")

	det := NewPythonProjectDetector(mock)
	projects := det.ListProjects([]string{dir})

	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
	wantPath := filepath.Join(dir, "proj", "myenv")
	if projects[0].Path != wantPath {
		t.Errorf("expected project path %q, got %q", wantPath, projects[0].Path)
	}
}

// Two venvs under the same parent must both be surfaced — keying by venv
// path (not parent) prevents the second from being silently dropped.
func TestPythonProjectDetector_MultipleVenvsSameParent(t *testing.T) {
	dir := t.TempDir()

	mustCreateFile(t, filepath.Join(dir, "proj", "venv-a", "pyvenv.cfg"))
	mustCreateFile(t, filepath.Join(dir, "proj", "venv-a", "bin", "pip"))
	mustCreateFile(t, filepath.Join(dir, "proj", "venv-b", "pyvenv.cfg"))
	mustCreateFile(t, filepath.Join(dir, "proj", "venv-b", "bin", "pip"))

	mock := executor.NewMock()
	mock.SetFile(filepath.Join(dir, "proj", "venv-a", "pyvenv.cfg"), []byte(""))
	mock.SetFile(filepath.Join(dir, "proj", "venv-a", "bin", "pip"), []byte(""))
	mock.SetFile(filepath.Join(dir, "proj", "venv-b", "pyvenv.cfg"), []byte(""))
	mock.SetFile(filepath.Join(dir, "proj", "venv-b", "bin", "pip"), []byte(""))
	mock.SetCommand(`[{"name":"requests","version":"2.32.0"}]`, "", 0,
		filepath.Join(dir, "proj", "venv-a", "bin", "pip"), "list", "--format", "json")
	mock.SetCommand(`[{"name":"flask","version":"3.0.0"}]`, "", 0,
		filepath.Join(dir, "proj", "venv-b", "bin", "pip"), "list", "--format", "json")

	det := NewPythonProjectDetector(mock)
	projects := det.ListProjects([]string{dir})

	if len(projects) != 2 {
		t.Fatalf("expected 2 projects (one per venv), got %d", len(projects))
	}
	got := map[string]bool{projects[0].Path: true, projects[1].Path: true}
	wantA := filepath.Join(dir, "proj", "venv-a")
	wantB := filepath.Join(dir, "proj", "venv-b")
	if !got[wantA] || !got[wantB] {
		t.Errorf("expected both %q and %q, got %+v", wantA, wantB, got)
	}
}

// Older virtualenvs (pre-pyvenv.cfg) ship bin/activate alongside bin/pip;
// detection should fall back to that pair.
func TestPythonProjectDetector_LegacyVenvWithActivate(t *testing.T) {
	dir := t.TempDir()

	mustCreateFile(t, filepath.Join(dir, "proj", "env", "bin", "pip"))
	mustCreateFile(t, filepath.Join(dir, "proj", "env", "bin", "activate"))

	mock := executor.NewMock()
	mock.SetFile(filepath.Join(dir, "proj", "env", "bin", "pip"), []byte(""))
	mock.SetFile(filepath.Join(dir, "proj", "env", "bin", "activate"), []byte(""))
	mock.SetCommand(`[]`, "", 0,
		filepath.Join(dir, "proj", "env", "bin", "pip"), "list", "--format", "json")

	det := NewPythonProjectDetector(mock)
	projects := det.ListProjects([]string{dir})

	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
}

// A bin/pip with neither pyvenv.cfg nor an activate script is not a venv —
// guards against, e.g., system /usr/local pretending to be a project.
func TestPythonProjectDetector_NotAVenv(t *testing.T) {
	dir := t.TempDir()

	mustCreateFile(t, filepath.Join(dir, "fake", "bin", "pip"))

	mock := executor.NewMock()
	mock.SetFile(filepath.Join(dir, "fake", "bin", "pip"), []byte(""))

	det := NewPythonProjectDetector(mock)
	projects := det.ListProjects([]string{dir})

	if len(projects) != 0 {
		t.Fatalf("expected 0 projects, got %d", len(projects))
	}
}

// Windows venvs use Scripts/pip.exe instead of bin/pip.
func TestPythonProjectDetector_WindowsLayout(t *testing.T) {
	dir := t.TempDir()

	mustCreateFile(t, filepath.Join(dir, "proj", ".venv", "pyvenv.cfg"))
	mustCreateFile(t, filepath.Join(dir, "proj", ".venv", "Scripts", "pip.exe"))

	mock := executor.NewMock()
	mock.SetFile(filepath.Join(dir, "proj", ".venv", "pyvenv.cfg"), []byte(""))
	mock.SetFile(filepath.Join(dir, "proj", ".venv", "Scripts", "pip.exe"), []byte(""))
	mock.SetCommand(`[{"name":"pytest","version":"8.0.0"}]`, "", 0,
		filepath.Join(dir, "proj", ".venv", "Scripts", "pip.exe"), "list", "--format", "json")

	det := NewPythonProjectDetector(mock)
	projects := det.ListProjects([]string{dir})

	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
	if len(projects[0].Packages) == 0 {
		t.Error("expected packages from Scripts/pip.exe")
	}
}

// Venvs created with `python -m venv --without-pip` carry pyvenv.cfg but no
// pip. They should still be reported (Packages empty), and the walker must
// not descend into the venv tree (regression guard for the perf bug).
func TestPythonProjectDetector_VenvWithoutPip(t *testing.T) {
	dir := t.TempDir()

	mustCreateFile(t, filepath.Join(dir, "proj", ".venv", "pyvenv.cfg"))
	// Filler file deep inside the venv. If WalkDir descends, it will be
	// visited; the SkipDir return on venv match prevents that.
	mustCreateFile(t, filepath.Join(dir, "proj", ".venv", "lib", "python3.12", "site-packages", "foo", "bar.py"))

	mock := executor.NewMock()
	mock.SetFile(filepath.Join(dir, "proj", ".venv", "pyvenv.cfg"), []byte(""))

	det := NewPythonProjectDetector(mock)
	projects := det.ListProjects([]string{dir})

	if len(projects) != 1 {
		t.Fatalf("expected 1 project (venv without pip), got %d", len(projects))
	}
	if len(projects[0].Packages) != 0 {
		t.Errorf("expected empty Packages when pip is absent, got %d", len(projects[0].Packages))
	}
	wantPath := filepath.Join(dir, "proj", ".venv")
	if projects[0].Path != wantPath {
		t.Errorf("expected path %q, got %q", wantPath, projects[0].Path)
	}
}

func mustCreateFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
}
