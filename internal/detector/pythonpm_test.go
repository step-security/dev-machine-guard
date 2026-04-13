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

	// project1: has venv — should be detected
	mustCreateFile(t, filepath.Join(dir, "project1", "pyproject.toml"))
	mustCreateFile(t, filepath.Join(dir, "project1", ".venv", "bin", "pip"))

	// project2: has venv — should be detected
	mustCreateFile(t, filepath.Join(dir, "project2", "setup.py"))
	mustCreateFile(t, filepath.Join(dir, "project2", "venv", "bin", "pip"))

	// project3: no venv — should be skipped
	mustCreateFile(t, filepath.Join(dir, "project3", "Pipfile"))

	mock := executor.NewMock()
	// Mock FileExists for venv pip paths
	mock.SetFile(filepath.Join(dir, "project1", ".venv", "bin", "pip"), []byte(""))
	mock.SetFile(filepath.Join(dir, "project2", "venv", "bin", "pip"), []byte(""))
	// Mock pip list output
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

func mustCreateFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
}
