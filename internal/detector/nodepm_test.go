package detector

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestNodePMDetector_FindsNPM(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("npm", "/usr/local/bin/npm")
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")

	det := NewNodePMDetector(mock)
	results := det.DetectManagers(context.Background())

	if len(results) < 1 {
		t.Fatal("expected at least 1 package manager")
	}
	if results[0].Name != "npm" {
		t.Errorf("expected npm, got %s", results[0].Name)
	}
	if results[0].Version != "10.2.0" {
		t.Errorf("expected 10.2.0, got %s", results[0].Version)
	}
}

func TestNodePMDetector_Multiple(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("npm", "/usr/local/bin/npm")
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")
	mock.SetPath("yarn", "/usr/local/bin/yarn")
	mock.SetCommand("1.22.19\n", "", 0, "yarn", "--version")

	det := NewNodePMDetector(mock)
	results := det.DetectManagers(context.Background())

	if len(results) != 2 {
		t.Fatalf("expected 2 package managers, got %d", len(results))
	}
}

func TestNodePMDetector_NoneFound(t *testing.T) {
	mock := executor.NewMock()
	det := NewNodePMDetector(mock)
	results := det.DetectManagers(context.Background())

	if len(results) != 0 {
		t.Errorf("expected 0 package managers, got %d", len(results))
	}
}

func TestNodePMDetector_Windows_FindsNPM(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetPath("npm", `C:\Program Files\nodejs\npm.cmd`)
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")

	det := NewNodePMDetector(mock)
	results := det.DetectManagers(context.Background())

	if len(results) < 1 {
		t.Fatal("expected at least 1 package manager on Windows")
	}
	if results[0].Name != "npm" {
		t.Errorf("expected npm, got %s", results[0].Name)
	}
	if results[0].Version != "10.2.0" {
		t.Errorf("expected 10.2.0, got %s", results[0].Version)
	}
	if results[0].Path != `C:\Program Files\nodejs\npm.cmd` {
		t.Errorf("expected Windows path, got %s", results[0].Path)
	}
}

// findPM returns the detected package manager with the given name, or nil.
func findPM(results []model.PkgManager, name string) *model.PkgManager {
	for i := range results {
		if results[i].Name == name {
			return &results[i]
		}
	}
	return nil
}

// When a manager isn't on PATH (launchd's stripped PATH) but exists in a
// default install dir, the fallback resolves it by absolute path instead of
// dropping it from the list.
func TestNodePMDetector_FallbackResolvesWhenNotOnPath(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetHomeDir("/Users/foo")
	// npm is NOT on PATH (no SetPath) but exists in the Homebrew dir.
	mock.SetFile("/opt/homebrew/bin/npm", []byte{})
	stubFallbackVersion(mock, "/opt/homebrew/bin/npm", "--version", "10.2.0\n")

	det := NewNodePMDetector(mock)
	results := det.DetectManagers(context.Background())

	npm := findPM(results, "npm")
	if npm == nil {
		t.Fatal("expected npm to be resolved via the default-path fallback")
	}
	if npm.Version != "10.2.0" {
		t.Errorf("version = %q, want 10.2.0", npm.Version)
	}
	if npm.Path != "/opt/homebrew/bin/npm" {
		t.Errorf("path = %q, want /opt/homebrew/bin/npm", npm.Path)
	}
}

// When a manager is on PATH but its `--version` returns nothing (a stripped-PATH
// shim), the fallback recovers the version. The path stays the PATH location,
// since the fallback only fills an empty path.
func TestNodePMDetector_FallbackRecoversVersionWhenPathVersionFails(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetHomeDir("/Users/foo")
	mock.SetPath("yarn", "/usr/local/bin/yarn")
	// No SetCommand for ["yarn" "--version"] → primary version stays empty.
	mock.SetFile("/opt/homebrew/bin/yarn", []byte{})
	stubFallbackVersion(mock, "/opt/homebrew/bin/yarn", "--version", "1.22.19\n")

	det := NewNodePMDetector(mock)
	results := det.DetectManagers(context.Background())

	yarn := findPM(results, "yarn")
	if yarn == nil {
		t.Fatal("expected yarn in results")
	}
	if yarn.Version != "1.22.19" {
		t.Errorf("version = %q, want 1.22.19 (recovered via fallback)", yarn.Version)
	}
	if yarn.Path != "/usr/local/bin/yarn" {
		t.Errorf("path = %q, want /usr/local/bin/yarn (LookPath location preserved)", yarn.Path)
	}
}

// A manager found neither on PATH nor in any default dir is still dropped.
func TestNodePMDetector_DroppedWhenFoundNowhere(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetHomeDir("/Users/foo")
	// Only npm is resolvable (via fallback); yarn/pnpm/bun exist nowhere.
	mock.SetFile("/opt/homebrew/bin/npm", []byte{})
	stubFallbackVersion(mock, "/opt/homebrew/bin/npm", "--version", "10.2.0\n")

	det := NewNodePMDetector(mock)
	results := det.DetectManagers(context.Background())

	if len(results) != 1 || results[0].Name != "npm" {
		t.Fatalf("expected only npm, got %+v", results)
	}
}

func TestDetectProjectPM_Windows(t *testing.T) {
	// Note: filepath.Join is host-OS dependent; on macOS it uses "/" even for
	// Windows-style project dirs. We use filepath.Join here to match what
	// DetectProjectPM produces internally.
	projectDir := `C:\Users\dev\myapp`
	tests := []struct {
		name     string
		lockFile string
		expected string
	}{
		{"npm lock", "package-lock.json", "npm"},
		{"yarn lock", "yarn.lock", "yarn"},
		{"pnpm lock", "pnpm-lock.yaml", "pnpm"},
		{"bun lock", "bun.lock", "bun"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetGOOS("windows")
			mock.SetFile(filepath.Join(projectDir, tt.lockFile), []byte{})
			got := DetectProjectPM(mock, projectDir)
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestDetectProjectPM(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		expected string
	}{
		{"bun lock", "/project/bun.lock", "bun"},
		{"pnpm lock", "/project/pnpm-lock.yaml", "pnpm"},
		{"yarn lock", "/project/yarn.lock", "yarn"},
		{"npm lock", "/project/package-lock.json", "npm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetFile(tt.file, []byte{})
			got := DetectProjectPM(mock, "/project")
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}
