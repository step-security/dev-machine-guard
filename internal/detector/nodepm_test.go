package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
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
