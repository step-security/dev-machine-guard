package detector

import (
	"context"
	"os"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestAgentDetector_FindsOpenclaw(t *testing.T) {
	mock := executor.NewMock()
	binaryPath := "/usr/local/bin/openclaw"
	mock.SetPath("openclaw", binaryPath)
	mock.SetCommand("0.5.2\n", "", 0, binaryPath, "--version")
	// Non-empty config dir.
	mock.SetDir("/Users/testuser/.openclaw")
	mock.SetDirEntries("/Users/testuser/.openclaw", []os.DirEntry{
		executor.MockDirEntry("config.toml", false),
	})
	mock.SetFile("/Users/testuser/.openclaw/config.toml", []byte("[settings]\nfoo = 1"))

	det := NewAgentDetector(mock)
	results := det.Detect(context.Background(), []string{"/Users/testuser"})

	var got *agentResult
	for i, r := range results {
		if r.Name == "openclaw" {
			got = &agentResult{r}
			_ = i
		}
	}
	if got == nil {
		t.Fatal("openclaw not found")
	}
	if got.Type != "general_agent" {
		t.Errorf("expected general_agent, got %s", got.Type)
	}
	if got.BinaryPath != binaryPath {
		t.Errorf("expected binary_path %s, got %s", binaryPath, got.BinaryPath)
	}
	if got.InstallPath != binaryPath {
		t.Errorf("expected install_path %s (resolved real path), got %s", binaryPath, got.InstallPath)
	}
	if got.ConfigDir != "/Users/testuser/.openclaw" {
		t.Errorf("expected config_dir /Users/testuser/.openclaw, got %s", got.ConfigDir)
	}
	if got.Version != "0.5.2" {
		t.Errorf("expected version 0.5.2, got %s", got.Version)
	}
}

// TestAgentDetector_NoFalsePositive_EmptyConfigDir asserts that an empty
// "~/.openclaw" left over from an uninstall (or a fixture) does NOT trick the
// detector into reporting openclaw as installed when the binary isn't on PATH.
// See bug 0001.
func TestAgentDetector_NoFalsePositive_EmptyConfigDir(t *testing.T) {
	mock := executor.NewMock()
	// Empty config dir present, but no binary anywhere.
	mock.SetDir("/Users/testuser/.openclaw")
	mock.SetDirEntries("/Users/testuser/.openclaw", []os.DirEntry{})

	det := NewAgentDetector(mock)
	results := det.Detect(context.Background(), []string{"/Users/testuser"})

	for _, r := range results {
		if r.Name == "openclaw" {
			t.Errorf("openclaw should not be detected from an empty config dir alone; got %+v", r)
		}
	}
}

// TestAgentDetector_NoFalsePositive_EmptyConfigFile asserts that a directory
// containing only a zero-byte config file (the actual fixture observed on the
// Linux test VM that triggered bug 0001) does not produce a phantom detection.
func TestAgentDetector_NoFalsePositive_EmptyConfigFile(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Users/testuser/.openclaw")
	mock.SetDirEntries("/Users/testuser/.openclaw", []os.DirEntry{
		executor.MockDirEntry("config.json", false),
	})
	mock.SetFile("/Users/testuser/.openclaw/config.json", []byte{}) // size=0

	det := NewAgentDetector(mock)
	results := det.Detect(context.Background(), []string{"/Users/testuser"})

	for _, r := range results {
		if r.Name == "openclaw" {
			t.Errorf("openclaw should not be detected from an empty config.json; got %+v", r)
		}
	}
}

// TestAgentDetector_ResolvesNpmInstallPath asserts that an agent installed via
// npm (binary is a symlink into node_modules) reports the package root as
// install_path instead of the shim path.
func TestAgentDetector_ResolvesNpmInstallPath(t *testing.T) {
	mock := executor.NewMock()
	shim := "/usr/local/bin/openclaw"
	target := "/usr/local/lib/node_modules/openclaw/bin/openclaw.js"
	pkgRoot := "/usr/local/lib/node_modules/openclaw"
	mock.SetPath("openclaw", shim)
	mock.SetSymlink(shim, target)
	mock.SetCommand("0.5.2\n", "", 0, shim, "--version")

	det := NewAgentDetector(mock)
	results := det.Detect(context.Background(), []string{"/Users/testuser"})

	var got *agentResult
	for _, r := range results {
		if r.Name == "openclaw" {
			r := r
			got = &agentResult{r}
		}
	}
	if got == nil {
		t.Fatal("openclaw not found")
	}
	if got.BinaryPath != shim {
		t.Errorf("expected binary_path %s, got %s", shim, got.BinaryPath)
	}
	if got.InstallPath != pkgRoot {
		t.Errorf("expected install_path %s (npm package root), got %s", pkgRoot, got.InstallPath)
	}
}

// agentResult is a tiny helper alias to keep test reads clean.
type agentResult struct{ model.AITool }

func TestAgentDetector_ClaudeCowork(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Claude.app")
	mock.SetFile("/Applications/Claude.app/Contents/Info.plist", []byte{})
	mock.SetCommand("0.7.5", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/Claude.app/Contents/Info.plist")

	det := NewAgentDetector(mock)
	results := det.Detect(context.Background(), []string{"/Users/testuser"})

	found := false
	for _, r := range results {
		if r.Name == "claude-cowork" {
			found = true
			if r.Vendor != "Anthropic" {
				t.Errorf("expected Anthropic, got %s", r.Vendor)
			}
			if r.Version != "0.7.5" {
				t.Errorf("expected 0.7.5, got %s", r.Version)
			}
		}
	}
	if !found {
		t.Error("claude-cowork not found")
	}
}

func TestAgentDetector_ClaudeCowork_OldVersion(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Claude.app")
	mock.SetFile("/Applications/Claude.app/Contents/Info.plist", []byte{})
	mock.SetCommand("0.6.9", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/Claude.app/Contents/Info.plist")

	det := NewAgentDetector(mock)
	results := det.Detect(context.Background(), []string{"/Users/testuser"})

	for _, r := range results {
		if r.Name == "claude-cowork" {
			t.Error("claude-cowork should not be detected for version 0.6.9")
		}
	}
}

func TestIsCoworkVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"0.7.0", true},
		{"0.7.5", true},
		{"0.9.0", true},
		{"1.0.0", true},
		{"1.5.2", true},
		{"0.6.9", false},
		{"0.1.0", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		got := isCoworkVersion(tt.version)
		if got != tt.want {
			t.Errorf("isCoworkVersion(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestAgentDetector_Windows_ClaudeCowork(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetHomeDir(`C:\Users\testuser`)
	mock.SetEnv("LOCALAPPDATA", `C:\Users\testuser\AppData\Local`)

	// detectClaudeCowork on Windows uses filepath.Join(localAppData, "Programs", "Claude").
	// On macOS host, filepath.Join keeps backslashes and inserts "/":
	claudePath := `C:\Users\testuser\AppData\Local` + "/Programs/Claude"
	mock.SetDir(claudePath)

	// Version via readRegistryVersion with appName "Claude".
	// First registry root tried by readRegistryVersion.
	mock.SetCommand(
		"HKLM\\SOFTWARE\\...\\Claude\n    DisplayVersion    REG_SZ    0.7.5\n",
		"", 0,
		"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "Claude", "/d",
	)

	det := NewAgentDetector(mock)
	results := det.Detect(context.Background(), []string{`C:\Users\testuser`})

	found := false
	for _, r := range results {
		if r.Name == "claude-cowork" {
			found = true
			if r.Vendor != "Anthropic" {
				t.Errorf("expected Anthropic, got %s", r.Vendor)
			}
			if r.Version != "0.7.5" {
				t.Errorf("expected 0.7.5, got %s", r.Version)
			}
			if r.InstallPath != claudePath {
				t.Errorf("expected install path %s, got %s", claudePath, r.InstallPath)
			}
		}
	}
	if !found {
		t.Error("claude-cowork not found")
	}
}
