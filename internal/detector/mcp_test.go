package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestMCPDetector_FindsConfigs(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/Users/testuser/Library/Application Support/Claude/claude_desktop_config.json", []byte(`{"mcpServers":{}}`))
	mock.SetFile("/Users/testuser/.cursor/mcp.json", []byte(`{"mcpServers":{}}`))

	det := NewMCPDetector(mock)
	results := det.Detect(context.Background(), "testuser", false)

	if len(results) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(results))
	}
	if results[0].ConfigSource != "claude_desktop" {
		t.Errorf("expected claude_desktop, got %s", results[0].ConfigSource)
	}
	if results[1].ConfigSource != "cursor" {
		t.Errorf("expected cursor, got %s", results[1].ConfigSource)
	}
}

func TestMCPDetector_NoConfigs(t *testing.T) {
	mock := executor.NewMock()
	det := NewMCPDetector(mock)
	results := det.Detect(context.Background(), "testuser", false)

	if len(results) != 0 {
		t.Errorf("expected 0 configs, got %d", len(results))
	}
}

func TestStripJSONCComments(t *testing.T) {
	input := []byte(`{
  // This is a comment
  "key": "value", /* block comment */
  "key2": "value2"
}`)

	result := stripJSONCComments(input)
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
	// Should not contain comments
	if containsString(string(result), "//") || containsString(string(result), "/*") {
		t.Error("comments not stripped")
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestMCPDetector_Enterprise(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/Users/testuser/Library/Application Support/Claude/claude_desktop_config.json",
		[]byte(`{"mcpServers":{"server1":{"command":"node","args":["server.js"],"env":{"SECRET":"key"}}}}`))

	det := NewMCPDetector(mock)
	results := det.DetectEnterprise(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 enterprise config, got %d", len(results))
	}
	if results[0].ConfigContentBase64 == "" {
		t.Error("expected non-empty base64 content")
	}
}

func TestMCPDetector_Windows_FindsConfigs(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetHomeDir(`C:\Users\testuser`)
	mock.SetEnv("APPDATA", `C:\Users\testuser\AppData\Roaming`)

	// claude_desktop WinConfigPath: "%APPDATA%/Claude/claude_desktop_config.json"
	// After resolveEnvPath on macOS host:
	//   env replacement -> "C:\Users\testuser\AppData\Roaming/Claude/claude_desktop_config.json"
	//   filepath.FromSlash (macOS no-op) -> same
	claudeConfigPath := `C:\Users\testuser\AppData\Roaming` + "/Claude/claude_desktop_config.json"
	mock.SetFile(claudeConfigPath, []byte(`{"mcpServers":{}}`))

	det := NewMCPDetector(mock)
	results := det.Detect(context.Background(), "testuser", false)

	if len(results) != 1 {
		t.Fatalf("expected 1 config, got %d", len(results))
	}
	if results[0].ConfigSource != "claude_desktop" {
		t.Errorf("expected claude_desktop, got %s", results[0].ConfigSource)
	}
	if results[0].ConfigPath != claudeConfigPath {
		t.Errorf("expected config path %s, got %s", claudeConfigPath, results[0].ConfigPath)
	}
	if results[0].Vendor != "Anthropic" {
		t.Errorf("expected Anthropic, got %s", results[0].Vendor)
	}
}
