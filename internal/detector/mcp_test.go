package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
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

	// Verify secrets are stripped from filtered output
	decoded, err := base64.StdEncoding.DecodeString(results[0].ConfigContentBase64)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	content := string(decoded)
	if strings.Contains(content, "SECRET") {
		t.Error("filtered content must not contain env var secrets")
	}
	if strings.Contains(content, "env") {
		t.Error("filtered content must not contain env field")
	}
	if !strings.Contains(content, "command") {
		t.Error("filtered content should contain command field")
	}
	if !strings.Contains(content, "args") {
		t.Error("filtered content should contain args field")
	}
}

func TestMCPDetector_Enterprise_NonJSON_OmitsContent(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/Users/testuser/.config/open-interpreter/config.yaml",
		[]byte("api_key: sk-secret-12345\nmodel: gpt-4\n"))

	det := NewMCPDetector(mock)
	results := det.DetectEnterprise(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 enterprise config, got %d", len(results))
	}
	if results[0].ConfigContentBase64 != "" {
		t.Error("non-JSON config must have empty content to avoid leaking secrets")
	}
	if results[0].ConfigSource != "open_interpreter" {
		t.Errorf("expected open_interpreter source, got %s", results[0].ConfigSource)
	}
}

func TestMCPDetector_Enterprise_InvalidJSON_OmitsContent(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/Users/testuser/Library/Application Support/Claude/claude_desktop_config.json",
		[]byte(`{invalid json with "env":{"API_KEY":"sk-secret"}}`))

	det := NewMCPDetector(mock)
	results := det.DetectEnterprise(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 enterprise config, got %d", len(results))
	}
	if results[0].ConfigContentBase64 != "" {
		t.Error("invalid JSON config must have empty content to avoid leaking secrets")
	}
}

func TestMCPDetector_Enterprise_NoMCPServers_OmitsContent(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/Users/testuser/Library/Application Support/Claude/claude_desktop_config.json",
		[]byte(`{"theme":"dark","api_key":"sk-secret-12345"}`))

	det := NewMCPDetector(mock)
	results := det.DetectEnterprise(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 enterprise config, got %d", len(results))
	}
	if results[0].ConfigContentBase64 != "" {
		t.Error("config without mcpServers must have empty content to avoid leaking secrets")
	}
}

func TestFilterMCPContent_StripsSecrets(t *testing.T) {
	mock := executor.NewMock()
	det := NewMCPDetector(mock)

	input := []byte(`{"mcpServers":{"myserver":{"command":"npx","args":["-y","server"],"env":{"API_KEY":"sk-secret"},"headers":{"Authorization":"Bearer token"}}}}`)

	filtered, ok := det.filterMCPContent("claude_desktop", "/path/config.json", input)
	if !ok {
		t.Fatal("expected filtering to succeed")
	}

	content := string(filtered)
	if strings.Contains(content, "sk-secret") {
		t.Error("filtered content must not contain API key")
	}
	if strings.Contains(content, "Bearer") {
		t.Error("filtered content must not contain auth headers")
	}
	if !strings.Contains(content, "command") || !strings.Contains(content, "npx") {
		t.Error("filtered content should preserve command")
	}
	if !strings.Contains(content, "args") {
		t.Error("filtered content should preserve args")
	}
}

func TestExtractMCPServers_ClaudeCodeProjectScoped(t *testing.T) {
	det := &MCPDetector{}

	// Claude Code ~/.claude.json with project-scoped mcpServers
	content := []byte(`{
		"numStartups": 10,
		"projects": {
			"/Users/test/project-a": {
				"allowedTools": [],
				"mcpServers": {
					"notion": {"url": "https://mcp.notion.com/mcp", "headers": {"secret": "redacted"}}
				}
			},
			"/Users/test/project-b": {
				"allowedTools": [],
				"mcpServers": {
					"linear": {"url": "https://mcp.linear.app/mcp"}
				}
			},
			"/Users/test/project-c": {
				"allowedTools": []
			}
		}
	}`)

	filtered, ok := det.filterMCPContent("claude_code", "/Users/test/.claude.json", content)
	if !ok {
		t.Fatal("expected filtering to succeed")
	}

	// Parse the result to verify structure
	var result map[string]any
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatalf("failed to parse filtered content: %v", err)
	}

	// Should have projects key
	projects, ok := result["projects"].(map[string]any)
	if !ok {
		t.Fatal("expected projects key in filtered output")
	}

	// Should only have projects with mcpServers (project-c should be excluded)
	if len(projects) != 2 {
		t.Errorf("expected 2 projects with mcpServers, got %d", len(projects))
	}

	// Should not have non-MCP fields like numStartups
	if _, ok := result["numStartups"]; ok {
		t.Error("non-MCP field numStartups should be filtered out")
	}

	// Verify server fields are filtered (no headers/secret)
	projA, ok := projects["/Users/test/project-a"].(map[string]any)
	if !ok {
		t.Fatal("expected project-a in output")
	}
	mcpServers, ok := projA["mcpServers"].(map[string]any)
	if !ok {
		t.Fatal("expected mcpServers in project-a")
	}
	notion, ok := mcpServers["notion"].(map[string]any)
	if !ok {
		t.Fatal("expected notion server in project-a")
	}
	if _, ok := notion["headers"]; ok {
		t.Error("headers should be filtered out from server config")
	}
	if notion["url"] != "https://mcp.notion.com/mcp" {
		t.Errorf("expected notion url, got %v", notion["url"])
	}
}

func TestExtractMCPServers_VSCodeFormat(t *testing.T) {
	det := &MCPDetector{}

	content := []byte(`{
		"servers": {
			"my-server": {"command": "npx", "args": ["-y", "server"], "env": {"SECRET": "key"}}
		}
	}`)

	filtered, ok := det.filterMCPContent("vscode", "/Users/test/.vscode/mcp.json", content)
	if !ok {
		t.Fatal("expected filtering to succeed")
	}

	var result map[string]any
	if err := json.Unmarshal(filtered, &result); err != nil {
		t.Fatalf("failed to parse filtered content: %v", err)
	}

	servers, ok := result["servers"].(map[string]any)
	if !ok {
		t.Fatal("expected servers key in filtered output")
	}

	srv, ok := servers["my-server"].(map[string]any)
	if !ok {
		t.Fatal("expected my-server in output")
	}
	if srv["command"] != "npx" {
		t.Errorf("expected command npx, got %v", srv["command"])
	}
	if _, ok := srv["env"]; ok {
		t.Error("env should be filtered out")
	}
}

func TestMCPDetector_DiscoverProjectMCPConfigs(t *testing.T) {
	mock := executor.NewMock()

	// Set up ~/.claude.json with project paths
	claudeJSON := `{
		"projects": {
			"/Users/testuser/project-a": {"allowedTools": []},
			"/Users/testuser/project-b": {"allowedTools": []},
			"/Users/testuser/project-c": {"allowedTools": []}
		}
	}`
	mock.SetFile("/Users/testuser/.claude.json", []byte(claudeJSON))

	// Only project-a and project-b have .mcp.json files
	mock.SetFile("/Users/testuser/project-a/.mcp.json",
		[]byte(`{"mcpServers":{"notion":{"url":"https://mcp.notion.com/mcp"}}}`))
	mock.SetFile("/Users/testuser/project-b/.mcp.json",
		[]byte(`{"mcpServers":{"linear":{"url":"https://mcp.linear.app/mcp"}}}`))

	det := NewMCPDetector(mock)
	results := det.DetectEnterprise(context.Background())

	// Should find: claude.json (global) + 2 project-level .mcp.json
	projectMCPCount := 0
	for _, r := range results {
		if r.ConfigSource == "project_mcp" {
			projectMCPCount++
		}
	}

	if projectMCPCount != 2 {
		t.Errorf("expected 2 project-level MCP configs, got %d", projectMCPCount)
	}

	// Verify project paths
	foundA := false
	foundB := false
	for _, r := range results {
		if r.ConfigPath == "/Users/testuser/project-a/.mcp.json" {
			foundA = true
		}
		if r.ConfigPath == "/Users/testuser/project-b/.mcp.json" {
			foundB = true
		}
	}
	if !foundA {
		t.Error("expected project-a .mcp.json to be found")
	}
	if !foundB {
		t.Error("expected project-b .mcp.json to be found")
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
