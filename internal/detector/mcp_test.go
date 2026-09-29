package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestCodexMCPContent(t *testing.T) {
	d := &MCPDetector{}
	content := []byte("model = 'example'\n[mcp_servers.docs]\nurl = 'https://docs.example.com/mcp'\nenabled = false\nhttp_headers = { Authorization = 'private-value' }\n[mcp_servers.local]\ncommand = 'example-server'\nargs = ['--workspace', '/work']\nenv = { API_KEY = 'private-value' }\n[plugins.'tools@catalog'.mcp_servers.other]\nenabled = true\n")
	filtered, ok := d.filterMCPContent("codex", "/home/test/.codex/config.toml", content)
	if !ok || strings.Contains(string(filtered), "private-value") || strings.Contains(string(filtered), "plugins") || strings.Contains(string(filtered), "model") {
		t.Fatalf("unexpected filtered content: %s", filtered)
	}
	if !strings.Contains(string(filtered), "mcp_servers.docs") || !strings.Contains(string(filtered), "mcp_servers.local") {
		t.Fatalf("missing server: %s", filtered)
	}
	for _, malformed := range []string{"[", "[mcp_servers]\ndocs = 42", "model='example'"} {
		if _, ok := d.filterMCPContent("codex", "/home/test/.codex/config.toml", []byte(malformed)); ok {
			t.Fatalf("accepted invalid or unrelated config: %s", malformed)
		}
	}
	m := executor.NewMock()
	m.SetEnv("CODEX_HOME", filepath.Join(testHome, "custom-codex"))
	d.exec = m
	if got := d.resolveConfigPath(mcpConfigSpec{SourceName: "codex"}, testHome); got != filepath.Join(testHome, "custom-codex/config.toml") {
		t.Fatalf("custom root = %s", got)
	}
}

func TestDiscoverClaudeProjectsPreservesProjectKeys(t *testing.T) {
	for _, tc := range []struct {
		name, contents string
		want           []string
	}{
		{"projects only", `{"projects":{"/Users/testuser/repo":{}}}`, []string{"/Users/testuser/repo"}},
		{"invalid usage is independent", `{"projects":{"/Users/testuser/repo":{}},"skillUsage":42}`, []string{"/Users/testuser/repo"}},
		{"paths are not normalized", `{"projects":{"/Users/testuser/project space/":null,"relative-project":{}}}`, []string{"/Users/testuser/project space/", "relative-project"}},
		{"missing projects", `{"skillUsage":{}}`, nil},
		{"null projects", `{"projects":null}`, nil},
		{"invalid projects", `{"projects":42}`, nil},
		{"malformed file", `{`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetFile(filepath.Join(testHome, ".claude.json"), []byte(tc.contents))
			got := discoverClaudeProjects(mock)
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("projects = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMCPDetector_FindsConfigs(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/Users/testuser/Library/Application Support/Claude/claude_desktop_config.json", []byte(`{"mcpServers":{}}`))
	mock.SetFile("/Users/testuser/.cursor/mcp.json", []byte(`{"mcpServers":{}}`))

	det := NewMCPDetector(mock)
	results := det.Detect(context.Background(), "testuser", nil, false)

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
	results := det.Detect(context.Background(), "testuser", nil, false)

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
	results := det.DetectEnterprise(context.Background(), nil)

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
	results := det.DetectEnterprise(context.Background(), nil)

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
	results := det.DetectEnterprise(context.Background(), nil)

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
	results := det.DetectEnterprise(context.Background(), nil)

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
	results := det.DetectEnterprise(context.Background(), nil)

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
	results := det.Detect(context.Background(), "testuser", nil, false)

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

// --------------------------------------------------------------------------
// OpenCode
//
// OpenCode keeps its MCP servers under a top-level "mcp" map, in either
// opencode.json or opencode.jsonc, and its own documented examples carry both
// comments and trailing commas.
// --------------------------------------------------------------------------

// openCodeGoldenConfig and openCodeGoldenEmitted are the wire contract, byte
// for byte. The backend parser is built in another repo against these same two
// literals, and no unit test on either side can catch a discrepancy between
// them — so they are copied verbatim rather than constructed, and a change to
// either is a change to the contract.
const openCodeGoldenConfig = `{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "widgets-local": {
      "type": "local",
      "command": ["npx", "-y", "widgets-mcp-server@1.2.3"],
      "cwd": "packages/widgets",
      "environment": { "WIDGETS_TOKEN": "s3cr3t" },
      "enabled": true,
      "timeout": 5000
    },
    "widgets-remote": {
      "type": "remote",
      "url": "https://mcp.example-org.test/mcp",
      "headers": { "Authorization": "Bearer s3cr3t" },
      "enabled": false
    }
  }
}`

const openCodeGoldenEmitted = `{"mcp":{"widgets-local":{"command":["npx","-y","widgets-mcp-server@1.2.3"]},"widgets-remote":{"url":"https://mcp.example-org.test/mcp"}}}`

const openCodeGlobalDir = "/Users/testuser/.config/opencode/"

// TestMCPDetector_OpenCode_KnownPaths: both spellings of the global config are
// known paths, reported under source "opencode" and vendor "OpenCode", and a
// home holding both yields both — one entry each, deduped by path.
func TestMCPDetector_OpenCode_KnownPaths(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  []string
	}{
		{"json", []string{"opencode.json"}, []string{openCodeGlobalDir + "opencode.json"}},
		{"jsonc", []string{"opencode.jsonc"}, []string{openCodeGlobalDir + "opencode.jsonc"}},
		{
			"both spellings",
			[]string{"opencode.json", "opencode.jsonc"},
			[]string{openCodeGlobalDir + "opencode.json", openCodeGlobalDir + "opencode.jsonc"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			for _, f := range tc.files {
				mock.SetFile(openCodeGlobalDir+f, []byte(openCodeGoldenConfig))
			}

			results := NewMCPDetector(mock).Detect(context.Background(), "testuser", nil, false)

			if len(results) != len(tc.want) {
				t.Fatalf("expected %d configs, got %d: %+v", len(tc.want), len(results), results)
			}
			for i, want := range tc.want {
				if results[i].ConfigPath != want {
					t.Errorf("config %d: path = %q, want %q", i, results[i].ConfigPath, want)
				}
				if results[i].ConfigSource != "opencode" {
					t.Errorf("config %d: source = %q, want opencode", i, results[i].ConfigSource)
				}
				if results[i].Vendor != "OpenCode" {
					t.Errorf("config %d: vendor = %q, want OpenCode", i, results[i].Vendor)
				}
			}
		})
	}
}

// TestMCPDetector_OpenCode_GoldenPayload: the golden config on disk emits the
// golden string byte for byte. encoding/json sorts map keys, so this is a
// stable literal comparison rather than a structural one — which is what lets
// the backend assert on the same string.
func TestMCPDetector_OpenCode_GoldenPayload(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile(openCodeGlobalDir+"opencode.json", []byte(openCodeGoldenConfig))

	results := NewMCPDetector(mock).DetectEnterprise(context.Background(), nil)

	if len(results) != 1 {
		t.Fatalf("expected 1 enterprise config, got %d", len(results))
	}
	decoded, err := base64.StdEncoding.DecodeString(results[0].ConfigContentBase64)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	if got := string(decoded); got != openCodeGoldenEmitted {
		t.Errorf("emitted content mismatch\n got: %s\nwant: %s", got, openCodeGoldenEmitted)
	}
}

// TestFilterMCPContent_OpenCode_DropsSecretBearingFields: environment, headers
// and oauth all carry live credentials and are outside the allowlist, so none
// of them — nor their values — reach the wire.
func TestFilterMCPContent_OpenCode_DropsSecretBearingFields(t *testing.T) {
	det := &MCPDetector{}

	input := []byte(`{
	  "mcp": {
	    "local": {
	      "type": "local",
	      "command": ["npx", "-y", "widgets-mcp-server"],
	      "environment": {"WIDGETS_TOKEN": "env-s3cr3t"}
	    },
	    "remote": {
	      "type": "remote",
	      "url": "https://mcp.example-org.test/mcp",
	      "headers": {"Authorization": "Bearer hdr-s3cr3t"},
	      "oauth": {"clientSecret": "oauth-s3cr3t"}
	    }
	  }
	}`)

	filtered, ok := det.filterMCPContent("opencode", openCodeGlobalDir+"opencode.json", input)
	if !ok {
		t.Fatal("expected filtering to succeed")
	}

	content := string(filtered)
	for _, forbidden := range []string{
		"environment", "headers", "oauth",
		"env-s3cr3t", "hdr-s3cr3t", "oauth-s3cr3t",
		"WIDGETS_TOKEN", "Authorization", "clientSecret",
	} {
		if strings.Contains(content, forbidden) {
			t.Errorf("filtered content must not contain %q: %s", forbidden, content)
		}
	}
	if !strings.Contains(content, `"command":["npx","-y","widgets-mcp-server"]`) {
		t.Errorf("filtered content should preserve the argv array: %s", content)
	}
	if !strings.Contains(content, `"url":"https://mcp.example-org.test/mcp"`) {
		t.Errorf("filtered content should preserve the remote url: %s", content)
	}
}

// TestFilterMCPContent_OpenCode_JSONC: comments and trailing commas both parse.
// The trailing-comma case is the one stripJSONCComments cannot handle — it
// removes the comment and leaves the comma, and json.Unmarshal then rejects the
// document — which is why OpenCode is normalized with hujson instead.
func TestFilterMCPContent_OpenCode_JSONC(t *testing.T) {
	// Copied from the vendor's own MCP documentation, which prints
	// `"enabled": true,` immediately before a closing brace.
	const trailingComma = `{
	  "mcp": {
	    "widgets": {
	      "type": "local",
	      "command": ["npx", "-y", "widgets-mcp-server@1.2.3"],
	      "enabled": true,
	    },
	  },
	}`

	const comments = `{
	  // the servers this project may talk to
	  "mcp": {
	    /* launched over stdio */
	    "widgets": {
	      "type": "local",
	      "command": ["npx", "-y", "widgets-mcp-server@1.2.3"]
	    }
	  }
	}`

	const both = `{
	  // the servers this project may talk to
	  "mcp": {
	    /* launched over stdio */
	    "widgets": {
	      "type": "local",
	      "command": ["npx", "-y", "widgets-mcp-server@1.2.3"],
	      "enabled": true,
	    },
	  },
	}`

	const wantEmitted = `{"mcp":{"widgets":{"command":["npx","-y","widgets-mcp-server@1.2.3"]}}}`

	cases := []struct {
		name  string
		path  string
		input string
	}{
		{"trailing comma", openCodeGlobalDir + "opencode.json", trailingComma},
		{"comments", openCodeGlobalDir + "opencode.json", comments},
		{"comments and trailing commas", openCodeGlobalDir + "opencode.json", both},
		{"jsonc spelling", openCodeGlobalDir + "opencode.jsonc", both},
		{"project-level, discovered source", "/Users/testuser/proj/opencode.jsonc", both},
	}

	det := &MCPDetector{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A project-level config arrives labelled discovered_mcp, so the
			// JSONC handling cannot key off the source name.
			source := "opencode"
			if strings.Contains(tc.path, "/proj/") {
				source = "discovered_mcp"
			}
			filtered, ok := det.filterMCPContent(source, tc.path, []byte(tc.input))
			if !ok {
				t.Fatalf("expected filtering to succeed for %s", tc.path)
			}
			if got := string(filtered); got != wantEmitted {
				t.Errorf("emitted content mismatch\n got: %s\nwant: %s", got, wantEmitted)
			}
		})
	}
}

// TestFilterMCPContent_OpenCode_FailsClosed: a config with no mcp key, and one
// that is not JSON at all, both emit nothing rather than falling back to raw
// content. The location is still reported (I8) — that is DetectEnterprise's
// job, asserted here through the full detector.
func TestFilterMCPContent_OpenCode_FailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"no mcp key", `{"theme":"dark","apiKey":"sk-secret-12345"}`},
		{"malformed json", `{"mcp": {"widgets": {"command": ["npx"` + "\n"},
		{"unterminated block comment", `{/* "mcp": {} }`},
		{"not an object", `["mcp"]`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			det := &MCPDetector{}
			filtered, ok := det.filterMCPContent("opencode", openCodeGlobalDir+"opencode.json", []byte(tc.content))
			if ok {
				t.Errorf("expected filtering to fail, got ok with %q", filtered)
			}
			if filtered != nil {
				t.Errorf("expected nil content on failure, got %q", filtered)
			}

			// I8: the location is still reported, with empty content.
			mock := executor.NewMock()
			mock.SetFile(openCodeGlobalDir+"opencode.json", []byte(tc.content))
			results := NewMCPDetector(mock).DetectEnterprise(context.Background(), nil)
			if len(results) != 1 {
				t.Fatalf("expected the location to still be reported, got %d configs", len(results))
			}
			if results[0].ConfigContentBase64 != "" {
				t.Errorf("expected empty content, got %q", results[0].ConfigContentBase64)
			}
			if results[0].ConfigSource != "opencode" || results[0].Vendor != "OpenCode" {
				t.Errorf("expected opencode/OpenCode, got %s/%s", results[0].ConfigSource, results[0].Vendor)
			}
		})
	}
}

// TestFilterMCPContent_ScalarMCPKeyDoesNotEvictSiblings: "mcp" is an ordinary
// enough word to appear as a scalar flag in a config whose real servers live
// under mcpServers. Reading the key is new, so without a guard it would emit
// "mcp":null for those files, the backend would reject the whole document, and
// the valid mcpServers beside it would be lost — a regression reaching every
// walked .mcp.json, not just OpenCode's own files.
func TestFilterMCPContent_ScalarMCPKeyDoesNotEvictSiblings(t *testing.T) {
	const siblings = `{"mcpServers":{"fs":{"command":"npx","args":["-y","s"]}},"mcp":%s}`
	const wantSiblings = `{"mcpServers":{"fs":{"args":["-y","s"],"command":"npx"}}}`

	for _, mcpValue := range []string{`true`, `"enabled"`, `["a"]`, `42`} {
		t.Run("keeps siblings when mcp is "+mcpValue, func(t *testing.T) {
			det := &MCPDetector{}
			content := fmt.Sprintf(siblings, mcpValue)
			filtered, ok := det.filterMCPContent("discovered_mcp", "/Users/testuser/proj/.mcp.json", []byte(content))
			if !ok {
				t.Fatalf("expected the valid mcpServers to still be emitted, got ok=false")
			}
			if string(filtered) != wantSiblings {
				t.Errorf("emitted %s, want %s", filtered, wantSiblings)
			}
			if strings.Contains(string(filtered), `"mcp"`) {
				t.Errorf("unusable mcp key must be dropped, not emitted empty: %s", filtered)
			}
		})

		t.Run("fails closed when only mcp is "+mcpValue, func(t *testing.T) {
			det := &MCPDetector{}
			content := fmt.Sprintf(`{"mcp":%s}`, mcpValue)
			filtered, ok := det.filterMCPContent("opencode", openCodeGlobalDir+"opencode.json", []byte(content))
			if ok || filtered != nil {
				t.Errorf("expected no content, got ok=%v %q", ok, filtered)
			}
		})
	}

	// An explicit null is the one non-map that json.Unmarshal accepts into a map
	// type, so it decodes to an empty server set rather than a filter failure and
	// is emitted as an empty object. That is not the eviction bug — an empty
	// object parses backend-side and drops nothing — and it is exactly what a
	// null under any of the other three keys already does, so the guard leaves
	// the existing convention alone rather than making "mcp" the odd one out.
	t.Run("null decodes to an empty set, like every other key", func(t *testing.T) {
		// Asserted byte-exact, not just "mcpServers survived": the point of this
		// subtest is that the empty object IS emitted. A looser check would keep
		// passing if "mcp" started being dropped here too, silently turning the
		// documented convention into the opposite behaviour.
		const wantNull = `{"mcp":{},"mcpServers":{"fs":{"args":["-y","s"],"command":"npx"}}}`

		det := &MCPDetector{}
		filtered, ok := det.filterMCPContent("discovered_mcp", "/Users/testuser/proj/.mcp.json", fmt.Appendf(nil, siblings, `null`))
		if !ok {
			t.Fatalf("expected content, got ok=false")
		}
		if string(filtered) != wantNull {
			t.Errorf("emitted %s, want %s", filtered, wantNull)
		}

		// Same shape under mcpServers, proving this is the pre-existing
		// convention and not something the mcp branch introduced.
		legacy, ok := det.filterMCPContent("cursor", "/Users/testuser/.cursor/mcp.json", []byte(`{"mcpServers":null}`))
		if !ok || string(legacy) != `{"mcpServers":{}}` {
			t.Errorf("mcpServers null convention changed: ok=%v %s", ok, legacy)
		}
	})

	// Control: a well-formed mcp map is still emitted, so the guard rejects only
	// what it cannot filter.
	det := &MCPDetector{}
	filtered, ok := det.filterMCPContent("opencode", openCodeGlobalDir+"opencode.json", []byte(openCodeGoldenConfig))
	if !ok || string(filtered) != openCodeGoldenEmitted {
		t.Errorf("valid mcp map regressed: ok=%v %s", ok, filtered)
	}
}

// TestMCPDetector_OpenCode_ResolvesUnderResolvedHome: OpenCode uses the same
// ~/.config/opencode layout on every platform, so both paths are expanded
// against the home the detector was given — never against the process
// environment, which on Windows belongs to the service account.
func TestMCPDetector_OpenCode_ResolvesUnderResolvedHome(t *testing.T) {
	cases := []struct {
		goos string
		home string
	}{
		{"windows", `C:\Users\testuser`},
		{"linux", "/home/dev"},
		{"darwin", "/Users/testuser"},
	}

	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetGOOS(tc.goos)
			mock.SetHomeDir(tc.home)
			// A roaming profile belonging to somebody else entirely: no
			// OpenCode path may be resolved through it.
			mock.SetEnv("APPDATA", `C:\Users\svc-account\AppData\Roaming`)

			for _, spelling := range []string{"opencode.json", "opencode.jsonc"} {
				path := filepath.Join(tc.home, ".config", "opencode", spelling)
				mock.SetFile(path, []byte(openCodeGoldenConfig))
			}

			results := NewMCPDetector(mock).Detect(context.Background(), "testuser", nil, false)

			if len(results) != 2 {
				t.Fatalf("expected 2 configs, got %d: %+v", len(results), results)
			}
			for _, r := range results {
				if !strings.HasPrefix(r.ConfigPath, tc.home) {
					t.Errorf("path %q is not under the resolved home %q", r.ConfigPath, tc.home)
				}
				if strings.Contains(r.ConfigPath, "svc-account") {
					t.Errorf("path %q was resolved through the process environment", r.ConfigPath)
				}
				if r.ConfigSource != "opencode" || r.Vendor != "OpenCode" {
					t.Errorf("expected opencode/OpenCode, got %s/%s", r.ConfigSource, r.Vendor)
				}
			}
		})
	}
}

// TestFilterMCPContent_NonOpenCodeUnchanged: adding OpenCode must not move any
// other source onto a different code path. Zed still goes through
// stripJSONCComments, the plain-JSON sources still go straight to the parser,
// and a non-JSON config still emits nothing.
func TestFilterMCPContent_NonOpenCodeUnchanged(t *testing.T) {
	cases := []struct {
		name    string
		source  string
		path    string
		content string
		wantOK  bool
		want    string
	}{
		{
			"cursor", "cursor", "/Users/testuser/.cursor/mcp.json",
			`{"mcpServers":{"notion":{"url":"https://mcp.notion.com/mcp","headers":{"k":"v"}}}}`,
			true, `{"mcpServers":{"notion":{"url":"https://mcp.notion.com/mcp"}}}`,
		},
		{
			"claude_desktop", "claude_desktop", "/Users/testuser/Library/Application Support/Claude/claude_desktop_config.json",
			`{"mcpServers":{"fs":{"command":"npx","args":["-y","server"],"env":{"K":"V"}}}}`,
			true, `{"mcpServers":{"fs":{"args":["-y","server"],"command":"npx"}}}`,
		},
		{
			"zed keeps the comment stripper", "zed", "/Users/testuser/.config/zed/settings.json",
			"{\n  // servers\n  \"context_servers\":{\"fs\":{\"command\":\"npx\"}}\n}",
			true, `{"context_servers":{"fs":{"command":"npx"}}}`,
		},
		{
			"vscode", "vscode", "/Users/testuser/.vscode/mcp.json",
			`{"servers":{"fs":{"command":"npx","env":{"K":"V"}}}}`,
			true, `{"servers":{"fs":{"command":"npx"}}}`,
		},
		{
			"codex toml", "codex", "/Users/testuser/.codex/config.toml",
			"[mcp_servers.fs]\ncommand = \"npx\"\n",
			true, "[mcp_servers]\n[mcp_servers.fs]\ncommand = 'npx'\n",
		},
	}

	det := &MCPDetector{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filtered, ok := det.filterMCPContent(tc.source, tc.path, []byte(tc.content))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (content %q)", ok, tc.wantOK, filtered)
			}
			if got := string(filtered); tc.wantOK && got != tc.want {
				t.Errorf("emitted content mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestFilterServerFields_RedactsSecretsInKeptFields: command/args/url/serverUrl
// are the fields we keep (env/headers are dropped outright), but real MCP
// configs sometimes carry a bearer token or API key inside those kept fields
// too — e.g. a query-string token on the server URL, or an --api-key flag in
// args. Those values must still be redacted before upload, not passed through
// verbatim just because the field name isn't "env" or "headers".
func TestFilterServerFields_RedactsSecretsInKeptFields(t *testing.T) {
	det := &MCPDetector{}
	content := `{"mcpServers":{"pipeboard":{
		"url":"https://meta-ads.mcp.pipeboard.co/?token=abcdEFGH12345678opaqueTokenValue",
		"command":"npx",
		"args":["-y","server","--api-key=abcdEFGH12345678opaqueTokenValue"]
	}}}`

	filtered, ok := det.filterMCPContent("cursor", "/Users/testuser/.cursor/mcp.json", []byte(content))
	if !ok {
		t.Fatalf("expected filtering to succeed")
	}
	if strings.Contains(string(filtered), "abcdEFGH12345678opaqueTokenValue") {
		t.Fatalf("secret leaked into filtered output: %s", filtered)
	}
	if !strings.Contains(string(filtered), "token=") || !strings.Contains(string(filtered), "REDACTED") {
		t.Errorf("expected the url token to be replaced with a redaction placeholder, got: %s", filtered)
	}
}

// TestMCPConfigDefinitions_OpenCodeIsPlatformAgnostic: the two OpenCode
// definitions leave the Windows and Linux fields empty on purpose, so every
// consumer that walks mcpConfigDefinitions — including the known-user-config
// resolver the credential inventory reads — expands them against the home it
// was given rather than a per-platform override.
func TestMCPConfigDefinitions_OpenCodeIsPlatformAgnostic(t *testing.T) {
	found := make(map[string]bool)
	for _, spec := range mcpConfigDefinitions {
		if spec.SourceName != "opencode" {
			continue
		}
		found[spec.ConfigPath] = true
		if spec.Vendor != "OpenCode" {
			t.Errorf("%s: vendor = %q, want OpenCode", spec.ConfigPath, spec.Vendor)
		}
		if spec.WinConfigPath != "" || spec.LinuxConfigPath != "" {
			t.Errorf("%s: expected empty per-platform overrides, got win=%q linux=%q",
				spec.ConfigPath, spec.WinConfigPath, spec.LinuxConfigPath)
		}
	}
	for _, want := range []string{
		"~/.config/opencode/opencode.json",
		"~/.config/opencode/opencode.jsonc",
	} {
		if !found[want] {
			t.Errorf("mcpConfigDefinitions is missing %s", want)
		}
	}
}
