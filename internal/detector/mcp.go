package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/tailscale/hujson"

	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

type mcpConfigSpec struct {
	SourceName      string
	ConfigPath      string // macOS/Unix path (~/... expanded)
	WinConfigPath   string // Windows path (%ENVVAR%/... expanded); empty means same as ConfigPath
	LinuxConfigPath string // Linux path (~/... expanded); empty means same as ConfigPath
	Vendor          string
}

var mcpConfigDefinitions = []mcpConfigSpec{
	{"claude_desktop", "~/Library/Application Support/Claude/claude_desktop_config.json", "%APPDATA%/Claude/claude_desktop_config.json", "~/.config/Claude/claude_desktop_config.json", "Anthropic"},
	{"claude_code", "~/.claude/settings.json", "", "", "Anthropic"},
	{"claude_code", "~/.claude.json", "", "", "Anthropic"},
	{"cursor", "~/.cursor/mcp.json", "", "", "Cursor"},
	{"windsurf", "~/.codeium/windsurf/mcp_config.json", "", "", "Codeium"},
	{"antigravity", "~/.gemini/antigravity/mcp_config.json", "", "", "Google"},
	{"zed", "~/.config/zed/settings.json", "", "", "Zed"},
	{"open_interpreter", "~/.config/open-interpreter/config.yaml", "", "", "OpenSource"},
	{"codex", "~/.codex/config.toml", "", "", "OpenAI"},
	// VS Code and VS Code-based editors keep user-level MCP servers in
	// <app-config>/User/mcp.json. These are targeted reads; on macOS the path
	// is under ~/Library, which the discovery walk deliberately never enters.
	{"vscode", "~/Library/Application Support/Code/User/mcp.json", "%APPDATA%/Code/User/mcp.json", "~/.config/Code/User/mcp.json", "Microsoft"},
	{"vscode_insiders", "~/Library/Application Support/Code - Insiders/User/mcp.json", "%APPDATA%/Code - Insiders/User/mcp.json", "~/.config/Code - Insiders/User/mcp.json", "Microsoft"},
	{"cursor_user", "~/Library/Application Support/Cursor/User/mcp.json", "%APPDATA%/Cursor/User/mcp.json", "~/.config/Cursor/User/mcp.json", "Cursor"},
	{"windsurf_user", "~/Library/Application Support/Windsurf/User/mcp.json", "%APPDATA%/Windsurf/User/mcp.json", "~/.config/Windsurf/User/mcp.json", "Codeium"},
	{"vscodium", "~/Library/Application Support/VSCodium/User/mcp.json", "%APPDATA%/VSCodium/User/mcp.json", "~/.config/VSCodium/User/mcp.json", "VSCodium"},
	// OpenCode uses the same ~/.config/opencode layout on every platform, so the
	// Windows and Linux fields stay empty and resolveConfigPath expands
	// ConfigPath against the resolved home. Both spellings are accepted by the
	// tool, so both are listed.
	{"opencode", "~/.config/opencode/opencode.json", "", "", "OpenCode"},
	{"opencode", "~/.config/opencode/opencode.jsonc", "", "", "OpenCode"},
}

// MCPDetector collects MCP configuration files.
type MCPDetector struct {
	exec    executor.Executor
	skipper *tcc.Skipper
}

func NewMCPDetector(exec executor.Executor) *MCPDetector {
	return &MCPDetector{exec: exec}
}

// WithSkipper attaches a TCC skipper so the discovery walk skips
// macOS-protected directories. A nil skipper is a no-op. Returns the detector
// for chaining.
func (d *MCPDetector) WithSkipper(s *tcc.Skipper) *MCPDetector {
	d.skipper = s
	return d
}

// Detect returns the MCP config locations found on the host as community-mode
// MCPConfig structs (path, source, and vendor only). It does not read config
// content — DetectEnterprise does that. The enterprise parameter is unused and
// kept only for call-site compatibility.
func (d *MCPDetector) Detect(_ context.Context, userIdentity string, searchDirs []string, enterprise bool) []model.MCPConfig {
	homeDir := getHomeDir(d.exec)
	var results []model.MCPConfig
	for _, loc := range d.allConfigLocations(homeDir, searchDirs) {
		results = append(results, model.MCPConfig{
			ConfigSource: loc.SourceName,
			ConfigPath:   loc.ConfigPath,
			Vendor:       loc.Vendor,
		})
	}
	return results
}

// DetectEnterprise returns enterprise-mode MCP configs with base64 content.
func (d *MCPDetector) DetectEnterprise(_ context.Context, searchDirs []string) []model.MCPConfigEnterprise {
	homeDir := getHomeDir(d.exec)
	var results []model.MCPConfigEnterprise

	for _, loc := range d.allConfigLocations(homeDir, searchDirs) {
		reader := d.exec
		if loc.SourceName == "codex" {
			reader = reader.GuardedFiles([]string{filepath.Dir(loc.ConfigPath)}, func(path string) string {
				if d.skipper.WithinProtected(path) {
					return "tcc_protected"
				}
				return ""
			}, maxJSONConfigBytes)
		}
		content, err := reader.ReadFile(loc.ConfigPath)
		if err != nil || len(content) == 0 {
			continue
		}

		// Extract only MCP-relevant fields from supported formats.
		// If filtering fails, omit content
		// to avoid leaking secrets like env vars and auth headers.
		var contentBase64 string
		if filtered, ok := d.filterMCPContent(loc.SourceName, loc.ConfigPath, content); ok {
			contentBase64 = base64.StdEncoding.EncodeToString(filtered)
		}

		results = append(results, model.MCPConfigEnterprise{
			ConfigSource:        loc.SourceName,
			ConfigPath:          loc.ConfigPath,
			Vendor:              loc.Vendor,
			ConfigContentBase64: contentBase64,
		})
	}

	return results
}

// discoverProjectMCPConfigs finds .mcp.json files in Claude Code's recorded projects.
func (d *MCPDetector) discoverProjectMCPConfigs() []mcpConfigSpec {
	var specs []mcpConfigSpec
	seen := make(map[string]bool)

	for _, projectPath := range discoverClaudeProjects(d.exec) {
		mcpPath := filepath.Join(projectPath, ".mcp.json")
		if seen[mcpPath] {
			continue
		}
		seen[mcpPath] = true

		if !d.exec.FileExists(mcpPath) {
			continue
		}

		specs = append(specs, mcpConfigSpec{
			SourceName: "project_mcp",
			ConfigPath: mcpPath,
			Vendor:     "Project",
		})
	}

	return specs
}

// resolveConfigPath returns the appropriate config path for the current platform.
func (d *MCPDetector) resolveConfigPath(spec mcpConfigSpec, homeDir string) string {
	if spec.SourceName == "codex" {
		if root := d.exec.Getenv("CODEX_HOME"); filepath.IsAbs(root) {
			return filepath.Join(root, "config.toml")
		}
	}
	if d.exec.GOOS() == model.PlatformWindows && spec.WinConfigPath != "" {
		return resolveEnvPath(d.exec, spec.WinConfigPath)
	}
	if d.exec.GOOS() != model.PlatformDarwin && spec.LinuxConfigPath != "" {
		return expandTilde(spec.LinuxConfigPath, homeDir)
	}
	return expandTilde(spec.ConfigPath, homeDir)
}

// filterMCPContent extracts MCP-relevant fields from a config file.
// Returns the filtered content and true on success, or nil and false if
// filtering failed (to avoid leaking secrets from raw fallback).
func (d *MCPDetector) filterMCPContent(sourceName, configPath string, content []byte) ([]byte, bool) {
	if sourceName == "codex" && strings.HasSuffix(configPath, ".toml") {
		var config struct {
			Servers map[string]map[string]any `toml:"mcp_servers"`
		}
		if toml.Unmarshal(content, &config) != nil || config.Servers == nil {
			return nil, false
		}
		raw, err := json.Marshal(config.Servers)
		if err != nil {
			return nil, false
		}
		filtered := filterServerFields(raw)
		if filtered == nil {
			return nil, false
		}
		out, err := toml.Marshal(map[string]any{"mcp_servers": filtered})
		return out, err == nil
	}
	if !strings.HasSuffix(configPath, ".json") && !strings.HasSuffix(configPath, ".jsonc") {
		return nil, false // Non-JSON formats cannot be safely filtered
	}

	jsonInput := content

	// Strip JSONC comments for Zed
	if sourceName == "zed" {
		jsonInput = stripJSONCComments(jsonInput)
	}

	// OpenCode accepts JSONC under either spelling, and its own documented
	// examples carry trailing commas as well as comments. stripJSONCComments
	// removes the comments but leaves the commas, which json.Unmarshal then
	// rejects — dropping the content and losing the servers. hujson handles
	// both, and is already this repo's front door for real-world JSONC.
	if isOpenCodeConfigPath(configPath) {
		standard, err := hujson.Standardize(jsonInput)
		if err != nil {
			return nil, false
		}
		jsonInput = standard
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(jsonInput, &raw); err != nil {
		return nil, false // Can't parse; don't return raw content
	}

	filtered := d.extractMCPServers(raw)
	if filtered == nil {
		return nil, false // No MCP servers found
	}

	out, err := json.Marshal(filtered)
	if err != nil {
		return nil, false
	}
	return out, true
}

// isOpenCodeConfigPath reports whether a path is an OpenCode config, in either
// spelling. It tests the basename rather than the whole path on purpose: a
// substring test would relabel an ordinary .mcp.json as OpenCode merely because
// some ancestor directory is named "opencode" — a checkout of the tool itself,
// say — while claiming nothing the basename does not already name.
func isOpenCodeConfigPath(configPath string) bool {
	switch strings.ToLower(filepath.Base(configPath)) {
	case "opencode.json", "opencode.jsonc":
		return true
	}
	return false
}

// extractMCPServers extracts mcpServers/context_servers/servers/mcp, keeping only command/args/serverUrl/url.
// Also handles Claude Code's project-scoped mcpServers nested under projects → <path> → mcpServers.
func (d *MCPDetector) extractMCPServers(raw map[string]json.RawMessage) map[string]any {
	result := make(map[string]any)
	found := false

	// Try mcpServers (Cursor, Claude Desktop)
	if servers, ok := raw["mcpServers"]; ok {
		result["mcpServers"] = filterServerFields(servers)
		found = true
	}
	// Try context_servers (Zed)
	if servers, ok := raw["context_servers"]; ok {
		result["context_servers"] = filterServerFields(servers)
		found = true
	}
	// Try servers (VS Code mcp.json)
	if servers, ok := raw["servers"]; ok {
		result["servers"] = filterServerFields(servers)
		found = true
	}
	// Try mcp (OpenCode), entries tagged local or remote. The vendor's own key
	// is preserved on the wire: this pipeline filters fields, it never rewrites
	// another vendor's schema into mcpServers.
	//
	// Unlike the keys above, "mcp" is an ordinary enough word to show up as a
	// scalar flag in a config that keeps its real servers elsewhere. Emitting a
	// null for it would make the backend reject the whole document and drop the
	// valid mcpServers sitting beside it, so a value that isn't a map of servers
	// is skipped rather than emitted empty.
	if servers, ok := raw["mcp"]; ok {
		if filtered := filterServerFields(servers); filtered != nil {
			result["mcp"] = filtered
			found = true
		}
	}
	// Try project-scoped mcpServers (Claude Code ~/.claude.json)
	// Structure: { "projects": { "<path>": { "mcpServers": { ... } } } }
	if projectsRaw, ok := raw["projects"]; ok {
		filteredProjects := filterProjectScopedMCPServers(projectsRaw)
		if filteredProjects != nil {
			result["projects"] = filteredProjects
			found = true
		}
	}

	if !found {
		return nil
	}
	return result
}

// filterProjectScopedMCPServers extracts mcpServers from each project in the projects map.
// Returns only projects that have mcpServers, with server fields filtered.
func filterProjectScopedMCPServers(projectsRaw json.RawMessage) map[string]any {
	var projects map[string]map[string]json.RawMessage
	if err := json.Unmarshal(projectsRaw, &projects); err != nil {
		return nil
	}

	filtered := make(map[string]any)
	for path, projectConfig := range projects {
		serversRaw, ok := projectConfig["mcpServers"]
		if !ok {
			continue
		}
		serverFields := filterServerFields(serversRaw)
		if len(serverFields) > 0 {
			filtered[path] = map[string]any{"mcpServers": serverFields}
		}
	}

	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

// filterServerFields keeps only command, args, serverUrl, url from each server
// entry. env and headers are dropped outright since those are the fields
// vendors document for credentials. But command/args/url/serverUrl are
// real-world credential locations too (a bearer token or API key in a query
// string, an --api-key flag baked into args), so the kept values still pass
// through redact.Value before being uploaded.
func filterServerFields(serversRaw json.RawMessage) map[string]any {
	var servers map[string]map[string]any
	if err := json.Unmarshal(serversRaw, &servers); err != nil {
		return nil
	}

	result := make(map[string]any)
	allowedKeys := map[string]bool{"command": true, "args": true, "serverUrl": true, "url": true}

	for name, serverConfig := range servers {
		filtered := make(map[string]any)
		for k, v := range serverConfig {
			if allowedKeys[k] {
				filtered[k] = redact.Value(v)
			}
		}
		result[name] = filtered
	}
	return result
}

// stripJSONCComments removes // and /* */ comments from JSONC content,
// respecting quoted strings (won't strip // inside "https://...").
func stripJSONCComments(input []byte) []byte {
	var out []byte
	i := 0
	for i < len(input) {
		// Skip over strings — don't modify content inside quotes
		if input[i] == '"' {
			out = append(out, input[i])
			i++
			for i < len(input) {
				out = append(out, input[i])
				if input[i] == '\\' && i+1 < len(input) {
					i++
					out = append(out, input[i])
				} else if input[i] == '"' {
					break
				}
				i++
			}
			i++
			continue
		}
		// Block comment
		if i+1 < len(input) && input[i] == '/' && input[i+1] == '*' {
			i += 2
			for i+1 < len(input) && (input[i] != '*' || input[i+1] != '/') {
				i++
			}
			i += 2 // skip */
			continue
		}
		// Line comment
		if i+1 < len(input) && input[i] == '/' && input[i+1] == '/' {
			i += 2
			for i < len(input) && input[i] != '\n' {
				i++
			}
			continue
		}
		out = append(out, input[i])
		i++
	}
	return out
}
