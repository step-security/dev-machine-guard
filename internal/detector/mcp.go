package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type mcpConfigSpec struct {
	SourceName    string
	ConfigPath    string // macOS/Unix path (~/... expanded)
	WinConfigPath string // Windows path (%ENVVAR%/... expanded); empty means same as ConfigPath
	Vendor        string
}

var mcpConfigDefinitions = []mcpConfigSpec{
	{"claude_desktop", "~/Library/Application Support/Claude/claude_desktop_config.json", "%APPDATA%/Claude/claude_desktop_config.json", "Anthropic"},
	{"claude_code", "~/.claude/settings.json", "", "Anthropic"},
	{"claude_code", "~/.claude.json", "", "Anthropic"},
	{"cursor", "~/.cursor/mcp.json", "", "Cursor"},
	{"windsurf", "~/.codeium/windsurf/mcp_config.json", "", "Codeium"},
	{"antigravity", "~/.gemini/antigravity/mcp_config.json", "", "Google"},
	{"zed", "~/.config/zed/settings.json", "", "Zed"},
	{"open_interpreter", "~/.config/open-interpreter/config.yaml", "", "OpenSource"},
	{"codex", "~/.codex/config.toml", "", "OpenAI"},
}

// MCPDetector collects MCP configuration files.
type MCPDetector struct {
	exec executor.Executor
}

func NewMCPDetector(exec executor.Executor) *MCPDetector {
	return &MCPDetector{exec: exec}
}

// Detect finds MCP configs. If enterprise is true, includes base64-encoded content.
// Returns community-mode MCPConfig structs (enterprise mode uses MCPConfigEnterprise separately).
func (d *MCPDetector) Detect(_ context.Context, userIdentity string, enterprise bool) []model.MCPConfig {
	homeDir := getHomeDir(d.exec)
	var results []model.MCPConfig

	for _, spec := range mcpConfigDefinitions {
		configPath := d.resolveConfigPath(spec, homeDir)

		if !d.exec.FileExists(configPath) {
			continue
		}

		results = append(results, model.MCPConfig{
			ConfigSource: spec.SourceName,
			ConfigPath:   configPath,
			Vendor:       spec.Vendor,
		})
	}

	// Discover project-level .mcp.json files from known project paths
	for _, projectMCP := range d.discoverProjectMCPConfigs(homeDir) {
		results = append(results, model.MCPConfig{
			ConfigSource: projectMCP.SourceName,
			ConfigPath:   projectMCP.ConfigPath,
			Vendor:       projectMCP.Vendor,
		})
	}

	return results
}

// DetectEnterprise returns enterprise-mode MCP configs with base64 content.
func (d *MCPDetector) DetectEnterprise(_ context.Context) []model.MCPConfigEnterprise {
	homeDir := getHomeDir(d.exec)
	var results []model.MCPConfigEnterprise

	for _, spec := range mcpConfigDefinitions {
		configPath := d.resolveConfigPath(spec, homeDir)

		if !d.exec.FileExists(configPath) {
			continue
		}

		content, err := d.exec.ReadFile(configPath)
		if err != nil || len(content) == 0 {
			continue
		}

		// Filter JSON configs to extract only MCP-relevant fields
		filteredContent := d.filterMCPContent(spec.SourceName, configPath, content)
		contentBase64 := base64.StdEncoding.EncodeToString(filteredContent)

		results = append(results, model.MCPConfigEnterprise{
			ConfigSource:        spec.SourceName,
			ConfigPath:          configPath,
			Vendor:              spec.Vendor,
			ConfigContentBase64: contentBase64,
		})
	}

	// Discover project-level .mcp.json files from known project paths
	for _, projectMCP := range d.discoverProjectMCPConfigs(homeDir) {
		content, err := d.exec.ReadFile(projectMCP.ConfigPath)
		if err != nil || len(content) == 0 {
			continue
		}

		filteredContent := d.filterMCPContent(projectMCP.SourceName, projectMCP.ConfigPath, content)
		contentBase64 := base64.StdEncoding.EncodeToString(filteredContent)

		results = append(results, model.MCPConfigEnterprise{
			ConfigSource:        projectMCP.SourceName,
			ConfigPath:          projectMCP.ConfigPath,
			Vendor:              projectMCP.Vendor,
			ConfigContentBase64: contentBase64,
		})
	}

	return results
}

// discoverProjectMCPConfigs finds project-level .mcp.json files by reading project paths
// from ~/.claude.json's "projects" section.
func (d *MCPDetector) discoverProjectMCPConfigs(homeDir string) []mcpConfigSpec {
	claudeJSONPath := expandTilde("~/.claude.json", homeDir)

	content, err := d.exec.ReadFile(claudeJSONPath)
	if err != nil || len(content) == 0 {
		return nil
	}

	var parsed struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(content, &parsed); err != nil || len(parsed.Projects) == 0 {
		return nil
	}

	var specs []mcpConfigSpec
	seen := make(map[string]bool)

	for projectPath := range parsed.Projects {
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
	if d.exec.GOOS() == "windows" && spec.WinConfigPath != "" {
		return resolveEnvPath(d.exec, spec.WinConfigPath)
	}
	return expandTilde(spec.ConfigPath, homeDir)
}

// filterMCPContent extracts MCP-relevant fields from a config file.
func (d *MCPDetector) filterMCPContent(sourceName, configPath string, content []byte) []byte {
	if !strings.HasSuffix(configPath, ".json") {
		return content // Return as-is for TOML/YAML
	}

	jsonInput := content

	// Strip JSONC comments for Zed
	if sourceName == "zed" {
		jsonInput = stripJSONCComments(jsonInput)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(jsonInput, &raw); err != nil {
		return content // Can't parse, return as-is
	}

	filtered := d.extractMCPServers(raw)
	if filtered == nil {
		return content
	}

	out, err := json.Marshal(filtered)
	if err != nil {
		return content
	}
	return out
}

// extractMCPServers extracts mcpServers/context_servers/servers, keeping only command/args/serverUrl/url.
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

// filterServerFields keeps only command, args, serverUrl, url from each server entry.
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
				filtered[k] = v
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
