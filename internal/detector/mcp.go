package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type mcpConfigSpec struct {
	SourceName string
	ConfigPath string // relative to home; uses ~ prefix
	Vendor     string
}

var mcpConfigDefinitions = []mcpConfigSpec{
	{"claude_desktop", "~/Library/Application Support/Claude/claude_desktop_config.json", "Anthropic"},
	{"claude_code", "~/.claude/settings.json", "Anthropic"},
	{"claude_code", "~/.claude.json", "Anthropic"},
	{"cursor", "~/.cursor/mcp.json", "Cursor"},
	{"windsurf", "~/.codeium/windsurf/mcp_config.json", "Codeium"},
	{"antigravity", "~/.gemini/antigravity/mcp_config.json", "Google"},
	{"zed", "~/.config/zed/settings.json", "Zed"},
	{"open_interpreter", "~/.config/open-interpreter/config.yaml", "OpenSource"},
	{"codex", "~/.codex/config.toml", "OpenAI"},
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
		configPath := expandTilde(spec.ConfigPath, homeDir)

		if !d.exec.FileExists(configPath) {
			continue
		}

		results = append(results, model.MCPConfig{
			ConfigSource: spec.SourceName,
			ConfigPath:   configPath,
			Vendor:       spec.Vendor,
		})
	}

	return results
}

// DetectEnterprise returns enterprise-mode MCP configs with base64 content.
func (d *MCPDetector) DetectEnterprise(_ context.Context) []model.MCPConfigEnterprise {
	homeDir := getHomeDir(d.exec)
	var results []model.MCPConfigEnterprise

	for _, spec := range mcpConfigDefinitions {
		configPath := expandTilde(spec.ConfigPath, homeDir)

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

	return results
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

// extractMCPServers extracts mcpServers/context_servers, keeping only command/args/serverUrl/url.
func (d *MCPDetector) extractMCPServers(raw map[string]json.RawMessage) map[string]any {
	// Try mcpServers
	if servers, ok := raw["mcpServers"]; ok {
		return map[string]any{"mcpServers": filterServerFields(servers)}
	}
	// Try context_servers
	if servers, ok := raw["context_servers"]; ok {
		return map[string]any{"context_servers": filterServerFields(servers)}
	}
	return nil
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
			for i+1 < len(input) && !(input[i] == '*' && input[i+1] == '/') {
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
