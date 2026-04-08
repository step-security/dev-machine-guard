package detector

import (
	"context"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type agentSpec struct {
	Name           string
	Vendor         string
	DetectionPaths []string // relative to home dir
	Binaries       []string
}

var agentDefinitions = []agentSpec{
	{"openclaw", "OpenSource", []string{".openclaw"}, []string{"openclaw"}},
	{"clawdbot", "OpenSource", []string{".clawdbot"}, []string{"clawdbot"}},
	{"moltbot", "OpenSource", []string{".moltbot"}, []string{"moltbot"}},
	{"moldbot", "OpenSource", []string{".moldbot"}, []string{"moldbot"}},
	{"gpt-engineer", "OpenSource", []string{".gpt-engineer"}, []string{"gpt-engineer"}},
}

// AgentDetector detects general-purpose AI agents.
type AgentDetector struct {
	exec executor.Executor
}

func NewAgentDetector(exec executor.Executor) *AgentDetector {
	return &AgentDetector{exec: exec}
}

func (d *AgentDetector) Detect(ctx context.Context, searchDirs []string) []model.AITool {
	homeDir := getHomeDir(d.exec)
	var results []model.AITool

	for _, spec := range agentDefinitions {
		installPath, found := d.findAgent(spec, homeDir)
		if !found {
			continue
		}

		version := d.getVersion(ctx, spec)

		results = append(results, model.AITool{
			Name:        spec.Name,
			Vendor:      spec.Vendor,
			Type:        "general_agent",
			Version:     version,
			InstallPath: installPath,
		})
	}

	// Claude Cowork special case
	if tool, ok := d.detectClaudeCowork(ctx); ok {
		results = append(results, tool)
	}

	return results
}

func (d *AgentDetector) findAgent(spec agentSpec, homeDir string) (string, bool) {
	// Check detection paths
	for _, relPath := range spec.DetectionPaths {
		fullPath := filepath.Join(homeDir, relPath)
		if d.exec.DirExists(fullPath) || d.exec.FileExists(fullPath) {
			return fullPath, true
		}
	}

	// Check binaries in PATH
	for _, bin := range spec.Binaries {
		if path, err := d.exec.LookPath(bin); err == nil {
			return path, true
		}
	}

	return "", false
}

func (d *AgentDetector) getVersion(ctx context.Context, spec agentSpec) string {
	for _, bin := range spec.Binaries {
		if _, err := d.exec.LookPath(bin); err == nil {
			stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, bin, "--version")
			if err == nil {
				lines := strings.SplitN(stdout, "\n", 2)
				if len(lines) > 0 {
					v := strings.TrimSpace(lines[0])
					if v != "" {
						return v
					}
				}
			}
		}
	}
	return "unknown"
}

// detectClaudeCowork checks for Claude Cowork (a mode within Claude Desktop 0.7+).
func (d *AgentDetector) detectClaudeCowork(ctx context.Context) (model.AITool, bool) {
	var claudePath, version string

	if d.exec.GOOS() == "windows" {
		localAppData := d.exec.Getenv("LOCALAPPDATA")
		claudePath = filepath.Join(localAppData, "Programs", "Claude")
		if !d.exec.DirExists(claudePath) {
			return model.AITool{}, false
		}
		version = readRegistryVersion(ctx, d.exec, "Claude")
	} else {
		claudePath = "/Applications/Claude.app"
		if !d.exec.DirExists(claudePath) {
			return model.AITool{}, false
		}
		version = readPlistVersion(ctx, d.exec, filepath.Join(claudePath, "Contents", "Info.plist"))
	}

	if version == "unknown" {
		return model.AITool{}, false
	}

	// Check if version >= 0.7 (supports Cowork)
	if !isCoworkVersion(version) {
		return model.AITool{}, false
	}

	return model.AITool{
		Name:        "claude-cowork",
		Vendor:      "Anthropic",
		Type:        "general_agent",
		Version:     version,
		InstallPath: claudePath,
	}, true
}

// isCoworkVersion returns true if version is 0.7+ or 1.0+.
var versionRe = regexp.MustCompile(`^(\d+)\.(\d+)`)

func isCoworkVersion(version string) bool {
	m := versionRe.FindStringSubmatch(version)
	if len(m) < 3 {
		return false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return false
	}
	if major >= 1 {
		return true
	}
	return major == 0 && minor >= 7
}
