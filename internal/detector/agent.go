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
	Name     string
	Vendor   string
	ConfigDirs []string // candidate config directories (relative to home or absolute, ~ expanded). Used as ConfigDir when populated alongside a discovered binary; never used as the sole proof of installation.
	Binaries []string // binary names to search via LookPath, or home-relative paths (~/...). At least one must resolve before the agent is considered installed.
}

var agentDefinitions = []agentSpec{
	{"openclaw", "OpenSource", []string{"~/.openclaw"}, []string{"openclaw", "~/.local/bin/openclaw"}},
	{"clawdbot", "OpenSource", []string{"~/.clawdbot"}, []string{"clawdbot", "~/.local/bin/clawdbot"}},
	{"moltbot", "OpenSource", []string{"~/.moltbot"}, []string{"moltbot", "~/.local/bin/moltbot"}},
	{"moldbot", "OpenSource", []string{"~/.moldbot"}, []string{"moldbot", "~/.local/bin/moldbot"}},
	{"gpt-engineer", "OpenSource", []string{"~/.gpt-engineer"}, []string{"gpt-engineer", "~/.local/bin/gpt-engineer"}},
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
		binaryPath, found := d.findAgentBinary(spec, homeDir)
		if !found {
			continue
		}

		// Prefer the resolved real path (and, for npm-packaged agents, the
		// package root) as install_path so investigators can find the actual
		// package contents rather than the shim on PATH.
		installPath := resolveInstallPath(d.exec, binaryPath)

		configDir := d.findConfigDir(spec, homeDir)
		version := d.getVersion(ctx, binaryPath)

		results = append(results, model.AITool{
			Name:        spec.Name,
			Vendor:      spec.Vendor,
			Type:        "general_agent",
			Version:     version,
			BinaryPath:  binaryPath,
			InstallPath: installPath,
			ConfigDir:   configDir,
		})
	}

	// Claude Cowork special case
	if tool, ok := d.detectClaudeCowork(ctx); ok {
		results = append(results, tool)
	}

	return results
}

// findAgentBinary searches for the agent's binary, treating any "~/..."
// entry as a home-relative file path and any other entry as a PATH-resolvable
// binary name. Returns the discovered path and a found flag.
//
// Existence of a config dir alone is intentionally NOT treated as proof of
// installation: an empty ~/.openclaw/ directory doesn't mean the openclaw
// agent is installed, and treating it as such produces phantom entries on
// machines that have stale dotfiles.
func (d *AgentDetector) findAgentBinary(spec agentSpec, homeDir string) (string, bool) {
	for _, bin := range spec.Binaries {
		expanded := expandTilde(bin, homeDir)
		if expanded != bin {
			// Home-relative: must exist on disk as a file.
			if d.exec.FileExists(expanded) {
				return expanded, true
			}
			if d.exec.GOOS() == model.PlatformWindows && !strings.HasSuffix(expanded, ".exe") {
				if d.exec.FileExists(expanded + ".exe") {
					return expanded + ".exe", true
				}
			}
			continue
		}
		if path, err := d.exec.LookPath(expanded); err == nil {
			return path, true
		}
	}
	return "", false
}

// findConfigDir returns the first config directory candidate that exists and
// is non-empty. An entirely empty directory is treated as "no config dir":
// stale dotfiles shouldn't get surfaced as a real config location. We don't
// inspect file sizes here — the binary-on-PATH requirement in
// findAgentBinary is what defends against false positives like an empty
// config.json. This check is purely cosmetic (whether to populate the field).
func (d *AgentDetector) findConfigDir(spec agentSpec, homeDir string) string {
	for _, dir := range spec.ConfigDirs {
		expanded := expandTilde(dir, homeDir)
		if !d.exec.DirExists(expanded) {
			continue
		}
		entries, err := d.exec.ReadDir(expanded)
		if err != nil || len(entries) == 0 {
			continue
		}
		return expanded
	}
	return ""
}

func (d *AgentDetector) getVersion(ctx context.Context, binaryPath string) string {
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, binaryPath, "--version")
	if err != nil {
		return "unknown"
	}
	return extractVersionFromOutput(stdout)
}

// detectClaudeCowork checks for Claude Cowork (a mode within Claude Desktop 0.7+).
func (d *AgentDetector) detectClaudeCowork(ctx context.Context) (model.AITool, bool) {
	var claudePath, version string

	switch d.exec.GOOS() {
	case model.PlatformWindows:
		localAppData := d.exec.Getenv("LOCALAPPDATA")
		claudePath = filepath.Join(localAppData, "Programs", "Claude")
		if !d.exec.DirExists(claudePath) {
			return model.AITool{}, false
		}
		version = readRegistryVersion(ctx, d.exec, "Claude")
	case model.PlatformDarwin:
		claudePath = "/Applications/Claude.app"
		if !d.exec.DirExists(claudePath) {
			return model.AITool{}, false
		}
		version = readPlistVersion(ctx, d.exec, filepath.Join(claudePath, "Contents", "Info.plist"))
	default: // linux — Claude Desktop not yet available
		return model.AITool{}, false
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
