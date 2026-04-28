package detector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type cliToolSpec struct {
	Name        string
	Vendor      string
	Binaries    []string // binary names or paths (~ expanded at runtime)
	ConfigDirs  []string // config directory candidates (~ expanded)
	VersionFlag string   // flag to get version; defaults to "--version"
	VerifyFunc  func(ctx context.Context, exec executor.Executor, binary string) bool
}

var cliToolDefinitions = []cliToolSpec{
	{
		Name:       "claude-code",
		Vendor:     "Anthropic",
		Binaries:   []string{"claude", "~/.claude/local/claude", "~/.local/bin/claude"},
		ConfigDirs: []string{"~/.claude"},
	},
	{
		Name:       "codex",
		Vendor:     "OpenAI",
		Binaries:   []string{"codex"},
		ConfigDirs: []string{"~/.codex"},
	},
	{
		Name:       "gemini-cli",
		Vendor:     "Google",
		Binaries:   []string{"gemini"},
		ConfigDirs: []string{"~/.gemini"},
	},
	{
		Name:       "amazon-q-cli",
		Vendor:     "Amazon",
		Binaries:   []string{"kiro-cli", "kiro", "q"},
		ConfigDirs: []string{"~/.q", "~/.kiro", "~/.aws/q"},
		VerifyFunc: func(ctx context.Context, exec executor.Executor, binary string) bool {
			stdout, _, _, err := exec.RunWithTimeout(ctx, 10*time.Second, binary, "--version")
			if err != nil {
				return false
			}
			lower := strings.ToLower(stdout)
			return strings.Contains(lower, "amazon") || strings.Contains(lower, "kiro") || strings.Contains(lower, "q developer")
		},
	},
	{
		Name:       "github-copilot-cli",
		Vendor:     "Microsoft",
		Binaries:   []string{"copilot", "gh-copilot"},
		ConfigDirs: []string{"~/.config/github-copilot"},
		// Reject the VS Code Copilot Chat extension's shim, which lives on PATH
		// even when the real CLI isn't installed and replies to `--version` with
		// "GitHub Copilot CLI is not installed. Would you like to install it? (Y/n)".
		VerifyFunc: func(ctx context.Context, exec executor.Executor, binary string) bool {
			stdout, _, exitCode, err := exec.RunWithTimeout(ctx, 10*time.Second, binary, "--version")
			if err != nil || exitCode != 0 {
				return false
			}
			lower := strings.ToLower(stdout)
			if strings.Contains(lower, "not installed") ||
				strings.Contains(lower, "would you like to install") {
				return false
			}
			return true
		},
	},
	{
		Name:       "microsoft-ai-shell",
		Vendor:     "Microsoft",
		Binaries:   []string{"aish", "ai"},
		ConfigDirs: []string{"~/.aish"},
	},
	{
		Name:       "aider",
		Vendor:     "OpenSource",
		Binaries:   []string{"aider"},
		ConfigDirs: []string{"~/.aider"},
	},
	{
		Name:        "opencode",
		Vendor:      "OpenSource",
		Binaries:    []string{"opencode", "~/.opencode/bin/opencode"},
		ConfigDirs:  []string{"~/.config/opencode"},
		VersionFlag: "-v",
	},
}

// AICLIDetector detects AI CLI tools.
type AICLIDetector struct {
	exec executor.Executor
}

func NewAICLIDetector(exec executor.Executor) *AICLIDetector {
	return &AICLIDetector{exec: exec}
}

func (d *AICLIDetector) Detect(ctx context.Context) []model.AITool {
	homeDir := getHomeDir(d.exec)
	var results []model.AITool

	for _, spec := range cliToolDefinitions {
		binaryPath, found := d.findBinary(ctx, spec, homeDir)
		if !found {
			continue
		}

		// Verify if needed (e.g., amazon-q-cli)
		if spec.VerifyFunc != nil && !spec.VerifyFunc(ctx, d.exec, binaryPath) {
			continue
		}

		version := d.getVersion(ctx, spec, binaryPath)
		configDir := d.findConfigDir(spec, homeDir)

		results = append(results, model.AITool{
			Name:       spec.Name,
			Vendor:     spec.Vendor,
			Type:       "cli_tool",
			Version:    version,
			BinaryPath: binaryPath,
			ConfigDir:  configDir,
		})
	}

	return results
}

func (d *AICLIDetector) findBinary(ctx context.Context, spec cliToolSpec, homeDir string) (string, bool) {
	for _, bin := range spec.Binaries {
		expanded := expandTilde(bin, homeDir)
		if expanded != bin {
			// Path was expanded from tilde — it's a home-relative path, check if it exists
			if d.exec.FileExists(expanded) {
				return expanded, true
			}
			// On Windows, also try with .exe suffix
			if d.exec.GOOS() == model.PlatformWindows && !strings.HasSuffix(expanded, ".exe") {
				if d.exec.FileExists(expanded + ".exe") {
					return expanded + ".exe", true
				}
			}
			continue
		}
		// Search in PATH
		if path, err := d.exec.LookPath(expanded); err == nil {
			return path, true
		}
	}
	return "", false
}

func (d *AICLIDetector) getVersion(ctx context.Context, spec cliToolSpec, binaryPath string) string {
	flag := "--version"
	if spec.VersionFlag != "" {
		flag = spec.VersionFlag
	}
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, binaryPath, flag)
	if err != nil {
		return "unknown"
	}
	lines := strings.SplitN(stdout, "\n", 2)
	if len(lines) > 0 {
		v := strings.TrimSpace(lines[0])
		if v != "" {
			return cleanVersionString(v)
		}
	}
	return "unknown"
}

// cleanVersionString strips a leading tool name prefix from version output.
// It finds the first token that looks like a version number (starts with a digit
// or "v" followed by a digit) and returns it, preserving any "v" prefix.
// e.g. "codex-cli 0.118.0" -> "0.118.0", "aider 0.86.2" -> "0.86.2", "v1.2.3" -> "v1.2.3"
func cleanVersionString(v string) string {
	parts := strings.Fields(v)
	for _, p := range parts {
		trimmed := strings.TrimLeft(p, "v")
		if len(trimmed) > 0 && trimmed[0] >= '0' && trimmed[0] <= '9' {
			return p
		}
	}
	return "unknown"
}

func (d *AICLIDetector) findConfigDir(spec cliToolSpec, homeDir string) string {
	for _, dir := range spec.ConfigDirs {
		expanded := expandTilde(dir, homeDir)
		if d.exec.DirExists(expanded) {
			return expanded
		}
	}
	return ""
}

func expandTilde(path, homeDir string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(homeDir, filepath.FromSlash(path[2:]))
	}
	return path
}

func getHomeDir(exec executor.Executor) string {
	u, err := exec.LoggedInUser()
	if err != nil {
		return os.TempDir()
	}
	return u.HomeDir
}

// resolveEnvPath replaces %ENVVAR% patterns in Windows-style paths using the executor.
func resolveEnvPath(exec executor.Executor, path string) string {
	for strings.Contains(path, "%") {
		start := strings.Index(path, "%")
		end := strings.Index(path[start+1:], "%")
		if end < 0 {
			break
		}
		envName := path[start+1 : start+1+end]
		envVal := exec.Getenv(envName)
		path = path[:start] + envVal + path[start+2+end:]
	}
	return filepath.FromSlash(path)
}
