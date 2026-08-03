package detector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/execguard"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/versionmeta"
)

type cliToolSpec struct {
	Name         string
	Vendor       string
	Binaries     []string // binary names or paths (~ expanded at runtime)
	ConfigDirs   []string // config directory candidates (~ expanded)
	VersionFlag  string   // flag to get version; defaults to "--version"
	MetadataOnly bool     // never execute the binary for version discovery
	VerifyFunc   func(ctx context.Context, exec executor.Executor, log *progress.Logger, binary string) bool
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
		VerifyFunc: func(ctx context.Context, exec executor.Executor, log *progress.Logger, binary string) bool {
			if !execguard.SafeToExec(ctx, exec, binary) {
				log.Warn("skipping %s: quarantined and rejected by Gatekeeper — cannot verify identity", binary)
				return false
			}
			log.Progress("exec fallback: running %s --version (amazon-q identity check)", binary)
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
		VerifyFunc: func(ctx context.Context, exec executor.Executor, log *progress.Logger, binary string) bool {
			// The real CLI is the @github/copilot npm package; confirming
			// identity from its manifest avoids exec'ing the binary at all.
			if versionmeta.NPMPackageName(exec, binary) == "@github/copilot" {
				return true
			}
			if !execguard.SafeToExec(ctx, exec, binary) {
				log.Warn("skipping %s: quarantined and rejected by Gatekeeper — cannot verify identity", binary)
				return false
			}
			log.Progress("exec fallback: running %s --version (copilot identity check)", binary)
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
		Name:         "patchwarden",
		Vendor:       "OpenSource",
		Binaries:     []string{"patchwarden"},
		MetadataOnly: true,
	},
	{
		Name:        "opencode",
		Vendor:      "OpenSource",
		Binaries:    []string{"opencode", "~/.opencode/bin/opencode"},
		ConfigDirs:  []string{"~/.config/opencode"},
		VersionFlag: "-v",
	},
	{
		Name:       "cursor-agent",
		Vendor:     "Cursor",
		Binaries:   []string{"cursor-agent", "~/.local/bin/cursor-agent"},
		ConfigDirs: []string{"~/.cursor"},
	},
}

// AICLIDetector detects AI CLI tools.
type AICLIDetector struct {
	exec executor.Executor
	log  *progress.Logger
}

func NewAICLIDetector(exec executor.Executor) *AICLIDetector {
	return &AICLIDetector{exec: exec, log: progress.NewNoop()}
}

// WithLogger injects a logger (used to surface exec fallbacks when metadata
// version resolution misses). Chainable, mirrors configaudit's WithSkipper.
func (d *AICLIDetector) WithLogger(log *progress.Logger) *AICLIDetector {
	if log != nil {
		d.log = log
	}
	return d
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
		if spec.VerifyFunc != nil && !spec.VerifyFunc(ctx, d.exec, d.log, binaryPath) {
			continue
		}

		version := d.getVersion(ctx, spec, binaryPath)
		configDir := d.findConfigDir(spec, homeDir)
		installPath := resolveInstallPath(d.exec, binaryPath)

		results = append(results, model.AITool{
			Name:        spec.Name,
			Vendor:      spec.Vendor,
			Type:        "cli_tool",
			Version:     version,
			BinaryPath:  binaryPath,
			InstallPath: installPath,
			ConfigDir:   configDir,
		})
	}

	return results
}

// resolveInstallPath returns the on-disk install root for a CLI tool, given
// the binary path that was found via PATH or a home-relative lookup.
//
// Many AI CLIs (claude-code, codex, opencode) ship as npm packages whose
// binary is exposed as a tiny shim under /usr/local/bin/. The shim's symlink
// target lives inside `node_modules/<scope>/<package>/...` — that directory
// is what an investigator actually wants when they ask "where is claude
// installed?". When we detect that pattern, return the package root.
//
// If symlink resolution fails or the resolved path doesn't sit inside a
// node_modules tree, return the resolved real path (or the original path if
// resolution failed) so we still surface a meaningful install location
// instead of leaving the field empty.
func resolveInstallPath(exec executor.Executor, binaryPath string) string {
	if binaryPath == "" {
		return ""
	}
	resolved, err := exec.EvalSymlinks(binaryPath)
	if err != nil || resolved == "" {
		resolved = binaryPath
	}
	if pkgRoot := versionmeta.NodeModulesPackageRoot(resolved); pkgRoot != "" {
		return pkgRoot
	}
	// Windows: npm publishes a `.cmd` (and `.ps1`) shim instead of a symlink,
	// so the resolved path points at the shim itself, not the package. Parse
	// the shim to recover the node_modules package root.
	if pkgRoot := versionmeta.NPMShimPackageRoot(exec, resolved); pkgRoot != "" {
		return pkgRoot
	}
	return resolved
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
	// Static-first, exec-last (AGENTS.md §3.4): launching a third-party CLI
	// just for --version can pop a Gatekeeper "unverified software" dialog
	// when the tool ships unsigned native code (cursor-agent's merkle-tree
	// addon did exactly that on customer machines).
	if v := versionmeta.FromBinary(ctx, d.exec, binaryPath); v != "" {
		return v
	}
	if spec.MetadataOnly {
		return "unknown"
	}
	flag := "--version"
	if spec.VersionFlag != "" {
		flag = spec.VersionFlag
	}
	if !execguard.SafeToExec(ctx, d.exec, binaryPath) {
		d.log.Warn("skipping %s version probe: quarantined and rejected by Gatekeeper", binaryPath)
		return "unknown"
	}
	d.log.Progress("exec fallback: running %s %s (no metadata version source)", binaryPath, flag)
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, binaryPath, flag)
	if err != nil {
		return "unknown"
	}
	return extractVersionFromOutput(stdout)
}

// extractVersionFromOutput finds the first line of `--version` output that
// contains a version-shaped token, then returns that token.
//
// Tools that talk to a daemon (ollama, lm-studio CLI) prepend warnings to
// their version output when the daemon isn't running, so we can't rely on the
// first line. Walking line-by-line and skipping lines without a version token
// keeps real version output ("codex-cli 0.118.0", "aider 0.86.2") working
// while making the detector robust against decorated output.
func extractVersionFromOutput(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if v := cleanVersionString(line); v != "unknown" {
			return v
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
	if u, err := exec.LoggedInUser(); err == nil {
		return u.HomeDir
	}
	// No console user (issue #63) — fall back to the current user's home
	// before giving up to TempDir, otherwise file-path expansion in this
	// detector would lose any chance of hitting the right files.
	if u, err := exec.CurrentUser(); err == nil {
		return u.HomeDir
	}
	return os.TempDir()
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
