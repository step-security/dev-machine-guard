package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

// Config holds all parsed CLI flags.
//
// The hidden `_hook` runtime is intentionally NOT represented here. Agents
// invoke `_hook` on every event and any non-zero exit is treated as a hook
// failure, so the hot path bypasses cli.Parse entirely — see main.go's
// early-return and internal/aiagents/cli.RunHook.
type Config struct {
	Command               string   // "", "install", "uninstall", "send-telemetry", "configure", "configure show", "hooks install", "hooks uninstall"
	OutputFormat          string   // "pretty", "json", "html"
	OutputFormatSet       bool     // true if --pretty/--json/--html was explicitly passed (not persisted)
	HTMLOutputFile        string   // set by --html (not persisted)
	ColorMode             string   // "auto", "always", "never"
	Verbose               bool     // --verbose (shortcut for --log-level=debug)
	LogLevel              string   // "" = unset; one of "error", "warn", "info", "debug"
	EnableNPMScan         *bool    // nil=auto, true/false=explicit
	EnableBrewScan        *bool    // nil=auto, true/false=explicit
	EnablePythonScan      *bool    // nil=auto, true/false=explicit
	IncludeBundledPlugins bool     // --include-bundled-plugins: include bundled/platform plugins in output
	SearchDirs            []string // defaults to ["$HOME"]

	// HooksAgent is the --agent value on `hooks install` / `hooks uninstall`;
	// "" means "every detected agent".
	HooksAgent string
}

// supportedHookAgents lists the agent names accepted by `hooks --agent <name>` and `_hook <agent> ...`.
// Phase 1 ships claude-code and codex; the list grows as adapters are added.
var supportedHookAgents = []string{"claude-code", "codex"}

func isSupportedHookAgent(name string) bool {
	return slices.Contains(supportedHookAgents, name)
}

// Parse parses CLI arguments and returns a Config.
func Parse(args []string) (*Config, error) {
	// AI-agent hooks subcommands have a deliberately narrow flag surface:
	// only `--agent <name>` (and `--help`) are accepted. None of the DMG
	// scan/output flags apply, so we branch off the main parser here to
	// reject them with a clear error rather than silently honoring them.
	//
	// Note: the hidden `_hook` runtime does NOT route through Parse — main
	// intercepts it before any init runs. Don't add a `_hook` arm here.
	if len(args) > 0 && args[0] == "hooks" {
		return parseHooks(args[1:])
	}

	cfg := &Config{
		OutputFormat: "pretty",
		ColorMode:    "auto",
		SearchDirs:   []string{"$HOME"},
	}

	searchDirsSet := false
	i := 0

	for i < len(args) {
		arg := args[i]
		switch {
		case arg == "install" || arg == "--install":
			cfg.Command = "install"
		case arg == "uninstall" || arg == "--uninstall":
			cfg.Command = "uninstall"
		case arg == "send-telemetry" || arg == "--send-telemetry":
			cfg.Command = "send-telemetry"
		case arg == "configure":
			// Check for "configure show" subcommand
			if i+1 < len(args) && args[i+1] == "show" {
				cfg.Command = "configure show"
				i++
			} else {
				cfg.Command = "configure"
			}
		case arg == "--pretty":
			cfg.OutputFormat = "pretty"
			cfg.OutputFormatSet = true
		case arg == "--json":
			cfg.OutputFormat = "json"
			cfg.OutputFormatSet = true
		case arg == "--html":
			cfg.OutputFormat = "html"
			cfg.OutputFormatSet = true
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--html requires a file path argument")
			}
			cfg.HTMLOutputFile = args[i]
		case arg == "--enable-npm-scan":
			v := true
			cfg.EnableNPMScan = &v
		case arg == "--disable-npm-scan":
			v := false
			cfg.EnableNPMScan = &v
		case arg == "--enable-brew-scan":
			v := true
			cfg.EnableBrewScan = &v
		case arg == "--disable-brew-scan":
			v := false
			cfg.EnableBrewScan = &v
		case arg == "--enable-python-scan":
			v := true
			cfg.EnablePythonScan = &v
		case arg == "--disable-python-scan":
			v := false
			cfg.EnablePythonScan = &v
		case arg == "--include-bundled-plugins":
			cfg.IncludeBundledPlugins = true
		case strings.HasPrefix(arg, "--color="):
			mode := strings.TrimPrefix(arg, "--color=")
			if mode != "auto" && mode != "always" && mode != "never" {
				return nil, fmt.Errorf("invalid color mode: %s (must be auto, always, or never)", mode)
			}
			cfg.ColorMode = mode
		case arg == "--search-dirs":
			i++
			if i >= len(args) || strings.HasPrefix(args[i], "--") {
				return nil, fmt.Errorf("--search-dirs requires at least one directory path argument")
			}
			if !searchDirsSet {
				cfg.SearchDirs = nil
				searchDirsSet = true
			}
			// Greedily consume non-flag arguments
			for i < len(args) && !strings.HasPrefix(args[i], "--") {
				cfg.SearchDirs = append(cfg.SearchDirs, args[i])
				i++
			}
			continue // skip the i++ at the bottom
		case arg == "--verbose":
			cfg.Verbose = true
		case strings.HasPrefix(arg, "--log-level="):
			level := strings.ToLower(strings.TrimPrefix(arg, "--log-level="))
			switch level {
			case "error", "warn", "warning", "info", "debug":
				if level == "warning" {
					level = "warn"
				}
				cfg.LogLevel = level
			default:
				return nil, fmt.Errorf("invalid log level: %s (must be error, warn, info, or debug)", level)
			}
		case arg == "-v" || arg == "--version" || arg == "version":
			_, _ = fmt.Fprintf(os.Stdout, "StepSecurity Dev Machine Guard v%s\n", buildinfo.VersionString())
			os.Exit(0)
		case arg == "-h" || arg == "--help" || arg == "help":
			printHelp()
			os.Exit(0)
		default:
			return nil, fmt.Errorf("unknown option: %s, run '%s --help' for usage information", arg, filepath.Base(os.Args[0]))
		}
		i++
	}

	return cfg, nil
}

// parseHooks handles `hooks install` and `hooks uninstall`.
//
// Accepted flags: --agent <name>, --help. Anything else (including DMG global
// flags like --json, --verbose, --search-dirs) is rejected so users get a
// clear signal that those flags don't apply to the hooks group.
func parseHooks(args []string) (*Config, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("missing subcommand: expected `hooks install` or `hooks uninstall`, run '%s hooks --help' for usage", filepath.Base(os.Args[0]))
	}

	verb := args[0]
	switch verb {
	case "install", "uninstall":
		// continue
	case "-h", "--help", "help":
		printHooksHelp()
		os.Exit(0)
	default:
		return nil, fmt.Errorf("unknown `hooks` subcommand: %s, run '%s hooks --help' for usage", verb, filepath.Base(os.Args[0]))
	}

	cfg := &Config{
		Command:      "hooks " + verb,
		OutputFormat: "pretty",
		ColorMode:    "auto",
		SearchDirs:   []string{"$HOME"},
	}

	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		switch {
		case arg == "--agent":
			i++
			if i >= len(rest) {
				return nil, fmt.Errorf("--agent requires an agent name (one of: %s)", strings.Join(supportedHookAgents, ", "))
			}
			name := rest[i]
			if !isSupportedHookAgent(name) {
				return nil, fmt.Errorf("unsupported agent: %s (supported: %s)", name, strings.Join(supportedHookAgents, ", "))
			}
			cfg.HooksAgent = name
		case strings.HasPrefix(arg, "--agent="):
			name := strings.TrimPrefix(arg, "--agent=")
			if name == "" {
				return nil, fmt.Errorf("--agent requires an agent name (one of: %s)", strings.Join(supportedHookAgents, ", "))
			}
			if !isSupportedHookAgent(name) {
				return nil, fmt.Errorf("unsupported agent: %s (supported: %s)", name, strings.Join(supportedHookAgents, ", "))
			}
			cfg.HooksAgent = name
		case arg == "-h" || arg == "--help":
			printHooksHelp()
			os.Exit(0)
		default:
			return nil, fmt.Errorf("unknown option for `hooks %s`: %s (only --agent is accepted)", verb, arg)
		}
	}

	return cfg, nil
}

func printHooksHelp() {
	name := filepath.Base(os.Args[0])
	_, _ = fmt.Fprintf(os.Stdout, `StepSecurity Dev Machine Guard v%s — AI agent hooks

Usage: %s hooks <install|uninstall> [--agent <name>]

Subcommands:
  install              Install audit-mode hooks for detected AI coding agents.
                       Hook events are uploaded to your StepSecurity dashboard;
                       no agent activity is blocked.
  uninstall            Remove hooks previously installed by this tool.

Options:
  --agent <name>       Target a specific agent (default: every detected agent).
                       Supported: %s

Examples:
  %s hooks install                       # install for every detected agent
  %s hooks install --agent claude-code   # install only for Claude Code
  %s hooks uninstall                     # remove all DMG-owned hook entries

Diagnostics:
  Hook errors are appended to ~/.stepsecurity/ai-agent-hook-errors.jsonl.

%s
`, buildinfo.Version, name, strings.Join(supportedHookAgents, ", "),
		name, name, name, buildinfo.AgentURL)
}

func printHelp() {
	name := filepath.Base(os.Args[0])
	_, _ = fmt.Fprintf(os.Stdout, `StepSecurity Dev Machine Guard v%s

Usage: %s [COMMAND] [OPTIONS]

Commands:
  configure            Configure enterprise settings and search directories
  configure show       Show current configuration
  install              Install scheduled scanning (enterprise)
  uninstall            Remove scheduled scanning (enterprise)
  send-telemetry       Upload scan results to the StepSecurity dashboard (enterprise)
  hooks                Install/uninstall AI coding agent hooks (run '%s hooks --help')

Output formats (community mode, mutually exclusive):
  --pretty             Pretty terminal output (default)
  --json               JSON output to stdout
  --html FILE          HTML report saved to FILE

Options:
  --search-dirs DIR [DIR...]  Search DIRs instead of $HOME (replaces default; repeatable)
  --enable-npm-scan      Enable Node.js package scanning
  --disable-npm-scan     Disable Node.js package scanning
  --enable-brew-scan     Enable Homebrew package scanning
  --disable-brew-scan    Disable Homebrew package scanning
  --enable-python-scan          Enable Python package scanning
  --disable-python-scan         Disable Python package scanning
  --include-bundled-plugins     Include bundled/platform plugins in output (Windows)
  --log-level=LEVEL      Log level: error | warn | info | debug (default: info)
  --verbose                     Shortcut for --log-level=debug
  --color=WHEN           Color mode: auto | always | never (default: auto)
  -v, --version          Show version
  -h, --help             Show this help

Examples:
  %s                                  # Pretty terminal output
  %s --json | python3 -m json.tool    # Formatted JSON
  %s --json > scan.json               # JSON to file
  %s --html report.html               # HTML report
  %s --verbose --enable-npm-scan      # Verbose with npm scan
  %s --search-dirs /Volumes/code                          # Search only /Volumes/code
  %s --search-dirs /tmp /opt                              # Multiple dirs, one flag
  %s --search-dirs "/path/with spaces" --search-dirs /opt # Mixed styles
  %s configure                          # Set up enterprise config and search dirs
  %s send-telemetry                   # Enterprise telemetry

Configuration:
  Config file: ~/.stepsecurity/config.json
  Run '%s configure' to set enterprise credentials and search directories interactively.

%s
`, buildinfo.Version, name, name,
		name, name, name, name, name, name, name, name,
		name, name, name,
		buildinfo.AgentURL)
}
