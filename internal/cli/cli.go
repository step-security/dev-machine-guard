package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

// Config holds all parsed CLI flags.
type Config struct {
	Command               string   // "", "install", "uninstall", "send-telemetry", "configure", "configure show"
	OutputFormat          string   // "pretty", "json", "html"
	OutputFormatSet       bool     // true if --pretty/--json/--html was explicitly passed (not persisted)
	HTMLOutputFile        string   // set by --html (not persisted)
	ColorMode             string   // "auto", "always", "never"
	Verbose               bool     // --verbose
	EnableNPMScan         *bool    // nil=auto, true/false=explicit
	EnableBrewScan        *bool    // nil=auto, true/false=explicit
	EnablePythonScan      *bool    // nil=auto, true/false=explicit
	IncludeBundledPlugins bool     // --include-bundled-plugins: include bundled/platform plugins in output
	SearchDirs            []string // defaults to ["$HOME"]
}

// Parse parses CLI arguments and returns a Config.
func Parse(args []string) (*Config, error) {
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
  --verbose                     Show progress messages (suppressed by default)
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
`, buildinfo.Version, name,
		name, name, name, name, name, name, name, name,
		name, name, name,
		buildinfo.AgentURL)
}
