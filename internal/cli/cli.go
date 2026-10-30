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
	Command               string // "", "install", "uninstall", "send-telemetry", "configure", "configure show", "hooks install", "hooks uninstall"
	OutputFormat          string // "pretty", "json", "html"
	OutputFormatSet       bool   // true if --pretty/--json/--html was explicitly passed (not persisted)
	HTMLOutputFile        string // set by --html (not persisted)
	ColorMode             string // "auto", "always", "never"
	Verbose               bool   // --verbose (shortcut for --log-level=debug)
	LogLevel              string // "" = unset; one of "error", "warn", "info", "debug"
	InstallDir            string // --install-dir=DIR base install directory; all non-bootstrap files (logs, hook errors, binary placement) live under this dir. "" w/ InstallDirSet=true means "explicitly disabled" (no file logging).
	InstallDirSet         bool   // true if --install-dir was passed (empty value = disable file logging for this run)
	EnableNPMScan         *bool  // nil=auto, true/false=explicit
	UseLegacyNodeScan     *bool  // nil=auto (disk scan); true=command path, false=disk path
	EnableBrewScan        *bool  // nil=auto, true/false=explicit
	EnablePythonScan      *bool  // nil=auto, true/false=explicit
	EnableRuntimeScan     *bool  // nil=auto (on), true/false=explicit
	UseLegacyPythonScan   *bool  // nil=auto (disk scan); true=pip path, false=disk path
	IncludeBundledPlugins bool   // --include-bundled-plugins: include bundled/platform plugins in output
	// IncludeTCCProtected is tristate: nil or false = skip the macOS
	// TCC-protected dirs (Documents, Downloads, ~/Library/Mail, ...)
	// so the agent never triggers permission prompts; true = scan them.
	// Customers who have granted the agent Full Disk Access (e.g., via
	// an MDM-pushed PPPC profile) flip this to true to opt back into
	// full scan coverage. See docs/macos-tcc-permissions.md.
	IncludeTCCProtected *bool
	// IncludeNetworkVolumes is tristate with the OPPOSITE default to
	// IncludeTCCProtected: nil or true = walk macOS network volumes
	// (container-runtime mounts — OrbStack, Docker Desktop, Colima — are
	// Network Volumes to macOS), false = skip them. Walking them is what
	// inventories packages inside dev containers, at the cost of a one-time
	// TCC prompt on machines with no PPPC pre-approval. Fleets that can't
	// pre-approve set this to false. See docs/macos-tcc-permissions.md.
	IncludeNetworkVolumes *bool
	NPMRCOnly             bool     // --npmrc: run only the npmrc audit and render verbose pretty output
	PipConfigOnly         bool     // --pipconfig: run only the pip config audit and render verbose pretty output
	PnpmRCOnly            bool     // --pnpmrc: run only the pnpm config audit and render verbose pretty output
	BunfigOnly            bool     // --bunfig: run only the bun config audit and render verbose pretty output
	YarnRCOnly            bool     // --yarnrc: run only the yarn config audit (both flavors) and render verbose pretty output
	SearchDirs            []string // defaults to ["$HOME"]

	// GateProceedReason is populated at runtime (not a CLI flag) by the run
	// gate when it lets a run proceed, so telemetry.Run can echo the gate
	// decision into the captured execution log (what "Download logs" shows).
	// The gate itself runs before log capture starts, so its live lines never
	// reach the downloadable log without this.
	GateProceedReason string

	// CredentialScanningDisabled is populated at runtime (not a CLI flag) by
	// the run gate from this invocation's dashboard check-in. True means
	// telemetry.Run must not build, probe with, or run the credential detector.
	// The zero value scans, so a caller that never consulted the gate, or one
	// whose check-in failed, behaves as before.
	CredentialScanningDisabled bool
	// DeltaScanEnabled is set by run-config, never by a CLI flag.
	DeltaScanEnabled bool

	// WSLScanEnabled and WSLScanReason are populated at runtime (not CLI flags)
	// from the run-config check-in's wsl_directive. They gate scanning INSIDE
	// WSL distros — a tenant-wide switch with no per-device granularity. Both
	// stay zero on every path that never reached a backend answer, so distro
	// scanning fails closed; host-side WSL detection does not consult them.
	WSLScanEnabled bool
	WSLScanReason  string

	// WSLHostSerial and WSLDistroID identify this run as happening INSIDE a WSL
	// distribution, and are passed by the Windows host that triggered it
	// (--wsl-host-serial, --wsl-distro-id). A distro cannot discover either for
	// itself. When both are set the agent derives a stable device id from them,
	// because a distro's own identity is unusable: it inherits the host's
	// hostname, and a minimal or WSL1 distro has no machine-id.
	WSLHostSerial string
	WSLDistroID   string

	// ConfigFile is --config: the exact config.json to read. Applied by a
	// pre-scan of argv before config.Load(), so this field is informational
	// once parsing is done.
	ConfigFile string

	// HooksAgent is the --agent value on `hooks install` / `hooks uninstall`;
	// "" means "every detected agent".
	HooksAgent string

	// Non-interactive `configure` inputs. Used by MSI/SCCM and other
	// orchestrators that can't drive a stdin prompt loop. NonInteractive
	// is implied when any flag saves a config value, and main.go routes
	// accordingly.
	NonInteractive bool
	ConfigFromFile string // --from-file: read full config JSON from path

	// ConfigValues holds the config.json keys this invocation's flags set
	// (flagSpec.saves), for `configure` to persist. Scan runs ignore it.
	ConfigValues map[string]any

	searchDirsSet bool // a --search-dirs replaced the $HOME default

	// IgnoreTelemetryError opts the `install` subcommand into treating an
	// initial-telemetry POST failure as a warning rather than a fatal exit.
	// Default behavior (flag absent) preserves dev-workflow ergonomics —
	// a failed first telemetry surfaces misconfigurations immediately. MSI
	// custom actions and other unattended orchestrators set this so a
	// transient network hiccup doesn't roll back the whole install.
	IgnoreTelemetryError bool

	// OverrideGate disables feature gating for this invocation, letting
	// every capability run regardless of the featuregate allowlist.
	// Internal — not advertised in --help. Equivalent env var:
	// STEPSECURITY_OVERRIDE_GATE=1.
	OverrideGate bool

	// ForceScan bypasses the server-driven run gate for this invocation: the
	// scan proceeds even when the backend's run-directive says "skip". The
	// documented debug/support escape — manual runs are otherwise gated
	// exactly like scheduler-fired ones (an MDM-launched run detects as
	// one_time too, so invocation method deliberately can't exempt manual
	// use). Equivalent env var: STEPSEC_FORCE_SCAN=1.
	// The check-in itself still happens (bounded by its own timeout), because
	// it also carries the tenant's credential-scanning setting, which a forced
	// run must honour.
	ForceScan bool

	// RulesFile makes the malicious-file detection engine load its RuleSet
	// from a local JSON file instead of fetching it from the backend.
	// Dev-only — not advertised in --help. Equivalent env var:
	// STEPSECURITY_RULES_FILE=PATH. Lets the engine be exercised offline
	// (rules live only in the backend, so an offline run would otherwise scan
	// nothing). Zero production impact when unset.
	RulesFile string

	// TelemetryOutFile makes an enterprise run write the assembled telemetry
	// Payload to a local JSON file and skip the S3 upload + run-status notify.
	// Dev-only — not advertised in --help. Equivalent env var:
	// STEPSECURITY_TELEMETRY_OUT=PATH. The dumped file is exactly what the
	// backend's process-uploaded sees after gunzip, so it doubles as a backend
	// ingestion fixture. Zero production impact when unset.
	TelemetryOutFile string
}

// supportedHookAgents lists the agent names accepted by `hooks --agent <name>` and `_hook <agent> ...`.
// Supported agents: claude-code and codex; the list grows as adapters are added.
var supportedHookAgents = []string{"claude-code", "codex"}

// boolCount returns how many of the booleans are true. Used to keep the
// "*-only" mutual-exclusion checks readable when the set grows past two.
func boolCount(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

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

	for i := 0; i < len(args); {
		arg := args[i]
		switch {
		case arg == "install":
			cfg.Command = "install"
		case arg == "uninstall":
			cfg.Command = "uninstall"
		case arg == "send-telemetry":
			cfg.Command = "send-telemetry"
		case arg == "configure":
			// Check for "configure show" subcommand
			if i+1 < len(args) && args[i+1] == "show" {
				cfg.Command = "configure show"
				i++
			} else {
				cfg.Command = "configure"
			}
		case arg == "-v" || arg == "--version" || arg == "version":
			_, _ = fmt.Fprintf(os.Stdout, "StepSecurity Dev Machine Guard v%s\n", buildinfo.VersionString())
			os.Exit(0)
		case arg == "-h" || arg == "--help" || arg == "help":
			printHelp()
			os.Exit(0)
		default:
			next, ok, err := parseFlag(cfg, args, i)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("unknown option: %s, run '%s --help' for usage information", arg, filepath.Base(os.Args[0]))
			}
			i = next
			continue
		}
		i++
	}

	if onlyCount := boolCount(cfg.NPMRCOnly, cfg.PipConfigOnly, cfg.PnpmRCOnly, cfg.BunfigOnly, cfg.YarnRCOnly); onlyCount > 1 {
		return nil, fmt.Errorf("--npmrc, --pipconfig, --pnpmrc, --bunfig, and --yarnrc are mutually exclusive; pick one")
	}

	// Env-var equivalents for the dev-only flags, so an installed
	// launchd/systemd unit need not change to exercise the offline harness.
	// An explicit flag wins over the env var.
	if cfg.RulesFile == "" {
		cfg.RulesFile = os.Getenv("STEPSECURITY_RULES_FILE")
	}
	if cfg.TelemetryOutFile == "" {
		cfg.TelemetryOutFile = os.Getenv("STEPSECURITY_TELEMETRY_OUT")
	}

	// --install-dir= (explicit empty) disables file logging by routing
	// paths.Home() to "" globally. That conflicts with `install` /
	// `uninstall`, whose platform installers (systemd / launchd) call
	// os.MkdirAll(paths.Home()) and bake STEPSECURITY_HOME into the unit
	// file — both break or write nonsense values when Home() is empty.
	// Reject the combination here with a clear message rather than
	// letting the installer fail opaquely on an empty path.
	if cfg.InstallDirSet && cfg.InstallDir == "" && (cfg.Command == "install" || cfg.Command == "uninstall") {
		return nil, fmt.Errorf("--install-dir= (empty) cannot be combined with %s — pass a directory or omit the flag", cfg.Command)
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
		case strings.HasPrefix(arg, "--install-dir="):
			cfg.InstallDir = strings.TrimPrefix(arg, "--install-dir=")
			cfg.InstallDirSet = true
		case arg == "--install-dir":
			i++
			if i >= len(rest) {
				return nil, fmt.Errorf("--install-dir requires a directory argument (use --install-dir= to disable file logging)")
			}
			cfg.InstallDir = rest[i]
			cfg.InstallDirSet = true
		case arg == "--override-gate":
			cfg.OverrideGate = true
		case arg == "-h" || arg == "--help":
			printHooksHelp()
			os.Exit(0)
		default:
			return nil, fmt.Errorf("unknown option for `hooks %s`: %s (only --agent and --install-dir are accepted)", verb, arg)
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
  --install-dir=DIR    Base directory the agent puts its files under
                       (default: ~/.stepsecurity). Pass --install-dir= (empty)
                       to disable file logging. Equivalent to $STEPSECURITY_HOME.

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
%s
Options:
%s  -v, --version          Show version
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

Non-interactive configure (for MSI / SCCM / Intune deployments):
%s%s
Configuration:
  Per-user config:    ~/.stepsecurity/config.json
  Machine-wide (Windows, admin): C:\ProgramData\StepSecurity\config.json
  Run '%s configure' to set credentials and search directories interactively.

%s
`, buildinfo.Version, name, name,
		helpFor(helpOutput), helpFor(helpOptions),
		name, name, name, name, name, name, name, name,
		name, name, helpFor(helpConfigure), savedFlagsNote(), name,
		buildinfo.AgentURL)
}

// ConfigPathFromArgs pre-scans argv for --config so main can pin the config
// path before config.Load() runs. Parse() happens after Load(), and Load()
// keeps whatever it read first, so the flag cannot be honoured any later.
// Deliberately forgiving: an unparseable argv is Parse()'s problem to report,
// not this helper's.
func ConfigPathFromArgs(args []string) string {
	for i, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--config="):
			return strings.TrimPrefix(arg, "--config=")
		case arg == "--config":
			if i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return ""
}
