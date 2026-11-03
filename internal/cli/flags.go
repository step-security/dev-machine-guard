package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// flagKind is how a flag takes its value.
type flagKind int

const (
	flagSwitch flagKind = iota // --x
	flagValue                  // --x VALUE or --x=VALUE
	flagSpaced                 // --x VALUE only
	flagEquals                 // --x=VALUE only
	flagList                   // --x V1 [V2...]: consumes args up to the next --flag
)

// helpSection is the --help block a flag is listed in.
type helpSection int

const (
	helpHidden helpSection = iota // dev-only, legacy, or rollback flags
	helpOutput
	helpOptions
	helpConfigure
)

// flagSpec is one CLI flag. flagTable is the single source for parsing,
// --help, and which config.json keys `configure` saves, so a flag can't be
// parsed without being documented or persisted without being declared.
type flagSpec struct {
	name    string
	kind    flagKind
	missing string   // error when the value is absent; "" = "<name> requires a value"
	saves   []string // config.json keys `configure` persists from this flag
	set     func(cfg *Config, v string) error
	section helpSection
	help    string // verbatim --help lines
}

// save records a config.json value for `configure` to persist.
func (c *Config) save(key string, v any) {
	if c.ConfigValues == nil {
		c.ConfigValues = map[string]any{}
	}
	c.ConfigValues[key] = v
}

// switchFlag sets a plain bool on the Config.
func switchFlag(name string, dst func(*Config) *bool, section helpSection, help string) flagSpec {
	return flagSpec{name: name, kind: flagSwitch, section: section, help: help,
		set: func(c *Config, _ string) error { *dst(c) = true; return nil }}
}

// triFlag sets a tristate (*bool) scan option to v and saves it under key.
func triFlag(name string, dst func(*Config) **bool, v bool, key string, section helpSection, help string) flagSpec {
	return flagSpec{name: name, kind: flagSwitch, saves: []string{key}, section: section, help: help,
		set: func(c *Config, _ string) error {
			b := v
			*dst(c) = &b
			c.save(key, v)
			return nil
		}}
}

// stringFlag sets a string on the Config.
func stringFlag(name string, dst func(*Config) *string, missing string, section helpSection, help string) flagSpec {
	return flagSpec{name: name, kind: flagValue, missing: missing, section: section, help: help,
		set: func(c *Config, v string) error { *dst(c) = v; return nil }}
}

// unsave drops a value an earlier flag on this command line saved, so the
// last occurrence of a repeated flag wins even when it is empty.
func (c *Config) unsave(key string) { delete(c.ConfigValues, key) }

// configFlag is a `configure`-only setting saved under key. An empty value
// leaves the setting unchanged.
func configFlag(name, key string, help string) flagSpec {
	return flagSpec{name: name, kind: flagValue, saves: []string{key}, section: helpConfigure, help: help,
		set: func(c *Config, v string) error {
			if v == "" {
				c.unsave(key)
			} else {
				c.save(key, v)
			}
			return nil
		}}
}

// intConfigFlag is a `configure`-only non-negative integer saved under key.
func intConfigFlag(name, key string, help string) flagSpec {
	return flagSpec{name: name, kind: flagValue, saves: []string{key}, section: helpConfigure, help: help,
		set: func(c *Config, v string) error {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return fmt.Errorf("%s must be a non-negative integer, got %q", name, v)
			}
			c.save(key, n)
			return nil
		}}
}

func command(name, cmd string) flagSpec {
	return flagSpec{name: name, kind: flagSwitch,
		set: func(c *Config, _ string) error { c.Command = cmd; return nil }}
}

func outputFormat(name, format string, help string) flagSpec {
	saved := format
	if format == "pretty" {
		saved = "" // the default is stored as an omitted key
	}
	return flagSpec{name: name, kind: flagSwitch, saves: []string{"output_format"}, section: helpOutput, help: help,
		set: func(c *Config, _ string) error {
			c.OutputFormat = format
			c.OutputFormatSet = true
			c.save("output_format", saved)
			return nil
		}}
}

// flagTable lists every flag in --help order within each section.
var flagTable = []flagSpec{
	command("--install", "install"),
	command("--uninstall", "uninstall"),
	command("--send-telemetry", "send-telemetry"),

	outputFormat("--pretty", "pretty", "  --pretty             Pretty terminal output (default)"),
	outputFormat("--json", "json", "  --json               JSON output to stdout"),
	{name: "--html", kind: flagSpaced, missing: "--html requires a file path argument",
		saves: []string{"output_format", "html_output_file"}, section: helpOutput,
		help: "  --html FILE          HTML report saved to FILE",
		set: func(c *Config, v string) error {
			c.OutputFormat = "html"
			c.OutputFormatSet = true
			c.HTMLOutputFile = v
			c.save("output_format", "html")
			c.save("html_output_file", v)
			return nil
		}},

	{name: "--search-dirs", kind: flagList, missing: "--search-dirs requires at least one directory path argument",
		saves: []string{"search_dirs"}, section: helpOptions,
		help: "  --search-dirs DIR [DIR...]  Search DIRs instead of $HOME (replaces default; repeatable)",
		set: func(c *Config, v string) error {
			if !c.searchDirsSet {
				c.SearchDirs = nil
				c.searchDirsSet = true
			}
			c.SearchDirs = append(c.SearchDirs, v)
			c.save("search_dirs", c.SearchDirs)
			return nil
		}},
	triFlag("--enable-npm-scan", func(c *Config) **bool { return &c.EnableNPMScan }, true, "enable_npm_scan", helpOptions,
		"  --enable-npm-scan      Enable Node.js package scanning"),
	triFlag("--disable-npm-scan", func(c *Config) **bool { return &c.EnableNPMScan }, false, "enable_npm_scan", helpOptions,
		"  --disable-npm-scan     Disable Node.js package scanning"),
	triFlag("--enable-brew-scan", func(c *Config) **bool { return &c.EnableBrewScan }, true, "enable_brew_scan", helpOptions,
		"  --enable-brew-scan     Enable Homebrew package scanning"),
	triFlag("--disable-brew-scan", func(c *Config) **bool { return &c.EnableBrewScan }, false, "enable_brew_scan", helpOptions,
		"  --disable-brew-scan    Disable Homebrew package scanning"),
	triFlag("--enable-python-scan", func(c *Config) **bool { return &c.EnablePythonScan }, true, "enable_python_scan", helpOptions,
		"  --enable-python-scan          Enable Python package scanning"),
	triFlag("--disable-python-scan", func(c *Config) **bool { return &c.EnablePythonScan }, false, "enable_python_scan", helpOptions,
		"  --disable-python-scan         Disable Python package scanning"),
	triFlag("--enable-runtime-scan", func(c *Config) **bool { return &c.EnableRuntimeScan }, true, "enable_runtime_scan", helpOptions,
		"  --enable-runtime-scan         Enable language runtime inventory (default)"),
	triFlag("--disable-runtime-scan", func(c *Config) **bool { return &c.EnableRuntimeScan }, false, "enable_runtime_scan", helpOptions,
		"  --disable-runtime-scan        Disable language runtime inventory"),
	triFlag("--legacy-node-scan", func(c *Config) **bool { return &c.UseLegacyNodeScan }, true, "use_legacy_node_scan", helpHidden, ""),
	triFlag("--disk-node-scan", func(c *Config) **bool { return &c.UseLegacyNodeScan }, false, "use_legacy_node_scan", helpHidden, ""),
	triFlag("--legacy-python-scan", func(c *Config) **bool { return &c.UseLegacyPythonScan }, true, "use_legacy_python_scan", helpHidden, ""),
	triFlag("--disk-python-scan", func(c *Config) **bool { return &c.UseLegacyPythonScan }, false, "use_legacy_python_scan", helpHidden, ""),
	switchFlag("--include-bundled-plugins", func(c *Config) *bool { return &c.IncludeBundledPlugins }, helpOptions,
		"  --include-bundled-plugins     Include bundled/platform plugins in output (Windows)"),
	triFlag("--include-tcc-protected", func(c *Config) **bool { return &c.IncludeTCCProtected }, true, "include_tcc_protected", helpOptions,
		`  --include-tcc-protected       Scan macOS TCC-protected dirs (Documents, Downloads,
                                ~/Library/Mail, etc.). Default: skipped to avoid
                                permission prompts. Pass after granting the agent
                                Full Disk Access via PPPC profile or System
                                Settings — see docs/macos-tcc-permissions.md.`),
	triFlag("--no-include-tcc-protected", func(c *Config) **bool { return &c.IncludeTCCProtected }, false, "include_tcc_protected", helpOptions,
		`  --no-include-tcc-protected    Skip macOS TCC-protected dirs even if config has
                                include_tcc_protected: true.`),
	triFlag("--no-include-network-volumes", func(c *Config) **bool { return &c.IncludeNetworkVolumes }, false, "include_network_volumes", helpOptions,
		`  --no-include-network-volumes  Skip macOS network volumes — which is how macOS
                                classifies container-runtime mounts (OrbStack,
                                Docker Desktop, Colima). Suppresses the one-time
                                "access files on a network volume" prompt at the
                                cost of the package inventory inside dev
                                containers. Default: walked. Fleets that can
                                pre-approve the prompt with a PPPC profile
                                should keep the default — see
                                docs/macos-tcc-permissions.md.`),
	triFlag("--include-network-volumes", func(c *Config) **bool { return &c.IncludeNetworkVolumes }, true, "include_network_volumes", helpOptions,
		`  --include-network-volumes     Walk macOS network volumes even if config has
                                include_network_volumes: false.`),
	switchFlag("--npmrc", func(c *Config) *bool { return &c.NPMRCOnly }, helpOptions,
		"  --npmrc                       Run ONLY the npm config audit (verbose pretty view; --json supported)"),
	switchFlag("--pipconfig", func(c *Config) *bool { return &c.PipConfigOnly }, helpOptions,
		"  --pipconfig                   Run ONLY the pip config audit (verbose pretty view; --json supported)"),
	switchFlag("--pnpmrc", func(c *Config) *bool { return &c.PnpmRCOnly }, helpOptions,
		"  --pnpmrc                      Run ONLY the pnpm config audit (verbose pretty view; --json supported)"),
	switchFlag("--bunfig", func(c *Config) *bool { return &c.BunfigOnly }, helpOptions,
		"  --bunfig                      Run ONLY the bun config audit (verbose pretty view; --json supported)"),
	switchFlag("--yarnrc", func(c *Config) *bool { return &c.YarnRCOnly }, helpOptions,
		"  --yarnrc                      Run ONLY the yarn config audit covering both v1 (.yarnrc) and v2+ (.yarnrc.yml) (verbose pretty view; --json supported)"),
	{name: "--log-level", kind: flagEquals, saves: []string{"log_level"}, section: helpOptions,
		help: "  --log-level=LEVEL      Log level: error | warn | info | debug (default: info)",
		set: func(c *Config, v string) error {
			level := strings.ToLower(v)
			switch level {
			case "error", "warn", "warning", "info", "debug":
				if level == "warning" {
					level = "warn"
				}
				c.LogLevel = level
				c.save("log_level", level)
				return nil
			}
			return fmt.Errorf("invalid log level: %s (must be error, warn, info, or debug)", level)
		}},
	{name: "--install-dir", kind: flagValue, saves: []string{"install_dir"}, section: helpOptions,
		missing: "--install-dir requires a directory argument (use --install-dir= to disable file logging)",
		help: `  --install-dir=DIR      Base directory the agent puts ALL its files under
                         (logs, hook errors, binary placement via loader).
                         Default: ~/.stepsecurity. The diagnostic log file is
                         <DIR>/agent.error.log, rotated at 5 MiB to .prev.
                         Equivalent to STEPSECURITY_HOME env var. Pass
                         --install-dir= (empty) to disable file logging for
                         this run. Note: config.json itself always lives at
                         ~/.stepsecurity/config.json for bootstrap.`,
		set: func(c *Config, v string) error {
			c.InstallDir = v
			c.InstallDirSet = true
			if v == "" { // empty disables file logging for this run only
				c.unsave("install_dir")
			} else {
				c.save("install_dir", v)
			}
			return nil
		}},
	switchFlag("--verbose", func(c *Config) *bool { return &c.Verbose }, helpOptions,
		"  --verbose                     Shortcut for --log-level=debug"),
	{name: "--color", kind: flagEquals, saves: []string{"color_mode"}, section: helpOptions,
		help: "  --color=WHEN           Color mode: auto | always | never (default: auto)",
		set: func(c *Config, v string) error {
			if v != "auto" && v != "always" && v != "never" {
				return fmt.Errorf("invalid color mode: %s (must be auto, always, or never)", v)
			}
			c.ColorMode = v
			saved := v
			if v == "auto" {
				saved = "" // the default is stored as an omitted key
			}
			c.save("color_mode", saved)
			return nil
		}},

	switchFlag("--non-interactive", func(c *Config) *bool { return &c.NonInteractive }, helpConfigure,
		"  --non-interactive             Skip prompts; require values via flags or --from-file"),
	stringFlag("--from-file", func(c *Config) *string { return &c.ConfigFromFile }, "--from-file requires a file path argument", helpConfigure,
		"  --from-file PATH              Read full config JSON from PATH (preferred for MSI)"),
	configFlag("--customer-id", "customer_id",
		"  --customer-id ID              Customer identifier"),
	configFlag("--api-endpoint", "api_endpoint",
		"  --api-endpoint URL            StepSecurity backend URL"),
	configFlag("--api-key", "api_key",
		"  --api-key KEY                 Authentication key (or set DMG_API_KEY env var)"),
	configFlag("--device-id", "device_id",
		"  --device-id ID                Custom device identifier (default: machine serial)"),
	func() flagSpec {
		f := configFlag("--scan-frequency", "scan_frequency_hours",
			"  --scan-frequency HOURS        Scheduled scan frequency")
		f.missing = "--scan-frequency requires a value (hours)"
		return f
	}(),
	func() flagSpec {
		f := configFlag("--max-execution-duration", "max_execution_duration",
			"  --max-execution-duration D    Whole-run watchdog (e.g. 2h, 30m; off to disable)")
		f.missing = "--max-execution-duration requires a value (e.g. 2h, 30m, off)"
		return f
	}(),
	{name: "--auto-update", kind: flagEquals, saves: []string{"auto_update"}, section: helpConfigure,
		help: "  --auto-update=BOOL            Windows MSI self-update on (default) or off",
		set: func(c *Config, v string) error {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("--auto-update must be true or false (also 1 or 0)")
			}
			c.save("auto_update", b)
			return nil
		}},
	configFlag("--update-mirror-url", "update_mirror_url",
		"  --update-mirror-url URL       HTTPS packages mirror for self-update"),
	intConfigFlag("--update-lag-behind", "update_lag_behind",
		"  --update-lag-behind N         Stay N releases behind the latest"),
	intConfigFlag("--update-cooldown-hours", "update_cooldown_hours",
		"  --update-cooldown-hours N     Wait N hours after a release before updating"),
	switchFlag("--ignore-telemetry-error", func(c *Config) *bool { return &c.IgnoreTelemetryError }, helpConfigure,
		`  --ignore-telemetry-error      On 'install', treat a failed initial telemetry POST
                                as a warning instead of a fatal exit (use in MSI
                                custom actions to avoid rollback on transient network)`),

	switchFlag("--override-gate", func(c *Config) *bool { return &c.OverrideGate }, helpHidden, ""),
	switchFlag("--force-scan", func(c *Config) *bool { return &c.ForceScan }, helpHidden, ""),
	stringFlag("--config", func(c *Config) *string { return &c.ConfigFile }, "--config requires a file path argument", helpHidden, ""),
	stringFlag("--wsl-host-serial", func(c *Config) *string { return &c.WSLHostSerial }, "", helpHidden, ""),
	stringFlag("--wsl-distro-id", func(c *Config) *string { return &c.WSLDistroID }, "", helpHidden, ""),
	stringFlag("--rules-file", func(c *Config) *string { return &c.RulesFile }, "--rules-file requires a file path argument", helpHidden, ""),
	stringFlag("--telemetry-out", func(c *Config) *string { return &c.TelemetryOutFile }, "--telemetry-out requires a file path argument", helpHidden, ""),
}

var flagsByName = func() map[string]*flagSpec {
	m := make(map[string]*flagSpec, len(flagTable))
	for i := range flagTable {
		m[flagTable[i].name] = &flagTable[i]
	}
	return m
}()

// parseFlag applies the flag at args[i] and returns the index of the next
// unconsumed argument. ok is false when args[i] is not a known flag.
func parseFlag(cfg *Config, args []string, i int) (next int, ok bool, err error) {
	name, value, hasValue := strings.Cut(args[i], "=")
	f := flagsByName[name]
	if f == nil {
		return i, false, nil
	}
	// A spelling the flag doesn't take (--json=x, a bare --color) is an
	// unknown option, as it always was.
	switch f.kind {
	case flagEquals:
		if !hasValue {
			return i, false, nil
		}
	case flagSwitch, flagSpaced, flagList:
		if hasValue {
			return i, false, nil
		}
	}
	missing := func() error {
		if f.missing != "" {
			return fmt.Errorf("%s", f.missing)
		}
		return fmt.Errorf("%s requires a value", f.name)
	}
	switch {
	case f.kind == flagSwitch:
		return i + 1, true, f.set(cfg, "")
	case hasValue:
		return i + 1, true, f.set(cfg, value)
	case f.kind == flagList:
		i++
		if i >= len(args) || strings.HasPrefix(args[i], "--") {
			return i, true, missing()
		}
		for ; i < len(args) && !strings.HasPrefix(args[i], "--"); i++ {
			if err := f.set(cfg, args[i]); err != nil {
				return i, true, err
			}
		}
		return i, true, nil
	default: // flagValue / flagSpaced without "="
		if i+1 >= len(args) {
			return i + 1, true, missing()
		}
		return i + 2, true, f.set(cfg, args[i+1])
	}
}

// helpFor renders a section's flags, one help entry per line.
func helpFor(section helpSection) string {
	var b strings.Builder
	for _, f := range flagTable {
		if f.section == section {
			b.WriteString(f.help)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// savedFlagsNote lists the documented scan/output flags that `configure`
// also writes to config.json.
func savedFlagsNote() string {
	var names []string
	for _, f := range flagTable {
		if len(f.saves) > 0 && (f.section == helpOutput || f.section == helpOptions) {
			names = append(names, f.name)
		}
	}
	var b strings.Builder
	b.WriteString("  Passed to 'configure', these flags are also saved to config.json:\n")
	line := " "
	for i, n := range names {
		word := " " + n
		if i < len(names)-1 {
			word += ","
		}
		if len(line)+len(word) > 78 {
			b.WriteString(line + "\n")
			line = " "
		}
		line += word
	}
	b.WriteString(line + "\n")
	return b.String()
}
