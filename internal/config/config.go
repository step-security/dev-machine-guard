package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Default placeholders (replaced by backend for enterprise installation scripts).
var (
	CustomerID          = "{{CUSTOMER_ID}}"
	APIEndpoint         = "{{API_ENDPOINT}}"
	APIKey              = "{{API_KEY}}" //#nosec G101 -- build-time placeholder substituted by the backend installer; the literal is not a real credential.
	ScanFrequencyHours  = "{{SCAN_FREQUENCY_HOURS}}"
	SearchDirs          []string
	EnableNPMScan       *bool  // nil=auto
	EnableBrewScan      *bool  // nil=auto
	EnablePythonScan    *bool  // nil=auto
	IncludeTCCProtected *bool  // nil or false = skip macOS TCC-protected dirs (default); true = walk them. The scan as a whole runs in both cases; only reads inside the TCC-protected subtrees themselves (Documents, Mail, etc.) need the agent to have Full Disk Access (PPPC or manual grant) — without that, those walks return EACCES per entry while the rest of the scan completes normally. See docs/macos-tcc-permissions.md.
	ColorMode           string // "" means auto
	OutputFormat        string // "" means default (pretty)
	HTMLOutputFile      string // "" means not set
	LogLevel            string // "" means default (info); one of error/warn/info/debug
	InstallDir          string // "" means default (~/.stepsecurity); non-empty makes the agent put all its files (logs, hook errors, future state) under this directory. Bootstrap config.json itself stays at the legacy location. Per-run opt-out is the CLI flag --install-dir=. Resolution: --install-dir flag > STEPSECURITY_HOME env > this field > default — see internal/paths.
	// UseLegacyPackageScan, when true, disables the scan-state delta-upload
	// optimization for npm and Python project scans — every run re-uploads
	// the full snapshot as in pre-1.13 agents. Default false = optimized.
	// Environment override: STEPSEC_DISABLE_SCAN_STATE=1 takes precedence.
	UseLegacyPackageScan bool
)

// MaxExecutionDuration is the whole-process execution-watchdog limit
// (STEPSEC_MAX_EXECUTION_DURATION). Persisted into config.json at install time
// so scheduler-fired runs (launchd/systemd/schtasks) — which invoke the binary
// directly and never inherit the loader-exported env var — resolve the same
// value the loader configured. "" means fall back to the binary's built-in
// default (4h). Declared in its own var block (not the placeholder group
// above) because it carries no build-time {{...}} placeholder. See
// telemetry.ExecutionDeadline.
var MaxExecutionDuration string

// ConfigFile is the JSON structure persisted to ~/.stepsecurity/config.json.
type ConfigFile struct {
	CustomerID           string   `json:"customer_id,omitempty"`
	APIEndpoint          string   `json:"api_endpoint,omitempty"`
	APIKey               string   `json:"api_key,omitempty"`
	ScanFrequencyHours   string   `json:"scan_frequency_hours,omitempty"`
	SearchDirs           []string `json:"search_dirs,omitempty"`
	EnableNPMScan        *bool    `json:"enable_npm_scan,omitempty"`
	EnableBrewScan       *bool    `json:"enable_brew_scan,omitempty"`
	EnablePythonScan     *bool    `json:"enable_python_scan,omitempty"`
	IncludeTCCProtected  *bool    `json:"include_tcc_protected,omitempty"`
	ColorMode            string   `json:"color_mode,omitempty"`
	OutputFormat         string   `json:"output_format,omitempty"`
	HTMLOutputFile       string   `json:"html_output_file,omitempty"`
	LogLevel             string   `json:"log_level,omitempty"`
	InstallDir           string   `json:"install_dir,omitempty"`
	MaxExecutionDuration string   `json:"max_execution_duration,omitempty"`
	UseLegacyPackageScan bool     `json:"use_legacy_package_scan,omitempty"`
}

// userConfigDir returns ~/.stepsecurity — the per-user config location.
// Used by community installs and by enterprise installs done via a
// developer's own login (not via MSI/SCCM).
func userConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".stepsecurity")
}

// machineConfigDir returns the machine-wide config dir on Windows (and ""
// elsewhere). Defined in config_windows.go / config_other.go.
//
// On Windows, MSI custom actions run as SYSTEM and the scheduled task runs
// as the logged-in user — the two never share a $HOME, so config has to
// live somewhere both can read. C:\ProgramData is that place.

// readConfigDir returns the directory we should READ config from.
// Prefers machine-wide if a config exists there (so an MSI-deployed install
// is visible even when the scanner runs as an unprivileged user).
func readConfigDir() string {
	if mcd := machineConfigDir(); mcd != "" {
		if _, err := os.Stat(filepath.Join(mcd, "config.json")); err == nil {
			return mcd
		}
	}
	return userConfigDir()
}

// writeConfigDir returns the directory we should WRITE config to.
// Elevated/admin/SYSTEM context → machine-wide (Windows only). Otherwise
// per-user. This is what makes `configure` invoked from an MSI custom
// action put the config where the scheduled task can later read it.
func writeConfigDir() string {
	if isElevated() {
		if mcd := machineConfigDir(); mcd != "" {
			return mcd
		}
	}
	return userConfigDir()
}

// ConfigFilePath returns the path to the config file (read-preferred).
func ConfigFilePath() string {
	return filepath.Join(readConfigDir(), "config.json")
}

// WriteConfigFilePath returns the path config would be written to under
// the current process's privilege level. Surfaced so `configure show` /
// install messages can name the exact file the next save will touch.
func WriteConfigFilePath() string {
	return filepath.Join(writeConfigDir(), "config.json")
}

// LegacyDirName is the basename of the per-user agent directory under
// $HOME. config.json always lives here so the agent can bootstrap;
// other files (logs, hook errors, the binary) may be relocated via the
// resolved install dir — see internal/paths.
const LegacyDirName = ".stepsecurity"

// LegacyDir returns the per-user agent directory (~/.stepsecurity), used
// as the reference point for the install-dir migration warning in main:
// if the operator has moved the install dir but this directory still
// holds diagnostic files, the agent surfaces a heads-up. Returns "" when
// $HOME can't be resolved.
//
// Distinct from ConfigFilePath / WriteConfigFilePath above: those follow
// the machine-vs-user resolution that lets MSI-deployed installs share
// config with a scheduled task running as a logged-in user. LegacyDir is
// always per-user, regardless of elevation.
func LegacyDir() string {
	return userConfigDir()
}

// Load reads the config file and applies values to the package-level variables.
// Values already set (not placeholders) are not overridden — build-time values take precedence.
func Load() {
	data, err := os.ReadFile(ConfigFilePath())
	if err != nil {
		return // no config file, use defaults
	}

	var cfg ConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return
	}

	if cfg.CustomerID != "" && isPlaceholder(CustomerID) {
		CustomerID = cfg.CustomerID
	}
	if cfg.APIEndpoint != "" && isPlaceholder(APIEndpoint) {
		APIEndpoint = NormalizeAPIEndpoint(cfg.APIEndpoint)
	}
	if cfg.APIKey != "" && isPlaceholder(APIKey) {
		APIKey = cfg.APIKey
	}
	if cfg.ScanFrequencyHours != "" && isPlaceholder(ScanFrequencyHours) {
		ScanFrequencyHours = cfg.ScanFrequencyHours
	}
	if len(cfg.SearchDirs) > 0 {
		SearchDirs = cfg.SearchDirs
	}
	if cfg.EnableNPMScan != nil && EnableNPMScan == nil {
		EnableNPMScan = cfg.EnableNPMScan
	}
	if cfg.EnableBrewScan != nil && EnableBrewScan == nil {
		EnableBrewScan = cfg.EnableBrewScan
	}
	if cfg.EnablePythonScan != nil && EnablePythonScan == nil {
		EnablePythonScan = cfg.EnablePythonScan
	}
	if cfg.IncludeTCCProtected != nil && IncludeTCCProtected == nil {
		IncludeTCCProtected = cfg.IncludeTCCProtected
	}
	if cfg.ColorMode != "" && ColorMode == "" {
		ColorMode = cfg.ColorMode
	}
	if cfg.OutputFormat != "" && OutputFormat == "" {
		OutputFormat = cfg.OutputFormat
	}
	if cfg.HTMLOutputFile != "" && HTMLOutputFile == "" {
		HTMLOutputFile = cfg.HTMLOutputFile
	}
	if cfg.LogLevel != "" && LogLevel == "" {
		LogLevel = cfg.LogLevel
	}
	if cfg.InstallDir != "" && InstallDir == "" {
		InstallDir = cfg.InstallDir
	}
	if cfg.MaxExecutionDuration != "" && MaxExecutionDuration == "" {
		MaxExecutionDuration = cfg.MaxExecutionDuration
	}
	if cfg.UseLegacyPackageScan {
		UseLegacyPackageScan = true
	}
}

// IsEnterpriseMode returns true if valid enterprise credentials are configured.
func IsEnterpriseMode() bool {
	return APIKey != "" && !strings.Contains(APIKey, "{{")
}

// RunConfigure interactively prompts for config values and saves to the config file.
func RunConfigure() error {
	reader := bufio.NewReader(os.Stdin)

	// Load existing config to show current values
	existing := loadExisting()

	fmt.Println("StepSecurity Dev Machine Guard — Configuration")
	fmt.Println()
	fmt.Println("Enter new values or press Enter to keep the current value.")
	fmt.Println("To clear a value, enter a single dash (-).")
	fmt.Println()

	existing.CustomerID = promptValue(reader, "Customer ID", existing.CustomerID)
	existing.APIEndpoint = promptValue(reader, "API Endpoint", existing.APIEndpoint)
	existing.APIKey = promptSecret(reader, "API Key", existing.APIKey)
	existing.ScanFrequencyHours = promptValue(reader, "Scan Frequency (hours)", existing.ScanFrequencyHours)

	// Search dirs
	currentDirs := ""
	if len(existing.SearchDirs) > 0 {
		currentDirs = strings.Join(existing.SearchDirs, ", ")
	}
	dirsInput := promptValue(reader, "Search Directories (comma-separated)", currentDirs)
	if dirsInput != "" {
		dirs := strings.Split(dirsInput, ",")
		existing.SearchDirs = nil
		for _, d := range dirs {
			d = strings.TrimSpace(d)
			if d != "" {
				existing.SearchDirs = append(existing.SearchDirs, d)
			}
		}
	} else {
		existing.SearchDirs = nil
	}

	// Enable npm scan
	currentNPM := "auto"
	if existing.EnableNPMScan != nil {
		if *existing.EnableNPMScan {
			currentNPM = "true"
		} else {
			currentNPM = "false"
		}
	}
	npmInput := promptValue(reader, "Enable NPM Scan (auto/true/false)", currentNPM)
	switch strings.ToLower(npmInput) {
	case "true":
		v := true
		existing.EnableNPMScan = &v
	case "false":
		v := false
		existing.EnableNPMScan = &v
	default:
		existing.EnableNPMScan = nil // auto
	}

	// Enable brew scan
	currentBrew := "auto"
	if existing.EnableBrewScan != nil {
		if *existing.EnableBrewScan {
			currentBrew = "true"
		} else {
			currentBrew = "false"
		}
	}
	brewInput := promptValue(reader, "Enable Homebrew Scan (auto/true/false)", currentBrew)
	switch strings.ToLower(brewInput) {
	case "true":
		v := true
		existing.EnableBrewScan = &v
	case "false":
		v := false
		existing.EnableBrewScan = &v
	default:
		existing.EnableBrewScan = nil
	}

	// Enable python scan
	currentPython := "auto"
	if existing.EnablePythonScan != nil {
		if *existing.EnablePythonScan {
			currentPython = "true"
		} else {
			currentPython = "false"
		}
	}
	pythonInput := promptValue(reader, "Enable Python Scan (auto/true/false)", currentPython)
	switch strings.ToLower(pythonInput) {
	case "true":
		v := true
		existing.EnablePythonScan = &v
	case "false":
		v := false
		existing.EnablePythonScan = &v
	default:
		existing.EnablePythonScan = nil
	}

	// Color mode
	currentColor := existing.ColorMode
	if currentColor == "" {
		currentColor = "auto"
	}
	colorInput := promptValue(reader, "Color Mode (auto/always/never)", currentColor)
	switch strings.ToLower(colorInput) {
	case "always", "never":
		existing.ColorMode = strings.ToLower(colorInput)
	default:
		existing.ColorMode = "" // auto (omit from config)
	}

	// Output format
	currentFormat := existing.OutputFormat
	if currentFormat == "" {
		currentFormat = "pretty"
	}
	formatInput := promptValue(reader, "Output Format (pretty/json/html)", currentFormat)
	switch strings.ToLower(formatInput) {
	case "json", "html":
		existing.OutputFormat = strings.ToLower(formatInput)
	default:
		existing.OutputFormat = "" // pretty is the default (omit from config)
	}

	// HTML output file (only relevant when output_format is html)
	if existing.OutputFormat == "html" {
		existing.HTMLOutputFile = promptValue(reader, "HTML Output File", existing.HTMLOutputFile)
	}

	// Log level
	currentLevel := existing.LogLevel
	if currentLevel == "" {
		currentLevel = "info"
	}
	levelInput := promptValue(reader, "Log Level (error/warn/info/debug)", currentLevel)
	switch strings.ToLower(strings.TrimSpace(levelInput)) {
	case "error", "warn", "warning", "info", "debug":
		existing.LogLevel = strings.ToLower(strings.TrimSpace(levelInput))
		if existing.LogLevel == "warning" {
			existing.LogLevel = "warn"
		}
	default:
		existing.LogLevel = "info"
	}

	// Install directory override (empty = ~/.stepsecurity). All
	// non-bootstrap files live under this directory: agent.log,
	// agent.error.log (+ .prev rotation), ai-agent-hook-errors.jsonl,
	// and the binary itself when placed via the loader script.
	// Bootstrap config.json keeps living at the legacy ~/.stepsecurity
	// path so the agent can always find it. To temporarily override
	// for one run, pass --install-dir=PATH or set $STEPSECURITY_HOME.
	existing.InstallDir = promptValue(reader, "Install Directory (blank = default)", existing.InstallDir)

	// Save
	if err := save(existing); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	fmt.Println()
	fmt.Printf("Configuration saved to %s\n", ConfigFilePath())
	return nil
}

// promptSecret shows a masked current value but keeps the real value on Enter.
func promptSecret(reader *bufio.Reader, label, current string) string {
	masked := maskSecret(current)
	if masked != "(not set)" {
		fmt.Printf("  %s [%s]: ", label, masked)
	} else {
		fmt.Printf("  %s: ", label)
	}

	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)

	if line == "-" {
		return "" // clear value
	}
	if line == "" {
		return current // keep real value
	}
	return line
}

func promptValue(reader *bufio.Reader, label, current string) string {
	if current != "" {
		fmt.Printf("  %s [%s]: ", label, current)
	} else {
		fmt.Printf("  %s: ", label)
	}

	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)

	if line == "-" {
		return "" // clear value
	}
	if line == "" {
		return current // keep existing
	}
	return line
}

func loadExisting() *ConfigFile {
	data, err := os.ReadFile(ConfigFilePath())
	if err != nil {
		return &ConfigFile{}
	}
	var cfg ConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return &ConfigFile{}
	}
	return &cfg
}

// NormalizeAPIEndpoint strips trailing slashes and surrounding whitespace
// from an API endpoint URL. Every callsite in the agent composes URLs as
// fmt.Sprintf("%s/v1/...", APIEndpoint, ...) — a trailing slash on the
// configured value would compose to "//v1/..." and some gateways respond
// with 403/500 instead of normalizing. Normalising once at the config
// boundary keeps every consumer simple.
func NormalizeAPIEndpoint(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}

func save(cfg *ConfigFile) error {
	cfg.APIEndpoint = NormalizeAPIEndpoint(cfg.APIEndpoint)
	dir := writeConfigDir()

	// File-mode bits below ARE meaningful on POSIX (per-user community installs
	// on macOS/Linux); on Windows they're ignored by the OS — access is
	// controlled exclusively by ACLs. We set the mode for POSIX correctness
	// and harden Windows access separately via hardenMachineConfigACL below.
	dirMode := os.FileMode(0o700)
	fileMode := os.FileMode(0o600)
	machineWide := isElevated() && machineConfigDir() != "" && dir == machineConfigDir()
	if machineWide {
		// Machine-wide install: the scheduled task fires under a less-privileged
		// logged-in user account (see schtasks.go's /ru INTERACTIVE), so the
		// file must be READABLE by that user — but should not be writable by
		// non-admins. hardenMachineConfigACL handles the Windows-specific ACL.
		dirMode = 0o755
		fileMode = 0o644
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, fileMode); err != nil {
		return err
	}

	if machineWide {
		// Best-effort ACL hardening. Failure does not block the install — the
		// config is still functional, just inheriting default ProgramData ACLs.
		// Note: api_key persists in plaintext on disk. On multi-user dev
		// machines this is a known tradeoff, documented in deploying-via-sccm.md.
		// Customers needing stronger isolation should use the --from-file
		// bootstrap pattern and lock down the bootstrap file separately.
		_ = hardenMachineConfigACL(configPath)
	}

	return nil
}

// ShowConfigure prints the current configuration to stdout.
func ShowConfigure() {
	cfg := loadExisting()

	fmt.Printf("Configuration (%s):\n\n", ConfigFilePath())
	fmt.Printf("  %-24s %s\n", "Customer ID:", displayValue(cfg.CustomerID))
	fmt.Printf("  %-24s %s\n", "API Endpoint:", displayValue(cfg.APIEndpoint))
	fmt.Printf("  %-24s %s\n", "API Key:", maskSecret(cfg.APIKey))
	fmt.Printf("  %-24s %s\n", "Scan Frequency:", displayFrequency(cfg.ScanFrequencyHours))
	fmt.Printf("  %-24s %s\n", "Search Directories:", displayDirs(cfg.SearchDirs))
	fmt.Printf("  %-24s %s\n", "Enable NPM Scan:", displayBoolScan(cfg.EnableNPMScan))
	fmt.Printf("  %-24s %s\n", "Enable Brew Scan:", displayBoolScan(cfg.EnableBrewScan))
	fmt.Printf("  %-24s %s\n", "Enable Python Scan:", displayBoolScan(cfg.EnablePythonScan))
	fmt.Printf("  %-24s %s\n", "Color Mode:", displayColorMode(cfg.ColorMode))
	fmt.Printf("  %-24s %s\n", "Output Format:", displayOutputFormat(cfg.OutputFormat))
	if cfg.OutputFormat == "html" {
		fmt.Printf("  %-24s %s\n", "HTML Output File:", displayValue(cfg.HTMLOutputFile))
	}
	fmt.Printf("  %-24s %s\n", "Log Level:", displayLogLevel(cfg.LogLevel))
	fmt.Printf("  %-24s %s\n", "Install Directory:", displayInstallDir(cfg.InstallDir))
}

func displayValue(v string) string {
	if v == "" {
		return "(not set)"
	}
	return v
}

func maskSecret(v string) string {
	if v == "" {
		return "(not set)"
	}
	if len(v) <= 6 {
		return "***"
	}
	return "***" + v[len(v)-4:]
}

func displayFrequency(v string) string {
	if v == "" {
		return "(not set)"
	}
	if v == "1" {
		return v + " hour"
	}
	return v + " hours"
}

func displayDirs(dirs []string) string {
	if len(dirs) == 0 {
		return "(not set — defaults to $HOME)"
	}
	return strings.Join(dirs, ", ")
}

func displayBoolScan(v *bool) string {
	if v == nil {
		return "auto"
	}
	if *v {
		return "true"
	}
	return "false"
}

func displayColorMode(v string) string {
	if v == "" {
		return "auto"
	}
	return v
}

func displayOutputFormat(v string) string {
	if v == "" {
		return "pretty"
	}
	return v
}

func displayLogLevel(level string) string {
	if level == "" {
		return "info (default)"
	}
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error", "warn", "warning", "info", "debug":
		return level
	default:
		return fmt.Sprintf("%s (invalid — using info)", level)
	}
}

func displayInstallDir(v string) string {
	if v == "" {
		return "~/.stepsecurity (default)"
	}
	return v
}

func isPlaceholder(v string) bool {
	return strings.Contains(v, "{{")
}

// NonInteractiveOptions captures every input the non-interactive configure
// path accepts. Populated by main.go from cli.Config plus the DMG_API_KEY
// env var fallback. Empty fields preserve the existing on-disk value
// (merge semantics — same as the interactive prompt's "press Enter to keep").
type NonInteractiveOptions struct {
	FromFile      string   // path to a complete ConfigFile JSON; wins over inline values
	CustomerID    string   // --customer-id
	APIEndpoint   string   // --api-endpoint
	APIKey        string   // --api-key (or DMG_API_KEY env)
	ScanFrequency string   // --scan-frequency (hours, as string)
	SearchDirs    []string // --search-dirs (re-used from scan flag; empty = unchanged)
}

// HasAny reports whether the caller supplied any inline value. Used by
// main.go to decide whether `configure` was invoked non-interactively
// even without the explicit --non-interactive flag (e.g. an MSI that only
// passes --from-file).
func (o NonInteractiveOptions) HasAny() bool {
	return o.FromFile != "" ||
		o.CustomerID != "" ||
		o.APIEndpoint != "" ||
		o.APIKey != "" ||
		o.ScanFrequency != "" ||
		len(o.SearchDirs) > 0
}

// RunConfigureNonInteractive applies the supplied options to the existing
// on-disk config and saves. Designed for MSI custom actions, CI, and any
// orchestrator that can't drive stdin prompts. Always writes to
// writeConfigDir() — so an MSI running as SYSTEM lands config under
// C:\ProgramData\StepSecurity where the scheduled task (running as the
// logged-in user) can read it.
func RunConfigureNonInteractive(opts NonInteractiveOptions) error {
	existing := loadExisting()

	// --from-file: replace base. Inline flags still override individual
	// fields below, so customers can ship a base config via the file and
	// inject the per-tenant API key via an env var on the command line.
	if opts.FromFile != "" {
		data, err := os.ReadFile(opts.FromFile)
		if err != nil {
			return fmt.Errorf("reading --from-file %q: %w", opts.FromFile, err)
		}
		var fromFile ConfigFile
		if err := json.Unmarshal(data, &fromFile); err != nil {
			return fmt.Errorf("parsing --from-file %q: %w", opts.FromFile, err)
		}
		existing = &fromFile
	}

	if opts.CustomerID != "" {
		existing.CustomerID = opts.CustomerID
	}
	if opts.APIEndpoint != "" {
		existing.APIEndpoint = opts.APIEndpoint
	}
	if opts.APIKey != "" {
		existing.APIKey = opts.APIKey
	}
	if opts.ScanFrequency != "" {
		existing.ScanFrequencyHours = opts.ScanFrequency
	}
	if len(opts.SearchDirs) > 0 {
		existing.SearchDirs = opts.SearchDirs
	}

	// Validation: an MSI deploy with no creds is almost certainly a bug.
	// Fail loud so the MSI transaction rolls back instead of silently
	// installing a half-configured agent.
	if existing.APIKey == "" {
		return fmt.Errorf("api_key is required (pass --api-key, --from-file, or DMG_API_KEY env var)")
	}
	if existing.CustomerID == "" {
		return fmt.Errorf("customer_id is required (pass --customer-id or --from-file)")
	}
	if existing.APIEndpoint == "" {
		return fmt.Errorf("api_endpoint is required (pass --api-endpoint or --from-file)")
	}

	if err := save(existing); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	fmt.Printf("Configuration saved to %s\n", WriteConfigFilePath())
	return nil
}

// PersistMaxExecutionDuration records the STEPSEC_MAX_EXECUTION_DURATION value
// the loader exported into config.json at install time. Scheduler-fired runs
// (launchd/systemd/schtasks) invoke the binary directly and never inherit the
// loader's exported env var, so without this they fall back to the built-in 4h
// default regardless of the loader's MAX_EXECUTION_DURATION_HOURS. Persisting
// it lets telemetry.ExecutionDeadline pick it up on every scheduled run.
// Read-modify-write so the loader-written customer_id/api_key/etc. survive.
// No-op when value is empty (a direct binary install with no loader-configured
// value keeps the built-in default).
func PersistMaxExecutionDuration(value string) error {
	if value == "" {
		return nil
	}
	existing := loadExisting()
	if existing.MaxExecutionDuration == value {
		return nil
	}
	existing.MaxExecutionDuration = value
	return save(existing)
}
