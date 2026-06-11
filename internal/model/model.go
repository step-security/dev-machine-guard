package model

// ScanResult is the community-mode JSON output structure.
type ScanResult struct {
	AgentVersion      string          `json:"agent_version"`
	AgentURL          string          `json:"agent_url"`
	ScanTimestamp     int64           `json:"scan_timestamp"`
	ScanTimestampISO  string          `json:"scan_timestamp_iso"`
	Device            Device          `json:"device"`
	AIAgentsAndTools  []AITool        `json:"ai_agents_and_tools"`
	IDEInstallations  []IDE           `json:"ide_installations"`
	IDEExtensions     []Extension     `json:"ide_extensions"`
	MCPConfigs        []MCPConfig     `json:"mcp_configs"`
	NodePkgManagers   []PkgManager    `json:"node_package_managers"`
	NodePackages      []any           `json:"node_packages"`
	NodeProjects      []ProjectInfo   `json:"node_projects"`
	BrewPkgManager    *PkgManager     `json:"brew_package_manager,omitempty"`
	BrewFormulae      []BrewPackage   `json:"brew_formulae"`
	BrewCasks         []BrewPackage   `json:"brew_casks"`
	PythonPkgManagers []PkgManager    `json:"python_package_managers"`
	PythonPackages    []PythonPackage `json:"python_packages"`
	PythonProjects    []ProjectInfo   `json:"python_projects"`
	SystemPkgManager  *PkgManager     `json:"system_package_manager,omitempty"`
	SystemPackages    []SystemPackage `json:"system_packages"`
	SnapPkgManager    *PkgManager     `json:"snap_package_manager,omitempty"`
	SnapPackages      []SystemPackage `json:"snap_packages"`
	FlatpakPkgManager *PkgManager     `json:"flatpak_package_manager,omitempty"`
	FlatpakPackages   []SystemPackage `json:"flatpak_packages"`
	NPMRCAudit        *NPMRCAudit     `json:"npmrc_audit,omitempty"`
	PipAudit          *PipAudit       `json:"pip_audit,omitempty"`
	PnpmAudit         *PnpmAudit      `json:"pnpm_audit,omitempty"`
	BunAudit          *BunAudit       `json:"bun_audit,omitempty"`
	YarnAudit         *YarnAudit      `json:"yarn_audit,omitempty"`
	Summary           Summary         `json:"summary"`
}

type Device struct {
	Hostname     string           `json:"hostname"`
	SerialNumber string           `json:"serial_number"`
	OSVersion    string           `json:"os_version"`
	Platform     string           `json:"platform"`
	UserIdentity string           `json:"user_identity"`
	Resources    MachineResources `json:"resources"`
}

// MachineResources captures the static hardware capacity of the machine —
// what's there, not what's currently in use. Answers "how much resource
// does this machine have?".
type MachineResources struct {
	CPUModel        string `json:"cpu_model"`        // e.g. "Apple M3 Pro", "Intel(R) Core(TM) i9-13900K"
	CPUArchitecture string `json:"cpu_architecture"` // "arm64", "amd64"
	PhysicalCores   int    `json:"physical_cores"`   // 0 if undeterminable
	LogicalCores    int    `json:"logical_cores"`    // includes SMT/hyperthreads
	MemoryBytes     uint64 `json:"memory_bytes"`     // total installed RAM
	DiskTotalBytes  uint64 `json:"disk_total_bytes"` // capacity of the system/root volume
}

// AITool represents a detected AI agent, CLI tool, framework, or general agent.
// Fields are conditionally present based on type (cli_tool, general_agent, framework).
type AITool struct {
	Name        string `json:"name"`
	Vendor      string `json:"vendor"`
	Type        string `json:"type"`
	Version     string `json:"version"`
	BinaryPath  string `json:"binary_path,omitempty"`
	InstallPath string `json:"install_path,omitempty"`
	ConfigDir   string `json:"config_dir,omitempty"`
	IsRunning   *bool  `json:"is_running,omitempty"`
}

type IDE struct {
	IDEType     string `json:"ide_type"`
	Version     string `json:"version"`
	InstallPath string `json:"install_path"`
	Vendor      string `json:"vendor"`
	IsInstalled bool   `json:"is_installed"`
}

type Extension struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallPath string `json:"install_path,omitempty"`
	InstallDate int64  `json:"install_date"`
	IDEType     string `json:"ide_type"`
	Source      string `json:"source,omitempty"` // "bundled" or "user_installed"
}

// MCPConfig represents a detected MCP server configuration (community mode).
type MCPConfig struct {
	ConfigSource string `json:"config_source"`
	ConfigPath   string `json:"config_path"`
	Vendor       string `json:"vendor"`
}

// MCPConfigEnterprise includes base64-encoded content for enterprise mode.
type MCPConfigEnterprise struct {
	ConfigSource        string `json:"config_source"`
	ConfigPath          string `json:"config_path"`
	Vendor              string `json:"vendor"`
	ConfigContentBase64 string `json:"config_content_base64,omitempty"`
}

type PkgManager struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

type Summary struct {
	AIAgentsAndToolsCount int `json:"ai_agents_and_tools_count"`
	IDEInstallationsCount int `json:"ide_installations_count"`
	IDEExtensionsCount    int `json:"ide_extensions_count"`
	MCPConfigsCount       int `json:"mcp_configs_count"`
	NodeProjectsCount     int `json:"node_projects_count"`
	BrewFormulaeCount     int `json:"brew_formulae_count"`
	BrewCasksCount        int `json:"brew_casks_count"`
	PythonProjectsCount   int `json:"python_projects_count"`
	SystemPackagesCount   int `json:"system_packages_count"`
	SnapPackagesCount     int `json:"snap_packages_count"`
	FlatpakPackagesCount  int `json:"flatpak_packages_count"`
}

// NodeScanResult holds raw scan output for enterprise telemetry.
// Used for both global packages and per-project scans.
type NodeScanResult struct {
	ProjectPath      string `json:"project_path"`
	PackageManager   string `json:"package_manager"`
	PMVersion        string `json:"package_manager_version"`
	WorkingDirectory string `json:"working_directory"`
	RawStdoutBase64  string `json:"raw_stdout_base64"`
	RawStderrBase64  string `json:"raw_stderr_base64"`
	Error            string `json:"error"`
	ExitCode         int    `json:"exit_code"`
	ScanDurationMs   int64  `json:"scan_duration_ms"`
}

// PackageDetail represents a single package name and version.
type PackageDetail struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ProjectInfo represents a detected project directory with its packages.
type ProjectInfo struct {
	Path           string          `json:"path"`
	PackageManager string          `json:"package_manager,omitempty"`
	Packages       []PackageDetail `json:"packages,omitempty"`
}

// SystemPackage represents a package installed via the system package manager
// (rpm, dpkg, pacman, apk, snap, flatpak).
type SystemPackage struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Arch            string `json:"arch,omitempty"`              // CPU architecture: x86_64, amd64, noarch, arm64, etc.
	Source          string `json:"source,omitempty"`            // Origin: source RPM, dpkg source, snap publisher, flatpak remote
	InstallPath     string `json:"install_path,omitempty"`      // On-disk install root. Populated for snap (/snap/<name>/current) and flatpak (~/.local/share/flatpak/app/<id> or /var/lib/flatpak/app/<id>). Not applicable for rpm/dpkg/pacman/apk (file collections).
	InstallTimeUnix int64  `json:"install_time_unix,omitempty"` // Unix epoch seconds when installed (rpm, dpkg, pacman)

	// Provenance & trust signals
	Vendor        string `json:"vendor,omitempty"`          // Distributor: rpm VENDOR, dpkg Origin
	Maintainer    string `json:"maintainer,omitempty"`      // Packager identity: rpm PACKAGER, dpkg Maintainer, apk maintainer, pacman Packager
	URL           string `json:"url,omitempty"`             // Upstream project URL
	License       string `json:"license,omitempty"`         // SPDX license expression
	Section       string `json:"section,omitempty"`         // dpkg Section category (e.g. "libs", "non-free/libs")
	Signature     string `json:"signature,omitempty"`       // Signature info: rpm SIGPGP/RSAHEADER, pacman Validated By
	BuildTimeUnix int64  `json:"build_time_unix,omitempty"` // Unix epoch when package was built (rpm, apk, pacman)

	// Size
	InstalledSize int64 `json:"installed_size,omitempty"` // Installed size in bytes (rpm SIZE, dpkg Installed-Size * 1024)

	// Sandboxing / confinement (snap, flatpak)
	Confinement string `json:"confinement,omitempty"` // snap: strict/classic/devmode
	Channel     string `json:"channel,omitempty"`     // snap tracking channel, flatpak branch
	Runtime     string `json:"runtime,omitempty"`     // flatpak runtime ref

	// Source control
	CommitHash string `json:"commit_hash,omitempty"` // apk commit, flatpak active commit
}

// BrewPackage represents a single installed Homebrew formula or cask.
type BrewPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`

	// Metadata (populated from brew info --json=v2)
	Tap                   string `json:"tap,omitempty"`                     // Source tap: "homebrew/core", "homebrew/cask", or custom
	Description           string `json:"description,omitempty"`             // Package description
	License               string `json:"license,omitempty"`                 // SPDX license (formulae only)
	Homepage              string `json:"homepage,omitempty"`                // Upstream project URL
	InstallPath           string `json:"install_path,omitempty"`            // On-disk install path: <prefix>/Cellar/<name>/<version> (formulae) or <prefix>/Caskroom/<token> (casks)
	InstallTimeUnix       int64  `json:"install_time_unix,omitempty"`       // Unix epoch when installed
	InstalledAsDependency bool   `json:"installed_as_dependency,omitempty"` // true if pulled in by another package
	Deprecated            bool   `json:"deprecated,omitempty"`              // true if package is deprecated upstream
	PouredFromBottle      bool   `json:"poured_from_bottle,omitempty"`      // true if installed from pre-built binary
	AutoUpdates           bool   `json:"auto_updates,omitempty"`            // cask: app handles its own updates
}

// PythonPackage represents a single installed Python package.
type PythonPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SystemPackageScanResult holds parsed system package data for enterprise telemetry.
// Unlike BrewScanResult (which sends raw base64), this sends pre-parsed packages
// since syspkg.go already handles the format-specific parsing edge cases.
type SystemPackageScanResult struct {
	ScanType       string          `json:"scan_type"` // "rpm", "dpkg", "pacman", "apk", "snap", "flatpak"
	PackageManager *PkgManager     `json:"package_manager,omitempty"`
	Packages       []SystemPackage `json:"packages"`
	PackagesCount  int             `json:"packages_count"`
	Error          string          `json:"error,omitempty"`
	ScanDurationMs int64           `json:"scan_duration_ms"`
}

// BrewScanResult holds raw Homebrew scan output for enterprise telemetry.
type BrewScanResult struct {
	ScanType        string `json:"scan_type"` // "formulae" or "casks"
	RawStdoutBase64 string `json:"raw_stdout_base64"`
	RawStderrBase64 string `json:"raw_stderr_base64"`
	Error           string `json:"error"`
	ExitCode        int    `json:"exit_code"`
	ScanDurationMs  int64  `json:"scan_duration_ms"`
	LineCount       int    `json:"line_count"`
}

// PythonScanResult holds raw Python scan output for enterprise telemetry.
type PythonScanResult struct {
	PackageManager  string `json:"package_manager"`
	PMVersion       string `json:"package_manager_version"`
	BinaryPath      string `json:"binary_path"` // Resolved path to the package manager binary
	RawStdoutBase64 string `json:"raw_stdout_base64"`
	RawStderrBase64 string `json:"raw_stderr_base64"`
	Error           string `json:"error"`
	ExitCode        int    `json:"exit_code"`
	ScanDurationMs  int64  `json:"scan_duration_ms"`
}

// FilterUserInstalledExtensions removes bundled/platform extensions,
// keeping only user-installed, marketplace, and dropins extensions.
func FilterUserInstalledExtensions(exts []Extension) []Extension {
	var filtered []Extension
	for _, ext := range exts {
		if ext.Source != "bundled" {
			filtered = append(filtered, ext)
		}
	}
	return filtered
}

// --- npmrc audit -------------------------------------------------------------
//
// Surface-only inventory of every .npmrc on the host plus the merged
// effective view npm itself would resolve. Drift detection (snapshot/diff
// across runs) and per-project effective overrides are intentionally out
// of scope for this iteration; see .plans/0005-npmrc-audit.md for the
// extension points.

// NPMRCAudit is the top-level structure produced by the npmrc detector.
type NPMRCAudit struct {
	Available      bool            `json:"npm_available"`
	NPMVersion     string          `json:"npm_version,omitempty"`
	NPMPath        string          `json:"npm_path,omitempty"`
	Files          []NPMRCFile     `json:"files"`
	Effective      *NPMRCEffective `json:"effective,omitempty"`
	Env            []NPMRCEnvVar   `json:"env"`
	DiscoveryError string          `json:"discovery_error,omitempty"`
}

// NPMRCFile is a single .npmrc file. Metadata is best-effort: fields that
// could not be determined (e.g. owner_name on Windows) are omitted.
type NPMRCFile struct {
	Path        string       `json:"path"`
	Scope       string       `json:"scope"` // builtin | global | user | project
	Exists      bool         `json:"exists"`
	Readable    bool         `json:"readable"`
	SizeBytes   int64        `json:"size_bytes,omitempty"`
	ModTimeUnix int64        `json:"mtime_unix,omitempty"`
	Mode        string       `json:"mode,omitempty"`
	OwnerUID    int          `json:"owner_uid,omitempty"`
	OwnerName   string       `json:"owner_name,omitempty"`
	GroupGID    int          `json:"group_gid,omitempty"`
	GroupName   string       `json:"group_name,omitempty"`
	SHA256      string       `json:"sha256,omitempty"`
	SymlinkTo   string       `json:"symlink_target,omitempty"`
	InGitRepo   bool         `json:"in_git_repo,omitempty"`
	GitTracked  bool         `json:"git_tracked,omitempty"`
	Entries     []NPMRCEntry `json:"entries,omitempty"`
	ParseError  string       `json:"parse_error,omitempty"`
}

// NPMRCEntry is one parsed line of a .npmrc file. DisplayValue is always
// safe to print: auth values are redacted to ***last4 (or *** when the
// secret is short). The raw value is never stored — ValueSHA256 is the
// only fingerprint kept.
type NPMRCEntry struct {
	Key          string   `json:"key"`
	DisplayValue string   `json:"display_value"`
	LineNum      int      `json:"line_num"`
	IsArray      bool     `json:"is_array,omitempty"`
	IsAuth       bool     `json:"is_auth,omitempty"`
	IsEnvRef     bool     `json:"is_env_ref,omitempty"`
	EnvRefVars   []string `json:"env_ref_vars,omitempty"`
	ValueSHA256  string   `json:"value_sha256,omitempty"`
	Quoted       bool     `json:"quoted,omitempty"`
}

// NPMRCEffective mirrors the merged-config view emitted by
// `npm config ls -l --json`. Auth values are returned by npm as
// "(protected)" — that's what we surface.
type NPMRCEffective struct {
	SourceByKey map[string]string `json:"source_by_key,omitempty"`
	Config      map[string]any    `json:"config,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// NPMRCEnvVar is a single npm-relevant process environment variable.
// Set=false records are kept so the audit shape stays stable across hosts.
type NPMRCEnvVar struct {
	Name         string `json:"name"`
	Set          bool   `json:"set"`
	DisplayValue string `json:"display_value,omitempty"`
	ValueSHA256  string `json:"value_sha256,omitempty"`
}

// PnpmAudit reuses NPMRCFile/NPMRCEnvVar — pnpm reads the same .npmrc syntax
// as npm. Only the effective view and env list diverge.
type PnpmAudit struct {
	Available      bool           `json:"pnpm_available"`
	PnpmVersion    string         `json:"pnpm_version,omitempty"`
	PnpmPath       string         `json:"pnpm_path,omitempty"`
	Files          []NPMRCFile    `json:"files"`
	Effective      *PnpmEffective `json:"effective,omitempty"`
	Env            []NPMRCEnvVar  `json:"env"`
	DiscoveryError string         `json:"discovery_error,omitempty"`
}

// PnpmEffective mirrors `pnpm config list --json`. SourceByKey is kept on
// the struct for renderer parity with npm but is typically empty — pnpm
// doesn't emit per-key source attribution.
type PnpmEffective struct {
	SourceByKey map[string]string `json:"source_by_key,omitempty"`
	Config      map[string]any    `json:"config,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// BunAudit has no Effective field — bun has no `config list` equivalent.
// Consumers render the union of parsed files. NPMRCFiles carries any .npmrc
// bun would read for auth.
type BunAudit struct {
	Available      bool            `json:"bun_available"`
	BunVersion     string          `json:"bun_version,omitempty"`
	BunPath        string          `json:"bun_path,omitempty"`
	Files          []BunConfigFile `json:"files"`
	NPMRCFiles     []NPMRCFile     `json:"npmrc_files"`
	Env            []NPMRCEnvVar   `json:"env"`
	DiscoveryError string          `json:"discovery_error,omitempty"`
}

// BunConfigFile is a single bunfig.toml. Scope: user | user-xdg | project.
type BunConfigFile struct {
	Path        string       `json:"path"`
	Scope       string       `json:"scope"`
	Exists      bool         `json:"exists"`
	Readable    bool         `json:"readable"`
	SizeBytes   int64        `json:"size_bytes,omitempty"`
	ModTimeUnix int64        `json:"mtime_unix,omitempty"`
	Mode        string       `json:"mode,omitempty"`
	OwnerUID    int          `json:"owner_uid,omitempty"`
	OwnerName   string       `json:"owner_name,omitempty"`
	GroupGID    int          `json:"group_gid,omitempty"`
	GroupName   string       `json:"group_name,omitempty"`
	SHA256      string       `json:"sha256,omitempty"`
	SymlinkTo   string       `json:"symlink_target,omitempty"`
	InGitRepo   bool         `json:"in_git_repo,omitempty"`
	GitTracked  bool         `json:"git_tracked,omitempty"`
	Sections    []BunSection `json:"sections,omitempty"`
	ParseError  string       `json:"parse_error,omitempty"`
}

// BunSection groups NPMRCEntry by dotted section path (e.g. "install",
// "install.scopes.@step-security"). Entry LineNum is always 0 — go-toml/v2
// doesn't cheaply expose per-key positions.
type BunSection struct {
	Name    string       `json:"name"`
	Entries []NPMRCEntry `json:"entries"`
}

// YarnAudit covers both classic (v1.x, .yarnrc) and berry (v2+, .yarnrc.yml).
// Top-level Flavor reflects the binary's major; per-file Flavor reflects the
// file's own syntax — the renderer flags mismatches.
type YarnAudit struct {
	Available      bool             `json:"yarn_available"`
	YarnVersion    string           `json:"yarn_version,omitempty"`
	YarnPath       string           `json:"yarn_path,omitempty"`
	Flavor         string           `json:"flavor,omitempty"` // "classic" | "berry" | "unknown"
	Files          []YarnConfigFile `json:"files"`
	NPMRCFiles     []NPMRCFile      `json:"npmrc_files"` // auth side-channel
	Env            []NPMRCEnvVar    `json:"env"`
	DiscoveryError string           `json:"discovery_error,omitempty"`
}

// YarnConfigFile is a discovered .yarnrc (classic) or .yarnrc.yml (berry).
type YarnConfigFile struct {
	Path        string      `json:"path"`
	Scope       string      `json:"scope"`  // "user" | "project"
	Flavor      string      `json:"flavor"` // "classic" | "berry"
	Exists      bool        `json:"exists"`
	Readable    bool        `json:"readable"`
	SizeBytes   int64       `json:"size_bytes,omitempty"`
	ModTimeUnix int64       `json:"mtime_unix,omitempty"`
	Mode        string      `json:"mode,omitempty"`
	OwnerUID    int         `json:"owner_uid,omitempty"`
	OwnerName   string      `json:"owner_name,omitempty"`
	GroupGID    int         `json:"group_gid,omitempty"`
	GroupName   string      `json:"group_name,omitempty"`
	SHA256      string      `json:"sha256,omitempty"`
	SymlinkTo   string      `json:"symlink_target,omitempty"`
	InGitRepo   bool        `json:"in_git_repo,omitempty"`
	GitTracked  bool        `json:"git_tracked,omitempty"`
	Entries     []YarnEntry `json:"entries,omitempty"`
	ParseError  string      `json:"parse_error,omitempty"`
}

// YarnEntry is a parsed key/value from either flavor. Berry nested maps
// flatten to dotted keys (e.g. `npmScopes.@step-security.npmAuthToken`) so
// the same slice carries both flavors.
type YarnEntry struct {
	Key          string   `json:"key"`
	DisplayValue string   `json:"display_value"`
	LineNum      int      `json:"line_num,omitempty"`
	IsAuth       bool     `json:"is_auth,omitempty"`
	IsEnvRef     bool     `json:"is_env_ref,omitempty"`
	EnvRefVars   []string `json:"env_ref_vars,omitempty"`
	ValueSHA256  string   `json:"value_sha256,omitempty"`
	Quoted       bool     `json:"quoted,omitempty"`
}

// --- pip configuration audit -------------------------------------------------
//
// Mirrors NPMRCAudit but reflects pip-specific realities: real INI
// sections, no env-var interpolation, and a fixed finding catalog
// (pip-001 .. pip-024) instead of free-form classification.

// PipAudit is the top-level pip audit object.
type PipAudit struct {
	Available      bool            `json:"pip_available"`
	Invocation     string          `json:"pip_invocation,omitempty"` // "pip" | "pip3" | "python3 -m pip"
	Version        string          `json:"pip_version,omitempty"`
	Path           string          `json:"pip_path,omitempty"`
	Files          []PipConfigFile `json:"files"`
	EnvVars        []PipEnvVar     `json:"env_vars"`
	Effective      *PipEffective   `json:"effective,omitempty"`
	Netrc          *PipNetrcStatus `json:"netrc,omitempty"`
	Findings       []PipFinding    `json:"findings"`
	DiscoveryError string          `json:"discovery_error,omitempty"`
}

// PipConfigFile is one pip.conf / pip.ini discovered on disk. Layer is the
// precedence layer pip itself assigns.
type PipConfigFile struct {
	Path        string       `json:"path"`
	Layer       string       `json:"layer"` // global | user | user-legacy | site | PIP_CONFIG_FILE
	Exists      bool         `json:"exists"`
	Readable    bool         `json:"readable"`
	SizeBytes   int64        `json:"size_bytes,omitempty"`
	ModTimeUnix int64        `json:"mtime_unix,omitempty"`
	Mode        string       `json:"mode,omitempty"`
	OwnerName   string       `json:"owner_name,omitempty"`
	GroupName   string       `json:"group_name,omitempty"`
	SHA256      string       `json:"sha256,omitempty"`
	InGitRepo   bool         `json:"in_git_repo,omitempty"`
	GitTracked  bool         `json:"git_tracked,omitempty"`
	Sections    []PipSection `json:"sections,omitempty"`
	ParseError  string       `json:"parse_error,omitempty"`
}

// PipSection is one [section] block in a pip config file.
type PipSection struct {
	Name    string        `json:"name"` // "global", "install", "freeze", "wheel", "list", "hash", ...
	LineNum int           `json:"line_num"`
	Entries []PipKeyValue `json:"entries"`
}

// PipKeyValue is a single key/value (or key/multi-value) entry inside a
// section. Repeatable options surface as multiple Values.
type PipKeyValue struct {
	Key string `json:"key"`
	// Values holds the raw, un-redacted parsed values. Used internally by
	// the findings engine (URL.User parsing, http-scheme detection, etc.)
	// — NEVER serialized to JSON or pretty output, since for keys like
	// `extra-index-url` it can hold a literal `user:pass@host` URL. Use
	// Display for any user-visible rendering.
	Values  []string `json:"-"`
	Display string   `json:"display,omitempty"` // human-readable single-line rendering, with creds redacted
	LineNum int      `json:"line_num"`
}

// PipEnvVar captures one PIP_* environment variable. Display is the
// finding-grade safe-to-print form (creds redacted in URLs). Unset vars
// are kept (Set=false) so the audit shape stays stable across hosts and a
// future change-tracking layer can detect newly-set vars between runs.
type PipEnvVar struct {
	Name    string `json:"name"`
	Set     bool   `json:"set"`
	Value   string `json:"-"` // raw; never serialized
	Display string `json:"display,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

// PipEffective is the merged-config view from `pip config list -v`. The
// SourceByKey map keys are "<section>.<key>" to disambiguate the same key
// appearing in multiple sections.
type PipEffective struct {
	SourceByKey map[string]string `json:"source_by_key,omitempty"`
	Config      map[string]string `json:"config,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// PipFinding is one detection from the rule catalog (pip-001 .. pip-024).
// ValueShown is always pre-redacted; the raw value never leaves the
// detector.
type PipFinding struct {
	ID          string `json:"id"`       // "pip-001" etc.
	Severity    string `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW | INFO
	Category    string `json:"category"`
	Source      string `json:"source"`            // file path or env var name
	Section     string `json:"section,omitempty"` // "global" / "install" / "" for env vars
	Key         string `json:"key,omitempty"`
	ValueShown  string `json:"value_shown,omitempty"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

// PipNetrcStatus is informational: pip falls back to ~/.netrc for
// credentials, so its presence + permissions matter even though we don't
// parse the contents (.netrc is shared with curl/wget/twine/etc.; auditing
// its content is a separate concern).
type PipNetrcStatus struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   string `json:"mode,omitempty"` // empty on Windows
}

// --- Malicious-file detection (rule_scan) ---
//
// These types are the agent → backend wire contract for the malicious-file
// detection engine (internal/detector/rules). They are emitted on the
// telemetry Payload as the additive `rule_scan` field. The agent never sends
// file content: a finding is a path, a whole-file hash, per-condition
// booleans, and file metadata.

// RuleScan is the top-level result of one malicious-file scan. It carries the
// scan-level completeness flag, every rule the engine evaluated (even those
// with zero matches), and the per-rule match results. ScanComplete is false
// when a global file/time budget cut the walk short, which suppresses backend
// auto-resolution for the whole run.
type RuleScan struct {
	ScanComplete   bool            `json:"scan_complete"`
	EvaluatedRules []EvaluatedRule `json:"evaluated_rules"`
	Results        []RuleResult    `json:"results"`
}

// EvaluatedRule records one rule the engine ran this scan, including rules
// that matched nothing. Complete is false if the rule hit its per-rule match
// cap (matches_truncated) or wasn't fully walked. RuleRevision is the opaque
// revision echoed back for backend audit/drift detection.
type EvaluatedRule struct {
	RuleID       string `json:"rule_id"`
	RuleRevision string `json:"rule_revision,omitempty"`
	Complete     bool   `json:"complete"`
}

// RuleResult is one rule that matched at least one file. MatchesTruncated is
// true when more than the per-rule cap (200) of files matched; the Files
// slice is capped and the corresponding EvaluatedRule.Complete is false.
type RuleResult struct {
	RuleID           string          `json:"rule_id"`
	RuleRevision     string          `json:"rule_revision,omitempty"`
	MatchesTruncated bool            `json:"matches_truncated,omitempty"`
	Files            []RuleFileMatch `json:"files"`
}

// RuleFileMatch is one candidate file reported for a rule. SizeExceeded is set
// when the file was larger than the rule's size guard: it is reported but not
// read, so FileSHA256 and Groups are empty. FileAttrs (Stat-only metadata) is
// always present.
type RuleFileMatch struct {
	Path         string        `json:"path"`
	MatchedGlob  string        `json:"matched_glob"`
	FileSHA256   string        `json:"file_sha256,omitempty"`
	SizeExceeded bool          `json:"size_exceeded,omitempty"`
	Groups       []GroupResult `json:"groups,omitempty"`
	FileAttrs    FileAttrs     `json:"file_attrs"`
}

// GroupResult reports one condition group. FullMatch is true when every
// condition in the group matched (after applying negation).
type GroupResult struct {
	GroupID    string            `json:"group_id"`
	FullMatch  bool              `json:"full_match"`
	Conditions []ConditionResult `json:"conditions"`
}

// ConditionResult reports the boolean outcome of one condition. No matched
// text is ever captured — only whether the condition matched.
type ConditionResult struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"` // "regex" | "sha256"
	Matched bool   `json:"matched"`
}

// FileAttrs is file metadata only, never content. Times are unix seconds UTC,
// 0 when unavailable on the platform.
type FileAttrs struct {
	SizeBytes  int64 `json:"size_bytes"`
	ModifiedAt int64 `json:"modified_at"` // mtime
	CreatedAt  int64 `json:"created_at"`  // birth time (best-effort)
	ChangedAt  int64 `json:"changed_at"`  // ctime
}
