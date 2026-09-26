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

	// AgentSkills is the flat list of discovered AI agent skills. AgentSkillScan
	// is the phase summary; its non-nil presence is the "scan ran" sentinel (a
	// nil section must never cause the backend to delete skill state).
	AgentSkills    []AgentSkill        `json:"agent_skills,omitempty"`
	AgentSkillScan *AgentSkillScanInfo `json:"agent_skill_scan,omitempty"`

	// CredentialScan is the credential-location inventory. Nil means the phase
	// did not run, which is the only "no information" signal a reader has — a
	// non-nil section with zero findings means it ran and found nothing.
	CredentialScan *CredentialScanInfo `json:"credential_scan,omitempty"`

	// BrowserExtensionScan is the browser extension inventory. Nil means the
	// phase did not run — the only "no information" signal a reader has, and the
	// difference between it and a section carrying zero findings is what keeps a
	// skipped scan from erasing a device's extensions.
	BrowserExtensionScan *BrowserExtensionScanInfo `json:"browser_extension_scan,omitempty"`

	// Nil plugin coverage means unreported, not an empty inventory.
	AgentPlugins *AgentPlugins `json:"agent_plugins,omitempty"`

	Summary Summary `json:"summary"`
}

type Device struct {
	Hostname     string           `json:"hostname"`
	SerialNumber string           `json:"serial_number"`
	OSVersion    string           `json:"os_version"`
	Platform     string           `json:"platform"`
	UserIdentity string           `json:"user_identity"`
	Resources    MachineResources `json:"resources"`
	// WSL reports Windows Subsystem for Linux on a Windows host. Nil on every
	// other platform, and nil on Windows unless the WSL-detection feature gate
	// is on — so `omitempty` drops it entirely rather than emitting a zero
	// value that a reader could mistake for "scanned, no WSL".
	WSL *WSLInfo `json:"wsl,omitempty"`
}

// WSL presence is tri-state. A probe that cannot read the registry (e.g. a
// SYSTEM-context run whose target user's hive is not loaded) reports
// WSLPresenceUnknown, never a false WSLPresenceNo.
const (
	WSLPresenceYes     = "yes"
	WSLPresenceNo      = "no"
	WSLPresenceUnknown = "unknown"
)

// WSLInfo reports Windows Subsystem for Linux on a Windows host: whether it is
// present, whether a distribution is currently running, the installed WSL
// package version, and the registered distributions. Populated only by the
// Windows agent (WSL detection is a host-side concern — the Linux binary runs
// *inside* a distro and identifies itself separately).
type WSLInfo struct {
	Presence  string      `json:"presence"`  // WSLPresence* — yes | no | unknown
	Installed bool        `json:"installed"` // WSL runtime service (WslService/LxssManager) present
	Active    bool        `json:"active"`    // at least one distribution running right now
	Version   string      `json:"version"`   // installed WSL package version; "unknown" if undeterminable
	Distros   []WSLDistro `json:"distros,omitempty"`
}

// WSLGuest identifies this agent as running INSIDE a WSL distribution and names
// the Windows host it belongs to. Set only from the flags the host passes at
// trigger time (--wsl-host-serial / --wsl-distro-id): a distro cannot discover
// either value for itself without depending on Windows interop.
//
// It exists because a distro has no usable identity of its own — it inherits the
// host's hostname, and a minimal or WSL1 distro has no /etc/machine-id at all.
// The backend pairs on DistroID against the host's own reported distro list.
type WSLGuest struct {
	HostDeviceID string `json:"host_device_id"`
	DistroID     string `json:"distro_id"`
}

// WSLDistro is one registered WSL distribution.
type WSLDistro struct {
	Name string `json:"name"`
	// DistroID is the distribution's registry key name, a GUID, and the only
	// stable per-distro identifier. It survives restarts and renames (renaming
	// rewrites DistributionName only — this WSL build has no `--rename` command
	// at all) and changes on unregister/re-import, which genuinely is a new
	// environment. Never derive it from BasePath: only store-installed distros
	// carry the GUID in their path, an imported one reads e.g. C:\wsl1\Alpine.
	DistroID string `json:"distro_id,omitempty"`
	// WSLVersion is 1 or 2 (0 if undeterminable), derived from the registry
	// Flags 0x8 bit — the per-distro Version DWORD is unreliable (it reads 2 on
	// WSL1 distros). Measured on both: WSL1 → Flags 0x7 → v1, WSL2 → Flags 0xF
	// → v2 (microsoft/WSL#4251; verified on the metal WSL2 test VM).
	WSLVersion int    `json:"wsl_version"`
	Running    bool   `json:"running"`
	Default    bool   `json:"default"`
	OwnerSID   string `json:"owner_sid,omitempty"`
	BasePath   string `json:"base_path,omitempty"`
	// DefaultUID is the uid `wsl -d <name>` runs as, read from the registry
	// DefaultUid value. Distinguishing 0 from absent matters: 0 means the
	// distro has no non-root user, so its home holds nothing worth scanning,
	// whereas nil means we could not read the value. Never scan as root
	// explicitly — root's home is empty and would read as a clean machine.
	DefaultUID *uint32 `json:"default_uid,omitempty"`
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
	AgentSkillsCount      int `json:"agent_skills_count"`
	AgentPluginsCount     int `json:"agent_plugins_count"`
}

// UnchangedProjectRef tells the backend a project is unchanged since the
// last successful upload. Backend bumps LastSeenAt on every package row
// whose ProjectPaths contains Path.
type UnchangedProjectRef struct {
	Path                    string `json:"path"`
	ScanOutputHash          string `json:"scan_output_hash"`
	LastUploadedExecutionID string `json:"last_uploaded_execution_id,omitempty"`
}

// RemovedProjectRef tells the backend a project has disappeared from disk.
// Backend drops Path from every matching row's ProjectPaths and bumps
// RecordUpdatedAt but not LastSeenAt.
type RemovedProjectRef struct {
	Path                    string `json:"path"`
	LastUploadedExecutionID string `json:"last_uploaded_execution_id,omitempty"`
}

// UnchangedGlobalRef tells the backend a PM's global package set is unchanged.
// Keyed by PM name (globals are PM-scoped, not path-scoped).
type UnchangedGlobalRef struct {
	PackageManager          string `json:"package_manager"`
	ScanOutputHash          string `json:"scan_output_hash"`
	LastUploadedExecutionID string `json:"last_uploaded_execution_id,omitempty"`
}

// NodeScanResult holds one project's (or one global root's) scan output for
// enterprise telemetry. Used for both global packages and per-project scans.
//
// Two mutually-exclusive shapes flow through this struct depending on how the
// scan was produced:
//   - Legacy (command) path: RawStdoutBase64 carries the raw `npm ls`/`yarn`/
//     `pnpm`/`bun` output; the backend parses it into packages on ingest.
//   - Disk-parse path: Packages is populated directly and RawStdoutBase64 is
//     left empty. The backend's ParseNodeProjects passes a project through
//     untouched when RawStdoutBase64 == "", so pre-parsed packages reach
//     storage with no backend change. Never set both: a non-empty
//     RawStdoutBase64 makes the backend re-parse and overwrite Packages.
//
// JSON tags match agent-api's ddbmodels.NodeProject so the payload
// deserializes server-side without a schema change.
type NodeScanResult struct {
	ProjectPath      string        `json:"project_path"`
	PackageManager   string        `json:"package_manager"`
	PMVersion        string        `json:"package_manager_version"`
	WorkingDirectory string        `json:"working_directory"`
	RawStdoutBase64  string        `json:"raw_stdout_base64,omitempty"`
	RawStderrBase64  string        `json:"raw_stderr_base64,omitempty"`
	Packages         []NodePackage `json:"packages,omitempty"`
	PackagesCount    int           `json:"packages_count"`
	Error            string        `json:"error"`
	ExitCode         int           `json:"exit_code"`
	ScanDurationMs   int64         `json:"scan_duration_ms"`
}

// NodePackage is one installed Node package discovered by disk parsing.
//
// Fields are intentionally limited to what the backend persists today
// (name, version, direct-vs-transitive) — see DeviceNPMPackageUsageInfo. The
// agent-api NodePackage additionally declares InstallPath and Dependencies,
// but both are parsed-then-discarded server-side and are omitted here on
// purpose. JSON tags match ddbmodels.NodePackage.
type NodePackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// IsDirect marks a top-level dependency (declared in the project's
	// package.json) versus a transitive one pulled in by another package.
	// Derived from lockfile structure, not from running the package manager.
	IsDirect bool `json:"is_direct,omitempty"`
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

// AgentSkill represents one discovered agent skill: a physical SKILL.md
// directory, optionally enriched with skills.sh lock provenance. Symlink shadows
// of the same physical dir are collapsed into one record (the linked roots
// listed in SymlinkSources). Never carries file content — identity, provenance,
// hashes, and census counts only.
type AgentSkill struct {
	Usage *SkillUsage `json:"usage,omitempty"`
	// Identity
	SkillSlug    string   `json:"skill_slug"`              // directory basename
	SkillName    string   `json:"skill_name"`              // frontmatter name, else slug
	Description  string   `json:"description,omitempty"`   // frontmatter description, ≤1024 runes (standard max)
	Version      string   `json:"version,omitempty"`       // frontmatter version (or metadata.version fallback)
	License      string   `json:"license,omitempty"`       // standard frontmatter license, ≤128 runes
	AllowedTools []string `json:"allowed_tools,omitempty"` // normalized from space/comma string or YAML list

	// Behavior/risk flags (frontmatter + body scan)
	DisableModelInvocation bool   `json:"disable_model_invocation,omitempty"`
	UserInvocableDisabled  bool   `json:"user_invocable_disabled,omitempty"` // frontmatter user-invocable: false
	ContextFork            bool   `json:"context_fork,omitempty"`            // context: fork (runs in subagent)
	ModelOverride          string `json:"model_override,omitempty"`          // frontmatter model
	HasHooks               bool   `json:"has_hooks,omitempty"`               // hooks key present in frontmatter
	HasShellInjection      bool   `json:"has_shell_injection,omitempty"`     // body has !`cmd` / ```! load-time exec

	// Attribution
	Agent  string `json:"agent"`  // "claude-code"|"codex"|"opencode"|"cursor"|"pi"|"factory"|"amp"|"copilot"|"gemini-cli"|"aider"|"grok-build"|"kimi-code"|"muse-code"|"hermes-agent"|"oh-my-pi"|"shared"
	Source string `json:"source"` // atomic attribution key. "claude_user"|"claude_project"|
	//                              // "agents_user"|"agents_project"|"codex_user"|"codex_system"|"codex_admin"|
	//                              // "opencode_user"|"opencode_project"|"cursor_user"|"cursor_project"|"pi_user"|
	//                              // "pi_project"|"factory_user"|"factory_project"|"factory_agent_project"|
	//                              // "factory_agent_user"|"amp_user"|"copilot_user"|"github_project"|
	//                              // "gemini_user"|"gemini_project"|"aider_project"|"grok_user"|"grok_project"|
	//                              // "kimi_user"|"kimi_project"|"muse_user"|"hermes_user"|"hermes_project"|
	//                              // "omp_user"|"omp_managed_user"|"omp_project"
	Scope       string `json:"scope"`                  // "global" | "project" | "system"
	ProjectPath string `json:"project_path,omitempty"` // project root for project scope
	PluginName  string `json:"plugin_name,omitempty"`  // owning plugin, from skills.sh lock pluginName

	// Location
	SkillDirPath   string   `json:"skill_dir_path,omitempty"` // absolute, symlink-resolved dir of the physical skill (the collapse group key)
	RootRelPath    string   `json:"root_rel_path,omitempty"`  // skill dir relative to its root, forward-slash ("frontend-design", "apps/web/frontend-design")
	SkillMDPath    string   `json:"skill_md_path,omitempty"`
	SymlinkSources []string `json:"symlink_sources,omitempty"` // sorted, deduped source labels that symlink to this physical skill dir; every entry is a symlink by definition

	// Content identity
	SkillMDHash string `json:"skill_md_hash,omitempty"` // hex(sha256(SKILL.md)) — identity/drift key

	// Empty DefinitionKind denotes SKILL.md. Commands use DefinitionPath and
	// DefinitionHash; their SKILL.md fields and directory census remain empty.
	DefinitionKind string `json:"definition_kind,omitempty"` // "" | AgentDefinitionSkill | AgentDefinitionCommand
	DefinitionPath string `json:"definition_path,omitempty"`
	DefinitionHash string `json:"definition_hash,omitempty"` // hex(sha256(raw definition bytes))
	// How the agent invokes this definition. A command takes its name from its
	// path under commands/, not from frontmatter.
	CallableNames []string `json:"callable_names,omitempty"`

	// File census (all stat-derived — no file bytes read)
	FileCount         int   `json:"file_count,omitempty"`
	CodeFileCount     int   `json:"code_file_count,omitempty"`
	SymlinkCount      int   `json:"symlink_count,omitempty"`
	TotalSizeBytes    int64 `json:"total_size_bytes,omitempty"`
	HasCode           bool  `json:"has_code,omitempty"`
	HasPluginManifest bool  `json:"has_plugin_manifest,omitempty"` // .claude-plugin/plugin.json in skill dir
	LastModified      int64 `json:"last_modified,omitempty"`       // unix, max mtime in dir

	// Frontmatter health
	HasFrontmatter   bool   `json:"has_frontmatter"`
	FrontmatterError string `json:"frontmatter_error,omitempty"` // "" | "invalid_yaml" | "missing_name" | "missing_description" | "file_too_large" | "unreadable"

	// skills.sh lock provenance (empty when unmanaged)
	ManagedBy          string `json:"managed_by,omitempty"`  // "skills.sh" | ""
	SourceSlug         string `json:"source_slug,omitempty"` // "vercel-labs/agent-skills" (alias only for sourceType=local)
	SourceType         string `json:"source_type,omitempty"` // "github"|"mintlify"|"huggingface"|"local"|"well-known"
	SourceURL          string `json:"source_url,omitempty"`
	Ref                string `json:"ref,omitempty"`                  // branch|tag|sha as recorded
	SkillPath          string `json:"skill_path,omitempty"`           // subdir within upstream repo
	UpstreamFolderHash string `json:"upstream_folder_hash,omitempty"` // GitHub tree SHA from lock (NOT sha256)
	InstalledAt        string `json:"installed_at,omitempty"`         // ISO8601 from lock
	UpdatedAt          string `json:"updated_at,omitempty"`           // ISO8601 from lock
	LockFilePath       string `json:"lock_file_path,omitempty"`
}

// AgentSkillScanInfo summarizes the skills phase. Its presence in the payload
// is the "scan ran" sentinel: a nil section means the scan did not run (no
// information), while a non-nil section with zero skills means "scan ran,
// nothing installed".
type AgentSkillScanInfo struct {
	RootsScanned    []string `json:"roots_scanned"` // absolute root paths probed AND existing
	ProjectsScanned int      `json:"projects_scanned"`
	LockFilesParsed int      `json:"lock_files_parsed"`
	SkillsFound     int      `json:"skills_found"`
	Truncated       bool     `json:"truncated,omitempty"`         // any cap hit (roots/projects/skills/home-walk)
	Errors          []string `json:"errors,omitempty"`            // bounded: ≤50 entries, each ≤256 chars
	WalkDirsVisited int      `json:"walk_dirs_visited,omitempty"` // home-walk ReadDir count
	WalkRootsFound  int      `json:"walk_roots_found,omitempty"`  // project-root candidates the home walk emitted (pre-union)
	// CommandsStatus covers standalone command roots. Empty means unreported;
	// only complete coverage permits removal of unseen commands.
	CommandsStatus string `json:"commands_status,omitempty"`
	DurationMs     int64  `json:"duration_ms"`
}

// GoInventorySchemaVersion versions the go_inventory and go_config_audit
// sections independently of the outer payload_schema_version.
const GoInventorySchemaVersion = 1

// Go inventory source kinds.
const (
	GoSourceProjectSearchRoot = "project_search_root"
	GoSourceProjectManifest   = "project_manifest"
	GoSourceAlternateManifest = "alternate_manifest"
	GoSourceWorkspace         = "workspace"
	GoSourceVendorRoot        = "vendor_root"
	GoSourceCacheRoot         = "cache_root"
	GoSourceBinRoot           = "bin_root"
	GoSourceBinary            = "binary"
	GoSourceChecksumFile      = "checksum_file"
)

// Go section and source statuses. A section is complete or partial; a source
// may also be skipped (never read).
const (
	GoStatusComplete = "complete"
	GoStatusPartial  = "partial"
	GoStatusSkipped  = "skipped"
)

// Go source presence. Only a permitted, successful lookup may report absent;
// a refusal or failure is unknown.
const (
	GoPresencePresent = "present"
	GoPresenceAbsent  = "absent"
	GoPresenceUnknown = "unknown"
)

// Go cache artifact kinds and statuses.
const (
	GoArtifactExtractedSource = "extracted_source"
	GoArtifactArchivePresent  = "archive_present"

	GoArtifactPresent    = "present"
	GoArtifactPartial    = "partial" // in-progress extraction, missing completion marker or capped check
	GoArtifactUnreadable = "unreadable"
)

// Go replacement kinds and version statuses.
const (
	GoReplaceModule = "module"
	GoReplaceLocal  = "local"

	GoVersionKnown   = "known"
	GoVersionUnknown = "unknown" // missing or (devel); the version is omitted, never invented
)

// Go recorded-checksum vocabulary. Checksums are recorded metadata, never
// verified by DMG.
const (
	GoChecksumRecorded      = "recorded"
	GoChecksumAbsent        = "absent"
	GoChecksumPartial       = "partial"
	GoChecksumUnreadable    = "unreadable"
	GoChecksumInvalid       = "invalid"
	GoChecksumUnsupported   = "unsupported"
	GoChecksumSkipped       = "skipped"
	GoChecksumNotApplicable = "not_applicable"

	GoChecksumKindModuleContent = "module_content"
	GoChecksumKindGoMod         = "go_mod"

	GoChecksumSourceProjectGoSum       = "project_go_sum" // go.sum or an alternate modfile's .sum
	GoChecksumSourceWorkspaceGoWorkSum = "workspace_go_work_sum"
	GoChecksumSourceCacheZiphash       = "cache_ziphash"
	GoChecksumSourceBinaryBuildInfo    = "binary_buildinfo"

	GoChecksumNotVerified = "not_verified"
)

// Go config-audit file scopes and statuses.
const (
	GoConfigScopeUser      = "user"      // the user go/env file
	GoConfigScopeToolchain = "toolchain" // GOROOT/go.env
	GoConfigScopeProcess   = "process"   // DMG's own verified process environment

	GoConfigPresent          = "present"
	GoConfigAbsent           = "absent"
	GoConfigDisabled         = "disabled" // GOENV=off
	GoConfigSkippedProtected = "skipped_protected"
	GoConfigUnreadable       = "unreadable"
	GoConfigInvalid          = "invalid"
	GoConfigUnsupported      = "unsupported"
)

// Go reason codes, shared by both sections.
const (
	GoReasonUserUnresolved              = "user_unresolved"
	GoReasonSkippedProtected            = "skipped_protected"
	GoReasonOutsideApprovedRoots        = "outside_approved_roots"
	GoReasonPathUnresolved              = "path_unresolved"
	GoReasonPermissionDenied            = "permission_denied"
	GoReasonSizeLimit                   = "size_limit"
	GoReasonEntryLimit                  = "entry_limit"
	GoReasonDepthLimit                  = "depth_limit"
	GoReasonRecordLimit                 = "record_limit"
	GoReasonOutputSizeLimit             = "output_size_limit"
	GoReasonDeadlineExceeded            = "deadline_exceeded"
	GoReasonParseError                  = "parse_error"
	GoReasonUnsupportedEntry            = "unsupported_entry"
	GoReasonRootRedirectUnknown         = "root_redirect_unknown"
	GoReasonVendorMismatch              = "vendor_mismatch"
	GoReasonMemberNotDiscovered         = "member_not_discovered"
	GoReasonBuildInfoUnusable           = "build_info_unusable"
	GoReasonChangedDuringScan           = "changed_during_scan"
	GoReasonExtractionIncomplete        = "extraction_incomplete" // .partial present or completion metadata missing
	GoReasonAlternateManifestUnresolved = "alternate_manifest_unresolved"
	GoReasonProcessContextUnverified    = "process_context_unverified"
	GoReasonCarriageReturn              = "carriage_return"
	GoReasonDuplicateKey                = "duplicate_key"
	GoReasonMalformedChecksumLine       = "malformed_checksum_line"
	GoReasonUnsupportedChecksumScheme   = "unsupported_checksum_scheme"
	GoReasonChecksumLineTooLong         = "checksum_line_too_long"
	GoReasonChecksumLineLimit           = "checksum_line_limit"
	GoReasonUnsupportedModfileName      = "unsupported_modfile_name"
)

// GoInventory is the enterprise go_inventory section: a full bounded snapshot
// of statically read Go evidence. Nil means the phase did not run.
type GoInventory struct {
	SchemaVersion   int                `json:"schema_version"`
	Status          string             `json:"status"`  // GoStatusComplete | GoStatusPartial
	Reasons         []string           `json:"reasons"` // global reasons plus those of every incomplete source
	Sources         []GoSource         `json:"sources"`
	Projects        []GoProject        `json:"projects"`
	Workspaces      []GoWorkspace      `json:"workspaces"`
	VendoredModules []GoVendoredModule `json:"vendored_modules"`
	CachedModules   []GoCachedModule   `json:"cached_modules"`
	InstalledTools  []GoInstalledTool  `json:"installed_tools"`
}

// GoSource is one thing the collector looked at. Its ID hashes the developer
// identity, kind and absolute logical path, so it survives content edits.
type GoSource struct {
	SourceID string   `json:"source_id"`
	Kind     string   `json:"kind"` // GoSource*
	Path     string   `json:"path"` // absolute logical path
	Status   string   `json:"status"`
	Presence string   `json:"presence"`
	Reasons  []string `json:"reasons"`
	// ParentSourceID names the discovery source that owns this one.
	ParentSourceID string `json:"parent_source_id,omitempty"`
	// DiscoveredSources lists every child found, including unreadable ones.
	DiscoveredSources []string `json:"discovered_sources"`
}

// GoChecksumEvidence is optional recorded-checksum metadata for the exact
// module path and version of the record that embeds it.
type GoChecksumEvidence struct {
	ChecksumStatus    string               `json:"checksum_status,omitempty"` // GoChecksum* status
	RecordedChecksums []GoRecordedChecksum `json:"recorded_checksums,omitempty"`
}

// GoRecordedChecksum is one recorded h1 value and the file or binary that held it.
type GoRecordedChecksum struct {
	Kind         string `json:"kind"`   // GoChecksumKind*
	Value        string `json:"value"`  // canonical h1:
	Source       string `json:"source"` // GoChecksumSource*
	SourceID     string `json:"source_id"`
	SourcePath   string `json:"source_path"`
	Verification string `json:"verification"` // always GoChecksumNotVerified
}

// GoProject is one parsed go.mod (default or alternate manifest). Requirements
// are declarations, not the selected build list.
type GoProject struct {
	SourceID       string            `json:"source_id"`
	Path           string            `json:"path"` // module directory
	ManifestPath   string            `json:"manifest_path"`
	ModulePath     string            `json:"module_path,omitempty"`
	GoVersion      string            `json:"go_version,omitempty"`
	Toolchain      string            `json:"toolchain,omitempty"`
	Requirements   []GoRequirement   `json:"requirements"`
	Replacements   []GoReplacement   `json:"replacements"`
	Exclusions     []GoModuleVersion `json:"exclusions"`
	Tools          []string          `json:"tools"`           // tool directive package paths
	WorkspacePaths []string          `json:"workspace_paths"` // go.work files that name this module
}

type GoRequirement struct {
	ModulePath       string `json:"module_path"`
	RequestedVersion string `json:"requested_version"` // a minimum, not the selected version
	Indirect         bool   `json:"indirect"`
	GoChecksumEvidence
}

// GoReplacement keeps the logical module and its provider apart; a local
// path is never a module identity.
type GoReplacement struct {
	FromPath     string `json:"from_path"`
	FromVersion  string `json:"from_version,omitempty"`
	Kind         string `json:"kind"` // GoReplaceModule | GoReplaceLocal
	ToModulePath string `json:"to_module_path,omitempty"`
	ToVersion    string `json:"to_version,omitempty"`
	ToLocalPath  string `json:"to_local_path,omitempty"` // as declared
	GoChecksumEvidence
}

type GoModuleVersion struct {
	ModulePath string `json:"module_path"`
	Version    string `json:"version"`
}

// GoWorkspace is one parsed go.work. Path is the go.work file.
type GoWorkspace struct {
	SourceID     string              `json:"source_id"`
	Path         string              `json:"path"`
	GoVersion    string              `json:"go_version,omitempty"`
	Toolchain    string              `json:"toolchain,omitempty"`
	Members      []GoWorkspaceMember `json:"members"`
	Replacements []GoReplacement     `json:"replacements"`
}

type GoWorkspaceMember struct {
	DeclaredPath    string `json:"declared_path"`
	ResolvedPath    string `json:"resolved_path,omitempty"`
	ProjectSourceID string `json:"project_source_id,omitempty"`
	Reason          string `json:"reason,omitempty"` // why ProjectSourceID is missing
}

// GoVendoredModule is a vendor/modules.txt module with at least one package
// directory corroborated on disk.
type GoVendoredModule struct {
	SourceID        string         `json:"source_id"` // the vendor_root source
	ModulePath      string         `json:"module_path"`
	ObservedVersion string         `json:"observed_version,omitempty"`
	Replacement     *GoReplacement `json:"replacement,omitempty"`
	VendorRoot      string         `json:"vendor_root"`
	PackagePaths    []string       `json:"package_paths"`
	GoChecksumEvidence
}

// GoCachedModule is one module version in a module cache root, merging its
// extracted source and archive evidence.
type GoCachedModule struct {
	SourceID        string            `json:"source_id"` // the cache_root source
	ModulePath      string            `json:"module_path"`
	ObservedVersion string            `json:"observed_version"`
	Root            string            `json:"root"`
	Artifacts       []GoCacheArtifact `json:"artifacts"`
	GoChecksumEvidence
}

type GoCacheArtifact struct {
	Kind   string `json:"kind"` // GoArtifactExtractedSource | GoArtifactArchivePresent
	Path   string `json:"path"`
	Status string `json:"status"` // GoArtifactPresent | GoArtifactPartial | GoArtifactUnreadable
}

// GoInstalledTool is a Go binary in the resolved install bin directory, from
// its embedded BuildInfo. Checksum fields describe the main module.
type GoInstalledTool struct {
	SourceID        string               `json:"source_id"` // the binary source
	BinaryPath      string               `json:"binary_path"`
	MainPackagePath string               `json:"main_package_path"`
	MainModulePath  string               `json:"main_module_path,omitempty"`
	ObservedVersion string               `json:"observed_version,omitempty"`
	VersionStatus   string               `json:"version_status"`
	Replacement     *GoReplacement       `json:"replacement,omitempty"`
	Dependencies    []GoBinaryDependency `json:"dependencies"`
	GoChecksumEvidence
}

// GoBinaryDependency inherits its binary's source ID.
type GoBinaryDependency struct {
	ModulePath      string         `json:"module_path"`
	ObservedVersion string         `json:"observed_version,omitempty"`
	VersionStatus   string         `json:"version_status"`
	Replacement     *GoReplacement `json:"replacement,omitempty"`
	GoChecksumEvidence
}

// GoConfigAudit is the enterprise go_config_audit section: observed Go
// settings per source, sanitized on the device, with no effective verdict.
type GoConfigAudit struct {
	SchemaVersion int               `json:"schema_version"`
	Status        string            `json:"status"`
	Reasons       []string          `json:"reasons"`
	Files         []GoConfigFile    `json:"files"`
	Findings      []GoConfigFinding `json:"findings"`
}

// GoConfigFile is one configuration source. The process scope has no path.
type GoConfigFile struct {
	SourceID    string            `json:"source_id"`
	Scope       string            `json:"scope"` // GoConfigScope*
	DefaultPath string            `json:"default_path,omitempty"`
	Path        string            `json:"path,omitempty"`
	Status      string            `json:"status"` // GoConfig* status
	Reasons     []string          `json:"reasons"`
	Settings    []GoConfigSetting `json:"settings"`
}

// GoConfigSetting is an allowlisted key with a sanitized display value.
// Redacted marks that credentials, query values or arguments were removed.
type GoConfigSetting struct {
	Key      string `json:"key"`
	Display  string `json:"display"`
	Redacted bool   `json:"redacted,omitempty"`
	SourceID string `json:"source_id"`
}

// GoConfigFinding is a stable-coded observation tied to the source where the
// value was seen. Detail never contains a value.
type GoConfigFinding struct {
	Code     string `json:"code"`     // go-001 …
	Severity string `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW | INFO
	SourceID string `json:"source_id"`
	Key      string `json:"key"`
	Detail   string `json:"detail"`
}
