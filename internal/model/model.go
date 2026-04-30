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
	Summary           Summary         `json:"summary"`
}

type Device struct {
	Hostname     string `json:"hostname"`
	SerialNumber string `json:"serial_number"`
	OSVersion    string `json:"os_version"`
	Platform     string `json:"platform"`
	UserIdentity string `json:"user_identity"`
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
	InstallTimeUnix int64  `json:"install_time_unix,omitempty"` // Unix epoch seconds when installed (rpm, dpkg, pacman)

	// Provenance & trust signals
	Vendor       string `json:"vendor,omitempty"`          // Distributor: rpm VENDOR, dpkg Origin
	Maintainer   string `json:"maintainer,omitempty"`      // Packager identity: rpm PACKAGER, dpkg Maintainer, apk maintainer, pacman Packager
	URL          string `json:"url,omitempty"`             // Upstream project URL
	License      string `json:"license,omitempty"`         // SPDX license expression
	Section      string `json:"section,omitempty"`         // dpkg Section category (e.g. "libs", "non-free/libs")
	Signature    string `json:"signature,omitempty"`       // Signature info: rpm SIGPGP/RSAHEADER, pacman Validated By
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

// --- npmrc audit ---------------------------------------------------------
//
// NPMRCAudit is the top-level structure produced by the npmrc detector.
// It captures every `.npmrc` discovered on disk, the merged effective config
// as npm itself would resolve it, and the relevant pieces of process env.
//
// Diff is populated by the change-tracking step: it describes how this run's
// state differs from the last persisted snapshot. On a first run Diff is
// non-nil with FirstRun=true and otherwise empty.
type NPMRCAudit struct {
	Available      bool            `json:"npm_available"`
	NPMVersion     string          `json:"npm_version,omitempty"`
	NPMPath        string          `json:"npm_path,omitempty"`
	Files          []NPMRCFile     `json:"files"`
	Effective      *NPMRCEffective `json:"effective,omitempty"`
	Env            []NPMRCEnvVar   `json:"env"`
	Diff           *NPMRCDiff      `json:"diff,omitempty"`
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

	// EffectiveOverrides is populated only for project-scope files. Each
	// entry describes how the *effective* npm config differs when the user
	// runs `npm install` from inside this project, compared to running it
	// from $HOME. This is the actionable supply-chain signal: a cloned repo
	// that silently flips the registry or ships an auth token surfaces here.
	EffectiveOverrides []NPMRCOverride `json:"effective_overrides,omitempty"`
	// OverrideError is set when we couldn't compute EffectiveOverrides
	// (e.g. npm not found, command timed out). Empty on success.
	OverrideError string `json:"override_error,omitempty"`
}

// NPMRCOverride describes a single key whose effective value changes when
// npm is invoked from a project directory rather than $HOME.
type NPMRCOverride struct {
	Key            string `json:"key"`
	BaselineValue  string `json:"baseline_value"`     // string-formatted; "<unset>" when key absent in baseline
	BaselineSource string `json:"baseline_source,omitempty"`
	ProjectValue   string `json:"project_value"`      // "<unset>" when key absent under project
	ProjectSource  string `json:"project_source,omitempty"`
	IsAuth         bool   `json:"is_auth,omitempty"`  // true when the key looks like an auth-scoped key
	IsNew          bool   `json:"is_new,omitempty"`   // baseline didn't have this key at all
	IsRemoved      bool   `json:"is_removed,omitempty"` // project hides a key that was in baseline
}

// NPMRCEntry is one parsed line of a .npmrc file.
//
// DisplayValue is always safe to print: auth values are redacted to
// `***last4` (or `***` when the secret is short). The raw value is never
// stored — ValueSHA256 is the only fingerprint kept for diffing.
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
// We record presence and a hash so changes are detectable across runs
// without ever storing the secret value.
type NPMRCEnvVar struct {
	Name         string `json:"name"`
	Set          bool   `json:"set"`
	DisplayValue string `json:"display_value,omitempty"`
	ValueSHA256  string `json:"value_sha256,omitempty"`
}

// --- Phase B: change tracking ---------------------------------------------
//
// The detector takes a digest snapshot of every audit and writes it to disk
// before returning. On the next run it loads the previous snapshot and
// produces an NPMRCDiff describing what's changed. The snapshot stores
// SHA-256 fingerprints rather than raw values, so diffing detects rotation
// (the registry url changed, the auth token rotated, an env var appeared)
// without ever persisting plaintext credentials.

// NPMRCSnapshot is the on-disk representation of an audit at a point in
// time. SnapshotVersion exists so future schema changes can be detected and
// gracefully handled (treat older versions as "no prior snapshot").
type NPMRCSnapshot struct {
	SnapshotVersion int                    `json:"snapshot_version"`
	AgentVersion    string                 `json:"agent_version"`
	TakenAt         int64                  `json:"taken_at"`
	Hostname        string                 `json:"hostname,omitempty"`
	Files           []NPMRCFileSnapshot    `json:"files"`
	Env             []NPMRCEnvVarSnapshot  `json:"env"`
}

// NPMRCFileSnapshot is the digest of a single .npmrc at snapshot time.
// Only fields needed for diffing are kept — line numbers, display values,
// parse error strings, etc. don't help detect change.
type NPMRCFileSnapshot struct {
	Path        string             `json:"path"`
	Scope       string             `json:"scope"`
	Exists      bool               `json:"exists"`
	SHA256      string             `json:"sha256,omitempty"`
	SizeBytes   int64              `json:"size_bytes,omitempty"`
	ModTimeUnix int64              `json:"mtime_unix,omitempty"`
	Mode        string             `json:"mode,omitempty"`
	OwnerName   string             `json:"owner_name,omitempty"`
	GroupName   string             `json:"group_name,omitempty"`
	Entries     []NPMRCEntryDigest `json:"entries,omitempty"`
}

// NPMRCEntryDigest is the per-key fingerprint kept across runs. Plaintext
// is intentionally absent: the value SHA is enough to notice rotation.
type NPMRCEntryDigest struct {
	Key         string `json:"key"`
	ValueSHA256 string `json:"value_sha256"`
	IsAuth      bool   `json:"is_auth,omitempty"`
	IsArray     bool   `json:"is_array,omitempty"`
}

// NPMRCEnvVarSnapshot mirrors NPMRCEnvVar but drops the display value.
type NPMRCEnvVarSnapshot struct {
	Name        string `json:"name"`
	Set         bool   `json:"set"`
	ValueSHA256 string `json:"value_sha256,omitempty"`
}

// NPMRCDiff is the human-readable answer to "what changed since the last
// scan?" It's emitted on every run; on the very first run all fields are
// empty (FirstRun=true is the only useful flag).
type NPMRCDiff struct {
	FirstRun       bool                    `json:"first_run,omitempty"`
	PreviousAt     int64                   `json:"previous_at,omitempty"`
	CurrentAt      int64                   `json:"current_at,omitempty"`
	AddedFiles     []NPMRCFileChange       `json:"added_files,omitempty"`
	RemovedFiles   []NPMRCFileChange       `json:"removed_files,omitempty"`
	ModifiedFiles  []NPMRCFileModification `json:"modified_files,omitempty"`
	EnvChanges     []NPMRCEnvChange        `json:"env_changes,omitempty"`
}

// HasChanges reports whether the diff is non-trivial (something actually
// changed). Used by the formatter to decide whether to render the section.
func (d *NPMRCDiff) HasChanges() bool {
	if d == nil {
		return false
	}
	return len(d.AddedFiles) > 0 || len(d.RemovedFiles) > 0 ||
		len(d.ModifiedFiles) > 0 || len(d.EnvChanges) > 0
}

// NPMRCFileChange identifies a file that newly appeared or disappeared.
// Existence transitions don't carry sub-detail — the file either is or
// isn't there.
type NPMRCFileChange struct {
	Path  string `json:"path"`
	Scope string `json:"scope"`
}

// NPMRCFileModification is the rich record for a file present in both
// snapshots whose content / metadata / entries differ.
type NPMRCFileModification struct {
	Path  string `json:"path"`
	Scope string `json:"scope"`

	ContentChanged bool `json:"content_changed,omitempty"` // sha256 differs

	// Metadata transitions — pointers because most changes touch only a
	// subset and we don't want to emit zero-value structs for unchanged
	// fields.
	OwnerChanged *NPMRCStringChange `json:"owner_changed,omitempty"`
	GroupChanged *NPMRCStringChange `json:"group_changed,omitempty"`
	ModeChanged  *NPMRCStringChange `json:"mode_changed,omitempty"`
	SizeChanged  *NPMRCInt64Change  `json:"size_changed,omitempty"`

	AddedEntries   []NPMRCEntryDigest    `json:"added_entries,omitempty"`
	RemovedEntries []NPMRCEntryDigest    `json:"removed_entries,omitempty"`
	ChangedEntries []NPMRCEntryValueDiff `json:"changed_entries,omitempty"`

	// Best-effort attribution. Notes accumulate human-readable summaries
	// (e.g. "owner changed from fedora to root — write performed by a
	// different user"). Suspects is the candidate process list captured
	// when ModTime is within ~5 min of the scan (heuristic; see the
	// detector for the exact rule).
	AttributionNotes []string       `json:"attribution_notes,omitempty"`
	Suspects         []NPMRCSuspect `json:"suspects,omitempty"`
}

// NPMRCEntryValueDiff records that a key kept its name but its value
// rotated. Plaintext is never emitted — the SHA pair is enough to prove
// the change happened.
type NPMRCEntryValueDiff struct {
	Key            string `json:"key"`
	IsAuth         bool   `json:"is_auth,omitempty"`
	PreviousSHA256 string `json:"previous_value_sha256"`
	CurrentSHA256  string `json:"current_value_sha256"`
}

// NPMRCEnvChange describes how a single env var transitioned.
type NPMRCEnvChange struct {
	Name           string `json:"name"`
	Type           string `json:"type"` // "appeared" | "disappeared" | "value_changed"
	PreviousSHA256 string `json:"previous_value_sha256,omitempty"`
	CurrentSHA256  string `json:"current_value_sha256,omitempty"`
}

// NPMRCStringChange is a generic "from / to" tuple for string-typed
// metadata.
type NPMRCStringChange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// NPMRCInt64Change is a generic "from / to" tuple for int64 metadata.
type NPMRCInt64Change struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// NPMRCSuspect is one process that was running near the file's mtime —
// best-effort, not authoritative. Cmd is the truncated command line as
// reported by `ps -ef` / `tasklist`.
type NPMRCSuspect struct {
	PID  int    `json:"pid"`
	User string `json:"user,omitempty"`
	Cmd  string `json:"cmd"`
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
