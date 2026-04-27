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
	SystemPkgManager    *PkgManager     `json:"system_package_manager,omitempty"`
	SystemPackages      []SystemPackage `json:"system_packages"`
	SnapPkgManager      *PkgManager     `json:"snap_package_manager,omitempty"`
	SnapPackages        []SystemPackage `json:"snap_packages"`
	FlatpakPkgManager   *PkgManager     `json:"flatpak_package_manager,omitempty"`
	FlatpakPackages     []SystemPackage `json:"flatpak_packages"`
	Summary             Summary         `json:"summary"`
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
// (rpm, dpkg, pacman, apk).
type SystemPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// BrewPackage represents a single installed Homebrew formula or cask.
type BrewPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
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
	ScanType       string          `json:"scan_type"`                    // "rpm", "dpkg", "pacman", "apk", "snap", "flatpak"
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
