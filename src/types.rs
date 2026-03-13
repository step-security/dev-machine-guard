use serde::{Deserialize, Serialize};

/// Version of the agent
pub const AGENT_VERSION: &str = "1.8.1";

/// Maximum sizes
pub const _MAX_LOG_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10MB
pub const _MAX_PACKAGE_OUTPUT_SIZE_BYTES: u64 = 50 * 1024 * 1024; // 50MB
pub const MAX_NODE_PROJECTS_SIZE_BYTES: u64 = 500 * 1024 * 1024; // 500MB
pub const MAX_NODE_PROJECTS: usize = 1000;

/// Enterprise configuration placeholders
pub const CUSTOMER_ID_PLACEHOLDER: &str = "{{CUSTOMER_ID}}";
pub const API_ENDPOINT_PLACEHOLDER: &str = "{{API_ENDPOINT}}";
pub const API_KEY_PLACEHOLDER: &str = "{{API_KEY}}";
pub const SCAN_FREQUENCY_HOURS_PLACEHOLDER: &str = "{{SCAN_FREQUENCY_HOURS}}";

// ─── Output format ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Pretty,
    Json,
    Html(String), // file path
}

#[derive(Debug, Clone, PartialEq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EnterpriseCommand {
    Install,
    Uninstall,
    SendTelemetry,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub output_format: OutputFormat,
    pub color_mode: ColorMode,
    pub verbose: bool,
    pub enable_npm_scan: NpmScanMode,
    pub enterprise_command: Option<EnterpriseCommand>,
    // Enterprise settings
    pub customer_id: String,
    pub api_endpoint: String,
    pub api_key: String,
    pub scan_frequency_hours: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NpmScanMode {
    Auto,
    Enabled,
    Disabled,
}

// ─── Scan result types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdeInstallation {
    pub ide_type: String,
    pub version: String,
    pub install_path: String,
    pub vendor: String,
    pub is_installed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTool {
    pub name: String,
    pub vendor: String,
    #[serde(rename = "type")]
    pub tool_type: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_running: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    pub config_source: String,
    pub config_path: String,
    pub vendor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_content_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdeExtension {
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: u64,
    pub ide_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManager {
    pub name: String,
    pub version: String,
    pub is_global: bool,
    pub binary_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeProjectScan {
    pub project_path: String,
    pub package_manager: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_manager_version: Option<String>,
    pub working_directory: String,
    pub raw_stdout_base64: String,
    pub raw_stderr_base64: String,
    pub error: String,
    pub exit_code: i32,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePackageEntry {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePackageFolder {
    pub folder: String,
    pub package_manager: String,
    pub packages: Vec<NodePackageEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub hostname: String,
    pub serial_number: String,
    pub os_version: String,
    pub platform: String,
    pub user_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub ai_agents_and_tools_count: usize,
    pub ide_installations_count: usize,
    pub ide_extensions_count: usize,
    pub mcp_configs_count: usize,
    pub node_projects_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutput {
    pub agent_version: String,
    pub agent_url: String,
    pub scan_timestamp: i64,
    pub scan_timestamp_iso: String,
    pub device: DeviceInfo,
    pub ai_agents_and_tools: Vec<AiTool>,
    pub ide_installations: Vec<IdeInstallation>,
    pub ide_extensions: Vec<IdeExtension>,
    pub mcp_configs: Vec<McpConfig>,
    pub node_package_managers: Vec<PackageManager>,
    pub node_packages: Vec<NodePackageFolder>,
    pub summary: ScanSummary,
}

/// Full scan results (internal, before formatting)
#[derive(Debug, Clone)]
pub struct ScanResults {
    pub device: DeviceInfo,
    pub ide_installations: Vec<IdeInstallation>,
    pub ai_tools: Vec<AiTool>,
    pub ide_extensions: Vec<IdeExtension>,
    pub mcp_configs: Vec<McpConfig>,
    pub node_package_managers: Vec<PackageManager>,
    pub node_global_scans: Vec<NodeProjectScan>,
    pub node_project_scans: Vec<NodeProjectScan>,
    pub node_projects_count: usize,
}

// ─── Enterprise telemetry types ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLogs {
    pub output_base64: String,
    pub start_time: i64,
    pub end_time: i64,
    pub exit_code: i32,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub extensions_count: usize,
    pub node_packages_scan_ms: u64,
    pub node_global_packages_count: usize,
    pub node_projects_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableTools {
    pub jq: bool,
    pub perl: bool,
    pub curl: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPayload {
    pub customer_id: String,
    pub device_id: String,
    pub serial_number: String,
    pub user_identity: String,
    pub hostname: String,
    pub platform: String,
    pub os_version: String,
    pub agent_version: String,
    pub collected_at: i64,
    pub no_user_logged_in: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_tools: Option<AvailableTools>,
    pub ide_extensions: Vec<IdeExtension>,
    pub ide_installations: Vec<IdeInstallation>,
    pub node_package_managers: Vec<PackageManager>,
    pub node_global_packages: Vec<NodeProjectScan>,
    pub node_projects: Vec<NodeProjectScan>,
    pub ai_agents: Vec<AiTool>,
    pub mcp_configs: Vec<McpConfig>,
    pub execution_logs: ExecutionLogs,
    pub performance_metrics: PerformanceMetrics,
}
