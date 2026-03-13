use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::detect::*;
use crate::node_scan::*;
use crate::types::*;
use crate::util::*;

// ─── Enterprise Mode Detection ──────────────────────────────────────────────

pub fn is_enterprise_mode(config: &Config) -> bool {
    !config.api_key.is_empty() && !config.api_key.contains("{{")
}

// ─── Instance Locking ───────────────────────────────────────────────────────

fn get_lock_file_path() -> String {
    let is_root = unsafe { libc::getuid() } == 0;
    if is_root {
        "/var/run/stepsecurity-agent.lock".to_string()
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let lock_dir = format!("{}/.stepsecurity", home);
        let _ = fs::create_dir_all(&lock_dir);
        format!("{}/agent.lock", lock_dir)
    }
}

pub fn acquire_lock() -> Result<(), String> {
    let lock_file = get_lock_file_path();
    let my_pid = std::process::id();

    if Path::new(&lock_file).exists() {
        if let Ok(contents) = fs::read_to_string(&lock_file) {
            if let Ok(existing_pid) = contents.trim().parse::<u32>() {
                // Check if process is still running
                let status = Command::new("kill")
                    .args(["-0", &existing_pid.to_string()])
                    .output();
                if let Ok(output) = status {
                    if output.status.success() {
                        return Err(format!(
                            "Another instance is already running (PID: {})",
                            existing_pid
                        ));
                    }
                }
                // Stale lock, remove it
                let _ = fs::remove_file(&lock_file);
            }
        }
    }

    // Write our PID
    if let Ok(mut f) = fs::File::create(&lock_file) {
        let _ = write!(f, "{}", my_pid);
    }

    Ok(())
}

pub fn release_lock() {
    let lock_file = get_lock_file_path();
    let my_pid = std::process::id();

    if let Ok(contents) = fs::read_to_string(&lock_file) {
        if let Ok(pid) = contents.trim().parse::<u32>() {
            if pid == my_pid {
                let _ = fs::remove_file(&lock_file);
            }
        }
    }
}

// ─── LaunchD Management ─────────────────────────────────────────────────────

pub fn configure_launchd(config: &Config) -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| format!("Failed to get executable path: {}", e))?;

    let is_root = unsafe { libc::getuid() } == 0;

    let scan_freq: u64 = config
        .scan_frequency_hours
        .parse::<u64>()
        .unwrap_or(6);
    let interval_seconds = scan_freq * 3600;

    eprintln!("Configuring launchd for periodic execution...");
    eprintln!("  Script: {}", exe_path);
    eprintln!("  Interval: Every {} hours ({} seconds)", scan_freq, interval_seconds);

    let (plist_path, log_dir) = if is_root {
        eprintln!("  Type: LaunchDaemon (system-wide)");
        let log_dir = "/var/log/stepsecurity";
        let _ = fs::create_dir_all(log_dir);
        (
            "/Library/LaunchDaemons/com.stepsecurity.agent.plist".to_string(),
            log_dir.to_string(),
        )
    } else {
        eprintln!("  Type: LaunchAgent (user-specific)");
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let agents_dir = format!("{}/Library/LaunchAgents", home);
        let _ = fs::create_dir_all(&agents_dir);
        let log_dir = format!("{}/.stepsecurity", home);
        let _ = fs::create_dir_all(&log_dir);
        (
            format!("{}/com.stepsecurity.agent.plist", agents_dir),
            log_dir,
        )
    };

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.stepsecurity.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>send-telemetry</string>
    </array>
    <key>StartInterval</key>
    <integer>{}</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>{}/agent.error.log</string>
</dict>
</plist>"#,
        exe_path, interval_seconds, log_dir, log_dir
    );

    fs::write(&plist_path, plist_content)
        .map_err(|e| format!("Failed to write plist: {}", e))?;

    // Load the plist
    let status = Command::new("launchctl")
        .args(["load", &plist_path])
        .output();

    match status {
        Ok(output) if output.status.success() => {
            eprintln!("launchd configuration completed successfully");
            eprintln!("  Plist: {}", plist_path);
            eprintln!("  Logs: {}/agent.log", log_dir);
            Ok(())
        }
        _ => Err("Failed to load launchd configuration".to_string()),
    }
}

pub fn uninstall_launchd() {
    let is_root = unsafe { libc::getuid() } == 0;
    let plist_path = if is_root {
        eprintln!("Removing LaunchDaemon configuration...");
        "/Library/LaunchDaemons/com.stepsecurity.agent.plist".to_string()
    } else {
        eprintln!("Removing LaunchAgent configuration...");
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/Library/LaunchAgents/com.stepsecurity.agent.plist", home)
    };

    // Check if loaded
    let list_output = run_command("launchctl", &["list"], None);
    if list_output.contains("com.stepsecurity.agent") {
        let _ = Command::new("launchctl")
            .args(["unload", &plist_path])
            .output();
        eprintln!("Unloaded launchd agent");
    }

    if Path::new(&plist_path).exists() {
        let _ = fs::remove_file(&plist_path);
        eprintln!("Removed plist file: {}", plist_path);
    } else {
        eprintln!("Plist file not found: {}", plist_path);
    }

    eprintln!("launchd configuration removed successfully");
}

pub fn is_launchd_configured() -> bool {
    let list_output = run_command("launchctl", &["list"], None);
    list_output.contains("com.stepsecurity.agent")
}

// ─── Telemetry Upload ───────────────────────────────────────────────────────

fn upload_telemetry_to_s3(
    device_id: &str,
    payload_file: &str,
    config: &Config,
) -> Result<(), String> {
    eprintln!("Requesting upload URL from backend...");

    let (response, _, code) = run_shell(
        &format!(
            r#"curl -s -X POST \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer {}" \
                -H "X-Agent-Version: {}" \
                -d '{{"device_id":"{}"}}' \
                "{}/v1/{}/developer-mdm-agent/telemetry/upload-url""#,
            config.api_key, AGENT_VERSION, device_id, config.api_endpoint, config.customer_id
        ),
        30,
    );

    if code != 0 {
        return Err("Failed to request upload URL".to_string());
    }

    // Extract upload_url and s3_key
    let upload_url = extract_json_string(&response, "upload_url")
        .ok_or("Failed to parse upload URL")?
        .replace("\\u0026", "&")
        .replace("\\u003d", "=")
        .replace("\\u002f", "/")
        .replace("\\/", "/");

    let s3_key = extract_json_string(&response, "s3_key")
        .ok_or("Failed to parse s3_key")?;

    eprintln!("Uploading telemetry to S3...");

    let (upload_response, _, _) = run_shell(
        &format!(
            r#"curl -w "\n%{{http_code}}" -X PUT \
                -H "Content-Type: application/json" \
                --upload-file {} \
                "{}""#,
            payload_file, upload_url
        ),
        60,
    );

    let http_code = upload_response.lines().last().unwrap_or("0");
    if http_code != "200" {
        return Err(format!("Failed to upload to S3 (HTTP {})", http_code));
    }

    eprintln!("Uploaded to S3");
    eprintln!("Notifying backend of upload...");

    let (notify_response, _, _) = run_shell(
        &format!(
            r#"curl -w "\n%{{http_code}}" -s -X POST \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer {}" \
                -H "X-Agent-Version: {}" \
                -d '{{"s3_key":"{}","device_id":"{}"}}' \
                "{}/v1/{}/developer-mdm-agent/telemetry/process-uploaded""#,
            config.api_key, AGENT_VERSION, s3_key, device_id,
            config.api_endpoint, config.customer_id
        ),
        30,
    );

    let notify_code = notify_response.lines().last().unwrap_or("0");
    if notify_code == "200" || notify_code == "201" {
        eprintln!("Backend processing initiated (HTTP {})", notify_code);
        Ok(())
    } else {
        Err(format!("Failed to notify backend (HTTP {})", notify_code))
    }
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ─── Run Telemetry (Enterprise Mode) ────────────────────────────────────────

pub fn run_telemetry(config: &Config) {
    println!("==========================================");
    println!("StepSecurity Device Agent v{}", AGENT_VERSION);
    println!("==========================================");
    println!();

    // Acquire lock
    if let Err(e) = acquire_lock() {
        print_error(&e);
        std::process::exit(1);
    }

    // Verify macOS
    let uname = run_command("uname", &["-s"], None);
    if uname != "Darwin" {
        print_error("This agent is for macOS only");
        release_lock();
        std::process::exit(1);
    }

    let jq_available = command_available("jq");
    let perl_available = command_available("perl");
    let curl_available = command_available("curl");

    eprintln!(
        "Tool availability: curl={}, jq={}, perl={}",
        curl_available, jq_available, perl_available
    );

    if !curl_available {
        print_error("curl not found (should be pre-installed on macOS)");
        release_lock();
        std::process::exit(1);
    }

    // Validate config
    if config.customer_id.contains("{{") || config.api_key.contains("{{") || config.api_endpoint.contains("{{") {
        print_error("This script needs to be customized with your customer details");
        release_lock();
        std::process::exit(1);
    }

    // Get device identity
    let serial_number = get_serial_number();
    let os_version = get_os_version();
    let device_id = serial_number.clone();
    let hostname = run_command("hostname", &[], None);

    // Get logged-in user
    let (logged_in_user, user_home) = get_logged_in_user_info();

    let collected_at = timestamp_secs();

    if logged_in_user.is_empty() || user_home.is_empty() {
        eprintln!("No user currently logged in - skipping data collection");

        let payload = TelemetryPayload {
            customer_id: config.customer_id.clone(),
            device_id: device_id.clone(),
            serial_number: serial_number.clone(),
            user_identity: "none".to_string(),
            hostname,
            platform: "darwin".to_string(),
            os_version,
            agent_version: AGENT_VERSION.to_string(),
            collected_at,
            no_user_logged_in: true,
            available_tools: None,
            ide_extensions: vec![],
            ide_installations: vec![],
            node_package_managers: vec![],
            node_global_packages: vec![],
            node_projects: vec![],
            ai_agents: vec![],
            mcp_configs: vec![],
            execution_logs: ExecutionLogs {
                output_base64: String::new(),
                start_time: collected_at,
                end_time: collected_at,
                exit_code: 0,
                agent_version: AGENT_VERSION.to_string(),
            },
            performance_metrics: PerformanceMetrics {
                extensions_count: 0,
                node_packages_scan_ms: 0,
                node_global_packages_count: 0,
                node_projects_count: 0,
            },
        };

        let payload_json = serde_json::to_string_pretty(&payload).unwrap_or_default();
        let tmp_file = "/tmp/stepsec-payload.json";
        let _ = fs::write(tmp_file, &payload_json);

        match upload_telemetry_to_s3(&device_id, tmp_file, config) {
            Ok(()) => {
                let _ = fs::remove_file(tmp_file);
                eprintln!("Telemetry sent successfully (no user logged in)");
                release_lock();
                std::process::exit(0);
            }
            Err(e) => {
                print_error(&format!("Telemetry upload failed: {}", e));
                release_lock();
                std::process::exit(1);
            }
        }
    }

    let developer_identity = get_developer_identity(&logged_in_user);

    eprintln!("Device ID (Serial): {}", device_id);
    eprintln!("OS Version: {}", os_version);
    eprintln!("Developer: {}", developer_identity);
    eprintln!("Running commands as user: {}", logged_in_user);
    println!();

    // Run detections
    let ide_installations = detect_ide_installations(&logged_in_user, true);
    let ai_cli_tools = detect_ai_cli_tools(&logged_in_user, &user_home, true);
    let general_ai_agents = detect_general_ai_agents(&user_home, true);
    let ai_frameworks = detect_ai_frameworks(&logged_in_user, true);

    let mut ai_agents = Vec::new();
    ai_agents.extend(ai_cli_tools);
    ai_agents.extend(general_ai_agents);
    ai_agents.extend(ai_frameworks);

    let mcp_configs = if jq_available && perl_available {
        collect_mcp_configs(&user_home, true, jq_available, perl_available, true)
    } else {
        print_error(&format!("Skipping MCP config collection (jq={}, perl={})", jq_available, perl_available));
        vec![]
    };

    let ide_extensions = collect_ide_extensions(&user_home, true);

    // Node.js scanning
    let enable_npm = config.enable_npm_scan != NpmScanMode::Disabled;
    let mut node_package_managers = vec![];
    let mut node_global_scans = vec![];
    let mut node_project_scans = vec![];
    let mut node_projects_count = 0;
    let node_scan_duration = 0u64;

    if enable_npm {
        eprintln!("Node.js package scanning is ENABLED");
        node_package_managers = detect_package_managers(&logged_in_user, true);
        node_global_scans = scan_global_packages(&logged_in_user, true);
        let (scans, count) = scan_node_projects(&user_home, &logged_in_user, true);
        node_project_scans = scans;
        node_projects_count = count;
    } else {
        eprintln!("Node.js package scanning is DISABLED");
    }

    let payload = TelemetryPayload {
        customer_id: config.customer_id.clone(),
        device_id: device_id.clone(),
        serial_number: serial_number.clone(),
        user_identity: developer_identity,
        hostname,
        platform: "darwin".to_string(),
        os_version,
        agent_version: AGENT_VERSION.to_string(),
        collected_at,
        no_user_logged_in: false,
        available_tools: Some(AvailableTools {
            jq: jq_available,
            perl: perl_available,
            curl: curl_available,
        }),
        ide_extensions: ide_extensions.clone(),
        ide_installations,
        node_package_managers,
        node_global_packages: node_global_scans,
        node_projects: node_project_scans,
        ai_agents,
        mcp_configs,
        execution_logs: ExecutionLogs {
            output_base64: String::new(),
            start_time: collected_at,
            end_time: timestamp_secs(),
            exit_code: 0,
            agent_version: AGENT_VERSION.to_string(),
        },
        performance_metrics: PerformanceMetrics {
            extensions_count: ide_extensions.len(),
            node_packages_scan_ms: node_scan_duration,
            node_global_packages_count: 0,
            node_projects_count,
        },
    };

    let payload_json = serde_json::to_string_pretty(&payload).unwrap_or_default();
    let tmp_file = "/tmp/stepsec-payload.json";
    let _ = fs::write(tmp_file, &payload_json);

    match upload_telemetry_to_s3(&device_id, tmp_file, config) {
        Ok(()) => {
            let _ = fs::remove_file(tmp_file);
            println!();
            eprintln!("Telemetry collection completed successfully");
            release_lock();
            std::process::exit(0);
        }
        Err(e) => {
            println!();
            print_error(&format!("Telemetry upload failed: {}", e));
            release_lock();
            std::process::exit(1);
        }
    }
}

// ─── Device Info Helpers ────────────────────────────────────────────────────

pub fn get_serial_number() -> String {
    let serial = run_command(
        "sh",
        &["-c", "ioreg -l | grep IOPlatformSerialNumber | awk '{print $4}' | tr -d '\"'"],
        None,
    );
    if serial.is_empty() {
        let fallback = run_command(
            "sh",
            &["-c", "system_profiler SPHardwareDataType | awk '/Serial/ {print $4}'"],
            None,
        );
        if fallback.is_empty() {
            "unknown".to_string()
        } else {
            fallback
        }
    } else {
        serial
    }
}

pub fn get_os_version() -> String {
    let ver = run_command("sw_vers", &["-productVersion"], None);
    if ver.is_empty() {
        "unknown".to_string()
    } else {
        ver
    }
}

pub fn get_developer_identity(username: &str) -> String {
    for var in &["USER_EMAIL", "DEVELOPER_EMAIL", "STEPSEC_DEVELOPER_EMAIL"] {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                return val;
            }
        }
    }
    username.to_string()
}

pub fn get_logged_in_user_info() -> (String, String) {
    let logged_in_user = run_command("stat", &["-f%Su", "/dev/console"], None);

    if logged_in_user.is_empty()
        || logged_in_user == "root"
        || logged_in_user == "_windowserver"
    {
        return (String::new(), String::new());
    }

    let user_home = run_command(
        "sh",
        &[
            "-c",
            &format!(
                "dscl . -read /Users/{} NFSHomeDirectory | awk '{{ print $2 }}'",
                logged_in_user
            ),
        ],
        None,
    );

    if user_home.is_empty() || !Path::new(&user_home).is_dir() {
        return (logged_in_user, String::new());
    }

    (logged_in_user, user_home)
}
