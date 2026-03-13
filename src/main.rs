mod detect;
mod enterprise;
mod node_scan;
mod output;
mod types;
mod util;

use std::io::{self, Write};
use std::process;
use std::time::Instant;

use types::*;
use util::*;

fn main() {
    // Set process priority to background (best-effort)
    #[cfg(unix)]
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
    }

    let config = match parse_args() {
        Ok(config) => config,
        Err(e) => {
            print_error(&e);
            eprintln!(
                "Run '{} --help' for usage information.",
                std::env::args().next().unwrap_or_else(|| "stepsecurity-dev-machine-guard".to_string())
            );
            process::exit(1);
        }
    };

    // Handle enterprise commands
    if let Some(ref cmd) = config.enterprise_command {
        match cmd {
            EnterpriseCommand::SendTelemetry => {
                if !enterprise::is_enterprise_mode(&config) {
                    print_error("Enterprise configuration not found. Please download the script from your StepSecurity dashboard.");
                    process::exit(1);
                }
                enterprise::run_telemetry(&config);
            }
            EnterpriseCommand::Install => {
                println!("StepSecurity Dev Machine Guard v{}", AGENT_VERSION);
                println!();

                if !enterprise::is_enterprise_mode(&config) {
                    print_error("Enterprise configuration not found. Please download the script from your StepSecurity dashboard.");
                    process::exit(1);
                }

                if enterprise::is_launchd_configured() {
                    eprintln!("Existing agent installation detected. Upgrading...");
                    enterprise::uninstall_launchd();
                    eprintln!("Previous installation removed. Installing new version...");
                }

                match enterprise::configure_launchd(&config) {
                    Ok(()) => {
                        println!();
                        eprintln!("Installation complete!");
                        eprintln!(
                            "The agent will now run automatically every {} hours",
                            config.scan_frequency_hours
                        );
                        println!();
                        eprintln!("Sending initial telemetry...");
                        println!();
                        enterprise::run_telemetry(&config);
                    }
                    Err(e) => {
                        print_error(&e);
                        process::exit(1);
                    }
                }
            }
            EnterpriseCommand::Uninstall => {
                println!("StepSecurity Dev Machine Guard v{}", AGENT_VERSION);
                println!();

                if !enterprise::is_launchd_configured() {
                    eprintln!("Agent is not currently configured for periodic execution");
                    process::exit(0);
                }

                enterprise::uninstall_launchd();
                process::exit(0);
            }
        }
        return;
    }

    // Community mode - check if enterprise config is set and no explicit output format
    if config.output_format == OutputFormat::Pretty && enterprise::is_enterprise_mode(&config) {
        enterprise::run_telemetry(&config);
        return;
    }

    // Community mode scan
    run_scan(&config);
}

fn run_scan(config: &Config) {
    // Verify macOS
    let uname = run_command("uname", &["-s"], None);
    if uname != "Darwin" {
        print_error(&format!(
            "This scanner only supports macOS (detected: {})",
            uname
        ));
        process::exit(1);
    }

    let scan_start = Instant::now();
    let is_json = config.output_format == OutputFormat::Json;
    let verbose = config.verbose;

    if !is_json {
        eprintln!();
        eprintln!("  StepSecurity Dev Machine Guard v{}", AGENT_VERSION);
        eprintln!();
    }

    // Step 1: Gather device information
    step_start("Gathering device information", is_json);
    let serial_number = enterprise::get_serial_number();
    let os_version = enterprise::get_os_version();
    let hostname = run_command("hostname", &[], None);
    let (logged_in_user, user_home) = enterprise::get_logged_in_user_info();

    if logged_in_user.is_empty() || user_home.is_empty() {
        print_error("No user currently logged in to console. Cannot scan.");
        process::exit(1);
    }

    let developer_identity = enterprise::get_developer_identity(&logged_in_user);
    step_done("Gathering device information", is_json, &scan_start);

    // Step 2: Detect IDEs & desktop apps
    let step_time = Instant::now();
    step_start("Scanning IDEs & desktop apps", is_json);
    let ide_installations = detect::detect_ide_installations(&logged_in_user, verbose);
    step_done("Scanning IDEs & desktop apps", is_json, &step_time);

    // Step 3: Detect AI agents and tools
    let step_time = Instant::now();
    step_start("Scanning AI agents & CLI tools", is_json);
    let ai_cli_tools = detect::detect_ai_cli_tools(&logged_in_user, &user_home, verbose);
    let general_ai_agents = detect::detect_general_ai_agents(&user_home, verbose);
    let ai_frameworks = detect::detect_ai_frameworks(&logged_in_user, verbose);
    step_done("Scanning AI agents & CLI tools", is_json, &step_time);

    // Merge AI tools
    let mut ai_tools = Vec::new();
    ai_tools.extend(ai_cli_tools);
    ai_tools.extend(general_ai_agents);
    ai_tools.extend(ai_frameworks);

    // Step 4: MCP configs
    let step_time = Instant::now();
    step_start("Scanning MCP server configs", is_json);
    let jq_available = command_available("jq");
    let perl_available = command_available("perl");
    let mcp_configs = if jq_available && perl_available {
        detect::collect_mcp_configs(
            &user_home,
            enterprise::is_enterprise_mode(config),
            jq_available,
            perl_available,
            verbose,
        )
    } else {
        print_error(&format!(
            "Skipping MCP config collection (jq={}, perl={})",
            jq_available, perl_available
        ));
        vec![]
    };
    step_done("Scanning MCP server configs", is_json, &step_time);

    // Step 5: IDE extensions
    let step_time = Instant::now();
    step_start("Scanning IDE extensions", is_json);
    let ide_extensions = detect::collect_ide_extensions(&user_home, verbose);
    step_done("Scanning IDE extensions", is_json, &step_time);

    // Step 6: Node.js scanning
    let enable_npm = match config.enable_npm_scan {
        NpmScanMode::Enabled => true,
        NpmScanMode::Disabled => false,
        NpmScanMode::Auto => false, // Community mode default: off
    };

    let mut node_package_managers = vec![];
    let mut node_global_scans = vec![];
    let mut node_project_scans = vec![];
    let mut node_projects_count = 0;

    if enable_npm {
        let step_time = Instant::now();
        step_start("Detecting Node.js package managers", is_json);
        node_package_managers = node_scan::detect_package_managers(&logged_in_user, verbose);
        step_done("Detecting Node.js package managers", is_json, &step_time);

        let step_time = Instant::now();
        step_start("Scanning global packages", is_json);
        node_global_scans = node_scan::scan_global_packages(&logged_in_user, verbose);
        step_done("Scanning global packages", is_json, &step_time);

        let step_time = Instant::now();
        step_start("Scanning Node.js projects", is_json);
        let (scans, count) =
            node_scan::scan_node_projects(&user_home, &logged_in_user, verbose);
        node_project_scans = scans;
        node_projects_count = count;
        step_done("Scanning Node.js projects", is_json, &step_time);
    } else {
        step_skip("Node.js packages (use --enable-npm-scan)", is_json);
    }

    let scan_elapsed = scan_start.elapsed().as_secs();
    if !is_json {
        eprintln!();
        eprintln!("  Scan completed in {}s", scan_elapsed);
        eprintln!();
    }

    let results = ScanResults {
        device: DeviceInfo {
            hostname,
            serial_number,
            os_version,
            platform: "darwin".to_string(),
            user_identity: developer_identity,
        },
        ide_installations,
        ai_tools,
        ide_extensions,
        mcp_configs,
        node_package_managers,
        node_global_scans,
        node_project_scans,
        node_projects_count,
    };

    // Output
    match &config.output_format {
        OutputFormat::Json => {
            let json = output::format_json_output(&results);
            println!("{}", json);
        }
        OutputFormat::Html(file) => {
            if let Err(e) = output::generate_html_report(file, &results) {
                print_error(&format!("Failed to generate HTML report: {}", e));
                process::exit(1);
            }
        }
        OutputFormat::Pretty => {
            output::format_pretty_output(&results, &config.color_mode);
        }
    }
}

// ─── Progress Helpers ───────────────────────────────────────────────────────

fn step_start(label: &str, is_json: bool) {
    if !is_json {
        eprint!("  ... {}...", label);
        io::stderr().flush().ok();
    }
}

fn step_done(label: &str, is_json: bool, start: &Instant) {
    if !is_json {
        let elapsed = start.elapsed().as_secs();
        eprint!("\r  \u{2713} {} ({}s)\x1b[K\n", label, elapsed);
    }
}

fn step_skip(label: &str, is_json: bool) {
    if !is_json {
        eprint!("\r  \u{25CB} {} (skipped)\x1b[K\n", label);
    }
}

// ─── CLI Argument Parser ────────────────────────────────────────────────────

fn parse_args() -> Result<Config, String> {
    let mut config = Config {
        output_format: OutputFormat::Pretty,
        color_mode: ColorMode::Auto,
        verbose: false,
        enable_npm_scan: NpmScanMode::Auto,
        enterprise_command: None,
        customer_id: CUSTOMER_ID_PLACEHOLDER.to_string(),
        api_endpoint: API_ENDPOINT_PLACEHOLDER.to_string(),
        api_key: API_KEY_PLACEHOLDER.to_string(),
        scan_frequency_hours: SCAN_FREQUENCY_HOURS_PLACEHOLDER.to_string(),
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "install" | "--install" => {
                config.enterprise_command = Some(EnterpriseCommand::Install);
            }
            "uninstall" | "--uninstall" => {
                config.enterprise_command = Some(EnterpriseCommand::Uninstall);
            }
            "send-telemetry" | "--send-telemetry" => {
                config.enterprise_command = Some(EnterpriseCommand::SendTelemetry);
            }
            "--pretty" => {
                config.output_format = OutputFormat::Pretty;
            }
            "--json" => {
                config.output_format = OutputFormat::Json;
            }
            "--html" => {
                i += 1;
                if i >= args.len() {
                    return Err("--html requires a file path argument".to_string());
                }
                config.output_format = OutputFormat::Html(args[i].clone());
            }
            "--enable-npm-scan" => {
                config.enable_npm_scan = NpmScanMode::Enabled;
            }
            "--disable-npm-scan" => {
                config.enable_npm_scan = NpmScanMode::Disabled;
            }
            "--verbose" => {
                config.verbose = true;
            }
            arg if arg.starts_with("--color=") => {
                let mode = &arg["--color=".len()..];
                config.color_mode = match mode {
                    "auto" => ColorMode::Auto,
                    "always" => ColorMode::Always,
                    "never" => ColorMode::Never,
                    _ => {
                        return Err(format!(
                            "Invalid color mode: {} (must be auto, always, or never)",
                            mode
                        ))
                    }
                };
            }
            "-v" | "--version" => {
                println!("StepSecurity Dev Machine Guard v{}", AGENT_VERSION);
                process::exit(0);
            }
            "-h" | "--help" | "help" => {
                show_help();
                process::exit(0);
            }
            "version" => {
                println!("StepSecurity Dev Machine Guard v{}", AGENT_VERSION);
                process::exit(0);
            }
            other => {
                return Err(format!("Unknown option: {}", other));
            }
        }
        i += 1;
    }

    Ok(config)
}

fn show_help() {
    let prog = std::env::args()
        .next()
        .unwrap_or_else(|| "stepsecurity-dev-machine-guard".to_string());

    eprintln!(
        r#"StepSecurity Dev Machine Guard v{}

Scans your macOS developer environment for IDEs, AI tools, extensions,
MCP servers, and security issues. Outputs results locally or sends
telemetry to StepSecurity backend (enterprise mode).

Usage: {} [COMMAND] [OPTIONS]

Commands (enterprise only):
  install              Install launchd for periodic scanning
  uninstall            Remove launchd configuration
  send-telemetry       Send scan data to StepSecurity backend

Output formats (community mode, mutually exclusive):
  --pretty             Pretty terminal output (default)
  --json               JSON output to stdout
  --html FILE          HTML report saved to FILE

Options:
  --enable-npm-scan    Enable Node.js package scanning
  --disable-npm-scan   Disable Node.js package scanning
  --verbose            Show progress messages (suppressed by default)
  --color=WHEN         Color mode: auto | always | never (default: auto)
  -v, --version        Show version
  -h, --help           Show this help

Examples:
  {}                                  # Pretty terminal output
  {} --json | python3 -m json.tool    # Formatted JSON
  {} --json > scan.json               # JSON to file
  {} --html report.html               # HTML report
  {} --verbose --enable-npm-scan      # Verbose with npm scan
  {} send-telemetry                   # Enterprise telemetry

https://github.com/step-security/dev-machine-guard"#,
        AGENT_VERSION, prog, prog, prog, prog, prog, prog, prog
    );
}
