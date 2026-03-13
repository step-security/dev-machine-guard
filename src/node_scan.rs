use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use base64::Engine;

use crate::types::*;
use crate::util::*;

// ─── Package Manager Detection ──────────────────────────────────────────────

pub fn detect_package_managers(logged_in_user: &str, verbose: bool) -> Vec<PackageManager> {
    print_progress(verbose, "Detecting Node.js package managers...");
    let mut managers = Vec::new();

    let checks: &[(&str, &str)] = &[
        ("npm", "npm --version 2>/dev/null"),
        ("yarn", "yarn --version 2>/dev/null"),
        ("pnpm", "pnpm --version 2>/dev/null"),
        ("bun", "bun --version 2>/dev/null"),
    ];

    for (name, version_cmd) in checks {
        let check = run_as_user(
            logged_in_user,
            &format!("command -v {} 2>/dev/null && {}", name, version_cmd),
            10,
        );
        if !check.is_empty() {
            let lines: Vec<&str> = check.lines().collect();
            let path = lines.first().unwrap_or(&"").to_string();
            let version = lines.last().unwrap_or(&"unknown").to_string();

            print_progress(verbose, &format!("  Found: {} v{} at {}", name, version, path));

            managers.push(PackageManager {
                name: name.to_string(),
                version: if version.is_empty() { "unknown".to_string() } else { version },
                is_global: true,
                binary_path: path,
            });
        }
    }

    if managers.is_empty() {
        print_progress(verbose, "  No Node.js package managers found");
    }

    managers
}

// ─── Global Package Scanning ────────────────────────────────────────────────

pub fn scan_global_packages(logged_in_user: &str, verbose: bool) -> Vec<NodeProjectScan> {
    print_progress(verbose, "Scanning globally installed packages...");
    let mut scans = Vec::new();

    // npm global
    scan_npm_global(logged_in_user, verbose, &mut scans);
    // yarn global
    scan_yarn_global(logged_in_user, verbose, &mut scans);
    // pnpm global
    scan_pnpm_global(logged_in_user, verbose, &mut scans);

    if scans.is_empty() {
        print_progress(verbose, "  No globally installed packages found");
    } else {
        print_progress(verbose, &format!("  Found {} global package location(s)", scans.len()));
    }

    scans
}

fn scan_npm_global(logged_in_user: &str, verbose: bool, scans: &mut Vec<NodeProjectScan>) {
    print_progress(verbose, "  Checking npm global packages...");

    let npm_version = run_as_user(logged_in_user, "npm --version 2>/dev/null", 10);
    let npm_prefix = run_as_user(logged_in_user, "npm config get prefix 2>/dev/null", 10);

    if npm_prefix.is_empty() {
        return;
    }

    let start = Instant::now();
    let (stdout, stderr, exit_code) = run_as_user_full(
        logged_in_user,
        "npm list -g --json --depth=3 2>&1",
        60,
    );

    let duration = start.elapsed().as_millis() as u64;
    let error = if exit_code != 0 {
        format!("npm list -g command failed with exit code {}", exit_code)
    } else {
        String::new()
    };

    scans.push(NodeProjectScan {
        project_path: npm_prefix.clone(),
        package_manager: "npm".to_string(),
        package_manager_version: Some(npm_version),
        working_directory: npm_prefix,
        raw_stdout_base64: base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
        raw_stderr_base64: base64::engine::general_purpose::STANDARD.encode(stderr.as_bytes()),
        error,
        exit_code,
        scan_duration_ms: duration,
    });
}

fn scan_yarn_global(logged_in_user: &str, verbose: bool, scans: &mut Vec<NodeProjectScan>) {
    print_progress(verbose, "  Checking yarn global packages...");

    let yarn_version = run_as_user(logged_in_user, "yarn --version 2>/dev/null", 10);
    let yarn_global_dir = run_as_user(logged_in_user, "yarn global dir 2>/dev/null", 10);

    if yarn_global_dir.is_empty() {
        return;
    }

    let start = Instant::now();
    let cmd = format!("cd '{}' && yarn list --json --depth=0 2>&1", yarn_global_dir);
    let (stdout, stderr, exit_code) = run_as_user_full(logged_in_user, &cmd, 60);

    let duration = start.elapsed().as_millis() as u64;
    let error = if exit_code != 0 {
        format!("yarn global list command failed with exit code {}", exit_code)
    } else {
        String::new()
    };

    scans.push(NodeProjectScan {
        project_path: yarn_global_dir.clone(),
        package_manager: "yarn".to_string(),
        package_manager_version: Some(yarn_version),
        working_directory: yarn_global_dir,
        raw_stdout_base64: base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
        raw_stderr_base64: base64::engine::general_purpose::STANDARD.encode(stderr.as_bytes()),
        error,
        exit_code,
        scan_duration_ms: duration,
    });
}

fn scan_pnpm_global(logged_in_user: &str, verbose: bool, scans: &mut Vec<NodeProjectScan>) {
    print_progress(verbose, "  Checking pnpm global packages...");

    let pnpm_version = run_as_user(logged_in_user, "pnpm --version 2>/dev/null", 10);
    let pnpm_global_dir = run_as_user(logged_in_user, "pnpm root -g 2>/dev/null", 10);

    if pnpm_global_dir.is_empty() {
        return;
    }

    // pnpm root -g returns node_modules path, get parent
    let pnpm_dir = Path::new(&pnpm_global_dir)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or(pnpm_global_dir.clone());

    let start = Instant::now();
    let (stdout, stderr, exit_code) = run_as_user_full(
        logged_in_user,
        "pnpm list -g --json --depth=3 2>&1",
        60,
    );

    let duration = start.elapsed().as_millis() as u64;
    let error = if exit_code != 0 {
        format!("pnpm list -g command failed with exit code {}", exit_code)
    } else {
        String::new()
    };

    scans.push(NodeProjectScan {
        project_path: pnpm_dir.clone(),
        package_manager: "pnpm".to_string(),
        package_manager_version: Some(pnpm_version),
        working_directory: pnpm_dir,
        raw_stdout_base64: base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
        raw_stderr_base64: base64::engine::general_purpose::STANDARD.encode(stderr.as_bytes()),
        error,
        exit_code,
        scan_duration_ms: duration,
    });
}

// ─── Node.js Project Scanning ───────────────────────────────────────────────

fn detect_project_package_manager(project_dir: &str) -> &'static str {
    if project_dir.contains("/.bun/install/") {
        return "bun";
    }

    let dir = Path::new(project_dir);
    if dir.join("bun.lock").exists() || dir.join("bun.lockb").exists() {
        "bun"
    } else if dir.join("pnpm-lock.yaml").exists() {
        "pnpm"
    } else if dir.join("yarn.lock").exists() {
        if dir.join(".yarnrc.yml").exists() || dir.join(".yarn/releases").is_dir() {
            "yarn-berry"
        } else {
            "yarn"
        }
    } else if dir.join("package-lock.json").exists() {
        "npm"
    } else {
        "npm"
    }
}

fn get_pm_version(pm: &str, logged_in_user: &str) -> String {
    let cmd = match pm {
        "npm" => "npm --version 2>/dev/null",
        "yarn" | "yarn-berry" => "yarn --version 2>/dev/null",
        "pnpm" => "pnpm --version 2>/dev/null",
        "bun" => "bun --version 2>/dev/null",
        _ => return "unknown".to_string(),
    };
    let ver = run_as_user(logged_in_user, cmd, 10);
    if ver.is_empty() { "unknown".to_string() } else { ver }
}

fn list_project_packages(
    project_dir: &str,
    package_manager: &str,
    logged_in_user: &str,
) -> Option<NodeProjectScan> {
    // Check node_modules for most package managers
    match package_manager {
        "npm" | "yarn" | "pnpm" | "bun" => {
            let nm = Path::new(project_dir).join("node_modules");
            if !nm.is_dir() {
                return None;
            }
        }
        _ => {}
    }

    let start = Instant::now();

    let list_cmd = match package_manager {
        "npm" => format!(
            "cd '{}' && command -v npm >/dev/null 2>&1 && npm ls --json --depth=3 2>&1 || echo 'npm command failed'",
            project_dir
        ),
        "yarn" => format!(
            "cd '{}' && command -v yarn >/dev/null 2>&1 && yarn list --json 2>&1 || echo 'yarn command failed'",
            project_dir
        ),
        "yarn-berry" => format!(
            "cd '{}' && command -v yarn >/dev/null 2>&1 && yarn info --all --json 2>&1 || echo 'yarn command failed'",
            project_dir
        ),
        "pnpm" => format!(
            "cd '{}' && command -v pnpm >/dev/null 2>&1 && pnpm ls --json --depth=3 2>&1 || echo 'pnpm command failed'",
            project_dir
        ),
        "bun" => format!(
            "cd '{}' && command -v bun >/dev/null 2>&1 && bun pm ls --all 2>&1 || echo 'bun command failed'",
            project_dir
        ),
        _ => return None,
    };

    let (stdout, stderr, exit_code) = run_as_user_full(logged_in_user, &list_cmd, 60);
    let duration = start.elapsed().as_millis() as u64;

    let error = if exit_code != 0 {
        format!("{} command failed with exit code {}", package_manager, exit_code)
    } else {
        String::new()
    };

    Some(NodeProjectScan {
        project_path: project_dir.to_string(),
        package_manager: package_manager.to_string(),
        package_manager_version: None,
        working_directory: project_dir.to_string(),
        raw_stdout_base64: base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
        raw_stderr_base64: base64::engine::general_purpose::STANDARD.encode(stderr.as_bytes()),
        error,
        exit_code,
        scan_duration_ms: duration,
    })
}

/// Check if a path is a global package directory
fn is_global_package_directory(check_path: &str, logged_in_user: &str) -> bool {
    // Check npm prefix
    let npm_prefix = run_as_user(logged_in_user, "npm config get prefix 2>/dev/null", 10);
    if !npm_prefix.is_empty() && check_path.starts_with(&npm_prefix) {
        return true;
    }

    // Check yarn global dir
    let yarn_dir = run_as_user(logged_in_user, "yarn global dir 2>/dev/null", 10);
    if !yarn_dir.is_empty() && check_path.starts_with(&yarn_dir) {
        return true;
    }

    // Check pnpm global dir
    let pnpm_root = run_as_user(logged_in_user, "pnpm root -g 2>/dev/null", 10);
    if !pnpm_root.is_empty() {
        let pnpm_dir = Path::new(&pnpm_root)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or(pnpm_root);
        if check_path.starts_with(&pnpm_dir) {
            return true;
        }
    }

    false
}

pub fn scan_node_projects(
    search_dir: &str,
    logged_in_user: &str,
    verbose: bool,
) -> (Vec<NodeProjectScan>, usize) {
    print_progress(verbose, "Searching for Node.js projects...");

    if search_dir.is_empty() {
        return (Vec::new(), 0);
    }

    let start = Instant::now();
    let mut scans = Vec::new();
    let mut project_count = 0;
    let mut cumulative_size: u64 = 0;
    let mut processed_paths: HashSet<String> = HashSet::new();

    print_progress(verbose, &format!("  Searching in: {}", search_dir));

    // Find package.json files, excluding node_modules, sorted by mtime (most recent first)
    let (find_output, _, _) = run_shell(
        &format!(
            "find '{}' -name 'package.json' -type f 2>/dev/null | grep -v '/node_modules/' | while IFS= read -r f; do stat -f '%m %N' \"$f\" 2>/dev/null; done | sort -rn | cut -d' ' -f2-",
            search_dir
        ),
        120,
    );

    for package_json in find_output.lines() {
        let package_json = package_json.trim();
        if package_json.is_empty() {
            continue;
        }

        let project_dir = match Path::new(package_json).parent() {
            Some(p) => p.to_string_lossy().to_string(),
            None => continue,
        };

        // Skip if inside node_modules of a processed project
        let skip = processed_paths.iter().any(|p| {
            let nm = format!("{}/node_modules", p);
            project_dir.starts_with(&nm)
        });
        if skip {
            continue;
        }

        // Skip already processed
        if processed_paths.contains(&project_dir) {
            continue;
        }

        // Skip global package directories
        if is_global_package_directory(&project_dir, logged_in_user) {
            print_progress(verbose, &format!("    Skipping global package directory: {}", project_dir));
            continue;
        }

        processed_paths.insert(project_dir.clone());

        print_progress(verbose, &format!("    Found project: {}", project_dir));

        let pm = detect_project_package_manager(&project_dir);
        print_progress(verbose, &format!("      Package manager: {}", pm));

        let pm_version = get_pm_version(pm, logged_in_user);

        let scan_result = match list_project_packages(&project_dir, pm, logged_in_user) {
            Some(mut scan) => {
                scan.package_manager_version = Some(pm_version);
                scan
            }
            None => {
                print_progress(verbose, "      Skipping (no node_modules directory)");
                continue;
            }
        };

        // Check cumulative size
        let result_size = serde_json::to_string(&scan_result).unwrap_or_default().len() as u64;
        if cumulative_size + result_size > MAX_NODE_PROJECTS_SIZE_BYTES {
            print_progress(verbose, &format!("    Reached data size limit ({} bytes collected)", cumulative_size));
            break;
        }
        cumulative_size += result_size;

        scans.push(scan_result);
        project_count += 1;

        if project_count >= MAX_NODE_PROJECTS {
            print_progress(verbose, "    Reached maximum of 1000 projects, stopping search");
            break;
        }
    }

    let duration = start.elapsed().as_millis();
    print_progress(verbose, &format!("Found {} Node.js projects", project_count));
    print_progress(verbose, &format!("  Scan duration: {}ms", duration));

    (scans, project_count)
}

// ─── Package Extraction (for pretty/HTML/JSON output) ───────────────────────

pub fn extract_packages_from_scans(scans: &[NodeProjectScan]) -> Vec<NodePackageFolder> {
    let mut folders = Vec::new();

    for scan in scans {
        if scan.raw_stdout_base64.is_empty() {
            continue;
        }

        let decoded = match base64::engine::general_purpose::STANDARD.decode(&scan.raw_stdout_base64) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => continue,
        };

        if decoded.is_empty() {
            continue;
        }

        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        // Try to parse as JSON for npm/pnpm
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&decoded) {
            extract_npm_packages(&value, &mut packages, &mut seen);
        }

        // If no packages found, try yarn JSON format
        if packages.is_empty() {
            for line in decoded.lines() {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(name) = value.get("name").and_then(|n| n.as_str()) {
                        if name.contains('@') {
                            let parts: Vec<&str> = name.rsplitn(2, '@').collect();
                            if parts.len() == 2 {
                                let key = format!("{}@{}", parts[1], parts[0]);
                                if seen.insert(key) {
                                    packages.push(NodePackageEntry {
                                        name: parts[1].to_string(),
                                        version: parts[0].to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Try bun text format
        if packages.is_empty() {
            for line in decoded.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("├── ").or_else(|| line.strip_prefix("└── ")) {
                    if let Some(at_pos) = rest.rfind('@') {
                        let name = &rest[..at_pos];
                        let version = &rest[at_pos + 1..];
                        let key = format!("{}@{}", name, version);
                        if seen.insert(key) {
                            packages.push(NodePackageEntry {
                                name: name.to_string(),
                                version: version.to_string(),
                            });
                        }
                    }
                }
            }
        }

        if !packages.is_empty() {
            packages.sort_by(|a, b| a.name.cmp(&b.name));
            folders.push(NodePackageFolder {
                folder: scan.project_path.clone(),
                package_manager: scan.package_manager.clone(),
                packages,
            });
        }
    }

    folders
}

fn extract_npm_packages(
    value: &serde_json::Value,
    packages: &mut Vec<NodePackageEntry>,
    seen: &mut HashSet<String>,
) {
    if let Some(deps) = value.get("dependencies").and_then(|d| d.as_object()) {
        for (name, info) in deps {
            if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                let key = format!("{}@{}", name, version);
                if seen.insert(key) {
                    packages.push(NodePackageEntry {
                        name: name.clone(),
                        version: version.to_string(),
                    });
                }
            }
            // Recurse into nested dependencies
            extract_npm_packages(info, packages, seen);
        }
    }
}
