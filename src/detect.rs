use std::fs;
use std::path::Path;

use crate::types::*;
use crate::util::*;

// ─── IDE Detection ──────────────────────────────────────────────────────────

struct IdeDefinition {
    app_name: &'static str,
    ide_type: &'static str,
    vendor: &'static str,
    app_path: &'static str,
    binary_path: &'static str,
    version_command: &'static str,
}

const IDE_DEFINITIONS: &[IdeDefinition] = &[
    IdeDefinition {
        app_name: "Visual Studio Code",
        ide_type: "vscode",
        vendor: "Microsoft",
        app_path: "/Applications/Visual Studio Code.app",
        binary_path: "Contents/Resources/app/bin/code",
        version_command: "--version",
    },
    IdeDefinition {
        app_name: "Cursor",
        ide_type: "cursor",
        vendor: "Cursor",
        app_path: "/Applications/Cursor.app",
        binary_path: "Contents/Resources/app/bin/cursor",
        version_command: "--version",
    },
    IdeDefinition {
        app_name: "Windsurf",
        ide_type: "windsurf",
        vendor: "Codeium",
        app_path: "/Applications/Windsurf.app",
        binary_path: "Contents/MacOS/Windsurf",
        version_command: "--version",
    },
    IdeDefinition {
        app_name: "Antigravity",
        ide_type: "antigravity",
        vendor: "Google",
        app_path: "/Applications/Antigravity.app",
        binary_path: "Contents/MacOS/Antigravity",
        version_command: "--version",
    },
    IdeDefinition {
        app_name: "Zed",
        ide_type: "zed",
        vendor: "Zed",
        app_path: "/Applications/Zed.app",
        binary_path: "",
        version_command: "",
    },
    IdeDefinition {
        app_name: "Claude",
        ide_type: "claude_desktop",
        vendor: "Anthropic",
        app_path: "/Applications/Claude.app",
        binary_path: "",
        version_command: "",
    },
    IdeDefinition {
        app_name: "Microsoft Copilot",
        ide_type: "microsoft_copilot_desktop",
        vendor: "Microsoft",
        app_path: "/Applications/Copilot.app",
        binary_path: "",
        version_command: "",
    },
];

pub fn detect_ide_installations(logged_in_user: &str, verbose: bool) -> Vec<IdeInstallation> {
    print_progress(verbose, "Detecting IDE and AI desktop app installations...");
    let mut results = Vec::new();

    for ide in IDE_DEFINITIONS {
        let app_path = Path::new(ide.app_path);
        if !app_path.is_dir() {
            continue;
        }

        let mut version = String::from("unknown");

        // Try to get version from binary
        if !ide.binary_path.is_empty() && !ide.version_command.is_empty() {
            let binary_full = format!("{}/{}", ide.app_path, ide.binary_path);
            if Path::new(&binary_full).exists() {
                let result = run_as_user(
                    logged_in_user,
                    &format!("{:?} {} 2>/dev/null | head -1", binary_full, ide.version_command),
                    10,
                );
                if !result.is_empty() {
                    version = result.lines().next().unwrap_or("unknown").trim().to_string();
                }
            }
        }

        // Fallback: try Info.plist
        if version == "unknown" {
            let plist_path = format!("{}/Contents/Info.plist", ide.app_path);
            if Path::new(&plist_path).exists() {
                let plist_ver = run_command(
                    "/usr/libexec/PlistBuddy",
                    &["-c", "Print :CFBundleShortVersionString", &plist_path],
                    None,
                );
                if !plist_ver.is_empty() {
                    version = plist_ver;
                }
            }
        }

        if version.is_empty() {
            version = "unknown".to_string();
        }

        print_progress(
            verbose,
            &format!("  Found: {} ({}) v{} at {}", ide.app_name, ide.vendor, version, ide.app_path),
        );

        results.push(IdeInstallation {
            ide_type: ide.ide_type.to_string(),
            version,
            install_path: ide.app_path.to_string(),
            vendor: ide.vendor.to_string(),
            is_installed: true,
        });
    }

    if results.is_empty() {
        print_progress(verbose, "  No IDEs or AI desktop apps found");
    }

    results
}

// ─── AI CLI Tools Detection ─────────────────────────────────────────────────

struct CliToolDefinition {
    tool_name: &'static str,
    vendor: &'static str,
    binary_names: &'static [&'static str],
    config_dirs: &'static [&'static str],
}

const CLI_TOOL_DEFINITIONS: &[CliToolDefinition] = &[
    CliToolDefinition {
        tool_name: "claude-code",
        vendor: "Anthropic",
        binary_names: &["claude"],
        config_dirs: &["~/.claude"],
    },
    CliToolDefinition {
        tool_name: "codex",
        vendor: "OpenAI",
        binary_names: &["codex"],
        config_dirs: &["~/.codex"],
    },
    CliToolDefinition {
        tool_name: "gemini-cli",
        vendor: "Google",
        binary_names: &["gemini"],
        config_dirs: &["~/.gemini"],
    },
    CliToolDefinition {
        tool_name: "amazon-q-cli",
        vendor: "Amazon",
        binary_names: &["kiro-cli", "kiro", "q"],
        config_dirs: &["~/.q", "~/.kiro", "~/.aws/q"],
    },
    CliToolDefinition {
        tool_name: "github-copilot-cli",
        vendor: "Microsoft",
        binary_names: &["copilot", "gh-copilot"],
        config_dirs: &["~/.config/github-copilot"],
    },
    CliToolDefinition {
        tool_name: "microsoft-ai-shell",
        vendor: "Microsoft",
        binary_names: &["aish", "ai"],
        config_dirs: &["~/.aish"],
    },
    CliToolDefinition {
        tool_name: "aider",
        vendor: "OpenSource",
        binary_names: &["aider"],
        config_dirs: &["~/.aider"],
    },
    CliToolDefinition {
        tool_name: "opencode",
        vendor: "OpenSource",
        binary_names: &["opencode"],
        config_dirs: &["~/.config/opencode"],
    },
];

pub fn detect_ai_cli_tools(logged_in_user: &str, user_home: &str, verbose: bool) -> Vec<AiTool> {
    print_progress(verbose, "Detecting AI CLI tools...");
    let mut results = Vec::new();

    for tool in CLI_TOOL_DEFINITIONS {
        let mut binary_path = String::new();
        let mut version = String::from("unknown");
        let mut found = false;

        // Also check home-relative paths for claude
        let mut all_binaries: Vec<String> = tool.binary_names.iter().map(|b| b.to_string()).collect();
        if tool.tool_name == "claude-code" {
            all_binaries.push(format!("{}/.claude/local/claude", user_home));
            all_binaries.push(format!("{}/.local/bin/claude", user_home));
        }
        if tool.tool_name == "opencode" {
            all_binaries.push(format!("{}/.opencode/bin/opencode", user_home));
        }

        for binary in &all_binaries {
            let check = if binary.contains('/') {
                // Absolute path check
                if Path::new(binary).exists() {
                    Some(binary.clone())
                } else {
                    None
                }
            } else {
                command_exists_for_user(logged_in_user, binary)
            };

            if let Some(path) = check {
                binary_path = path;
                found = true;

                // Get version
                let version_flag = match tool.tool_name {
                    "opencode" => "-v",
                    _ => "--version",
                };

                // Special handling for amazon-q-cli - verify it's actually Amazon Q
                if tool.tool_name == "amazon-q-cli" {
                    let verify = run_as_user(
                        logged_in_user,
                        &format!("{} --version 2>/dev/null | grep -i 'amazon\\|kiro\\|q developer'", binary),
                        10,
                    );
                    if verify.is_empty() {
                        found = false;
                        continue;
                    }
                }

                let ver = run_as_user(
                    logged_in_user,
                    &format!("{} {} 2>/dev/null | head -1", binary, version_flag),
                    10,
                );
                if !ver.is_empty() {
                    version = ver.lines().next().unwrap_or("unknown").trim().to_string();
                }
                break;
            }
        }

        if found {
            // Check for config directory
            let mut config_dir = None;
            for config_candidate in tool.config_dirs {
                let expanded = config_candidate.replace("~", user_home);
                if Path::new(&expanded).is_dir() {
                    config_dir = Some(expanded);
                    break;
                }
            }

            print_progress(
                verbose,
                &format!("  Found: {} ({}) v{} at {}", tool.tool_name, tool.vendor, version, binary_path),
            );

            results.push(AiTool {
                name: tool.tool_name.to_string(),
                vendor: tool.vendor.to_string(),
                tool_type: "cli_tool".to_string(),
                version,
                binary_path: Some(binary_path),
                config_dir,
                install_path: None,
                is_running: None,
            });
        }
    }

    if results.is_empty() {
        print_progress(verbose, "  No AI CLI tools found");
    } else {
        print_progress(verbose, &format!("  Found {} AI CLI tool(s)", results.len()));
    }

    results
}

// ─── General-Purpose AI Agents Detection ────────────────────────────────────

struct AgentDefinition {
    agent_name: &'static str,
    vendor: &'static str,
    detection_dir: &'static str, // relative to home
    binary_name: &'static str,
}

const AGENT_DEFINITIONS: &[AgentDefinition] = &[
    AgentDefinition { agent_name: "openclaw", vendor: "OpenSource", detection_dir: ".openclaw", binary_name: "openclaw" },
    AgentDefinition { agent_name: "clawdbot", vendor: "OpenSource", detection_dir: ".clawdbot", binary_name: "clawdbot" },
    AgentDefinition { agent_name: "moltbot", vendor: "OpenSource", detection_dir: ".moltbot", binary_name: "moltbot" },
    AgentDefinition { agent_name: "moldbot", vendor: "OpenSource", detection_dir: ".moldbot", binary_name: "moldbot" },
    AgentDefinition { agent_name: "gpt-engineer", vendor: "OpenSource", detection_dir: ".gpt-engineer", binary_name: "gpt-engineer" },
];

pub fn detect_general_ai_agents(user_home: &str, verbose: bool) -> Vec<AiTool> {
    print_progress(verbose, "Detecting general-purpose AI agents...");
    let mut results = Vec::new();

    for agent in AGENT_DEFINITIONS {
        let detection_path = format!("{}/{}", user_home, agent.detection_dir);
        let mut found = false;
        let mut install_path = String::new();
        let mut version = String::from("unknown");

        // Check detection path
        if Path::new(&detection_path).exists() {
            found = true;
            install_path = detection_path.clone();
        }

        // Check binary in PATH
        if !found {
            if let Some(path) = command_exists_for_user("", agent.binary_name) {
                found = true;
                install_path = path;
            }
        }

        if found {
            // Try to get version
            if command_available(agent.binary_name) {
                let ver = run_command(agent.binary_name, &["--version"], Some(10));
                if !ver.is_empty() {
                    version = ver.lines().next().unwrap_or("unknown").trim().to_string();
                }
            }

            print_progress(verbose, &format!("  Found: {} ({}) at {}", agent.agent_name, agent.vendor, install_path));

            results.push(AiTool {
                name: agent.agent_name.to_string(),
                vendor: agent.vendor.to_string(),
                tool_type: "general_agent".to_string(),
                version,
                binary_path: None,
                config_dir: None,
                install_path: Some(install_path),
                is_running: None,
            });
        }
    }

    // Check for Claude Cowork (special case - mode within Claude Desktop)
    let claude_desktop_path = "/Applications/Claude.app";
    if Path::new(claude_desktop_path).is_dir() {
        let plist_path = format!("{}/Contents/Info.plist", claude_desktop_path);
        if Path::new(&plist_path).exists() {
            let claude_version = run_command(
                "/usr/libexec/PlistBuddy",
                &["-c", "Print :CFBundleShortVersionString", &plist_path],
                None,
            );

            if !claude_version.is_empty() {
                // Check if version supports Cowork (v0.7.0+)
                let supports_cowork = if let Some(first_char) = claude_version.chars().next() {
                    if first_char == '0' {
                        // Check 0.7+
                        claude_version.starts_with("0.7")
                            || claude_version.starts_with("0.8")
                            || claude_version.starts_with("0.9")
                    } else {
                        first_char.is_ascii_digit() && first_char != '0'
                    }
                } else {
                    false
                };

                if supports_cowork {
                    print_progress(
                        verbose,
                        &format!("  Found: claude-cowork (Anthropic) - mode within Claude Desktop v{}", claude_version),
                    );

                    results.push(AiTool {
                        name: "claude-cowork".to_string(),
                        vendor: "Anthropic".to_string(),
                        tool_type: "general_agent".to_string(),
                        version: claude_version,
                        binary_path: None,
                        config_dir: None,
                        install_path: Some(claude_desktop_path.to_string()),
                        is_running: None,
                    });
                }
            }
        }
    }

    if results.is_empty() {
        print_progress(verbose, "  No general-purpose AI agents found");
    } else {
        print_progress(verbose, &format!("  Found {} general-purpose AI agent(s)", results.len()));
    }

    results
}

// ─── AI Frameworks Detection ────────────────────────────────────────────────

struct FrameworkDefinition {
    framework_name: &'static str,
    binary_name: &'static str,
    process_name: &'static str,
}

const FRAMEWORK_DEFINITIONS: &[FrameworkDefinition] = &[
    FrameworkDefinition { framework_name: "ollama", binary_name: "ollama", process_name: "ollama" },
    FrameworkDefinition { framework_name: "localai", binary_name: "local-ai", process_name: "local-ai" },
    FrameworkDefinition { framework_name: "lm-studio", binary_name: "lm-studio", process_name: "lm-studio" },
    FrameworkDefinition { framework_name: "text-generation-webui", binary_name: "textgen", process_name: "textgen" },
];

pub fn detect_ai_frameworks(logged_in_user: &str, verbose: bool) -> Vec<AiTool> {
    print_progress(verbose, "Detecting AI frameworks and runtimes...");
    let mut results = Vec::new();

    for framework in FRAMEWORK_DEFINITIONS {
        let binary_path = run_as_user(
            logged_in_user,
            &format!("command -v {} 2>/dev/null", framework.binary_name),
            10,
        );

        if !binary_path.is_empty() {
            let version_output = run_as_user(
                logged_in_user,
                &format!("{} --version 2>/dev/null | head -1", framework.binary_name),
                10,
            );
            let version = if version_output.is_empty() {
                "unknown".to_string()
            } else {
                version_output.lines().next().unwrap_or("unknown").trim().to_string()
            };

            // Check if process is running
            let is_running = run_command("pgrep", &["-x", framework.process_name], None)
                .is_empty()
                == false;

            print_progress(
                verbose,
                &format!(
                    "  Found: {} v{} at {} (running: {})",
                    framework.framework_name, version, binary_path, is_running
                ),
            );

            results.push(AiTool {
                name: framework.framework_name.to_string(),
                vendor: "Unknown".to_string(),
                tool_type: "framework".to_string(),
                version,
                binary_path: Some(binary_path),
                config_dir: None,
                install_path: None,
                is_running: Some(is_running),
            });
        }
    }

    // Check for LM Studio as an application
    let lm_studio_app = "/Applications/LM Studio.app";
    if Path::new(lm_studio_app).is_dir() {
        let plist_path = format!("{}/Contents/Info.plist", lm_studio_app);
        let version = if Path::new(&plist_path).exists() {
            let ver = run_command(
                "/usr/libexec/PlistBuddy",
                &["-c", "Print :CFBundleShortVersionString", &plist_path],
                None,
            );
            if ver.is_empty() { "unknown".to_string() } else { ver }
        } else {
            "unknown".to_string()
        };

        let is_running = !run_command("pgrep", &["-f", "LM Studio"], None).is_empty();

        print_progress(
            verbose,
            &format!("  Found: lm-studio v{} at {} (running: {})", version, lm_studio_app, is_running),
        );

        results.push(AiTool {
            name: "lm-studio".to_string(),
            vendor: "LM Studio".to_string(),
            tool_type: "framework".to_string(),
            version,
            binary_path: Some(lm_studio_app.to_string()),
            config_dir: None,
            install_path: None,
            is_running: Some(is_running),
        });
    }

    if results.is_empty() {
        print_progress(verbose, "  No AI frameworks found");
    } else {
        print_progress(verbose, &format!("  Found {} AI framework(s)", results.len()));
    }

    results
}

// ─── MCP Config Collection ──────────────────────────────────────────────────

struct McpConfigSource {
    source_name: &'static str,
    config_path: &'static str, // relative to home, or absolute
    vendor: &'static str,
}

const MCP_CONFIG_SOURCES: &[McpConfigSource] = &[
    McpConfigSource { source_name: "claude_desktop", config_path: "Library/Application Support/Claude/claude_desktop_config.json", vendor: "Anthropic" },
    McpConfigSource { source_name: "claude_code", config_path: ".claude/settings.json", vendor: "Anthropic" },
    McpConfigSource { source_name: "claude_code", config_path: ".claude.json", vendor: "Anthropic" },
    McpConfigSource { source_name: "cursor", config_path: ".cursor/mcp.json", vendor: "Cursor" },
    McpConfigSource { source_name: "windsurf", config_path: ".codeium/windsurf/mcp_config.json", vendor: "Codeium" },
    McpConfigSource { source_name: "antigravity", config_path: ".gemini/antigravity/mcp_config.json", vendor: "Google" },
    McpConfigSource { source_name: "zed", config_path: ".config/zed/settings.json", vendor: "Zed" },
    McpConfigSource { source_name: "open_interpreter", config_path: ".config/open-interpreter/config.yaml", vendor: "OpenSource" },
    McpConfigSource { source_name: "codex", config_path: ".codex/config.toml", vendor: "OpenAI" },
];

pub fn collect_mcp_configs(user_home: &str, is_enterprise: bool, jq_available: bool, perl_available: bool, verbose: bool) -> Vec<McpConfig> {
    print_progress(verbose, "Collecting MCP configuration files...");
    let mut results = Vec::new();

    let jq_filter = r#"
      def extract: map_values(
        {command, args, serverUrl, url}
        | with_entries(select(.value != null))
      );
      if .mcpServers then {mcpServers: (.mcpServers | extract)}
      elif .context_servers then {context_servers: (.context_servers | extract)}
      elif .projects then {mcpServers: ([.projects[].mcpServers // {} | to_entries[]] | from_entries | extract)}
      else {} end
    "#;

    for source in MCP_CONFIG_SOURCES {
        let config_path = format!("{}/{}", user_home, source.config_path);
        let path = Path::new(&config_path);

        if !path.is_file() {
            continue;
        }

        let content = match fs::read_to_string(&config_path) {
            Ok(c) if !c.is_empty() => c,
            _ => {
                print_progress(verbose, &format!("  Skipping {}: empty or unreadable config", source.source_name));
                continue;
            }
        };

        // For JSON configs, filter with jq if available
        let filtered_content = if jq_available && config_path.ends_with(".json") {
            let mut json_input = content.clone();

            // Strip JSONC comments for Zed
            if source.source_name == "zed" && perl_available {
                let (stripped, _, _) = run_shell(
                    &format!("echo {} | perl -0777 -pe 's{{/\\*.*?\\*/}}{{}}gs; s{{//[^\\n]*}}{{}}g'",
                        shell_escape(&json_input)),
                    10,
                );
                if !stripped.is_empty() {
                    json_input = stripped;
                }
            }

            let (filtered, _, code) = run_shell(
                &format!("echo {} | jq -c {}", shell_escape(&json_input), shell_escape(jq_filter)),
                10,
            );
            if code == 0 && !filtered.is_empty() {
                filtered
            } else {
                content.clone()
            }
        } else {
            content.clone()
        };

        print_progress(verbose, &format!("  Found: {} config ({})", source.source_name, source.vendor));

        let config_content_base64 = if is_enterprise {
            Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                filtered_content.as_bytes(),
            ))
        } else {
            None
        };

        results.push(McpConfig {
            config_source: source.source_name.to_string(),
            config_path: config_path.to_string(),
            vendor: source.vendor.to_string(),
            config_content_base64,
        });
    }

    if results.is_empty() {
        print_progress(verbose, "  No MCP config files found");
    } else {
        print_progress(verbose, &format!("  Found {} MCP config file(s)", results.len()));
    }

    results
}

/// Simple shell escaping for use in sh -c commands
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ─── IDE Extension Collection ───────────────────────────────────────────────

pub fn collect_ide_extensions(user_home: &str, verbose: bool) -> Vec<IdeExtension> {
    print_progress(verbose, "Scanning IDE extensions...");
    let mut all_extensions = Vec::new();

    // VSCode extensions
    let vscode_dir = format!("{}/.vscode/extensions", user_home);
    if Path::new(&vscode_dir).is_dir() {
        let exts = scan_extension_dir(&vscode_dir, "vscode", verbose);
        print_progress(verbose, &format!("  Found {} VSCode extensions", exts.len()));
        all_extensions.extend(exts);
    }

    // Cursor extensions
    let cursor_dir = format!("{}/.cursor/extensions", user_home);
    if Path::new(&cursor_dir).is_dir() {
        let exts = scan_extension_dir(&cursor_dir, "openvsx", verbose);
        print_progress(verbose, &format!("  Found {} Cursor extensions", exts.len()));
        all_extensions.extend(exts);
    }

    if all_extensions.is_empty() {
        print_progress(verbose, "  No IDE extensions found");
    } else {
        print_progress(verbose, &format!("Found total of {} IDE extensions", all_extensions.len()));
    }

    all_extensions
}

fn scan_extension_dir(ext_dir: &str, ide_type: &str, _verbose: bool) -> Vec<IdeExtension> {
    let mut extensions = Vec::new();

    // Load obsolete extensions
    let obsolete_path = format!("{}/.obsolete", ext_dir);
    let obsolete_content = fs::read_to_string(&obsolete_path).unwrap_or_else(|_| "{}".to_string());

    let entries = match fs::read_dir(ext_dir) {
        Ok(entries) => entries,
        Err(_) => return extensions,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let dirname = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };

        // Skip special entries
        if dirname == "extensions.json" || dirname == ".obsolete" {
            continue;
        }

        // Check if obsolete
        if obsolete_content.contains(&format!("\"{}\":true", dirname)) {
            continue;
        }

        // Parse: publisher.name-version or publisher.name-version-platform
        let (publisher, rest) = match dirname.split_once('.') {
            Some((p, r)) => (p.to_string(), r.to_string()),
            None => continue,
        };

        // Remove platform suffix
        let rest = rest
            .strip_suffix("-universal")
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                // Strip -darwin-* suffix
                if let Some(idx) = rest.find("-darwin-") {
                    rest[..idx].to_string()
                } else {
                    rest.clone()
                }
            });

        // Split name-version (version is after last hyphen)
        let (name, version) = match rest.rfind('-') {
            Some(idx) => (rest[..idx].to_string(), rest[idx + 1..].to_string()),
            None => continue,
        };

        if publisher.is_empty() || name.is_empty() || version.is_empty() {
            continue;
        }

        // Get install date from directory mtime
        let install_date = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        extensions.push(IdeExtension {
            id: format!("{}.{}", publisher, name),
            name,
            version,
            publisher,
            install_date,
            ide_type: ide_type.to_string(),
        });
    }

    extensions
}
