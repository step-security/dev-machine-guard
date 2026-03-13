use std::fs;
use std::io;

use crate::node_scan::extract_packages_from_scans;
use crate::types::*;
use crate::util::*;

// ─── JSON Output ────────────────────────────────────────────────────────────

pub fn format_json_output(results: &ScanResults) -> String {
    let scan_ts = timestamp_secs();
    let scan_iso = timestamp_to_iso(scan_ts);

    let all_scans: Vec<&NodeProjectScan> = results
        .node_global_scans
        .iter()
        .chain(results.node_project_scans.iter())
        .collect();
    let all_scans_owned: Vec<NodeProjectScan> = all_scans.into_iter().cloned().collect();
    let node_packages = extract_packages_from_scans(&all_scans_owned);

    let output = ScanOutput {
        agent_version: AGENT_VERSION.to_string(),
        agent_url: "https://github.com/step-security/dev-machine-guard".to_string(),
        scan_timestamp: scan_ts,
        scan_timestamp_iso: scan_iso,
        device: results.device.clone(),
        ai_agents_and_tools: results.ai_tools.clone(),
        ide_installations: results.ide_installations.clone(),
        ide_extensions: results.ide_extensions.clone(),
        mcp_configs: results.mcp_configs.clone(),
        node_package_managers: results.node_package_managers.clone(),
        node_packages,
        summary: ScanSummary {
            ai_agents_and_tools_count: results.ai_tools.len(),
            ide_installations_count: results.ide_installations.len(),
            ide_extensions_count: results.ide_extensions.len(),
            mcp_configs_count: results.mcp_configs.len(),
            node_projects_count: results.node_projects_count,
        },
    };

    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
}

// ─── Pretty Output ──────────────────────────────────────────────────────────

pub fn format_pretty_output(results: &ScanResults, color_mode: &ColorMode) {
    let is_tty = unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 };
    let use_colors = should_use_colors(color_mode, is_tty);

    let (p, g, b, d, r, _rd, _y) = if use_colors {
        (
            "\x1b[0;35m",  // Purple
            "\x1b[0;32m",  // Green
            "\x1b[1m",     // Bold
            "\x1b[2m",     // Dim
            "\x1b[0m",     // Reset
            "\x1b[0;31m",  // Red
            "\x1b[0;33m",  // Yellow
        )
    } else {
        ("", "", "", "", "", "", "")
    };

    let scan_ts = timestamp_secs();
    let scan_time = timestamp_to_display(scan_ts);

    // Banner
    let box_width = 58;
    let title = format!("StepSecurity Dev Machine Guard v{}", AGENT_VERSION);
    let url = "https://github.com/step-security/dev-machine-guard";
    let title_pad = box_width - 2 - title.len();
    let url_pad = box_width - 2 - url.len();

    println!();
    print!("  {p}┌");
    for _ in 0..box_width {
        print!("─");
    }
    println!("┐{r}");
    println!("  {p}│{r}  {b}{}{r}{:>width$}{p}│{r}", title, "", width = title_pad);
    println!("  {p}│{r}  {d}{}{r}{:>width$}{p}│{r}", url, "", width = url_pad);
    print!("  {p}└");
    for _ in 0..box_width {
        print!("─");
    }
    println!("┘{r}");
    println!("  {d}Scanned at {}{r}", scan_time);
    println!();

    // DEVICE section
    println!("  {p}{b}DEVICE{r}");
    println!("    {:<16} {}", "Hostname", results.device.hostname);
    println!("    {:<16} {}", "Serial", results.device.serial_number);
    println!("    {:<16} {}", "macOS", results.device.os_version);
    println!("    {:<16} {}", "User", results.device.user_identity);
    println!();

    let ai_count = results.ai_tools.len();
    let ide_count = results.ide_installations.len();
    let ext_count = results.ide_extensions.len();
    let mcp_count = results.mcp_configs.len();

    // SUMMARY section
    println!("  {p}{b}SUMMARY{r}");
    println!("    {:<24} {g}{}{r}", "AI Agents and Tools", ai_count);
    println!("    {:<24} {g}{}{r}", "IDEs & Desktop Apps", ide_count);
    println!("    {:<24} {g}{}{r}", "IDE Extensions", ext_count);
    println!("    {:<24} {g}{}{r}", "MCP Servers", mcp_count);
    if !results.node_package_managers.is_empty() {
        println!("    {:<24} {g}{}{r}", "Node.js Projects", results.node_projects_count);
    }
    println!();

    // AI AGENTS AND TOOLS section
    println!(
        "  {p}{b}AI AGENTS AND TOOLS{r}{:>width$}{g}{} found{r}",
        "",
        ai_count,
        width = 35 - 19
    );
    if ai_count > 0 {
        for tool in &results.ai_tools {
            let type_label = match tool.tool_type.as_str() {
                "cli_tool" => "cli",
                "general_agent" => "agent",
                "framework" => "framework",
                other => other,
            };
            let name = truncate(&tool.name, 24);
            let version = truncate(&tool.version, 20);
            println!(
                "    {:<24} {d}v{:<20} [{:<10}] {}{r}",
                name, version, type_label, tool.vendor
            );
        }
    } else {
        println!("    {d}None detected{r}");
    }
    println!();

    // IDE & AI DESKTOP APPS section
    println!(
        "  {p}{b}IDE & AI DESKTOP APPS{r}{:>width$}{g}{} found{r}",
        "",
        ide_count,
        width = 35 - 21
    );
    if ide_count > 0 {
        for ide in &results.ide_installations {
            let display_name = match ide.ide_type.as_str() {
                "vscode" => "Visual Studio Code",
                "cursor" => "Cursor",
                "windsurf" => "Windsurf",
                "antigravity" => "Antigravity",
                "zed" => "Zed",
                "claude_desktop" => "Claude",
                "microsoft_copilot_desktop" => "Microsoft Copilot",
                other => other,
            };
            let name = truncate(display_name, 24);
            let version = truncate(&ide.version, 20);
            println!("    {:<24} {d}v{:<20} {}{r}", name, version, ide.vendor);
        }
    } else {
        println!("    {d}None detected{r}");
    }
    println!();

    // MCP SERVERS section
    println!(
        "  {p}{b}MCP SERVERS{r}{:>width$}{g}{} found{r}",
        "",
        mcp_count,
        width = 35 - 11
    );
    if mcp_count > 0 {
        for mcp in &results.mcp_configs {
            println!("    {:<24} {d}{}{r}", mcp.config_source, mcp.vendor);
        }
    } else {
        println!("    {d}None detected{r}");
    }
    println!();

    // IDE EXTENSIONS section
    println!(
        "  {p}{b}IDE EXTENSIONS{r}{:>width$}{g}{} found{r}",
        "",
        ext_count,
        width = 35 - 14
    );
    if ext_count > 0 {
        // Group by ide_type
        let mut ide_types: Vec<String> = results
            .ide_extensions
            .iter()
            .map(|e| e.ide_type.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        ide_types.sort();

        for ide_type in &ide_types {
            let type_exts: Vec<&IdeExtension> = results
                .ide_extensions
                .iter()
                .filter(|e| &e.ide_type == ide_type)
                .collect();

            let ide_display = match ide_type.as_str() {
                "vscode" => "VSCode",
                "openvsx" => "OpenVSX",
                "windsurf" => "Windsurf",
                other => other,
            };

            println!(
                "    {p}{b}{}{r}{:>width$}{g}{} found{r}",
                ide_display,
                "",
                type_exts.len(),
                width = 33 - ide_display.len()
            );

            for ext in &type_exts {
                let ext_id = truncate(&ext.id, 42);
                let ext_ver = truncate(&ext.version, 14);
                println!(
                    "      {:<42} {d}v{:<14} {}{r}",
                    ext_id, ext_ver, ext.publisher
                );
            }
        }
    } else {
        println!("    {d}None detected{r}");
    }
    println!();

    // NODE.JS PACKAGES section
    if !results.node_package_managers.is_empty() {
        let pm_count = results.node_package_managers.len();
        println!(
            "  {p}{b}NODE.JS PACKAGE MANAGERS{r}{:>width$}{g}{} found{r}",
            "",
            pm_count,
            width = 35 - 23
        );
        for pm in &results.node_package_managers {
            println!("    {:<24} {d}v{}{r}", pm.name, pm.version);
        }
        println!();

        println!(
            "  {p}{b}NODE.JS PROJECTS{r}{:>width$}{g}{} found{r}",
            "",
            results.node_projects_count,
            width = 35 - 16
        );
        println!();

        println!("  {p}{b}NODE.JS PACKAGES{r}");
        let all_scans: Vec<NodeProjectScan> = results
            .node_global_scans
            .iter()
            .chain(results.node_project_scans.iter())
            .cloned()
            .collect();
        let folders = extract_packages_from_scans(&all_scans);

        if folders.is_empty() {
            println!("    {d}No packages found{r}");
        } else {
            for folder in &folders {
                println!();
                println!(
                    "    {p}{b}{}{r} {d}({}){r}",
                    folder.folder, folder.package_manager
                );
                for pkg in &folder.packages {
                    println!("      {}@{}", pkg.name, pkg.version);
                }
            }
        }
        println!();
    }
}

// ─── HTML Output ────────────────────────────────────────────────────────────

pub fn generate_html_report(output_file: &str, results: &ScanResults) -> io::Result<()> {
    let scan_ts = timestamp_secs();
    let scan_time = timestamp_to_display(scan_ts);
    let mcp_count = results.mcp_configs.len();
    let ai_count = results.ai_tools.len();
    let ide_count = results.ide_installations.len();
    let ext_count = results.ide_extensions.len();

    let h_hostname = html_escape(&results.device.hostname);
    let h_serial = html_escape(&results.device.serial_number);
    let h_os = html_escape(&results.device.os_version);
    let h_identity = html_escape(&results.device.user_identity);

    // Generate AI tools rows
    let ai_rows = if results.ai_tools.is_empty() {
        r#"<tr><td colspan="4" style="text-align:center;color:#8a94a6;">None detected</td></tr>"#.to_string()
    } else {
        results.ai_tools.iter().map(|t| {
            let type_label = match t.tool_type.as_str() {
                "cli_tool" => "CLI Tool",
                "general_agent" => "Agent",
                "framework" => "Framework",
                other => other,
            };
            format!(
                r#"<tr><td>{}</td><td>{}</td><td><span style="background:#f0ebff;color:#7037f5;padding:2px 8px;border-radius:10px;font-size:0.8em;">{}</span></td><td>{}</td></tr>"#,
                html_escape(&t.name), html_escape(&t.version), type_label, html_escape(&t.vendor)
            )
        }).collect::<Vec<_>>().join("\n    ")
    };

    // Generate IDE rows
    let ide_rows = if results.ide_installations.is_empty() {
        r#"<tr><td colspan="4" style="text-align:center;color:#8a94a6;">None detected</td></tr>"#.to_string()
    } else {
        results.ide_installations.iter().map(|ide| {
            let display_name = match ide.ide_type.as_str() {
                "vscode" => "Visual Studio Code",
                "cursor" => "Cursor",
                "windsurf" => "Windsurf",
                "antigravity" => "Antigravity",
                "zed" => "Zed",
                "claude_desktop" => "Claude",
                "microsoft_copilot_desktop" => "Microsoft Copilot",
                other => other,
            };
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td style="color:#8a94a6;font-size:0.85em;">{}</td></tr>"#,
                display_name, html_escape(&ide.version), html_escape(&ide.vendor), html_escape(&ide.install_path)
            )
        }).collect::<Vec<_>>().join("\n    ")
    };

    // Generate MCP rows
    let mcp_rows = if results.mcp_configs.is_empty() {
        r#"<tr><td colspan="2" style="text-align:center;color:#8a94a6;">None detected</td></tr>"#.to_string()
    } else {
        results.mcp_configs.iter().map(|m| {
            format!("<tr><td>{}</td><td>{}</td></tr>", html_escape(&m.config_source), html_escape(&m.vendor))
        }).collect::<Vec<_>>().join("\n    ")
    };

    // Generate extension rows
    let ext_rows = if results.ide_extensions.is_empty() {
        r#"<tr><td colspan="4" style="text-align:center;color:#8a94a6;">None detected</td></tr>"#.to_string()
    } else {
        results.ide_extensions.iter().map(|e| {
            let ide_display = match e.ide_type.as_str() {
                "vscode" => "VSCode",
                "openvsx" => "OpenVSX",
                "windsurf" => "Windsurf",
                other => other,
            };
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&e.id), html_escape(&e.version), html_escape(&e.publisher), ide_display
            )
        }).collect::<Vec<_>>().join("\n    ")
    };

    // Generate node package rows
    let all_scans: Vec<NodeProjectScan> = results
        .node_global_scans
        .iter()
        .chain(results.node_project_scans.iter())
        .cloned()
        .collect();
    let folders = extract_packages_from_scans(&all_scans);
    let node_pkg_rows = if folders.is_empty() {
        r#"<tr><td colspan="4" style="text-align:center;color:#8a94a6;">No packages found (use --enable-npm-scan)</td></tr>"#.to_string()
    } else {
        let mut rows = Vec::new();
        for folder in &folders {
            for pkg in &folder.packages {
                rows.push(format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(&folder.folder),
                    html_escape(&folder.package_manager),
                    html_escape(&pkg.name),
                    html_escape(&pkg.version)
                ));
            }
        }
        rows.join("\n    ")
    };

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>StepSecurity Dev Machine Guard Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #faf7fb; color: #193447; line-height: 1.6;
  }}
  .header {{
    background: linear-gradient(135deg, #7037f5, #9b59f5);
    color: #fff; padding: 32px 0; text-align: center;
  }}
  .header h1 {{ font-size: 1.6em; font-weight: 600; margin-bottom: 4px; }}
  .header p {{ opacity: 0.85; font-size: 0.95em; }}
  .container {{ max-width: 960px; margin: 0 auto; padding: 24px 16px; }}
  .summary-cards {{
    display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap;
  }}
  .card {{
    flex: 1; min-width: 140px; background: #fff; border-radius: 10px;
    padding: 18px 16px; text-align: center;
    border: 1px solid #e8e0f0; box-shadow: 0 1px 3px rgba(112,55,245,0.06);
  }}
  .card .number {{ font-size: 2em; font-weight: 700; color: #7037f5; }}
  .card .label {{ font-size: 0.82em; color: #8a94a6; margin-top: 2px; }}
  .device-grid {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 8px 32px;
    background: #fff; border-radius: 10px; padding: 20px 24px;
    margin-bottom: 28px; border: 1px solid #e8e0f0;
  }}
  .device-grid .field {{ display: flex; gap: 12px; padding: 6px 0; }}
  .device-grid .field-label {{ color: #8a94a6; min-width: 90px; font-size: 0.9em; }}
  .device-grid .field-value {{ font-weight: 500; }}
  .section {{ margin-bottom: 28px; }}
  .section h2 {{
    font-size: 1.1em; color: #7037f5; margin-bottom: 12px;
    padding-bottom: 6px; border-bottom: 2px solid #f0ebff;
  }}
  .section h2 .count {{
    float: right; background: #f0ebff; color: #7037f5;
    padding: 2px 10px; border-radius: 10px; font-size: 0.85em;
  }}
  table {{
    width: 100%; border-collapse: collapse; background: #fff;
    border-radius: 10px; overflow: hidden; border: 1px solid #e8e0f0;
  }}
  th {{
    background: #f0ebff; color: #7037f5; font-weight: 600;
    text-align: left; padding: 10px 14px; font-size: 0.85em;
    text-transform: uppercase; letter-spacing: 0.5px;
  }}
  td {{ padding: 9px 14px; border-top: 1px solid #f0ebff; font-size: 0.92em; }}
  tr:hover td {{ background: #faf7fb; }}
  .footer {{
    text-align: center; padding: 24px; color: #8a94a6; font-size: 0.85em;
    border-top: 1px solid #e8e0f0; margin-top: 12px;
  }}
  .footer a {{ color: #7037f5; text-decoration: none; }}
  .footer a:hover {{ text-decoration: underline; }}
  .scan-meta {{ text-align: center; color: #8a94a6; font-size: 0.85em; margin-bottom: 20px; }}
  @media print {{
    body {{ background: #fff; }}
    .header {{ background: #7037f5; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .card {{ break-inside: avoid; }}
  }}
  @media (max-width: 600px) {{
    .summary-cards {{ flex-direction: column; }}
    .device-grid {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>
<div class="header">
  <h1>StepSecurity Dev Machine Guard Report</h1>
  <p>Developer Environment Security Scanner</p>
</div>
<div class="container">
<p class="scan-meta">Scanned at {scan_time} &middot; Agent v{version}</p>

<div class="summary-cards">
  <div class="card"><div class="number">{ai_count}</div><div class="label">AI Agents and Tools</div></div>
  <div class="card"><div class="number">{ide_count}</div><div class="label">IDEs & Desktop Apps</div></div>
  <div class="card"><div class="number">{ext_count}</div><div class="label">IDE Extensions</div></div>
  <div class="card"><div class="number">{mcp_count}</div><div class="label">MCP Servers</div></div>
  <div class="card"><div class="number">{node_count}</div><div class="label">Node.js Projects</div></div>
</div>

<div class="device-grid">
  <div class="field"><span class="field-label">Hostname</span><span class="field-value">{h_hostname}</span></div>
  <div class="field"><span class="field-label">Serial</span><span class="field-value">{h_serial}</span></div>
  <div class="field"><span class="field-label">macOS</span><span class="field-value">{h_os}</span></div>
  <div class="field"><span class="field-label">User</span><span class="field-value">{h_identity}</span></div>
</div>

<div class="section">
  <h2>AI Agents and Tools <span class="count">{ai_count}</span></h2>
  <table>
    <tr><th>Name</th><th>Version</th><th>Type</th><th>Vendor</th></tr>
    {ai_rows}
  </table>
</div>

<div class="section">
  <h2>IDE & AI Desktop Apps <span class="count">{ide_count}</span></h2>
  <table>
    <tr><th>Name</th><th>Version</th><th>Vendor</th><th>Path</th></tr>
    {ide_rows}
  </table>
</div>

<div class="section">
  <h2>MCP Servers <span class="count">{mcp_count}</span></h2>
  <table>
    <tr><th>Source</th><th>Vendor</th></tr>
    {mcp_rows}
  </table>
</div>

<div class="section">
  <h2>IDE Extensions <span class="count">{ext_count}</span></h2>
  <table>
    <tr><th>Extension ID</th><th>Version</th><th>Publisher</th><th>IDE</th></tr>
    {ext_rows}
  </table>
</div>

<div class="section">
  <h2>Node.js Packages</h2>
  <table>
    <tr><th>Folder</th><th>Package Manager</th><th>Package</th><th>Version</th></tr>
    {node_pkg_rows}
  </table>
</div>

</div>
<div class="footer">
  Generated by <a href="https://github.com/step-security/dev-machine-guard">StepSecurity Dev Machine Guard</a> v{version}
</div>
</body>
</html>"##,
        scan_time = scan_time,
        version = AGENT_VERSION,
        ai_count = ai_count,
        ide_count = ide_count,
        ext_count = ext_count,
        mcp_count = mcp_count,
        node_count = results.node_projects_count,
        h_hostname = h_hostname,
        h_serial = h_serial,
        h_os = h_os,
        h_identity = h_identity,
        ai_rows = ai_rows,
        ide_rows = ide_rows,
        mcp_rows = mcp_rows,
        ext_rows = ext_rows,
        node_pkg_rows = node_pkg_rows,
    );

    fs::write(output_file, html)?;
    eprintln!("HTML report saved to {}", output_file);
    Ok(())
}
