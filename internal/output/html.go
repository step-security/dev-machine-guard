package output

import (
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type htmlData struct {
	ScanTime         string
	Version          string
	Device           model.Device
	AITools          []model.AITool
	IDEInstallations []model.IDE
	IDEExtensions    []model.Extension
	MCPConfigs       []model.MCPConfig
	NodePkgManagers  []model.PkgManager
	Summary          model.Summary
}

func typeLabel(t string) string {
	switch t {
	case "cli_tool":
		return "CLI Tool"
	case "general_agent":
		return "Agent"
	case "framework":
		return "Framework"
	default:
		return t
	}
}

// HTML generates a self-contained HTML report file.
func HTML(outputFile string, result *model.ScanResult) error {
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("creating HTML file: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanTime := time.Unix(result.ScanTimestamp, 0).Format("2006-01-02 15:04:05")

	data := htmlData{
		ScanTime:         scanTime,
		Version:          buildinfo.Version,
		Device:           result.Device,
		AITools:          result.AIAgentsAndTools,
		IDEInstallations: result.IDEInstallations,
		IDEExtensions:    result.IDEExtensions,
		MCPConfigs:       result.MCPConfigs,
		NodePkgManagers:  result.NodePkgManagers,
		Summary:          result.Summary,
	}

	funcMap := template.FuncMap{
		"ideDisplayName": ideDisplayName,
		"typeLabel":      typeLabel,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	return tmpl.Execute(f, data)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>StepSecurity Dev Machine Guard Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #faf7fb; color: #193447; line-height: 1.6;
  }
  .header {
    background: linear-gradient(135deg, #7037f5, #9b59f5);
    color: #fff; padding: 32px 0; text-align: center;
  }
  .header h1 { font-size: 1.6em; font-weight: 600; margin-bottom: 4px; }
  .header p { opacity: 0.85; font-size: 0.95em; }
  .container { max-width: 960px; margin: 0 auto; padding: 24px 16px; }
  .summary-cards {
    display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap;
  }
  .card {
    flex: 1; min-width: 140px; background: #fff; border-radius: 10px;
    padding: 18px 16px; text-align: center;
    border: 1px solid #e8e0f0; box-shadow: 0 1px 3px rgba(112,55,245,0.06);
  }
  .card .number { font-size: 2em; font-weight: 700; color: #7037f5; }
  .card .label { font-size: 0.82em; color: #8a94a6; margin-top: 2px; }
  .device-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 8px 32px;
    background: #fff; border-radius: 10px; padding: 20px 24px;
    margin-bottom: 28px; border: 1px solid #e8e0f0;
  }
  .device-grid .field { display: flex; gap: 12px; padding: 6px 0; }
  .device-grid .field-label { color: #8a94a6; min-width: 90px; font-size: 0.9em; }
  .device-grid .field-value { font-weight: 500; }
  .section { margin-bottom: 28px; }
  .section h2 {
    font-size: 1.1em; color: #7037f5; margin-bottom: 12px;
    padding-bottom: 6px; border-bottom: 2px solid #f0ebff;
  }
  .section h2 .count {
    float: right; background: #f0ebff; color: #7037f5;
    padding: 2px 10px; border-radius: 10px; font-size: 0.85em;
  }
  table {
    width: 100%; border-collapse: collapse; background: #fff;
    border-radius: 10px; overflow: hidden; border: 1px solid #e8e0f0;
  }
  th {
    background: #f0ebff; color: #7037f5; font-weight: 600;
    text-align: left; padding: 10px 14px; font-size: 0.85em;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  td { padding: 9px 14px; border-top: 1px solid #f0ebff; font-size: 0.92em; }
  tr:hover td { background: #faf7fb; }
  .type-badge {
    background: #f0ebff; color: #7037f5; padding: 2px 8px;
    border-radius: 10px; font-size: 0.8em;
  }
  .footer {
    text-align: center; padding: 24px; color: #8a94a6; font-size: 0.85em;
    border-top: 1px solid #e8e0f0; margin-top: 12px;
  }
  .footer a { color: #7037f5; text-decoration: none; }
  .footer a:hover { text-decoration: underline; }
  .scan-meta { text-align: center; color: #8a94a6; font-size: 0.85em; margin-bottom: 20px; }
  @media print {
    body { background: #fff; }
    .header { background: #7037f5; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .card { break-inside: avoid; }
  }
  @media (max-width: 600px) {
    .summary-cards { flex-direction: column; }
    .device-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="header">
  <h1>StepSecurity Dev Machine Guard Report</h1>
  <p>Developer Environment Security Scanner</p>
</div>
<div class="container">

<p class="scan-meta">Scanned at {{.ScanTime}} &middot; Agent v{{.Version}}</p>

<div class="summary-cards">
  <div class="card"><div class="number">{{.Summary.AIAgentsAndToolsCount}}</div><div class="label">AI Agents and Tools</div></div>
  <div class="card"><div class="number">{{.Summary.IDEInstallationsCount}}</div><div class="label">IDEs & Desktop Apps</div></div>
  <div class="card"><div class="number">{{.Summary.IDEExtensionsCount}}</div><div class="label">IDE Extensions</div></div>
  <div class="card"><div class="number">{{.Summary.MCPConfigsCount}}</div><div class="label">MCP Servers</div></div>
  <div class="card"><div class="number">{{.Summary.NodeProjectsCount}}</div><div class="label">Node.js Projects</div></div>
</div>

<div class="device-grid">
  <div class="field"><span class="field-label">Hostname</span><span class="field-value">{{.Device.Hostname}}</span></div>
  <div class="field"><span class="field-label">Serial</span><span class="field-value">{{.Device.SerialNumber}}</span></div>
  <div class="field"><span class="field-label">{{if eq .Device.Platform "windows"}}Windows{{else}}macOS{{end}}</span><span class="field-value">{{.Device.OSVersion}}</span></div>
  <div class="field"><span class="field-label">User</span><span class="field-value">{{.Device.UserIdentity}}</span></div>
</div>

<div class="section">
  <h2>AI Agents and Tools <span class="count">{{.Summary.AIAgentsAndToolsCount}}</span></h2>
  <table>
    <tr><th>Name</th><th>Version</th><th>Type</th><th>Vendor</th></tr>
    {{if .AITools}}{{range .AITools}}<tr><td>{{.Name}}</td><td>{{.Version}}</td><td><span class="type-badge">{{typeLabel .Type}}</span></td><td>{{.Vendor}}</td></tr>
    {{end}}{{else}}<tr><td colspan="4" style="text-align:center;color:#8a94a6;">None detected</td></tr>{{end}}
  </table>
</div>

<div class="section">
  <h2>IDE &amp; AI Desktop Apps <span class="count">{{.Summary.IDEInstallationsCount}}</span></h2>
  <table>
    <tr><th>Name</th><th>Version</th><th>Vendor</th><th>Path</th></tr>
    {{if .IDEInstallations}}{{range .IDEInstallations}}<tr><td>{{ideDisplayName .IDEType}}</td><td>{{.Version}}</td><td>{{.Vendor}}</td><td style="color:#8a94a6;font-size:0.85em;">{{.InstallPath}}</td></tr>
    {{end}}{{else}}<tr><td colspan="4" style="text-align:center;color:#8a94a6;">None detected</td></tr>{{end}}
  </table>
</div>

<div class="section">
  <h2>MCP Servers <span class="count">{{.Summary.MCPConfigsCount}}</span></h2>
  <table>
    <tr><th>Source</th><th>Vendor</th></tr>
    {{if .MCPConfigs}}{{range .MCPConfigs}}<tr><td>{{.ConfigSource}}</td><td>{{.Vendor}}</td></tr>
    {{end}}{{else}}<tr><td colspan="2" style="text-align:center;color:#8a94a6;">None detected</td></tr>{{end}}
  </table>
</div>

<div class="section">
  <h2>IDE Extensions <span class="count">{{.Summary.IDEExtensionsCount}}</span></h2>
  <table>
    <tr><th>Extension ID</th><th>Version</th><th>Publisher</th><th>IDE</th></tr>
    {{if .IDEExtensions}}{{range .IDEExtensions}}<tr><td>{{.ID}}</td><td>{{.Version}}</td><td>{{.Publisher}}</td><td>{{.IDEType}}</td></tr>
    {{end}}{{else}}<tr><td colspan="4" style="text-align:center;color:#8a94a6;">None detected</td></tr>{{end}}
  </table>
</div>

<div class="section">
  <h2>Node.js Packages</h2>
  <table>
    <tr><th>Package Manager</th><th>Version</th><th>Path</th></tr>
    {{if .NodePkgManagers}}{{range .NodePkgManagers}}<tr><td>{{.Name}}</td><td>{{.Version}}</td><td>{{.Path}}</td></tr>
    {{end}}{{else}}<tr><td colspan="3" style="text-align:center;color:#8a94a6;">No packages found (use --enable-npm-scan)</td></tr>{{end}}
  </table>
</div>

</div>
<div class="footer">
  Generated by <a href="https://github.com/step-security/dev-machine-guard">StepSecurity Dev Machine Guard</a> v{{.Version}}
</div>
</body>
</html>`
