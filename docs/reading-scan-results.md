# StepSecurity Dev Machine Guard — Reading Scan Results

This guide explains how to interpret the output from Dev Machine Guard in all three output formats: pretty terminal output, JSON, and HTML.

> Back to [README](../README.md) | See also: [Community Mode](community-mode.md) | [MCP Audit](mcp-audit.md)

---

## Pretty Terminal Output

The default output format is a styled, color-coded report printed to the terminal. It is organized into the following sections:

### Banner

```
  ┌──────────────────────────────────────────────────────────┐
  │  StepSecurity Dev Machine Guard v1.8.1                   │
  │  https://github.com/step-security/dev-machine-guard      │
  └──────────────────────────────────────────────────────────┘
  Scanned at 2026-03-27 14:30:00
```

Shows the StepSecurity agent version and the timestamp of the scan.

### DEVICE

```
  DEVICE
    Hostname         MacBook-Pro.local
    Serial           XXXXXXXXXXXX
    macOS            15.3
    User             user@example.com
```

Basic device identification. The user is determined from the currently logged-in console user.

### SUMMARY

```
  SUMMARY
    AI Agents and Tools      5
    IDEs & Desktop Apps      3
    IDE Extensions           47
```

High-level counts for each detection category.

### AI AGENTS AND TOOLS

```
  AI AGENTS AND TOOLS                                5 found
    claude-code              v1.0.12        [cli]         Anthropic
    codex                    v0.1.0         [cli]         OpenAI
    openclaw                 v0.5.2         [agent]       OpenSource
    ollama                   v0.5.4         [framework]   Unknown
    claude-cowork            v0.7.1         [agent]       Anthropic
```

Lists all detected AI tools, grouped by type:
- **cli** -- Command-line AI coding assistants (Claude Code, Codex, Gemini CLI, etc.)
- **agent** -- General-purpose AI agents (OpenClaw, GPT-Engineer, Claude Cowork, etc.)
- **framework** -- AI frameworks and runtimes (Ollama, LM Studio, LocalAI, etc.)

### IDE & AI DESKTOP APPS

```
  IDE & AI DESKTOP APPS                              3 found
    Visual Studio Code       v1.96.0        Microsoft
    Cursor                   v0.50.1        Cursor
    Claude                   v0.7.1         Anthropic
```

Lists installed IDEs and AI desktop applications found in `/Applications/`.

### IDE EXTENSIONS

```
  IDE EXTENSIONS                                     47 found
    VSCode                                           35 found
      ms-python.python                v2024.22.0  ms-python
      esbenp.prettier-vscode          v10.4.0     esbenp
      ...
    Cursor                                           12 found
      ms-python.python                v2024.20.0  ms-python
      ...
```

Lists all installed extensions, grouped by IDE. Each entry shows the extension ID, version, and publisher.

---

## JSON Output

When you run with `--json`, the scanner outputs a single JSON object to stdout. Here is the complete schema:

```json
{
  "agent_version": "1.8.1",
  "scan_timestamp": 1709136000,
  "scan_timestamp_iso": "2026-02-28T14:00:00Z",
  "device": {
    "hostname": "MacBook-Pro.local",
    "serial_number": "XXXXXXXXXXXX",
    "os_version": "15.3",
    "platform": "darwin",
    "user_identity": "user@example.com"
  },
  "ai_agents_and_tools": [
    {
      "name": "claude-code",
      "vendor": "Anthropic",
      "type": "cli_tool",
      "version": "1.0.12",
      "binary_path": "/usr/local/bin/claude",
      "config_dir": "/Users/dev/.claude"
    },
    {
      "name": "openclaw",
      "vendor": "OpenSource",
      "type": "general_agent",
      "version": "0.5.2",
      "install_path": "/Users/dev/.openclaw"
    },
    {
      "name": "ollama",
      "vendor": "Unknown",
      "type": "framework",
      "version": "0.5.4",
      "binary_path": "/usr/local/bin/ollama",
      "is_running": true
    }
  ],
  "ide_installations": [
    {
      "ide_type": "vscode",
      "version": "1.96.0",
      "install_path": "/Applications/Visual Studio Code.app",
      "vendor": "Microsoft",
      "is_installed": true
    }
  ],
  "ide_extensions": [
    {
      "id": "ms-python.python",
      "name": "python",
      "version": "2024.22.0",
      "publisher": "ms-python",
      "install_date": 1709000000,
      "ide_type": "vscode"
    }
  ],
  "mcp_configs": [
    {
      "source": "claude_desktop",
      "vendor": "Anthropic",
      "config_path": "/Users/dev/Library/Application Support/Claude/claude_desktop_config.json",
      "servers": [
        {
          "name": "filesystem",
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/projects"]
        }
      ]
    }
  ],
  "node_package_managers": [
    {
      "name": "npm",
      "version": "10.2.0",
      "path": "/usr/local/bin/npm"
    }
  ],
  "summary": {
    "ai_agents_and_tools_count": 5,
    "ide_installations_count": 3,
    "ide_extensions_count": 47,
    "mcp_configs_count": 1,
    "node_projects_count": 0
  }
}
```

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `agent_version` | string | Version of the scanner binary |
| `scan_timestamp` | number | Unix timestamp (seconds) of the scan |
| `scan_timestamp_iso` | string | ISO 8601 timestamp |
| `device` | object | Device identification information |
| `ai_agents_and_tools` | array | All detected AI tools, agents, and frameworks |
| `ide_installations` | array | Installed IDEs and AI desktop apps |
| `ide_extensions` | array | All installed IDE extensions |
| `mcp_configs` | array | MCP server configurations found across AI tools |
| `node_package_managers` | array | Detected Node.js package managers (npm, yarn, pnpm, bun) |
| `summary` | object | Count summaries |

### AI Tool Types

| `type` value | Description |
|--------------|-------------|
| `cli_tool` | Command-line AI coding assistant |
| `general_agent` | General-purpose AI agent |
| `framework` | AI framework or runtime |

### IDE Types

| `ide_type` value | Description |
|------------------|-------------|
| `vscode` | Visual Studio Code |
| `cursor` | Cursor |
| `windsurf` | Windsurf |
| `antigravity` | Antigravity (Google) |
| `zed` | Zed |
| `claude_desktop` | Claude Desktop |
| `microsoft_copilot_desktop` | Microsoft Copilot |

---

## HTML Output

The HTML report (`--html report.html`) generates a self-contained HTML file with the following layout:

1. **Header** -- Purple gradient banner with "StepSecurity Dev Machine Guard Report" title
2. **Scan metadata** -- Timestamp and agent version
3. **Summary cards** -- Three cards showing counts for AI Agents and Tools, IDEs & Desktop Apps, and IDE Extensions
4. **Device grid** -- Hostname, serial, macOS version, and user in a two-column grid
5. **AI Agents and Tools table** -- Name, version, type (with a styled badge), and vendor
6. **IDE & AI Desktop Apps table** -- Name, version, vendor, and install path
7. **IDE Extensions table** -- Extension ID, version, publisher, and IDE

The HTML report is styled with StepSecurity branding (purple accent colors) and is fully responsive. It can be printed or shared as a standalone file.

---

## Tips for Scripting with JSON Output

### Extract all AI tool names

```bash
./stepsecurity-dev-machine-guard --json | jq -r '.ai_agents_and_tools[].name'
```

### Count extensions per IDE

```bash
./stepsecurity-dev-machine-guard --json | jq '[.ide_extensions[] | .ide_type] | group_by(.) | map({(.[0]): length}) | add'
```

### Check if a specific extension is installed

```bash
./stepsecurity-dev-machine-guard --json | jq '.ide_extensions[] | select(.id == "ms-python.python")'
```

### Export extension list as CSV

```bash
./stepsecurity-dev-machine-guard --json | jq -r '.ide_extensions[] | [.id, .version, .publisher, .ide_type] | @csv'
```

---

## Further Reading

- [Community Mode](community-mode.md) -- output format options and CLI flags
- [MCP Audit](mcp-audit.md) -- understanding MCP server config auditing
- [SCAN_COVERAGE.md](../SCAN_COVERAGE.md) -- full catalog of what is detected

---

*[StepSecurity](https://stepsecurity.io) -- securing the developer toolchain, from CI/CD to the dev machine.*
