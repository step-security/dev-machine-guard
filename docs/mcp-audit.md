# StepSecurity Dev Machine Guard — MCP Server Config Audit

Dev Machine Guard scans MCP (Model Context Protocol) configuration files across your AI tools to provide visibility into which external servers and tools your AI agents have access to.

> Back to [README](../README.md) | See also: [Adding Detections](adding-detections.md)

---

## What Is MCP?

The [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) is an open standard that allows AI agents and coding assistants to connect to external tools and data sources. MCP servers can provide AI agents with capabilities such as:

- Reading and writing files
- Executing shell commands
- Accessing databases
- Calling external APIs
- Browsing the web
- Interacting with cloud services

MCP configs are typically JSON files that list the servers an AI tool is authorized to communicate with, along with the commands used to start those servers.

---

## Why Auditing MCP Configs Matters

MCP servers represent a significant expansion of what AI agents can do on your machine. Security implications include:

- **Unauthorized access:** A misconfigured or malicious MCP server could give an AI agent access to sensitive files, credentials, or internal APIs.
- **Supply chain risk:** Third-party MCP servers from npm packages or GitHub repos may contain malicious code that executes with the AI agent's permissions.
- **Lateral movement:** An MCP server that connects to internal services could be used as a pivot point if compromised.
- **Data exfiltration:** MCP servers that connect to external APIs could be used to exfiltrate code or secrets.

By auditing MCP configs, security teams gain visibility into which external tools and servers are connected to developer AI agents -- a blind spot that traditional EDR/MDM tools do not cover.

---

## Which Tools' Configs Are Scanned

Dev Machine Guard scans MCP configuration files for the following tools:

| Tool | macOS / Linux Path | Windows Path (if different) | Vendor |
|------|--------------------|-----------------------------|--------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `%APPDATA%/Claude/claude_desktop_config.json` | Anthropic |
| Claude Code | `~/.claude/settings.json` | _(same)_ | Anthropic |
| Claude Code | `~/.claude.json` | _(same)_ | Anthropic |
| Cursor | `~/.cursor/mcp.json` | _(same)_ | Cursor |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | _(same)_ | Codeium |
| Antigravity | `~/.gemini/antigravity/mcp_config.json` | _(same)_ | Google |
| Zed | `~/.config/zed/settings.json` | _(same)_ | Zed |
| Open Interpreter | `~/.config/open-interpreter/config.yaml` | _(same)_ | Open Source |
| Codex | `~/.codex/config.toml` | _(same)_ | OpenAI |

---

## What Information Is Shown

The MCP audit is designed to provide **visibility without exposing secrets**.

### What IS collected

- **Server names** (the key names under `mcpServers` or equivalent)
- **Commands** used to launch the server (e.g., `npx`, `node`, `python`)
- **Arguments** passed to the launch command
- **Server URLs** (if the server is accessed via URL rather than a local command)
- **Config path** (the file path of the config on disk)

### What is NOT collected

- **Environment variables** (`env` blocks in MCP configs often contain API keys and tokens -- these are stripped before collection)
- **HTTP headers** (may contain authentication tokens)
- **Any other sensitive fields** that are not directly related to server identification

In the enterprise agent, a Go-native filter extracts only the fields listed above before base64-encoding the config. For JSON configs, only `mcpServers` / `context_servers` entries are kept, and within each server only `command`, `args`, `serverUrl`, and `url` fields are retained. Non-JSON configs (TOML, YAML) are included as-is.

---

## Community Mode Behavior

In [community mode](community-mode.md), MCP config information is displayed locally in the scan output:

- **Pretty output:** MCP servers are listed with their source name, vendor, and config path.
- **JSON output:** MCP config details are included in the `mcp_configs` array with source, vendor, and config path.
- **HTML output:** MCP servers are displayed in a dedicated section of the report with source, vendor, and config path.

No data is transmitted anywhere. The MCP configs are read from disk and displayed locally only. Config file contents are not shown in community mode.

---

## Enterprise Mode Behavior

In enterprise mode, MCP config data is:

1. Read from the config files on disk
2. Filtered to include only server names, commands, args, and URLs (environment variables and secrets are stripped)
3. Base64-encoded
4. Included in the telemetry payload uploaded to the StepSecurity backend
5. Parsed and displayed in the StepSecurity dashboard for centralized analysis

This allows security teams to:
- See which MCP servers are in use across the organization
- Detect unauthorized or unexpected MCP servers
- Track changes to MCP configurations over time
- Enforce policies about approved MCP servers

---

## Example: Claude Desktop MCP Config

A typical `claude_desktop_config.json` might look like this:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/projects"],
      "env": {
        "NODE_ENV": "production"
      }
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_xxxxxxxxxxxx"
      }
    }
  }
}
```

Dev Machine Guard will report:
- Server `filesystem` with command `npx` and args `["-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/projects"]`
- Server `github` with command `npx` and args `["-y", "@modelcontextprotocol/server-github"]`

The `GITHUB_TOKEN` environment variable is **not** included in the output.

---

## Further Reading

- [Adding Detections](adding-detections.md) -- how to add a new MCP config source
- [SCAN_COVERAGE.md](../SCAN_COVERAGE.md) -- full list of MCP config sources
- [Community Mode](community-mode.md) -- running MCP audit locally

