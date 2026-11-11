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
| OpenCode | `~/.config/opencode/opencode.json` (and `.jsonc`) | _(same)_ | OpenCode |
| OpenCode (project) | `opencode.json` / `opencode.jsonc` in a project directory | _(same)_ | OpenCode |

---

## What Information Is Shown

The MCP audit is designed to provide **visibility without exposing secrets**. A server's command, arguments, URL, headers, environment and even its name can carry a credential, and no filter can prove that an arbitrary string holds none. So the enterprise agent reads each config on the device and sends a rebuilt config instead of a filtered copy.

### What IS collected

- **Config path** (the file path of the config on disk), source and vendor
- **Known server identities.** A server is identified when its launch matches one of these forms and its target is in a bundled snapshot of the [official MCP registry](https://registry.modelcontextprotocol.io/):

  | Declared launch | Sent as |
  |-----------------|---------|
  | `npx [-y or --yes] <package> ...` | `command: "npx"`, `args: [<package>]` |
  | `uvx <package> ...` | `command: "uvx"`, `args: [<package>]` |
  | `uv run <package> ...` | `command: "uv"`, `args: ["run", <package>]` |
  | `docker run [--rm] [-i] [-t] [-it] [-e or --env <value>] <image> ...` | `command: "docker"`, `args: ["run", <image>]` |
  | A remote URL equal to a registry endpoint once userinfo, query and fragment are removed | `url: <endpoint>` |

  A launcher given by its full path (`/opt/homebrew/bin/npx`) or with a Windows `.exe` or `.cmd` suffix matches by its name; the path is never sent. The package, image or endpoint text comes from the snapshot, never from the config. Versions, tags, further arguments and environment operands are dropped.
- **Unidentified presence.** Every other server (an unknown package or image, another launcher or option, a shell wrapper, an unmatched URL) is folded into at most one marker per transport and config file:
  - `unidentified-local` with `command: "stepsecurity-unidentified-mcp-local"`
  - `unidentified-remote` with `url: "https://unidentified-mcp.invalid"`

  The marker command is never run, and the reserved `.invalid` host never resolves. The number of unidentified servers is not reported.

### What is NOT collected

- **Server names.** Known entries are keyed by labels generated from their identity, so the runtime aliases written in the config are not kept.
- **Arguments, URLs and paths** other than the snapshot identity
- **Environment variables** (`env`, and OpenCode's `environment`) and **HTTP headers**
- **Any other field** of a server entry, including Pi's `enabled` flag

The rebuilt JSON config always uses the `mcpServers` key, whatever key the tool itself uses (`context_servers`, `servers`, `mcp`, or Claude Code's per-project `mcpServers`). Codex's `config.toml` is rebuilt as TOML under `mcp_servers`. Plugin MCP declarations are reported as one `MCP configuration` component per plugin file or inline block, with the same rebuilt body. YAML configs, and JSON configs that fail to parse or have no recognized server key, are still reported by location, but no content is sent.

A registry match identifies a server; it does not prove the server is safe, running or used.

### Refreshing the registry snapshot

The snapshot is `internal/detector/builtin/mcp_registry.json`. It is refreshed deliberately with releases and is never fetched during a scan or a build. To refresh it:

1. Fetch every page of `https://registry.modelcontextprotocol.io/v0/servers?limit=100&version=latest`, following `metadata.nextCursor` until it is absent.
2. Skip servers whose official registry status is `deleted`. Keep the `identifier` of each `npm`, `pypi` and `oci` package (an OCI identifier without its tag or digest) and the `url` of each remote. Drop remote URLs that contain userinfo, a query, a fragment, a `{template}` variable or an `.invalid` host.
3. Write the sorted, de-duplicated lists as `npm_packages`, `pypi_packages`, `oci_images` and `remote_urls`, together with `source` (the URL above), `fetched_at`, `fetched_sha256` (the SHA-256 of the fetched pages concatenated in order), `servers_read` and the counts of excluded entries.

A server that the current snapshot does not list stays unidentified until a release ships a snapshot that does.

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
2. Rebuilt from known public server identities and unidentified presence markers (names, arguments, URLs, environment variables and headers are not copied)
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
    "browser": {
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest", "--user-data-dir", "/Users/dev/.browser"]
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

If the bundled registry snapshot lists `@playwright/mcp` but not `@modelcontextprotocol/server-github`, Dev Machine Guard sends:

```json
{
  "mcpServers": {
    "npx:@playwright/mcp": {
      "command": "npx",
      "args": ["@playwright/mcp"]
    },
    "unidentified-local": {
      "command": "stepsecurity-unidentified-mcp-local"
    }
  }
}
```

The server names `browser` and `github`, the version, the `--user-data-dir` argument and the `GITHUB_TOKEN` environment variable are **not** included.

---

## Further Reading

- [Adding Detections](adding-detections.md) -- how to add a new MCP config source
- [SCAN_COVERAGE.md](../SCAN_COVERAGE.md) -- full list of MCP config sources
- [Community Mode](community-mode.md) -- running MCP audit locally

