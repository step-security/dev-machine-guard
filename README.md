<h1 align="center">StepSecurity Dev Machine Guard</h1>

<p align="center">
  <img src="images/banner.png" alt="StepSecurity Dev Machine Guard — shield logo with terminal prompt" width="800">
</p>

<p align="center">
  <img src="images/demo.gif" alt="StepSecurity Dev Machine Guard demo" width="800">
</p>

<p align="center">
  <a href="https://github.com/step-security/dev-machine-guard/actions/workflows/tests.yml"><img src="https://github.com/step-security/dev-machine-guard/actions/workflows/tests.yml/badge.svg?branch=main" alt="Tests"></a>
  <a href="https://github.com/step-security/dev-machine-guard/actions/workflows/gosec.yml"><img src="https://github.com/step-security/dev-machine-guard/actions/workflows/gosec.yml/badge.svg?branch=main" alt="Gosec"></a>
  <a href="https://github.com/step-security/dev-machine-guard/actions/workflows/release.yml"><img src="https://github.com/step-security/dev-machine-guard/actions/workflows/release.yml/badge.svg" alt="Release"></a>
  <a href="https://goreportcard.com/report/github.com/step-security/dev-machine-guard"><img src="https://goreportcard.com/badge/github.com/step-security/dev-machine-guard" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/step-security/dev-machine-guard"><img src="https://pkg.go.dev/badge/github.com/step-security/dev-machine-guard.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://github.com/step-security/dev-machine-guard/releases"><img src="https://img.shields.io/github/v/release/step-security/dev-machine-guard?label=release&color=purple" alt="Latest release"></a>
</p>

<p align="center">
  <b>Scan your dev machine for AI agents, MCP servers, IDE extensions, suspicious files, and risky package-manager configs — in seconds.</b>
</p>

## Why Dev Machine Guard?

Developer machines are the new attack surface. They hold high-value assets — GitHub tokens, cloud credentials, SSH keys — and routinely execute untrusted code through dependencies and AI-powered tools. Recent supply chain attacks have shown that malicious VS Code extensions can steal credentials, rogue MCP servers can access your codebase, and compromised npm packages can exfiltrate secrets.

<p align="center">
  <img src="images/attack-surface.png" alt="Developer machine attack surface — malicious extensions, rogue MCP servers, unvetted AI agents, compromised packages" width="800">
</p>

**EDR and traditional MDM solutions** monitor device posture and compliance, but they have **zero visibility** into the developer tooling layer:

| Capability                  | EDR / MDM | Dev Machine Guard |
| --------------------------- | :-------: | :---------------: |
| IDE extension audit         |           |        Yes        |
| AI agent & tool inventory   |           |        Yes        |
| MCP server config audit     |           |        Yes        |
| Package scanning (Node.js, Homebrew, Python, system) |  |  Yes  |
| Package-manager config audit (registry, cooldown, auth) |  |  Yes  |
| Suspicious file / IOC detection |       |        Yes        |
| Cross-platform (macOS, Windows, Linux) | Yes | Yes        |
| Device posture & compliance |    Yes    |                   |
| Malware / virus detection   |    Yes    |                   |

**Dev Machine Guard is complementary to EDR/MDM — not a replacement.** Deploy it alongside your existing tools via MDM (Jamf, Kandji, Intune) or run it standalone.

<p align="center">
  <img src="images/blind-spots.png" alt="The developer tooling blind spot — EDR and MDM miss IDE extensions, AI agents, MCP servers, and npm packages" width="800">
</p>

## Quick Start

The steps below install the binary directly and are intended for **community users** evaluating Dev Machine Guard on a single machine.

**Enterprise customers should not install the binary manually.** Deploy Dev Machine Guard across your fleet using the loader script through your MDM or EDR tooling. See the [Installation Script documentation](https://docs.stepsecurity.io/developer-machines/installation-script) for the supported, auto-updating deployment flow.

### Install from release (community)

Release assets are named `stepsecurity-dev-machine-guard-<version>-<os>` (for example, `stepsecurity-dev-machine-guard-1.12.0-darwin`). Rather than hardcoding a version, discover the latest asset dynamically so the command keeps working across releases.

**macOS:**

```bash
# Discover and download the latest macOS (darwin) release asset
ASSET=$(curl -s https://api.github.com/repos/step-security/dev-machine-guard/releases/latest \
  | jq -r '.assets[].name | select(test("^stepsecurity-dev-machine-guard-[0-9.]+-darwin$"))')

curl -fL "https://github.com/step-security/dev-machine-guard/releases/latest/download/$ASSET" \
  -o stepsecurity-dev-machine-guard
chmod +x stepsecurity-dev-machine-guard

# Run the scan
./stepsecurity-dev-machine-guard
```

To pin a specific version instead, download the matching asset directly:

```bash
curl -fL https://github.com/step-security/dev-machine-guard/releases/latest/download/stepsecurity-dev-machine-guard-1.12.0-darwin \
  -o stepsecurity-dev-machine-guard
chmod +x stepsecurity-dev-machine-guard
./stepsecurity-dev-machine-guard
```

**Windows:**

```powershell
# x64
Invoke-WebRequest -Uri "https://github.com/step-security/dev-machine-guard/releases/latest/download/stepsecurity-dev-machine-guard_windows_amd64.exe" -OutFile "stepsecurity-dev-machine-guard.exe"

# ARM64
Invoke-WebRequest -Uri "https://github.com/step-security/dev-machine-guard/releases/latest/download/stepsecurity-dev-machine-guard_windows_arm64.exe" -OutFile "stepsecurity-dev-machine-guard.exe"

# Run the scan
.\stepsecurity-dev-machine-guard.exe
```

**Linux:**

```bash
# x64
curl -sSL https://github.com/step-security/dev-machine-guard/releases/latest/download/stepsecurity-dev-machine-guard_linux_amd64 -o stepsecurity-dev-machine-guard
chmod +x stepsecurity-dev-machine-guard

# ARM64
curl -sSL https://github.com/step-security/dev-machine-guard/releases/latest/download/stepsecurity-dev-machine-guard_linux_arm64 -o stepsecurity-dev-machine-guard
chmod +x stepsecurity-dev-machine-guard

# Run the scan
./stepsecurity-dev-machine-guard
```

Pre-built `.deb` and `.rpm` packages are also available on the [releases page](https://github.com/step-security/dev-machine-guard/releases).

### Build from source

```bash
git clone https://github.com/step-security/dev-machine-guard.git
cd dev-machine-guard
make build
./stepsecurity-dev-machine-guard
```

Requires Go 1.24+. The binary has zero external dependencies.

## Usage

```
stepsecurity-dev-machine-guard [COMMAND] [OPTIONS]
```

### Commands

| Command          | Description                                                     |
| ---------------- | --------------------------------------------------------------- |
| _(none)_         | Run a scan (community mode, pretty output)                      |
| `configure`      | Interactively set all settings (enterprise, scan, output)       |
| `configure show` | Show current configuration (API key masked)                     |
| `install`        | Install scheduled scanning — launchd (macOS), systemd (Linux), schtasks (Windows) |
| `uninstall`      | Remove scheduled scanning configuration                                           |
| `send-telemetry` | Upload scan results to the StepSecurity dashboard (enterprise)  |

### Output Formats

| Flag          | Description                              |
| ------------- | ---------------------------------------- |
| `--pretty`    | Pretty terminal output (default)         |
| `--json`      | JSON output to stdout                    |
| `--html FILE` | Self-contained HTML report saved to FILE |

### Options

| Flag                         | Description                                                   |
| ---------------------------- | ------------------------------------------------------------- |
| `--search-dirs DIR [DIR...]` | Search DIRs instead of `$HOME` (replaces default; repeatable) |
| `--enable-npm-scan`          | Enable Node.js package scanning                               |
| `--disable-npm-scan`         | Disable Node.js package scanning                              |
| `--enable-brew-scan`         | Enable Homebrew package scanning                              |
| `--disable-brew-scan`        | Disable Homebrew package scanning                             |
| `--enable-python-scan`       | Enable Python package scanning                                |
| `--disable-python-scan`      | Disable Python package scanning                               |
| `--include-bundled-plugins`  | Include bundled/platform IDE plugins in output                |
| `--log-level=LEVEL`          | Log level: `error` \| `warn` \| `info` \| `debug`             |
| `--verbose`                  | Shortcut for `--log-level=debug`                              |
| `--color=WHEN`               | Color mode: `auto` \| `always` \| `never` (default: `auto`)   |
| `-v`, `--version`            | Show version                                                  |
| `-h`, `--help`               | Show help                                                     |

### Examples

```bash
# Pretty terminal output (default)
./stepsecurity-dev-machine-guard

# JSON output
./stepsecurity-dev-machine-guard --json
./stepsecurity-dev-machine-guard --json | python3 -m json.tool   # formatted
./stepsecurity-dev-machine-guard --json > scan.json               # to file

# HTML report
./stepsecurity-dev-machine-guard --html report.html

# Verbose scan with npm packages — shows progress spinners and timing
./stepsecurity-dev-machine-guard --verbose --enable-npm-scan

# Scan specific directories instead of $HOME
./stepsecurity-dev-machine-guard --search-dirs /Volumes/code
./stepsecurity-dev-machine-guard --search-dirs /tmp /opt          # multiple dirs

# Pipe JSON through jq to extract just AI tools
./stepsecurity-dev-machine-guard --json | jq '.ai_agents_and_tools'

# Count IDE extensions
./stepsecurity-dev-machine-guard --json | jq '.summary.ide_extensions_count'

# Check for MCP configs (exit 1 if any found — useful in CI)
count=$(./stepsecurity-dev-machine-guard --json | jq '.summary.mcp_configs_count')
[ "$count" -gt 0 ] && echo "MCP servers detected!" && exit 1

# Disable colors for piping or logging
./stepsecurity-dev-machine-guard --color=never 2>&1 | tee scan.log

# Enterprise: configure all settings interactively
./stepsecurity-dev-machine-guard configure

# Enterprise: view saved configuration (API key masked)
./stepsecurity-dev-machine-guard configure show

# Enterprise: install scheduled scanning (launchd / systemd / schtasks)
./stepsecurity-dev-machine-guard install

# Enterprise: one-time telemetry upload
./stepsecurity-dev-machine-guard send-telemetry

# Enterprise: remove scheduled scanning
./stepsecurity-dev-machine-guard uninstall
```

## Configuration

Run `configure` to set up enterprise credentials and default search directories:

```bash
./stepsecurity-dev-machine-guard configure
```

This interactively prompts for all configurable settings:

| Setting            | Description                                 | Default         |
| ------------------ | ------------------------------------------- | --------------- |
| Customer ID        | Your StepSecurity customer identifier       | _(not set)_     |
| API Endpoint       | StepSecurity backend URL                    | _(not set)_     |
| API Key            | Authentication key for telemetry uploads    | _(not set)_     |
| Scan Frequency     | How often scheduled scans run (hours)       | _(not set)_     |
| Search Directories | Comma-separated list of directories to scan | `$HOME`         |
| Enable NPM Scan    | Node.js package scanning                    | `auto`          |
| Enable Brew Scan   | Homebrew package scanning                   | `auto`          |
| Enable Python Scan | Python package scanning                     | `auto`          |
| Color Mode         | Terminal color output                       | `auto`          |
| Output Format      | Default output format                       | `pretty`        |
| HTML Output File   | Default path for HTML reports               | _(not set)_     |
| Log Level          | Logging verbosity                           | `error`         |

View current settings:

```bash
./stepsecurity-dev-machine-guard configure show
```

```
Configuration (~/.stepsecurity/config.json):

  Customer ID:             my-company
  API Endpoint:            https://api.stepsecurity.io
  API Key:                 ***a1b2
  Scan Frequency:          4 hours
  Search Directories:      $HOME, /Volumes/code
  Enable NPM Scan:         auto
  Enable Brew Scan:        auto
  Enable Python Scan:      auto
  Color Mode:              auto
  Output Format:           pretty
  Log Level:               error
```

Configuration is saved to `~/.stepsecurity/config.json` with `0600` permissions (owner read/write only).

**CLI flags always override config file values** — this matches the shell script behavior. For example, if your config has `output_format: json`, running `./stepsecurity-dev-machine-guard --pretty` uses pretty output. To clear a value during configuration, enter a single dash (`-`).

### Logging and Verbose Mode

By default in community mode, progress messages (spinners, step details) are **suppressed** — you only see the final output. This keeps stdout clean for piping.

```bash
# Default: quiet — clean output, no progress spinners
./stepsecurity-dev-machine-guard --json > scan.json

# Verbose: show progress spinners and step timing
./stepsecurity-dev-machine-guard --verbose

# Fine-grained control: set log level
./stepsecurity-dev-machine-guard --log-level=info

# Save log level in config so it persists across runs
./stepsecurity-dev-machine-guard configure
```

In enterprise mode (`send-telemetry`, `install`), progress is **always shown** regardless of the log level — the output is captured as execution logs and sent to the backend for debugging.

## What It Detects

See [SCAN_COVERAGE.md](SCAN_COVERAGE.md) for the full catalog of supported detections.

| Category             | Examples                                                                                 |
| -------------------- | ---------------------------------------------------------------------------------------- |
| IDEs & Desktop Apps  | VS Code, Cursor, Windsurf, Antigravity, Zed, Claude, Copilot, JetBrains suite (13 IDEs), Eclipse, Android Studio |
| AI CLI Tools         | Claude Code, Codex, Gemini CLI, Kiro, GitHub Copilot CLI, Aider, OpenCode, Cursor Agent  |
| AI Agents            | Claude Cowork, OpenClaw, ClawdBot, GPT-Engineer                                          |
| AI Frameworks        | Ollama, LM Studio, LocalAI, Text Generation WebUI                                        |
| MCP Server Configs   | Claude Desktop, Claude Code, Cursor, Windsurf, Antigravity, Zed, Open Interpreter, Codex |
| IDE Extensions       | VS Code, Cursor, Windsurf, Antigravity, JetBrains, Eclipse, Xcode, Android Studio        |
| Node.js Packages     | npm, yarn, pnpm, bun (opt-in)                                                            |
| Homebrew Packages    | Formulae and casks with rich metadata (opt-in)                                            |
| Python Packages      | pip, poetry, pipenv, uv, conda, rye (opt-in)                                             |
| System Packages      | rpm, dpkg, pacman, apk, snap, flatpak (Linux)                                            |
| Package Configs      | npm (`.npmrc`), pnpm, bun (`bunfig.toml`), yarn classic & berry (`.yarnrc`/`.yarnrc.yml`), pip (`pip.conf`) — effective registry, cooldown policy, and auth surface across every scope |
| Suspicious Files     | Malicious-file IOCs from StepSecurity-maintained rules — e.g. `binding.gyp` that runs during `npm install`, and editor/AI-tool config files that auto-execute on project open |

## Package Configs & Suspicious Files

Beyond inventorying *what* is installed, Dev Machine Guard inspects *how* each machine is configured to pull packages, and *whether* any files associated with known attacks are present.

### Package-manager config auditing

Compromised packages most often reach a machine because that machine resolves directly from a public registry with no cooldown window against freshly published versions. Dev Machine Guard audits the package-manager configuration on each machine across every scope (project, user, and global) and resolves three things per package manager:

- **Effective registry** — the registry packages actually resolve from, accounting for configuration precedence, so you can confirm machines route through StepSecurity Secure Registry or an internal artifact manager rather than straight to the public registry.
- **Cooldown policy** — whether a cooldown window against newly published packages is in effect.
- **Authentication surface** — what credentials are configured against the registry.

Configuration is read from `.npmrc` (npm), pnpm config, `bunfig.toml` (bun), `.yarnrc` / `.yarnrc.yml` (yarn classic and berry), and `pip.conf` (pip). In enterprise mode this rolls up into the **Package Configs** view in the dashboard, where you can spot machines that are unprotected or pointed at the wrong registry.

### Suspicious file detection

Some supply chain attacks plant files that trigger code execution outside the package lifecycle scripts most tools watch — for example a malicious `binding.gyp` that runs during `npm install`, or an editor configuration file that runs when a project is opened. Dev Machine Guard ships a rules-engine scanner that flags these files as IOCs and wires the results into scan telemetry. The detector streams one file at a time, so scan memory stays bounded regardless of repository size.

The detection rules are authored and maintained by StepSecurity, so the feature works out of the box with nothing to configure. As new attack techniques are identified, the rule set is updated centrally and your machines are evaluated against the new rules automatically. In enterprise mode, flagged files surface in the **Suspicious Files** view with a confidence level and attribution to the associated attack campaign.

## Output Formats

### Pretty Terminal Output (default)

```bash
./stepsecurity-dev-machine-guard
```

<p align="center">
  <img src="images/pretty-output.png" alt="Pretty terminal output showing device info, AI agents, IDEs, MCP servers, and extensions" width="700">
</p>

### JSON Output

```bash
./stepsecurity-dev-machine-guard --json
```

See [examples/sample-output.json](examples/sample-output.json) for the full schema, or [Reading Scan Results](docs/reading-scan-results.md) for the schema reference. Recent scans also emit package-manager configuration inventory and `pnpm_audit` / `bun_audit` / `yarn_audit` results on the wire payload.

### HTML Report

```bash
./stepsecurity-dev-machine-guard --html report.html
```

<p align="center">
  <img src="images/html-report.png" alt="HTML report with summary cards, device info, and detailed tables" width="700">
</p>

## Community vs Enterprise

| Feature                       | Community (Free) | Enterprise |
| ----------------------------- | :--------------: | :--------: |
| AI agent & tool inventory     |       Yes        |    Yes     |
| IDE extension scanning        |       Yes        |    Yes     |
| MCP server config audit       |       Yes        |    Yes     |
| Pretty / JSON / HTML output   |       Yes        |    Yes     |
| Package scanning (Node.js, Homebrew, Python) | Opt-in | Default on |
| System package scanning (Linux) |    Yes     |    Yes     |
| Package-manager config auditing |    Yes     |    Yes     |
| Suspicious file detection     |       Yes        |    Yes     |
| Interactive configuration     |       Yes        |    Yes     |
| Centralized dashboard         |                  |    Yes     |
| Policy enforcement & alerting |                  |    Yes     |
| Scheduled scans (launchd / systemd / schtasks) | |   Yes     |
| Historical trends & reporting |                  |    Yes     |

Enterprise mode requires a StepSecurity subscription. [Start a 14-day free trial](https://www.stepsecurity.io/start-free) by installing the StepSecurity GitHub App.

### Enterprise Setup

```bash
# 1. Configure credentials (interactive)
./stepsecurity-dev-machine-guard configure

# 2. Install scheduled scanning (launchd on macOS, systemd on Linux, schtasks on Windows)
./stepsecurity-dev-machine-guard install

# 3. Or run a one-time telemetry upload
./stepsecurity-dev-machine-guard send-telemetry

# 4. Uninstall scheduled scanning
./stepsecurity-dev-machine-guard uninstall
```

**Open-source commitment:** StepSecurity enterprise customers use the exact same binary from this repository. There is no separate closed-source version — all scanning capabilities are developed and maintained here in the open. Enterprise mode adds centralized infrastructure (dashboard, policy engine, alerting) on top of the same open-source scanning engine.

## How It Works

<p align="center">
  <img src="images/how-it-works.png" alt="Architecture diagram — scan sources flow through the binary to terminal, JSON, HTML, or StepSecurity dashboard outputs" width="800">
</p>

Dev Machine Guard is a single compiled binary that scans your developer environment. Here's what it does and — importantly — what it does **not** do:

**What it collects:**

- Installed IDEs, AI tools, and their versions
- IDE extension/plugin names, publishers, and versions (VS Code, Cursor, Windsurf, Antigravity, JetBrains, Eclipse, Xcode, Android Studio)
- MCP server configuration (server names and commands only)
- Node.js, Homebrew, Python, and system package listings (opt-in)
- Package-manager configuration: effective registry, cooldown policy, and authentication surface across every scope (`.npmrc`, pnpm config, `bunfig.toml`, `.yarnrc`/`.yarnrc.yml`, `pip.conf`)
- Suspicious files flagged by StepSecurity-maintained malicious-file rules (path and matched rule only — file contents are not collected)

Detection uses platform-specific methods: `/Applications/` and `Info.plist` on macOS, `%LOCALAPPDATA%`/`%PROGRAMFILES%` and Windows Registry on Windows, `/opt`/`/usr/share`/`.desktop` files on Linux, and `$PATH` lookups on all platforms.

**What it does NOT collect:**

- Source code, file contents, or project data
- Secrets, credentials, API keys, or tokens
- Browsing history or personal files
- Any data from your IDE workspaces

**In community mode**, all data stays on your machine. Nothing is sent anywhere.

**In enterprise mode**, scan data is sent to the StepSecurity backend for centralized visibility. The source code is fully open — you can audit exactly what is collected and transmitted.

## Building from Source

```bash
# Build
make build

# Run unit tests (with race detector)
make test

# Run integration smoke tests
make smoke

# Run linter
make lint

# Clean build artifacts
make clean
```

### Project Structure

```
cmd/stepsecurity-dev-machine-guard/   # Binary entry point
internal/
├── buildinfo/     # Version and build metadata
├── cli/           # Argument parser
├── config/        # Configuration file management and configure command
├── detector/      # All scanners (IDE, AI CLI, agents, frameworks, MCP, extensions, Node.js) — cross-platform
├── device/        # Device info (hostname, serial, OS version)
├── executor/      # OS abstraction interface (enables mocked unit tests)
├── launchd/       # macOS launchd install/uninstall
├── lock/          # PID-file instance locking
├── model/         # JSON struct types
├── output/        # Formatters (JSON, pretty, HTML)
├── progress/      # Progress spinner and logging
├── scan/          # Community mode orchestrator
├── schtasks/      # Windows Task Scheduler install/uninstall
├── systemd/       # Linux systemd user timer install/uninstall
└── telemetry/     # Enterprise mode orchestrator and S3 upload
```

## How It Compares

Dev Machine Guard is **not a replacement** for dependency scanners, vulnerability databases, or endpoint security tools. It covers a different layer — the developer tooling surface — that these tools were never designed to inspect.

| Tool Category                             | What It Does Well                                            | What It Misses                                                                                               |
| ----------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| **`npm audit` / `yarn audit`**            | Flags known CVEs in declared dependencies                    | Has no visibility into IDEs, AI tools, MCP servers, or IDE extensions                                        |
| **OWASP Dep-Check / Snyk / Socket**       | Deep dependency vulnerability and supply-chain risk analysis | Does not scan the broader developer tooling layer (AI agents, IDE extensions, MCP configs)                   |
| **EDR / MDM (CrowdStrike, Jamf, Intune)** | Device posture, compliance, and malware detection            | Zero visibility into developer-specific tooling like IDE extensions, MCP servers, or AI agent configurations |

Dev Machine Guard fills the gap by inventorying what is actually running in your developer environment. Deploy it alongside your existing security stack for complete coverage.

## Known Limitations

- **Package scanning** (Node.js, Homebrew, Python) is opt-in in community mode and results are basic (package manager detection and package/project lists). Full dependency tree analysis is available in enterprise mode.
- **MCP config auditing** shows which tools have MCP configs (source, vendor, and config path) but does not display config file contents in community mode. Enterprise mode sends filtered config data (server names and commands only, no secrets) to the dashboard.
- **System package scanning** (rpm, dpkg, pacman, apk, snap, flatpak) is Linux-only.
- **Package-manager config auditing** reports the effective registry, cooldown status, and authentication surface from configuration files; it reflects configuration as written and does not intercept package installs at runtime.
- **Suspicious file detection** flags files that match StepSecurity-maintained rules and records the path and matched rule. It does not collect or transmit file contents. Confidence levels and attack-campaign attribution surface in the enterprise dashboard.

## Roadmap

Check out the [GitHub Issues](https://github.com/step-security/dev-machine-guard/issues) for planned features and improvements. Feedback and suggestions are welcome — open an issue to start a conversation.

## JSON Schema

See [examples/sample-output.json](examples/sample-output.json) for a complete sample of the JSON output, or [Reading Scan Results](docs/reading-scan-results.md) for the full schema reference.

## Contributing

We welcome contributions! Whether it's adding detection for a new AI tool, improving documentation, or reporting bugs.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick contribution ideas:**

- Add a new AI tool or IDE to the detection list
- Improve [documentation](docs/)
- Report bugs or request features via [issues](https://github.com/step-security/dev-machine-guard/issues)

## Resources

- [Changelog](CHANGELOG.md)
- [Scan Coverage](SCAN_COVERAGE.md) — full catalog of detections
- [Release Process](docs/release-process.md) — how releases are signed and verified
- [Deploying via SCCM](docs/deploying-via-sccm.md) — Windows fleet rollout via Microsoft Configuration Manager (signed MSI, no PowerShell)
- [macOS TCC Permissions](docs/macos-tcc-permissions.md) — how the agent handles Documents/Downloads/Mail TCC dirs, PPPC profile for MDM-pushed Full Disk Access, and the `include_tcc_protected` config field
- [Versioning](VERSIONING.md) — why the version starts at 1.8.1
- [Security Policy](SECURITY.md) — reporting vulnerabilities
- [Code of Conduct](CODE_OF_CONDUCT.md)

## License

This project is licensed under the [Apache License 2.0](LICENSE).

---

If you find Dev Machine Guard useful, please consider giving it a star. It helps others discover the project.