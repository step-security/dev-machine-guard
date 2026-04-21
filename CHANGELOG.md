# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

See [VERSIONING.md](VERSIONING.md) for why the version starts at 1.8.1.

## [Unreleased]

### Added

- **Glob-based Windows path matching**: `detectWindows` supports wildcard patterns in `WinPaths` for JetBrains IDEs that embed version numbers in folder names. Picks the newest installation when multiple versions are present.
- **`product-info.json` version extraction**: Reads JetBrains `product-info.json` for accurate marketing version numbers on Windows (avoids registry build numbers).
- **`.eclipseproduct` version extraction**: Reads Eclipse's `.eclipseproduct` properties file for version detection on Windows.
- **JetBrains plugin detection enhancements**: Reads `productVendor` from `product-info.json` for correct config paths (handles Android Studio's `Google` vendor). Checks `idea.plugins.path` override in `idea.properties`.

### Fixed

- **Windows project package scanning**: Added `RunInDir` to Executor interface to bypass `cmd.exe` quote escaping issues. Fixes project-level NPM packages not being collected on Windows.

## [1.10.0] - 2026-04-20

### Added

- Windows support: cross-platform detection for IDEs, extensions, AI tools, frameworks, MCP configs, and Node.js scanning on Windows.
- Homebrew scanning: detects formulae and casks with raw output capture for enterprise telemetry.
- Python scanning: detects package managers, global packages, and projects with virtual environments.
- User-aware executor: commands like `brew`, `pip3`, and `npm` now run in the logged-in user's context when the agent runs as root.
- IDE plugin detection: JetBrains IDEs, Xcode Source Editor extensions, and Eclipse plugins with bundled/user-installed source tagging.
- Project-level MCP configuration discovery and filtering.
- S3 upload retry mechanism with exponential backoff and extended timeout for large payloads.
- Enhanced user shell resolution for macOS `RunAsUser`.

### Fixed

- Populated missing performance metrics fields (brew formulae/cask counts, Python global packages/project counts).
- S3 retry logging now includes the actual error value for easier debugging.
- Retry backoff respects context cancellation during shutdown.

## [1.9.2] - 2026-04-15

### Fixed

- LaunchDaemon now sets `HOME` in the plist environment so `configDir()` resolves correctly at runtime (fixes "Enterprise configuration not found" error in periodic scans).
- Progress and error log lines now include timestamps for easier debugging.

## [1.9.1] - 2026-04-07

### Fixed

- Config `quiet: false` now correctly shows progress (was ignored previously).
- Enterprise auto-detect mode respects the configured quiet setting instead of overriding it.
- Release now produces a single universal macOS binary (amd64 + arm64).

## [1.9.0] - 2026-04-03

Migrated from shell script to a compiled Go binary. All existing scanning features, detection logic, CLI flags, output formats, and enterprise telemetry are preserved — this release changes the implementation, not the functionality.

### Added

- **Go binary**: Single compiled binary (`stepsecurity-dev-machine-guard`) replaces the shell script. Zero external dependencies, no runtime required.
- **`configure` / `configure show` commands**: Interactive setup and display of enterprise credentials, search directories, and preferences. Saved to `~/.stepsecurity/config.json`.

## [1.8.2] - 2026-03-17

### Added

- `--search-dirs DIR [DIR...]` flag to scan specific directories instead of `$HOME` (replaces default; repeatable)
  - Accepts multiple directories in a single flag: `--search-dirs /tmp /opt /var`
  - Supports repeated use: `--search-dirs /tmp --search-dirs /opt`
  - Quoted paths with spaces work: `--search-dirs "/path/with spaces"`

## [1.8.1] - 2026-03-10

First open-source release. The scanning engine was previously an internal enterprise tool (v1.0.0-v1.8.1) running in production. This release adds community mode for local-only scanning while keeping the enterprise codebase intact.

### Added

- **Community mode** with three output formats: pretty terminal, JSON, and HTML report
- **AI agent and CLI tool detection**: Claude Code, Codex, Gemini CLI, Kiro, Aider, OpenCode, and more
- **General-purpose AI agent detection**: OpenClaw, ClawdBot, GPT-Engineer, Claude Cowork
- **AI framework detection**: Ollama, LM Studio, LocalAI, Text Generation WebUI
- **MCP server config auditing** across Claude Desktop, Claude Code, Cursor, Windsurf, Antigravity, Zed, Open Interpreter, and Codex
- **IDE extension scanning** for VS Code and Cursor (with publisher, version, and install date)
- **Node.js package scanning** for npm, yarn, pnpm, and bun (opt-in in community mode)
- CLI flags: `--pretty`, `--json`, `--html FILE`, `--verbose`, `--enable-npm-scan`, `--color=WHEN`
- Documentation: community mode guide, enterprise mode guide, MCP audit guide, adding detections guide, reading scan results guide
- GitHub issue templates for bugs, feature requests, and new detections
- ShellCheck CI workflow with Harden-Runner

### Changed

- Enterprise config variables are now clearly labeled and placed below the community-facing header
- Progress messages suppressed by default in community mode (enable with `--verbose`)
- Node.js scanning off by default in community mode (enable with `--enable-npm-scan`)

### Enterprise (unchanged from v1.8.1)

- `install`, `uninstall`, and `send-telemetry` commands
- Launchd scheduling (LaunchDaemon for root, LaunchAgent for user)
- S3 presigned URL upload with backend notification
- Execution log capture and base64 encoding
- Instance locking to prevent concurrent runs

[1.10.0]: https://github.com/step-security/dev-machine-guard/compare/v1.9.2...v1.10.0
[1.9.2]: https://github.com/step-security/dev-machine-guard/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/step-security/dev-machine-guard/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/step-security/dev-machine-guard/compare/v1.8.2...v1.9.0
[1.8.2]: https://github.com/step-security/dev-machine-guard/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/step-security/dev-machine-guard/releases/tag/v1.8.1
