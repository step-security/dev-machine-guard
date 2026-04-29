# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

See [VERSIONING.md](VERSIONING.md) for why the version starts at 1.8.1.

## [1.11.0] - 2026-04-29

### Added

- **Linux support**: Cross-platform scanning on Linux with feature parity for the core workflow — IDE/extension/AI tool/MCP/Node.js/Python detection plus the device, telemetry, and locking subsystems.
  - **systemd scheduling**: LaunchDaemon/LaunchAgent equivalent on Linux, using systemd timers/services to run scheduled scans.
  - **Native Linux package detection**: rpm, deb, snap, and flatpak packages enumerated and reported.
  - **JetBrains IDE detection on Linux**.
  - **BIOS serial number** used for device identification on Linux when system serial is unavailable.
- **Linux distro-native release artifacts**: Release workflow now produces `.deb` and `.rpm` packages alongside the raw Linux binaries, packaged via goreleaser.
- **System package metadata + security context**: Brew formulae/casks (macOS) and system packages (Linux: rpm/deb/snap/flatpak) now report rich metadata — name, version, vendor, install date, and per-package security context (signature/signing-key information where available) — in the telemetry payload.
- **Telemetry run status reporting**: Agent reports run start/success/failure status to telemetry separately from scan results, so backend can track agent health independently of scan content.
- **Gzip compression for telemetry uploads**: Telemetry payload upload to S3 is now gzip-compressed, reducing transfer size on slow networks.
- **Log level configuration**: New `--log-level` flag and config option replace hard-coded logging; progress and component logs honor the configured level throughout the application.
- **Cursor Agent CLI detection**: `cursor-agent` (Cursor's agent CLI, installed via `curl https://cursor.com/install`) is now detected as a distinct AI CLI tool, separate from the existing Cursor IDE record. Machines with both installed will now report two artifacts.

### Changed

- **Legacy shell script removed**: The original `stepsecurity-dev-machine-guard.sh` (and its accompanying shellcheck CI workflow and shell smoke tests) has been removed. The Go binary, introduced in 1.9.0, is now the only entry point.
- **UUID generation**: Replaced custom UUID generator with the `google/uuid` library for telemetry IDs.

### Fixed

- **Python project detection**: Virtual-environment path discovery now handles venvs created without pip, and project detection inside such venvs no longer skips them.
- **GitHub Copilot CLI detection**: Detector rejects non-zero exit codes from the version probe (previously yielded false positives) and correctly parses the Copilot CLI's version output format.

## [1.10.2] - 2026-04-22

### Added

- **Windows Eclipse plugin detection**: Multi-stage detection pipeline using detected IDE install paths (registry-aware), well-known path probes (Oomph installer, vendor variants like STS/MyEclipse, D:-Z: drive scanning), and install validation to eliminate false positives.
- **Eclipse p2 director integration**: Uses `eclipsec.exe -listInstalledRoots` for authoritative marketplace plugin identification. Falls back to `bundles.info` parsing if unavailable.
- **`--include-bundled-plugins` flag**: Bundled/platform plugins (e.g., Eclipse's 500+ OSGi bundles) are now filtered out by default to reduce noise and payload size (~124KB → ~21KB). Use the flag to include them.
- **Sigstore signing retry logic**: Release workflow retries artifact signing with Sigstore on transient failures.

### Changed

- **Quiet mode now defaults to `false`**: Progress output is shown by default in community mode, matching the behavior already documented in the README. `configure` prompt and `configure show` now display `false` when the value is unset.
- **S3 telemetry upload timeout increased from 60 seconds to 10 minutes**: Large scan payloads on slower networks were exhausting the previous 60 s budget and forcing the retry loop to redo the entire upload.

## [1.10.1] - 2026-04-21

### Added

- **Glob-based Windows path matching**: `detectWindows` supports wildcard patterns in `WinPaths` for JetBrains IDEs that embed version numbers in folder names. Picks the newest installation when multiple versions are present.
- **`product-info.json` version extraction**: Reads JetBrains `product-info.json` for accurate marketing version numbers on Windows (avoids registry build numbers).
- **`.eclipseproduct` version extraction**: Reads Eclipse's `.eclipseproduct` properties file for version detection on Windows.
- **JetBrains plugin detection enhancements**: Reads `productVendor` from `product-info.json` for correct config paths (handles Android Studio's `Google` vendor). Checks `idea.plugins.path` override in `idea.properties`.

### Fixed

- **Windows project package scanning**: Added `RunInDir` to Executor interface to bypass `cmd.exe` quote escaping issues. Fixes project-level NPM packages not being collected on Windows.
- `RunAsUser` now sources `~/.zshrc` (or `~/.bashrc`) for full PATH resolution when running as root. Tools installed via nvm, n, fnm, bun, or npm-global were invisible in LaunchDaemon/IRU contexts because the login shell skipped `.zshrc`.
- `RunAsUser` now propagates non-zero exit codes as errors instead of silently returning nil.
- `LookPath` validates that `which` output is an absolute path, preventing zsh's "not found" stdout messages from being treated as valid binary paths.
- `UserAwareExecutor.Run` now extracts actual exit codes from `RunAsUser` errors, fixing `isProcessRunning` false positives for AI frameworks.

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

[1.11.0]: https://github.com/step-security/dev-machine-guard/compare/v1.10.2...v1.11.0
[1.10.2]: https://github.com/step-security/dev-machine-guard/compare/v1.10.1...v1.10.2
[1.10.1]: https://github.com/step-security/dev-machine-guard/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/step-security/dev-machine-guard/compare/v1.9.2...v1.10.0
[1.9.2]: https://github.com/step-security/dev-machine-guard/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/step-security/dev-machine-guard/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/step-security/dev-machine-guard/compare/v1.8.2...v1.9.0
[1.8.2]: https://github.com/step-security/dev-machine-guard/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/step-security/dev-machine-guard/releases/tag/v1.8.1
