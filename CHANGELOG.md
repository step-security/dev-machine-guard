# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

See [VERSIONING.md](VERSIONING.md) for why the version starts at 1.8.1.

## [1.13.0] - 2026-07-08

### Added

- **Device policy enforcement**: the agent now applies device policy profiles fetched from run-config, including OS-native enforcement of a VS Code extension allowlist. Policy identity is target-aware (category + target) and on-device state is keyed by category; state files written by a newer schema version are rejected.
- **Classic Visual Studio detection**: scans now discover classic Visual Studio installs and their extensions.
- **Disk-based package scanning**: npm packages are discovered by parsing lockfiles and Python packages by reading `dist-info` metadata on disk, so package inventory no longer depends solely on invoking the package manager.
- **Run-on-login scheduling and scheduler diagnostics**: scans can be scheduled to run on login, Windows Task Scheduler history is enabled, and a new scheduler-info subsystem reports cross-platform scheduling state for troubleshooting.
- **Last-run heartbeat**: a `last-run.json` heartbeat is written at the start of telemetry send, and this run's loader-script logs are included in telemetry.
- **Scan-state delta upload protocol**: infrastructure to upload only package add/remove deltas between runs (opt-in; disabled by default).

### Changed

- **Legacy package scan remains the default**: the scan-state delta protocol is gated off by default; `use_legacy_package_scan` controls the legacy full-inventory path.
- **schtasks frequencies of 24h+ now use a DAILY schedule** instead of a minute-interval trigger.
- **Go toolchain bumped to 1.26.**
- **Lock-acquisition contention** is now logged and reported at info level.

### Fixed

- **Node package-manager version resolution**: PM versions are resolved via default install paths, and `NodeScanner.pmAvailability` access is guarded by a mutex.
- **Scan cap and delta gating**: disk-discovered packages now count toward the scan cap, and delta upload is gated on a resolved PM version.
- **Lock failures** are no longer assumed to indicate contention.
- **IDE policy under SYSTEM**: the installer no longer enforces IDE policy inline when running as SYSTEM.
- **Device policy source**: policy is fetched from run-config; the removed effective-policy endpoint is no longer called.
- **scan-state persistence**: scan-state is written to the `--telemetry-out` path when specified.

## [1.12.0] - 2026-06-09

### Added

- **Malicious-file detection**: new rules-engine scanner that flags suspicious files as IOCs and wires the results into scan telemetry. The detector streams one file at a time to keep scan memory bounded regardless of repository size.
- **pnpm configuration inventory**: scans now surface the contents of pnpm configuration.
- **bun configuration inventory**: scans now surface `bunfig.toml` configuration.
- **yarn configuration inventory**: scans now surface both yarn classic and yarn berry configuration.

### Changed

- **pnpm/bun/yarn audits enabled by default**: the agent now runs all three audits on every scan and emits `pnpm_audit`, `bun_audit`, and `yarn_audit` on the wire payload (gated via rc-config feature gates).
- **npm and pip rc-config scanning enabled by default**.
- **macOS service management**: the agent now uses `launchctl bootstrap`/`bootout` instead of the deprecated `load`/`unload`.

### Fixed

- **pnpm path resolution**: corrected pnpm path handling on both Linux and Windows.
- **Package-manager resolution under launchd**: package managers are now resolved correctly under the LaunchAgent's stripped `PATH`.
- **Shell quoting in `RunAsUser`**: command and argument quoting is now handled correctly when executing as the target user.
- **Windows empty payloads**: empty payloads are handled gracefully when npm is not present.
- **launchd failures surfaced**: `bootstrap`/`bootout` failures are now reported instead of silently swallowed.
- **brew raw scan output**: raw scan output is now synthesized from the rich brew data.

## [1.11.7] - 2026-05-31

### Added

- **Antigravity IDE detection**: scans now recognize the Antigravity editor.
- **Bounded scan execution**: scans are now capped by a global deadline (60m default; override via `STEPSEC_MAX_SCAN_DURATION`, or `0` to disable) plus per-phase deadlines, so a single stuck phase no longer hangs the whole run. Subprocesses are killed by process group on cancel, preventing forked grandchildren (Electron `--version`, npm/yarn/pnpm `ls`) from blocking on inherited file descriptors.
- **Log tail in heartbeat**: heartbeats now carry a gzipped+base64 tail of recent stderr (throttled), and log capture uses a bounded ring buffer to cap memory on long runs, surfacing where a scan is stuck.

### Fixed

- **`api_endpoint` trailing slash**: configured `api_endpoint` values are now normalized to strip trailing slashes at the config boundary, avoiding malformed `//v1/...` URLs that some gateways reject with 403/500.
- **pip detection triggering CLT install dialog**: pip detection no longer invokes a command that could pop the macOS Command Line Tools install dialog.
- **macOS IDE pop-ups and stuck processes**: macOS scans are further hardened against IDE permission pop-ups and processes that never exit.
- **Execution-watchdog limit via config**: the execution-watchdog limit is now delivered through `config.json`.

## [1.11.6] - 2026-05-27

### Fixed

- **macOS Tahoe Media Library prompt**: the project walker now skips `~/Library` wholesale instead of curating individual TCC-protected subpaths. This prevents new TCC prompts (e.g. `kTCCServiceMediaLibrary` from `~/Library/Application Support/com.apple.avfoundation/`) from firing after each macOS release adds Apple-managed subtrees behind new TCC services. Targeted detectors that read specific files under `~/Library` (JetBrains plugins, Claude desktop MCP config, pip global config) keep working unchanged.

## [1.11.5] - 2026-05-27

### Added

- **macOS TCC-protected directory skipping**: scanners now skip TCC-protected paths (Photos, Media Library, App Management, etc.) by default when running under launchd, avoiding spurious permission prompts and noisy denials. Hits are logged so operators can see which paths were skipped.
- **PPPC configuration guide**: new docs explain how to grant the agent the necessary TCC permissions via a PPPC profile for environments that want full coverage.
- **`verify-msi.ps1` script**: client-side PowerShell script for verifying the integrity and Authenticode signature of distributed MSI artifacts.

### Fixed

- **Empty `--install-dir` rejected**: install/uninstall commands now reject an empty `--install-dir` value instead of silently falling back to a default, preventing accidental installs to the wrong location.
- **`install_dir` config field is authoritative**: the configured `install_dir` is now treated as the source of truth across install/uninstall paths, resolving inconsistencies when the field disagreed with runtime defaults.

## [1.11.4] - 2026-05-26

### Added

- **Authenticode-signed Windows binaries and MSIs**: release artifacts are now signed via Azure Trusted Signing, so installs no longer trip SmartScreen/EDR unsigned-binary heuristics on Windows.
- **Feature gate for selective scanning**: new feature-gate mechanism allows disabling or enabling individual scanners at runtime, giving operators a way to scope what a deployment reports without rebuilding.
- **Invocation method + in-flight status reporting**: telemetry now records how the agent was invoked (launchd / systemd / scheduled task / interactive) and emits structured per-phase status info while a scan is running.
- **`$HOME` expansion in configured paths**: path-style config values now expand `$HOME` (and `~`) consistently across platforms.

### Fixed

- **Windows console window flashes during scheduled scans**: the scheduled task no longer pops a visible console window on each run.
- **Telemetry post-phase is non-blocking**: post-phase telemetry submission can no longer stall scan completion if the backend is slow or unreachable; sandbox invocation tests added to cover the path.
- **Canonicalised `$HOME`/`~` expansion**: path expansion now goes through `filepath.Join` so the resulting paths are normalised across `/`-vs-`\` and trailing-separator edge cases.

### Changed

- **Per-phase telemetry sub-progress incl. upload phase**: progress reporting now tracks sub-progress within each phase and adds an explicit upload phase, giving the dashboard finer-grained visibility into long-running scans.
- **CI: on-demand test-binary + MSI workflow** added so non-release builds can be produced from a PR without cutting a tag.
- **CI: msi-smoke workflow hardened** following StepSecurity best-practice review.

## [1.11.3] - 2026-05-21

### Added

- **AI agent hook state polling**: agents periodically check the StepSecurity backend for desired hook enable/disable state and reconcile local installation to match. Silent no-op in community mode; failures are logged but never crash the scanner.
- **Static machine resource info in device payload**: each scan now reports CPU model and count, total RAM, and disk capacity for the scanned host, giving the dashboard a clearer picture of the endpoint context.
- **Configurable install directory + persistent stderr logs**: new `--install-dir` flag (and matching env var/config field) relocates all non-bootstrap agent state, and stderr is now captured to a rotated `agent.error.log` under the install dir so MDM/service deployments have durable diagnostics (#88).

### Fixed

- **Auto-update signing**: fixed a signing regression in the previous 1.11.2 release that prevented auto-update from working. v1.11.2 has been removed; install or upgrade to 1.11.3 directly.
- **Windows scheduled task user context**: the scheduled task now runs under the logged-in user via `/ru INTERACTIVE` instead of `SYSTEM`, so the scanner can read `HKCU`, `%USERPROFILE%`, and the user's `PATH` — fixing a class of missed detections for tools installed in user scope.
- **Windows agent log directory permissions**: `C:\ProgramData\StepSecurity` now grants `BUILTIN\Users` Modify rights so the scheduled task (running as the logged-in user) can append to `agent.log` instead of failing with Access Denied.
- **AI agent hook command path on Windows**: hook entries written into agent config files now use forward-slash paths, avoiding Windows shell quoting issues that could prevent the hook from firing.
- **pnpm v11 global scan regression**: globally installed pnpm packages were missing from the npm scan output on pnpm v11; detection logic updated for the new layout.
- **Linux/macOS lock contention race**: an edge case where the singleton-lock check could misidentify the console user on systems with no active interactive session is fixed.

### Changed

- **CI: gosec SAST scan** added to the workflow set, with a corresponding badge in the README.
- **CI: cross-platform build + vet/fmt/tidy** checks added to the Tests workflow, surfacing platform-specific compile errors at PR time instead of at release time.

## [1.11.1] - 2026-05-05

### Added

- **Install path in scan output**: Installed packages and IDE extensions now report their on-disk install location alongside name and version. Covers Homebrew formulae and casks, JetBrains/Eclipse/Xcode/VS Code-family extensions, and Linux snap and flatpak system packages.

### Fixed

- **IDE and AI CLI detection through symlinks**: Tools installed or invoked via symlinks (for example, Homebrew shims or user-managed aliases) are now resolved to their real install path so they are detected and reported correctly instead of being missed or duplicated.
- **Windows AI CLI detection on relative PATH entries**: AI CLI detection on Windows no longer fails when `PATH` contains relative directory entries — these are resolved before the binary probe runs.

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

[1.13.0]: https://github.com/step-security/dev-machine-guard/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/step-security/dev-machine-guard/compare/v1.11.7...v1.12.0
[1.11.7]: https://github.com/step-security/dev-machine-guard/compare/v1.11.6...v1.11.7
[1.11.6]: https://github.com/step-security/dev-machine-guard/compare/v1.11.5...v1.11.6
[1.11.5]: https://github.com/step-security/dev-machine-guard/compare/v1.11.4...v1.11.5
[1.11.4]: https://github.com/step-security/dev-machine-guard/compare/v1.11.3...v1.11.4
[1.11.3]: https://github.com/step-security/dev-machine-guard/compare/v1.11.1...v1.11.3
[1.11.1]: https://github.com/step-security/dev-machine-guard/compare/v1.11.0...v1.11.1
[1.11.0]: https://github.com/step-security/dev-machine-guard/compare/v1.10.2...v1.11.0
[1.10.2]: https://github.com/step-security/dev-machine-guard/compare/v1.10.1...v1.10.2
[1.10.1]: https://github.com/step-security/dev-machine-guard/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/step-security/dev-machine-guard/compare/v1.9.2...v1.10.0
[1.9.2]: https://github.com/step-security/dev-machine-guard/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/step-security/dev-machine-guard/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/step-security/dev-machine-guard/compare/v1.8.2...v1.9.0
[1.8.2]: https://github.com/step-security/dev-machine-guard/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/step-security/dev-machine-guard/releases/tag/v1.8.1
