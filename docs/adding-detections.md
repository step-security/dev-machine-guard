# StepSecurity Dev Machine Guard — Adding Detections

This guide walks you through adding new detections to Dev Machine Guard. Whether it is a new IDE, AI CLI tool, AI agent, or MCP config source, the process follows a consistent pattern.

> Back to [README](../README.md) | See also: [SCAN_COVERAGE.md](../SCAN_COVERAGE.md) | [CONTRIBUTING.md](../CONTRIBUTING.md)

---

## Overview

Dev Machine Guard uses array-driven detection. Each detection category has a function that iterates over a defined array of entries. To add a new detection, you add an entry to the appropriate array and (optionally) handle any special cases.

The detection code lives in the `internal/detector/` directory, with each detector category in its own `.go` file.

**Cross-platform note:** Detections should work on both macOS and Windows. CLI tools and agents use `$PATH` lookups and home-relative paths, which are inherently cross-platform. IDE/desktop app detections need explicit macOS (`AppPath`) and Windows (`WinPaths`) entries. The `executor.Executor` interface abstracts OS operations and is used by all detectors.

---

## 1. Adding a New IDE or Desktop App

### File: `internal/detector/ide.go`

The IDE detector uses an `ideSpec` struct with platform-specific fields:

| Field | Description |
|-------|-------------|
| `AppName` | Human-readable display name (e.g., "Visual Studio Code") |
| `IDEType` | Unique identifier for JSON output (e.g., `vscode`, `cursor`, `zed`) |
| `Vendor` | The company or organization (e.g., "Microsoft", "Cursor") |
| `AppPath` | macOS: full path to the `.app` bundle in `/Applications/` |
| `BinaryPath` | macOS: relative path from the app bundle to the CLI binary for version extraction |
| `WinPaths` | Windows: candidate install directories (may contain `%ENVVAR%` patterns) |
| `WinBinary` | Windows: binary name relative to the install directory |
| `VersionFlag` | CLI flag to get the version (e.g., `--version`). Leave empty if not applicable. |

### Example: Adding a hypothetical "CodeForge" IDE

Find the `ideDefinitions` array in `ide.go` and add:

```go
{
    AppName: "CodeForge", IDEType: "codeforge", Vendor: "CodeForge Inc",
    AppPath: "/Applications/CodeForge.app", BinaryPath: "Contents/MacOS/CodeForge",
    WinPaths: []string{`%LOCALAPPDATA%\Programs\CodeForge`}, WinBinary: "CodeForge.exe",
    VersionFlag: "--version",
},
```

**macOS detection** checks if `AppPath` exists, then tries `BinaryPath --version`, falling back to `Info.plist` (`CFBundleShortVersionString`).

**Windows detection** iterates `WinPaths`, resolves `%ENVVAR%` patterns, checks if the directory exists, then tries `WinBinary --version`, falling back to Windows Registry (`DisplayVersion` under Uninstall keys).

---

## 2. Adding a New AI CLI Tool

### File: `internal/detector/aicli.go`

The CLI tool detector uses a `cliToolSpec` struct:

| Field | Description |
|-------|-------------|
| `Name` | Unique name for the tool, used in JSON output (e.g., `claude-code`, `codex`) |
| `Vendor` | The company or organization (e.g., "Anthropic", "OpenAI", "OpenSource") |
| `Binaries` | Binary names to search for in `$PATH`, or home-relative paths (use `~` prefix) |
| `ConfigDirs` | Config directory paths to check (use `~` for home directory) |
| `VersionFlag` | Override the default `--version` flag (e.g., `-v`) |
| `VerifyFunc` | Optional function to verify the binary is the correct tool (e.g., for generic names like `q`) |

### Example: Adding a hypothetical "DevPilot" CLI

```go
{
    Name:       "devpilot",
    Vendor:     "DevPilot Inc",
    Binaries:   []string{"devpilot", "dp"},
    ConfigDirs: []string{"~/.devpilot", "~/.config/devpilot"},
},
```

The scanner will:
1. Check if `devpilot` or `dp` exists in the user's PATH (cross-platform)
2. If found, run `devpilot --version` (or `dp --version`) to get the version
3. Check if `~/.devpilot` or `~/.config/devpilot` exists as a config directory

Home-relative binary paths (e.g., `~/.claude/local/claude`) are checked by file existence. On Windows, `.exe` suffixes are tried automatically.

---

## 3. Adding a New AI Agent

### File: `internal/detector/agent.go`

The agent detector uses an `agentSpec` struct:

| Field | Description |
|-------|-------------|
| `Name` | Unique name for the agent (e.g., `openclaw`, `gpt-engineer`) |
| `Vendor` | The company or organization (e.g., "OpenSource", "Anthropic") |
| `DetectionPaths` | Home-relative paths (directories or files) that indicate the agent is installed |
| `Binaries` | Binary names for `$PATH` lookup and version extraction |

### Example: Adding a hypothetical "AutoDev" agent

```go
{"autodev", "AutoDev Inc", []string{".autodev"}, []string{"autodev"}},
```

The scanner will (cross-platform):
1. Check if `~/.autodev` exists (directory or file)
2. If not found, check if `autodev` binary exists in PATH
3. If found either way, try to run `autodev --version` for version info

---

## 4. Adding a New MCP Config Source

### File: `internal/detector/mcp.go`

The MCP detector uses an `mcpConfigSpec` struct:

| Field | Description |
|-------|-------------|
| `SourceName` | Unique identifier for the source (e.g., `claude_desktop`, `cursor`) |
| `ConfigPath` | macOS/Linux config file path. Use `~` for the home directory. |
| `WinConfigPath` | Windows-specific config path (if different). Use `%ENVVAR%` patterns. Leave empty to use `ConfigPath` on all platforms. |
| `Vendor` | The company or organization (e.g., "Anthropic", "Cursor") |

### Example: Adding a hypothetical "CodeAssist" MCP config

```go
{"codeassist", "~/.codeassist/mcp_config.json", "", "CodeAssist Inc"},
```

If the tool uses a different path on Windows:

```go
{"codeassist", "~/.codeassist/mcp_config.json", "%APPDATA%/CodeAssist/mcp_config.json", "CodeAssist Inc"},
```

The scanner will:
1. Check if the config file exists at the platform-appropriate path
2. Read the file contents
3. In enterprise mode: Go-native filter extracts only server names, commands, args, and URLs from JSON configs, then base64-encodes the result
4. In community mode: display the server source, vendor, and config path

---

## 5. Testing Your Changes Locally

After making changes, build and test locally with all three output formats:

```bash
# Build the binary
make build

# Pretty output with progress messages
./stepsecurity-dev-machine-guard --verbose

# JSON output (validate it is well-formed)
./stepsecurity-dev-machine-guard --json | python3 -m json.tool

# HTML report
./stepsecurity-dev-machine-guard --html test-report.html
```

### Run the linter and tests

The CI pipeline runs `golangci-lint` and tests on every PR. Run them locally before submitting:

```bash
make lint
make test
make smoke
```

### Verify your new detection appears

1. If possible, install the tool you are adding detection for.
2. Run the scanner with `--verbose` to see progress messages.
3. Look for "Found: [your-tool-name]" in the progress output.
4. Verify the tool appears in the correct section of the output.

### If you do not have the tool installed

You can still verify your detection is correct by:
1. Creating a test directory or dummy binary that matches the detection path
2. Running the scanner against it
3. Cleaning up after testing

---

## 6. Updating Documentation

After adding a new detection, update the following:

- **[SCAN_COVERAGE.md](../SCAN_COVERAGE.md)** -- add your new detection to the appropriate table
- **[README.md](../README.md)** -- update the "What It Detects" table if applicable

---

## Submitting Your Contribution

1. Fork the repository
2. Create a feature branch: `git checkout -b add-detection-codeforge`
3. Make your changes
4. Test locally (all three output formats)
5. Run `make lint` and `make test`
6. Submit a PR using the [PR template](https://github.com/step-security/dev-machine-guard/blob/main/.github/pull_request_template.md)

See [CONTRIBUTING.md](../CONTRIBUTING.md) for full contribution guidelines.
