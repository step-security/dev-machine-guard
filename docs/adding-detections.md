# StepSecurity Dev Machine Guard — Adding Detections

This guide walks you through adding new detections to Dev Machine Guard. Whether it is a new IDE, AI CLI tool, AI agent, or MCP config source, the process follows a consistent pattern.

> Back to [README](../README.md) | See also: [SCAN_COVERAGE.md](../SCAN_COVERAGE.md) | [CONTRIBUTING.md](../CONTRIBUTING.md)

---

## Overview

Dev Machine Guard uses array-driven detection. Each detection category has a function that iterates over a defined array of entries. To add a new detection, you add an entry to the appropriate array and (optionally) handle any special cases.

The detection code lives in the `internal/detector/` directory, with each detector category in its own `.go` file.

---

## 1. Adding a New IDE or Desktop App

### File: `internal/detector/ide.go`

### Format String

```
"App Name|type_id|Vendor|/Applications/App.app|Contents/MacOS/binary|--version"
```

| Field | Description |
|-------|-------------|
| App Name | Human-readable display name (e.g., "Visual Studio Code") |
| type_id | Unique identifier for the IDE type, used in JSON output (e.g., `vscode`, `cursor`, `zed`) |
| Vendor | The company or organization that makes the app (e.g., "Microsoft", "Cursor") |
| App path | Full path to the `.app` bundle in `/Applications/` |
| Binary path | Relative path (from the app bundle root) to the binary used for version extraction. Leave empty if version comes from `Info.plist`. |
| Version command | The CLI flag to get the version (e.g., `--version`). Leave empty if not applicable. |

### Example: Adding a hypothetical "CodeForge" IDE

Find the `apps` array inside the IDE detector and add:

```go
{
    Name:           "CodeForge",
    TypeID:         "codeforge",
    Vendor:         "CodeForge Inc",
    AppPath:        "/Applications/CodeForge.app",
    BinaryPath:     "Contents/MacOS/CodeForge",
    VersionCommand: "--version",
}
```

If the app stores its version in `Info.plist` instead of a CLI binary, leave the binary path and version command empty. The scanner will automatically fall back to reading `CFBundleShortVersionString` from `Info.plist`.

---

## 2. Adding a New AI CLI Tool

### File: `internal/detector/ai_cli.go`

### Format String

```
"tool-name|Vendor|binary1,binary2|~/.config-dir1,~/.config-dir2"
```

| Field | Description |
|-------|-------------|
| tool-name | Unique name for the tool, used in JSON output (e.g., `claude-code`, `codex`) |
| Vendor | The company or organization (e.g., "Anthropic", "OpenAI", "OpenSource") |
| binary_names | Comma-separated list of binary names to search for in PATH |
| config_dirs | Comma-separated list of config directory paths (use `~` for home directory) |

### Example: Adding a hypothetical "DevPilot" CLI

```go
{
    Name:       "devpilot",
    Vendor:     "DevPilot Inc",
    Binaries:   []string{"devpilot", "dp"},
    ConfigDirs: []string{"~/.devpilot", "~/.config/devpilot"},
}
```

The scanner will:
1. Check if `devpilot` or `dp` exists in the user's PATH
2. If found, run `devpilot --version` (or `dp --version`) to get the version
3. Check if `~/.devpilot` or `~/.config/devpilot` exists as a config directory

---

## 3. Adding a New AI Agent

### File: `internal/detector/agent.go`

### Format String

```
"agent-name|Vendor|/detection/path1,/detection/path2|binary1,binary2"
```

| Field | Description |
|-------|-------------|
| agent-name | Unique name for the agent (e.g., `openclaw`, `gpt-engineer`) |
| Vendor | The company or organization (e.g., "OpenSource", "Anthropic") |
| detection_paths | Comma-separated paths (directories or files) that indicate the agent is installed |
| binary_names | Comma-separated binary names for version extraction |

### Example: Adding a hypothetical "AutoDev" agent

```go
{
    Name:           "autodev",
    Vendor:         "AutoDev Inc",
    DetectionPaths: []string{"~/.autodev"},
    Binaries:       []string{"autodev"},
}
```

The scanner will:
1. Check if `~/.autodev` exists (directory or file)
2. If not found, check if `autodev` binary exists in PATH
3. If found either way, try to run `autodev --version` for version info

---

## 4. Adding a New MCP Config Source

### File: `internal/detector/mcp.go`

### Format String

```
"source_name|/path/to/config.json|Vendor"
```

| Field | Description |
|-------|-------------|
| source_name | Unique identifier for the source (e.g., `claude_desktop`, `cursor`) |
| config_path | Full path to the config file. Use `~` for the home directory. |
| Vendor | The company or organization (e.g., "Anthropic", "Cursor") |

### Example: Adding a hypothetical "CodeAssist" MCP config

```go
{
    Source:     "codeassist",
    ConfigPath: "~/.codeassist/mcp_config.json",
    Vendor:     "CodeAssist Inc",
}
```

The scanner will:
1. Check if the config file exists at the specified path
2. Read the file contents
3. In enterprise mode: filter to extract only server names and commands, then base64-encode
4. In community mode: display the server information locally

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
