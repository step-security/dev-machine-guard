# StepSecurity Dev Machine Guard — Community Mode

Community mode is the free, open-source way to run Dev Machine Guard locally on your macOS developer machine. All scanning happens on-device. **No data leaves your machine.**

> Back to [README](../README.md) | See also: [Reading Scan Results](reading-scan-results.md)

---

## Quick Start

```bash
git clone https://github.com/step-security/dev-machine-guard.git
cd dev-machine-guard
make build
./stepsecurity-dev-machine-guard
```

Or download a pre-built binary without cloning:

```bash
curl -sSL https://github.com/step-security/dev-machine-guard/releases/latest/download/stepsecurity-dev-machine-guard_darwin_arm64 -o stepsecurity-dev-machine-guard
chmod +x stepsecurity-dev-machine-guard
./stepsecurity-dev-machine-guard
```

---

## Output Formats

Dev Machine Guard supports three mutually exclusive output formats.

### Pretty Terminal Output (default)

```bash
./stepsecurity-dev-machine-guard
```

Pretty mode prints a styled, human-readable report directly to your terminal, including sections for Device information, Summary counts, AI Agents and Tools, IDEs and Desktop Apps, MCP Servers, and IDE Extensions.

### JSON Output

```bash
# Print JSON to stdout
./stepsecurity-dev-machine-guard --json

# Pipe through python for formatted output
./stepsecurity-dev-machine-guard --json | python3 -m json.tool

# Save to a file
./stepsecurity-dev-machine-guard --json > scan.json
```

JSON mode writes a single JSON object to stdout. This is useful for scripting, piping into other tools, or storing results for later analysis. See [Reading Scan Results](reading-scan-results.md) for the full schema reference.

### HTML Report

```bash
./stepsecurity-dev-machine-guard --html report.html
```

HTML mode generates a self-contained HTML file with a styled report. The report can be opened in any browser and is suitable for sharing with team leads or printing.

---

## Options

| Flag | Description |
|------|-------------|
| `--pretty` | Pretty terminal output (this is the default if no format is specified) |
| `--json` | JSON output to stdout |
| `--html FILE` | HTML report saved to FILE |
| `--verbose` | Show progress messages during the scan (suppressed by default) |
| `--color=WHEN` | Color mode: `auto` (default), `always`, or `never`. In `auto` mode, colors are used only when stdout is a terminal. |
| `--enable-npm-scan` | Enable Node.js package scanning (npm, yarn, pnpm, bun). Off by default in community mode because it can be slow on machines with many projects. |
| `--version` | Print the scanner version and exit |
| `--help` | Show the full usage help and exit |

---

## Examples

### Basic scan with pretty output

```bash
./stepsecurity-dev-machine-guard
```

Runs the scan and prints a styled report to the terminal. Progress messages are suppressed by default.

### Verbose scan to see what is happening

```bash
./stepsecurity-dev-machine-guard --verbose
```

Same as above, but progress messages (e.g., "Detecting IDE installations...", "Found: Cursor (Cursor) v0.50.1") are printed to stderr so you can follow along.

### JSON scan piped to jq

```bash
./stepsecurity-dev-machine-guard --json | jq '.ai_agents_and_tools[] | .name'
```

Extracts the name of every detected AI tool.

### JSON scan with npm packages included

```bash
./stepsecurity-dev-machine-guard --json --enable-npm-scan > full-scan.json
```

Produces a comprehensive JSON scan including globally installed npm/yarn/pnpm/bun packages and per-project dependency listings.

### HTML report without colors in progress messages

```bash
./stepsecurity-dev-machine-guard --html report.html --verbose --color=never
```

Generates an HTML report while showing progress messages without ANSI color codes (useful when piping stderr to a log file).

---

## Privacy

In community mode:

- **No data leaves your machine.** There is no backend, no API calls, no telemetry.
- The source code is fully open. You can audit exactly what it does.
- All output is written to stdout (JSON, pretty) or to a local file (HTML). Nothing is transmitted over the network.

If you need centralized visibility across a fleet of developer machines, [start a 14-day free trial](https://www.stepsecurity.io/start-free) by installing the StepSecurity GitHub App.

---

## Further Reading

- [Reading Scan Results](reading-scan-results.md) -- understand what each section and field means
- [Adding Detections](adding-detections.md) -- contribute new tool or IDE detections
- [SCAN_COVERAGE.md](../SCAN_COVERAGE.md) -- full catalog of supported detections
- [CONTRIBUTING.md](../CONTRIBUTING.md) -- how to contribute to the project
