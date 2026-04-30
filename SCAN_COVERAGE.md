# StepSecurity Dev Machine Guard — Scan Coverage

This document catalogs everything Dev Machine Guard detects. Contributions to expand coverage are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## IDEs & AI Desktop Apps

Detection uses platform-specific paths: `/Applications/*.app` on macOS, `%LOCALAPPDATA%` / `%PROGRAMFILES%` on Windows. Version is extracted from the CLI binary (`--version`), `Info.plist` (macOS), or the Windows Registry.

| Application        | Vendor    | macOS Path                              | Windows Path(s)                                                                 |
|--------------------|-----------|-----------------------------------------|---------------------------------------------------------------------------------|
| Visual Studio Code | Microsoft | `/Applications/Visual Studio Code.app`  | `%PROGRAMFILES%\Microsoft VS Code`, `%LOCALAPPDATA%\Programs\Microsoft VS Code` |
| Cursor             | Cursor    | `/Applications/Cursor.app`              | `%LOCALAPPDATA%\Programs\cursor`                                                |
| Windsurf           | Codeium   | `/Applications/Windsurf.app`            | `%LOCALAPPDATA%\Programs\Windsurf`                                              |
| Antigravity        | Google    | `/Applications/Antigravity.app`         | `%LOCALAPPDATA%\Programs\Antigravity`                                           |
| Zed                | Zed       | `/Applications/Zed.app`                 | `%LOCALAPPDATA%\Zed`                                                            |
| Claude Desktop     | Anthropic | `/Applications/Claude.app`              | `%LOCALAPPDATA%\Programs\Claude`                                                |
| Microsoft Copilot  | Microsoft | `/Applications/Copilot.app`             | `%LOCALAPPDATA%\Programs\Copilot`                                               |

## AI CLI Tools

Detection is cross-platform — binaries are located via `$PATH` lookup and home-relative config directories.

| Tool                  | Vendor    | Binary Names                | Config Directories              |
|-----------------------|-----------|-----------------------------|---------------------------------|
| Claude Code           | Anthropic | `claude`                    | `~/.claude`                     |
| Codex                 | OpenAI    | `codex`                     | `~/.codex`                      |
| Gemini CLI            | Google    | `gemini`                    | `~/.gemini`                     |
| Amazon Q / Kiro CLI   | Amazon    | `kiro-cli`, `kiro`, `q`     | `~/.q`, `~/.kiro`, `~/.aws/q`  |
| GitHub Copilot CLI    | Microsoft | `copilot`, `gh-copilot`     | `~/.config/github-copilot`      |
| Microsoft AI Shell    | Microsoft | `aish`, `ai`                | `~/.aish`                       |
| Aider                 | OpenSource| `aider`                     | `~/.aider`                      |
| OpenCode              | OpenSource| `opencode`                  | `~/.config/opencode`            |

## General-Purpose AI Agents

Detection is cross-platform — home-relative paths and `$PATH` lookups work on macOS, Windows, and Linux.

| Agent                 | Vendor    | Detection Paths             |
|-----------------------|-----------|-----------------------------|
| OpenClaw              | OpenSource| `~/.openclaw`               |
| ClawdBot              | OpenSource| `~/.clawdbot`               |
| MoltBot               | OpenSource| `~/.moltbot`                |
| MoldBot               | OpenSource| `~/.moldbot`                |
| GPT-Engineer          | OpenSource| `~/.gpt-engineer`           |
| Claude Cowork         | Anthropic | Claude Desktop v0.7.0+      |

## AI Frameworks & Runtimes

Binaries are found via `$PATH` lookup (cross-platform). LM Studio is additionally detected as a GUI application.

| Framework             | Binary     | Notes                                                                           |
|-----------------------|------------|---------------------------------------------------------------------------------|
| Ollama                | `ollama`   | Checks if process is running                                                    |
| LocalAI               | `local-ai` | Checks if process is running                                                    |
| LM Studio             | `lm-studio`| GUI: `/Applications/LM Studio.app` (macOS) or `%LOCALAPPDATA%\Programs\LM Studio` (Windows) |
| Text Generation WebUI | `textgen`  | Checks if process is running                                                    |

## MCP Configuration Sources

On Windows, `~` refers to the user's home directory (`%USERPROFILE%`). Claude Desktop uses a Windows-specific path via `%APPDATA%`.

| Source           | macOS / Linux Path                                               | Windows Path (if different)                    | Vendor    |
|------------------|------------------------------------------------------------------|------------------------------------------------|-----------|
| Claude Desktop   | `~/Library/Application Support/Claude/claude_desktop_config.json`| `%APPDATA%/Claude/claude_desktop_config.json`  | Anthropic |
| Claude Code      | `~/.claude/settings.json`                                        | _(same)_                                       | Anthropic |
| Claude Code      | `~/.claude.json`                                                 | _(same)_                                       | Anthropic |
| Cursor           | `~/.cursor/mcp.json`                                             | _(same)_                                       | Cursor    |
| Windsurf         | `~/.codeium/windsurf/mcp_config.json`                            | _(same)_                                       | Codeium   |
| Antigravity      | `~/.gemini/antigravity/mcp_config.json`                          | _(same)_                                       | Google    |
| Zed              | `~/.config/zed/settings.json`                                    | _(same)_                                       | Zed       |
| Open Interpreter | `~/.config/open-interpreter/config.yaml`                         | _(same)_                                       | OpenSource|
| Codex            | `~/.codex/config.toml`                                           | _(same)_                                       | OpenAI    |

## IDE Extensions

Extension directories are the same across macOS, Windows, and Linux (`~` is the user's home directory on all platforms).

| IDE         | Extensions Directory           | Format                        |
|-------------|--------------------------------|-------------------------------|
| VS Code     | `~/.vscode/extensions`         | `publisher.name-version`      |
| Cursor      | `~/.cursor/extensions`         | `publisher.name-version`      |

Each extension entry includes: ID, name, version, publisher, install date, and IDE type. Obsolete extensions (listed in `.obsolete`) are excluded.

## Node.js Package Scanning (Optional)

| Package Manager | Global Packages | Project Packages              |
|-----------------|-----------------|-------------------------------|
| npm             | `npm list -g`   | `npm ls --json` per project   |
| yarn            | `yarn global list` | `yarn list --json` per project |
| pnpm            | `pnpm list -g`  | `pnpm ls --json` per project  |
| bun             | N/A             | `bun pm ls` per project       |

Node.js scanning is **off by default** in community mode (it can be slow). Enable with `--enable-npm-scan`.

---

## Adding New Detections

Want to add detection for a new tool, IDE, or framework? See [docs/adding-detections.md](docs/adding-detections.md) or open a [New Detection issue](.github/ISSUE_TEMPLATE/new_detection.yml).
