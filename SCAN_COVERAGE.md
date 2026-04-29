# StepSecurity Dev Machine Guard — Scan Coverage

This document catalogs everything Dev Machine Guard detects. Contributions to expand coverage are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## IDEs & AI Desktop Apps

| Application           | Vendor            | macOS Detection                          | Windows Detection                                        | Version Extraction                  |
|-----------------------|-------------------|------------------------------------------|----------------------------------------------------------|-------------------------------------|
| Visual Studio Code    | Microsoft         | `/Applications/Visual Studio Code.app`   | `%PROGRAMFILES%\Microsoft VS Code`                       | Binary `--version`                  |
| Cursor                | Cursor            | `/Applications/Cursor.app`               | `%LOCALAPPDATA%\Programs\cursor`                         | Binary `--version`                  |
| Windsurf              | Codeium           | `/Applications/Windsurf.app`             | `%LOCALAPPDATA%\Programs\Windsurf`                       | Binary `--version`                  |
| Antigravity           | Google            | `/Applications/Antigravity.app`          | `%LOCALAPPDATA%\Programs\Antigravity`                    | Binary `--version`                  |
| Zed                   | Zed               | `/Applications/Zed.app`                  | `%LOCALAPPDATA%\Zed`                                     | `Info.plist`                        |
| Claude Desktop        | Anthropic         | `/Applications/Claude.app`               | `%LOCALAPPDATA%\Programs\Claude`                         | `Info.plist` / Registry             |
| Microsoft Copilot     | Microsoft         | `/Applications/Copilot.app`              | `%LOCALAPPDATA%\Programs\Copilot`                        | `Info.plist` / Registry             |
| IntelliJ IDEA Ultimate| JetBrains         | `/Applications/IntelliJ IDEA.app`        | `%PROGRAMFILES%\JetBrains\IntelliJ IDEA <ver>`          | `product-info.json` / `Info.plist`  |
| IntelliJ IDEA CE      | JetBrains         | `/Applications/IntelliJ IDEA CE.app`     | `%PROGRAMFILES%\JetBrains\IntelliJ IDEA Community Edition <ver>` | `product-info.json` / `Info.plist`  |
| PyCharm Professional  | JetBrains         | `/Applications/PyCharm.app`              | `%PROGRAMFILES%\JetBrains\PyCharm <ver>`                 | `product-info.json` / `Info.plist`  |
| PyCharm CE            | JetBrains         | `/Applications/PyCharm CE.app`           | `%PROGRAMFILES%\JetBrains\PyCharm Community Edition <ver>` | `product-info.json` / `Info.plist`  |
| WebStorm              | JetBrains         | `/Applications/WebStorm.app`             | `%PROGRAMFILES%\JetBrains\WebStorm <ver>`                | `product-info.json` / `Info.plist`  |
| GoLand                | JetBrains         | `/Applications/GoLand.app`               | `%PROGRAMFILES%\JetBrains\GoLand <ver>`                  | `product-info.json` / `Info.plist`  |
| PhpStorm              | JetBrains         | `/Applications/PhpStorm.app`             | `%PROGRAMFILES%\JetBrains\PhpStorm <ver>`                | `product-info.json` / `Info.plist`  |
| CLion                 | JetBrains         | `/Applications/CLion.app`                | `%PROGRAMFILES%\JetBrains\CLion <ver>`                   | `product-info.json` / `Info.plist`  |
| Rider                 | JetBrains         | `/Applications/Rider.app`                | `%PROGRAMFILES%\JetBrains\JetBrains Rider <ver>`        | `product-info.json` / `Info.plist`  |
| RubyMine              | JetBrains         | `/Applications/RubyMine.app`             | `%PROGRAMFILES%\JetBrains\RubyMine <ver>`               | `product-info.json` / `Info.plist`  |
| DataGrip              | JetBrains         | `/Applications/DataGrip.app`             | `%PROGRAMFILES%\JetBrains\DataGrip <ver>`               | `product-info.json` / `Info.plist`  |
| Android Studio        | Google            | `/Applications/Android Studio.app`       | `%PROGRAMFILES%\Android\Android Studio`                  | `product-info.json` / `Info.plist`  |
| Eclipse IDE           | Eclipse Foundation| `/Applications/Eclipse.app`              | `%PROGRAMFILES%\eclipse`, `C:\eclipse`, `%USERPROFILE%\eclipse\*\eclipse` | `.eclipseproduct` / `Info.plist` |

## AI CLI Tools

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
| Cursor Agent          | Cursor    | `cursor-agent`              | `~/.cursor`                     |

## General-Purpose AI Agents

| Agent                 | Vendor    | Detection Paths             |
|-----------------------|-----------|-----------------------------|
| OpenClaw              | OpenSource| `~/.openclaw`               |
| ClawdBot              | OpenSource| `~/.clawdbot`               |
| MoltBot               | OpenSource| `~/.moltbot`                |
| MoldBot               | OpenSource| `~/.moldbot`                |
| GPT-Engineer          | OpenSource| `~/.gpt-engineer`           |
| Claude Cowork         | Anthropic | Claude Desktop v0.7.0+      |

## AI Frameworks & Runtimes

| Framework             | Binary    | Notes                       |
|-----------------------|-----------|-----------------------------|
| Ollama                | `ollama`  | Checks if process is running|
| LocalAI               | `local-ai`| Checks if process is running|
| LM Studio             | `lm-studio` or `/Applications/LM Studio.app` | GUI app detection |
| Text Generation WebUI | `textgen` | Checks if process is running|

## MCP Configuration Sources

| Source                | Config Path                                         | Vendor    |
|-----------------------|-----------------------------------------------------|-----------|
| Claude Desktop        | `~/Library/Application Support/Claude/claude_desktop_config.json` | Anthropic |
| Claude Code           | `~/.claude/settings.json`                           | Anthropic |
| Cursor                | `~/.cursor/mcp.json`                                | Cursor    |
| Windsurf              | `~/.codeium/windsurf/mcp_config.json`               | Codeium   |
| Antigravity           | `~/.gemini/antigravity/mcp_config.json`             | Google    |
| Zed                   | `~/.config/zed/settings.json`                       | Zed       |
| Open Interpreter      | `~/.config/open-interpreter/config.yaml`            | OpenSource|
| Codex                 | `~/.codex/config.toml`                              | OpenAI    |

## IDE Extensions & Plugins

| IDE              | Extensions/Plugins Directory                                                  | Format                        |
|------------------|-------------------------------------------------------------------------------|-------------------------------|
| VS Code          | `~/.vscode/extensions`                                                        | `publisher.name-version`      |
| Cursor           | `~/.cursor/extensions`                                                        | `publisher.name-version`      |
| JetBrains IDEs   | macOS: `~/Library/Application Support/JetBrains/<dataDir>/plugins/`           | `<name>/lib/<name>-version.jar` |
|                  | Windows: `%APPDATA%\JetBrains\<dataDir>\plugins\`                            |                               |

JetBrains plugin detection reads `product-info.json` from the IDE install path to resolve the `dataDirectoryName` (e.g., `GoLand2025.1`), then scans user-installed plugins. Only user-installed plugins are reported (bundled plugins in the install directory are excluded).

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
