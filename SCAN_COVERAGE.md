# StepSecurity Dev Machine Guard — Scan Coverage

This document catalogs everything Dev Machine Guard detects. Contributions to expand coverage are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## IDEs & AI Desktop Apps

Detection uses platform-specific paths: `/Applications/*.app` on macOS, `%LOCALAPPDATA%`/`%PROGRAMFILES%` on Windows, `/opt`/`/usr/share`/`/snap` and `.desktop` file discovery on Linux. Version is extracted from the CLI binary (`--version`), `Info.plist` (macOS), `product-info.json` (JetBrains), `.eclipseproduct` (Eclipse), or the Windows Registry.

| Application            | Vendor             | macOS Detection                          | Windows Detection                                                | Linux Detection                          |
|------------------------|--------------------|------------------------------------------|------------------------------------------------------------------|------------------------------------------|
| Visual Studio Code     | Microsoft          | `/Applications/Visual Studio Code.app`   | `%PROGRAMFILES%\Microsoft VS Code`                               | `/usr/share/code`, `/snap/code`, LookPath |
| Cursor                 | Cursor             | `/Applications/Cursor.app`               | `%LOCALAPPDATA%\Programs\cursor`                                 | LookPath, `.desktop` files               |
| Windsurf               | Codeium            | `/Applications/Windsurf.app`             | `%LOCALAPPDATA%\Programs\Windsurf`                               | LookPath, `.desktop` files               |
| Antigravity            | Google             | `/Applications/Antigravity.app`          | `%LOCALAPPDATA%\Programs\Antigravity`                            | LookPath, `.desktop` files               |
| Zed                    | Zed                | `/Applications/Zed.app`                  | `%LOCALAPPDATA%\Zed`                                             | LookPath, `.desktop` files               |
| Claude Desktop         | Anthropic          | `/Applications/Claude.app`               | `%LOCALAPPDATA%\Programs\Claude`                                 | LookPath, `.desktop` files               |
| Microsoft Copilot      | Microsoft          | `/Applications/Copilot.app`              | `%LOCALAPPDATA%\Programs\Copilot`                                | LookPath, `.desktop` files               |
| IntelliJ IDEA Ultimate | JetBrains          | `/Applications/IntelliJ IDEA.app`        | `%PROGRAMFILES%\JetBrains\IntelliJ IDEA <ver>`                  | `/opt/idea-IU-*`, LookPath              |
| IntelliJ IDEA CE       | JetBrains          | `/Applications/IntelliJ IDEA CE.app`     | `%PROGRAMFILES%\JetBrains\IntelliJ IDEA Community Edition <ver>` | `/opt/idea-IC-*`, LookPath              |
| PyCharm Professional   | JetBrains          | `/Applications/PyCharm.app`              | `%PROGRAMFILES%\JetBrains\PyCharm <ver>`                         | `/opt/pycharm-*`, LookPath              |
| PyCharm CE             | JetBrains          | `/Applications/PyCharm CE.app`           | `%PROGRAMFILES%\JetBrains\PyCharm Community Edition <ver>`       | `/opt/pycharm-community-*`, LookPath    |
| WebStorm               | JetBrains          | `/Applications/WebStorm.app`             | `%PROGRAMFILES%\JetBrains\WebStorm <ver>`                        | `/opt/webstorm-*`, LookPath             |
| GoLand                 | JetBrains          | `/Applications/GoLand.app`               | `%PROGRAMFILES%\JetBrains\GoLand <ver>`                          | `/opt/goland-*`, LookPath               |
| PhpStorm               | JetBrains          | `/Applications/PhpStorm.app`             | `%PROGRAMFILES%\JetBrains\PhpStorm <ver>`                        | `/opt/phpstorm-*`, LookPath             |
| CLion                  | JetBrains          | `/Applications/CLion.app`                | `%PROGRAMFILES%\JetBrains\CLion <ver>`                           | `/opt/clion-*`, LookPath                |
| Rider                  | JetBrains          | `/Applications/Rider.app`                | `%PROGRAMFILES%\JetBrains\JetBrains Rider <ver>`                | `/opt/rider-*`, LookPath                |
| RubyMine               | JetBrains          | `/Applications/RubyMine.app`             | `%PROGRAMFILES%\JetBrains\RubyMine <ver>`                       | `/opt/rubymine-*`, LookPath             |
| DataGrip               | JetBrains          | `/Applications/DataGrip.app`             | `%PROGRAMFILES%\JetBrains\DataGrip <ver>`                       | `/opt/datagrip-*`, LookPath             |
| Fleet                  | JetBrains          | `/Applications/Fleet.app`                | `%LOCALAPPDATA%\Programs\Fleet`                                  | LookPath, `.desktop` files               |
| Android Studio         | Google             | `/Applications/Android Studio.app`       | `%PROGRAMFILES%\Android\Android Studio`                          | `/opt/android-studio`, LookPath         |
| Eclipse IDE            | Eclipse Foundation | `/Applications/Eclipse.app`              | `%PROGRAMFILES%\eclipse`, `C:\eclipse`, `%USERPROFILE%\eclipse`  | LookPath, `.desktop` files               |

JetBrains Windows paths use glob patterns to match version-numbered directories (e.g., `IntelliJ IDEA 2024.3.2`). On Linux, IDEs are also discovered via `.desktop` files in XDG directories (`~/.local/share/applications`, `/usr/share/applications`, etc.).

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
| Cursor Agent          | Cursor    | `cursor-agent`              | `~/.cursor`                     |

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

## IDE Extensions & Plugins

### VS Code-Family Extensions

Extension directories are cross-platform (`~` is the user's home directory on all platforms). Extensions are parsed from directory names in `publisher.name-version` format. Obsolete extensions (listed in `.obsolete`) are excluded.

| IDE          | Extensions Directory              |
|--------------|-----------------------------------|
| VS Code      | `~/.vscode/extensions`            |
| Cursor       | `~/.cursor/extensions`            |
| Windsurf     | `~/.windsurf/extensions`          |
| Antigravity  | `~/.antigravity/extensions`       |

Each extension entry includes: ID, name, version, publisher, install date, and IDE type.

### JetBrains Plugins

JetBrains plugin detection reads `product-info.json` from the IDE install path to resolve the `dataDirectoryName` (e.g., `GoLand2025.1`), then scans user-installed plugins. Plugin metadata is extracted from `META-INF/plugin.xml` (or from JAR files in the `lib/` directory).

| Platform | User Plugin Config Path                                          |
|----------|------------------------------------------------------------------|
| macOS    | `~/Library/Application Support/JetBrains/<dataDir>/plugins/`     |
| Windows  | `%APPDATA%\JetBrains\<dataDir>\plugins\`                        |
| Linux    | `~/.config/JetBrains/<dataDir>/plugins/`                         |

Android Studio uses the same mechanism with a different config path: `~/Library/Application Support/Google/AndroidStudio*/plugins/` (macOS), `%APPDATA%\Google\AndroidStudio*\plugins\` (Windows).

Only user-installed plugins are reported by default. Use `--include-bundled-plugins` to include bundled plugins.

### Eclipse Plugins

| Platform | Detection Method                                                                |
|----------|---------------------------------------------------------------------------------|
| macOS    | Scans `features/` and `dropins/` within the Eclipse app bundle                  |
| Windows  | Multi-stage: detected IDE paths, well-known paths, registry, drive letter probes; validates with `.ini` + `plugins/` + `configuration/`; uses p2 director and `bundles.info` for feature lists |

Plugins are classified as `bundled`, `marketplace`, or `dropins` based on their location and bundle ID prefix.

### Xcode Extensions (macOS only)

Discovered via `pluginkit -mAD -p com.apple.dt.Xcode.extension.source-editor`. Returns bundle ID, version, and publisher for Xcode Source Editor extensions.

## Node.js Package Scanning (Optional)

| Package Manager | Global Packages | Project Packages              |
|-----------------|-----------------|-------------------------------|
| npm             | `npm list -g`   | `npm ls --json` per project   |
| yarn            | `yarn global list` | `yarn list --json` per project |
| pnpm            | `pnpm list -g`  | `pnpm ls --json` per project  |
| bun             | N/A             | `bun pm ls` per project       |

Node.js scanning is **off by default** in community mode (it can be slow). Enable with `--enable-npm-scan`.

## Homebrew Package Scanning (Optional)

Homebrew scanning detects installed formulae and casks with rich metadata. Enable with `--enable-brew-scan`.

| Data           | Source                                          |
|----------------|-------------------------------------------------|
| Formulae       | `brew info --json=v2 --installed` (preferred), fallback to `INSTALL_RECEIPT.json` in Cellar |
| Casks          | `brew info --json=v2 --installed` (preferred), fallback to `INSTALL_RECEIPT.json` in Caskroom |

**Metadata per package:** name, version, tap (source), description, license, homepage, install time, installed-as-dependency flag, deprecated flag, poured-from-bottle flag, auto-updates (casks).

## Python Package Scanning (Optional)

Python scanning detects package managers, globally installed packages, and project virtual environments. Enable with `--enable-python-scan`.

| Package Manager | Version Detection        | Global Packages              |
|-----------------|--------------------------|------------------------------|
| python3         | `python3 --version`      | —                            |
| pip3            | `pip3 --version`         | `pip3 list --format json`    |
| poetry          | `poetry --version`       | —                            |
| pipenv          | `pipenv --version`       | —                            |
| uv              | `uv --version`           | `uv pip list --format json`  |
| conda           | `conda --version`        | `conda list --json`          |
| rye             | `rye --version`          | —                            |

**Project detection:** Discovers `pyproject.toml`, `setup.py`, and `requirements.txt` patterns in search directories.

## System Package Scanning (Linux)

System package scanning is **automatic on Linux** — no opt-in flag required. Multiple package managers can coexist.

| Package Manager | Distributions                          | Rich Metadata                                                                 |
|-----------------|----------------------------------------|-------------------------------------------------------------------------------|
| rpm             | Fedora, RHEL, CentOS, SUSE, Amazon    | Name, version, arch, install time, source RPM, vendor, packager, URL, license, build time, size, signature |
| dpkg            | Debian, Ubuntu, Mint, Pop!_OS          | Package, version, arch, source, maintainer, origin, section, installed size   |
| pacman          | Arch, Manjaro, EndeavourOS             | Name, version, arch, URL, license, packager, build/install date, size, validation |
| apk             | Alpine Linux                           | Name, version, arch, URL, license, origin, maintainer, build time, commit hash, size |

### Snap Packages

Detected if `snap` is installed. Metadata: name, version, revision, tracking channel, publisher, confinement (strict/classic/devmode).

### Flatpak Packages

Detected if `flatpak` is installed. Metadata: app ID, name, version, arch, branch, origin, active commit, runtime.

---

## Adding New Detections

Want to add detection for a new tool, IDE, or framework? See [docs/adding-detections.md](docs/adding-detections.md) or open a [New Detection issue](.github/ISSUE_TEMPLATE/new_detection.yml).
