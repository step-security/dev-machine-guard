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
| GitHub Copilot CLI    | Microsoft | `copilot`, `gh-copilot`†    | `~/.config/github-copilot`, `~/.copilot` |
| Microsoft AI Shell    | Microsoft | `aish`, `ai`                | `~/.aish`                       |
| Aider                 | OpenSource| `aider`                     | `~/.aider`                      |
| OpenCode              | OpenSource| `opencode`                  | `~/.config/opencode`            |
| Cursor Agent          | Cursor    | `cursor-agent`              | `~/.cursor`                     |
| Pi                    | Earendil  | `pi`                        | `~/.pi/agent`                   |
| Factory Droid         | Factory   | `droid`                     | `~/.factory`                    |
| Amp                   | Sourcegraph| `amp`                      | `~/.config/amp`                 |
| Grok Build            | xAI       | `grok`                      | `~/.grok`                       |
| Kimi Code             | Moonshot  | `kimi`                      | `~/.kimi-code`                  |
| Muse Code             | Meta      | `muse`                      | `~/.config/muse`                |
| Hermes Agent          | Nous Research | `hermes`                | `~/AppData/Local/hermes`, `~/.hermes` |
| Oh My Pi              | Stencil   | `omp`                       | `~/.omp/agent`                  |

† `gh copilot` launches this same `@github/copilot` CLI, downloading it into gh's own data directory when it isn't already on `$PATH` — so that install never lands on `$PATH`. After the two binary names miss, Copilot is also looked for at `~/.local/share/gh/copilot/copilot`, `~/.local/bin/copilot`, `~/AppData/Local/GitHub CLI/copilot/copilot`, `~/AppData/Local/Microsoft/WinGet/Links/copilot.exe`, `~/AppData/Roaming/npm/copilot.cmd`, and the `gh-copilot` extension directory under both `~/.local/share/gh/extensions` and `~/AppData/Local/GitHub CLI/extensions`. A non-default `$XDG_DATA_HOME` is not followed, and WinGet's hashed `Packages\GitHub.Copilot_<hash>\` payload directory is not globbed — only its `Links` shim.

Pi, Factory Droid, Amp, Grok Build, Kimi Code, Muse Code, Hermes Agent and Oh My Pi share their binary names with unrelated popular tools, so a `$PATH` hit alone does not report them — each is confirmed from an on-disk artifact (a package manifest, an installer anchor directory plus a corroborating sidecar, virtualenv or size floor, a Homebrew Cellar or cask root, a winget or pacman package entry), and is searched for in the common global-install prefixes (including mise's Oh My Pi install tree) as well as on `$PATH`. Of these eight, all but Factory Droid are never executed — macOS Gatekeeper prompts on their binaries — so their versions come from disk (a manifest, a versioned filename, a Python `dist-info` directory name, a Homebrew version segment) or are reported as `unknown`. Every winget-installed one reports `unknown`. No agent's config, auth, session or log files are read.

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

| Source             | macOS / Linux Path                                               | Windows Path (if different)                    | Vendor    |
|--------------------|------------------------------------------------------------------|------------------------------------------------|-----------|
| Claude Desktop     | `~/Library/Application Support/Claude/claude_desktop_config.json`| `%APPDATA%/Claude/claude_desktop_config.json`  | Anthropic |
| Claude Code        | `~/.claude/settings.json`                                        | _(same)_                                       | Anthropic |
| Claude Code        | `~/.claude.json`                                                 | _(same)_                                       | Anthropic |
| Cursor             | `~/.cursor/mcp.json`                                             | _(same)_                                       | Cursor    |
| Windsurf           | `~/.codeium/windsurf/mcp_config.json`                            | _(same)_                                       | Codeium   |
| Antigravity        | `~/.gemini/antigravity/mcp_config.json`                          | _(same)_                                       | Google    |
| Zed                | `~/.config/zed/settings.json`                                    | _(same)_                                       | Zed       |
| Open Interpreter   | `~/.config/open-interpreter/config.yaml`                         | _(same)_                                       | OpenSource|
| Codex              | `~/.codex/config.toml`                                           | _(same)_                                       | OpenAI    |
| OpenCode           | `~/.config/opencode/opencode.json` (and `.jsonc`)                | _(same)_                                       | OpenCode  |
| OpenCode (project) | `opencode.json` / `opencode.jsonc` in a project directory        | _(same)_                                       | OpenCode  |

## AI Agent Skills

Dev Machine Guard inventories every installed **agent skill** — a directory containing a `SKILL.md` manifest — across Claude Code, Codex, OpenCode, Cursor, Gemini CLI, GitHub Copilot, Pi, Factory, Amp, Grok Build (`~/.grok/skills`, `.grok/skills`), Kimi Code (`~/.kimi-code/skills`, `.kimi-code/skills`), Muse Code (`~/.config/muse/skills`), Hermes Agent (`~/.hermes/skills` or `%LOCALAPPDATA%\hermes\skills`, `.hermes/skills`), Oh My Pi (`~/.omp/agent/skills`, `~/.omp/agent/managed-skills`, `.omp/skills`), the cross-agent `~/.agents` convention, and skills installed via [skills.sh](https://skills.sh). It probes each agent's global, system, project, and plugin skill directories; skills.sh lock files add upstream provenance (joined by symlink-resolved path). Detection is pure filesystem reads (no subprocesses), bounded by a 60-second budget and per-root caps.

**Privacy: only metadata and a single SHA-256 hash of each `SKILL.md` are collected — no other file is ever read, and file contents are never transmitted.** The file census (counts, sizes, timestamps) comes entirely from directory listings and `stat`. For skills installed from a local path, the on-disk source path is never serialized — only the skill's alias.

Per skill, the scan records identity and frontmatter (name, description, version, license, allowed tools), capability flags (load-time shell execution, hooks, plugin manifest, subagent context), a stat-only file census, the `SKILL.md` hash, and — when lock-managed — upstream provenance.

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

## Browser Extensions

Extensions are read from the browsers' own state files under the logged-in user's home directory. On Linux, Firefox is also scanned under its snap and flatpak roots, and Edge under its flatpak root. A browser installed anywhere other than the paths below, including under a packaging not listed here or with a custom data directory, is reported as not present.

| Browser        | Engine   | macOS                                          | Windows                                  | Linux                   |
|----------------|----------|------------------------------------------------|------------------------------------------|-------------------------|
| Google Chrome  | Chromium | `~/Library/Application Support/Google/Chrome`   | `%LOCALAPPDATA%\Google\Chrome\User Data`  | `~/.config/google-chrome` |
| Microsoft Edge | Chromium | `~/Library/Application Support/Microsoft Edge`  | `%LOCALAPPDATA%\Microsoft\Edge\User Data` | `~/.config/microsoft-edge` |
| Mozilla Firefox | Gecko   | `~/Library/Application Support/Firefox`         | `%APPDATA%\Mozilla\Firefox`               | `~/.mozilla/firefox`    |

Per extension, the scan records identity (id, name, version, manifest version), enabled state and why it is disabled, where it was installed from, its store and listing status, signature state, and the permissions the browser is currently honouring for it.

**Privacy: only these state files are read. Browsing history, cookies, saved passwords, page content, and profile names are never collected.** No browser is launched and no extension store is contacted.

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

Python scanning detects installed packages and project virtual environments. Enable with `--enable-python-scan`. **No Python interpreter or package manager is executed** — packages are read from on-disk install metadata (`*.dist-info/METADATA` and `*.egg-info/PKG-INFO`, per PEP 376/627), so scanning never triggers a macOS install prompt. (The pre-1.13 command-based path is still available via `--legacy-python-scan` / `use_legacy_python_scan`.)

### Global / system packages

Discovered by walking a bounded set of Python **install trees** and recognizing package metadata anywhere beneath them. This is **independent of `search_dirs`**:

- **Frameworks (macOS):** Command Line Tools, Xcode, and python.org (`/Library/Frameworks/Python*.framework/…`). The `/usr/bin/python3` wrapper does not resolve into these, so they are found structurally.
- **Homebrew:** `/opt/homebrew/lib/python*`, `/opt/homebrew/Cellar/python*`.
- **System:** `/usr/local/lib/python*`; Linux `/usr/lib/python*`, `/usr/lib64/python*`.
- **Version managers:** pyenv, asdf, uv, rye, conda/mamba (base + named envs), pipx.
- **User site:** `~/.local/lib/python*`, and `~/Library/Python/*` on macOS.

### Project virtual environments

Discovered by scanning the **search directories** for virtual environments (`pyvenv.cfg`) and reading each venv's installed metadata. The default search directory is the user's **`$HOME`**; override with `--search-dirs` or the `search_dirs` config key.

### Coverage and limitations

**Covered by default:** global installs in the trees above (regardless of `search_dirs`), and project venvs anywhere under `$HOME` that is not TCC-protected.

**Not covered by default:**

- **TCC-protected user directories** — the project/venv walk skips `~/Documents`, `~/Desktop`, `~/Downloads`, and `~/Library` to avoid macOS permission prompts. (The macOS global user-site `~/Library/Python/*` is the exception: it is scanned as its own explicit global root, so global user-site packages are still covered.) A **project virtual environment** kept under one of these directories is missed unless `include_tcc_protected: true` is set **and** the agent has Full Disk Access (see [macos-tcc-permissions.md](docs/macos-tcc-permissions.md)).
- **Locations outside `$HOME`** — e.g. `/opt`, `/srv`, `/data`, `/Users/Shared`, or a separate repos volume. Add them via `search_dirs`.
- **Global interpreters at non-standard prefixes** not under any tree listed above. Add the prefix (or a parent) via `search_dirs`.

The set of global install roots scanned is logged once per scan at info level (full paths at debug), so field logs show exactly where the agent looked.

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
