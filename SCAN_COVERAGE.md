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
| Kiro                   | Amazon             | `/Applications/Kiro.app`‡                | `%LOCALAPPDATA%\Programs\Kiro`‡                                  | `/usr/share/kiro`‡                              |
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
| Kiro CLI              | Amazon    | `kiro-cli`, `kiro`, `q`§    | `~/.q`, `~/.kiro`, `~/.aws/q`  |
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

‡ Kiro IDE is detected only at those exact roots, and only when the root itself proves it is Kiro: macOS requires the bundle identifier `dev.kiro.desktop` in `Info.plist` (read in-process) plus the shipped CLI shim `Contents/Resources/app/bin/code`, with the version from `CFBundleShortVersionString`; Windows and Linux require `Kiro.exe` / `kiro` in the root plus `resources/app/package.json` naming `Kiro`, with the version from that manifest. A missing or malformed version is reported as `unknown`. Every path the resolver touches is first checked, component by component from the root down, for a symlink or junction before anything is followed; a link anywhere on it (the root, an intermediate directory, the metadata file, the binary) makes the install undetected rather than resolved. Also not detected: portable Linux trees reachable only through `$PATH` or `.desktop` files, Windows installs at custom paths, and installs known only from Windows Uninstall registry rows — that registry is never consulted for Kiro, since its DisplayName match is a substring and "Kiro" matches the "Kiro CLI" row. Nothing Kiro ships is ever launched.

§ Kiro CLI (reported as `amazon-q-cli`) is identified passively, per platform, and never launched — earlier releases ran every `kiro-cli`/`kiro`/`q` on `$PATH` with `--version` to read its banner. macOS: the candidate must resolve into `Kiro CLI.app/Contents/MacOS/kiro-cli` and the bundle's `Info.plist` must carry `com.amazon.codewhisperer` (read in-process); the version is `CFBundleShortVersionString`. Windows: the candidate must be `kiro-cli.exe` inside the `InstallPath` recorded at `HKCU\SOFTWARE\Kiro\CLI`, which also supplies `ProductVersion` (`2.21.1.0`-style) and is probed directly for non-default install locations; HKCU only, since scans run as the interactive user. Linux: either the `kiro-cli` dpkg package owns the binary (its version is reported), or the binary is `kiro-cli` with the installer's `kiro-cli-chat` and `kiro-cli-term` beside it (version `unknown`). The IDE's `kiro` launcher and the `q` shell wrapper are rejected. Not covered: the AppImage build, pre-rename Amazon Q layouts, and Windows installs whose key lives in another user's hive.

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
| LM Studio             | `lm-studio`| GUI: `/Applications/LM Studio.app` (macOS), `%LOCALAPPDATA%\Programs\LM Studio` (Windows), `~/.local/share/LM Studio` or `/opt/LM Studio` (Linux). Never executed for its version — see below |
| Text Generation WebUI | `textgen`  | Checks if process is running                                                    |

### Version probes never launch a desktop app

`lm-studio` names the desktop application's launcher, not a CLI (LM Studio's CLI is a
separate binary, `lms`). A packaged Electron app does not implement `--version`, so probing
it that way opens the app's window instead of printing a version. Its version therefore comes
only from on-disk metadata — the macOS bundle `Info.plist`, the Windows uninstall registry, or
on Linux the dpkg entry for the `.deb`, the snap manifest, or the version in an AppImage
filename — and reads `unknown` when none of those resolve. The tool is still reported as
installed either way.

This is also enforced generically: before any version probe execs a binary, the agent checks
whether it is a packaged Electron app's entry point, which is visible on disk
(`resources/app.asar` and the Chromium runtime sit beside the executable; a CLI shim's
directory holds neither). On macOS the equivalent check is Gatekeeper quarantine assessment.
A refused probe reports `unknown`. Only Electron apps are detected — a GTK or Qt application
on `$PATH` is not.

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
Dev Machine Guard inventories every installed **agent skill** — a directory containing a `SKILL.md` manifest — across Claude Code, Codex, OpenCode, Cursor, Gemini CLI, GitHub Copilot, Pi, Factory, Amp, Grok Build (`~/.grok/skills`, `.grok/skills`), Kimi Code (`~/.kimi-code/skills`, `.kimi-code/skills`), Muse Code (`~/.config/muse/skills`), Hermes Agent (`~/.hermes/skills` or `%LOCALAPPDATA%\hermes\skills`, `.hermes/skills`), Oh My Pi (`~/.omp/agent/skills`, `~/.omp/agent/managed-skills`, `.omp/skills`), Kiro (IDE and CLI, one shared root), Windsurf, Antigravity, OpenClaw, the cross-agent `~/.agents` convention, and skills installed via [skills.sh](https://skills.sh). It probes each agent's global, system, project, and plugin skill directories; skills.sh lock files add upstream provenance (joined by symlink-resolved path). Detection is pure filesystem reads (no subprocesses), bounded by a 60-second budget and per-root caps.

Roots added for the Kiro/Windsurf/Antigravity/OpenClaw conventions: `~/.kiro/skills` and `<project>/.kiro/skills`; `~/.codeium/windsurf/skills`, `<project>/.windsurf/skills`, and the managed root (`/Library/Application Support/Windsurf/skills`, `/etc/windsurf/skills`, `%ProgramData%\Windsurf\skills`); `~/.gemini/config/skills` and `~/.gemini/antigravity/skills`; `~/.openclaw/skills` and the default `~/.openclaw/workspace/skills` (named `workspace-<agentId>` and relocated workspaces are not discovered); and `<project>/.codex/skills`. JetBrains AI Assistant's embedded-agent cache roots are not scanned. The singular `.agent/skills` roots keep their `factory_agent_*` source labels but are attributed to the shared agent, since Factory and Antigravity both read them.

A skill reached through several roots is one record: symlinks and, on Windows, the directory junctions skills.sh creates in place of symlinks are folded into the physical skill's record, with each linking root listed in `symlink_sources`. Linked skill targets are resolved component by component with `safepath`, guarding ancestor-link destinations before traversal; directory and metadata reads use its verified opens. Targets must stay within the scanned user's home, the declared skills root, or its project root. Unrelated external targets are skipped. This protects linked-skill access, not every scanner discovery path, and is not a scanner-wide no-prompt guarantee. On Windows, junction targets that name a volume by GUID, a `UNC\` path or a `\\server\share` are skipped; off Windows a target is taken literally, so no Windows spelling is applied to it. The Kiro CLI's bundle `Info.plist` and installer siblings are rejected when they are links rather than followed.

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

**Projects inside dev containers are covered on macOS.** Container runtimes (OrbStack, Docker Desktop, Colima) expose the guest filesystem through a mount under `$HOME` — `~/OrbStack`, for example — so a project living inside a running container is walked like any other. macOS classifies those mounts as *network volumes* and gates the first access behind a TCC prompt; the agent walks them anyway, because that inventory is not reachable any other way. Fleets that would rather not see the prompt turn the walk off with `include_network_volumes: false`, or pre-approve it via PPPC — see [macos-tcc-permissions.md](docs/macos-tcc-permissions.md).

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
- **macOS network volumes when a fleet opts out** — venvs under a container-runtime mount (`~/OrbStack`, Docker Desktop / Colima shares) *are* covered by default; they're missed only where an admin set `include_network_volumes: false` to suppress the TCC prompt. The mounts given up are named in the run's warning log.
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

## WSL Detection (Windows)

Host-side detection of Windows Subsystem for Linux, reported by the **Windows agent** under `device.wsl`. Answers "is WSL present, and is a distribution actively running right now?" so a fleet dashboard can flag machines with WSL environments that the Linux agent has not yet scanned. It does **not** mount or scan distro filesystems — run the Linux binary inside a distro for that.

| Signal | Source | Notes |
|--------|--------|-------|
| Registered distros | `HKU\<SID>\...\CurrentVersion\Lxss` (all loaded user hives) | Enumerating HKU (not just HKCU) lets a SYSTEM-context scan still see a signed-in user's distros. Name, WSL version, default flag, owning SID, base path. |
| Distro ID | the Lxss subkey name (a GUID) | The only stable per-distro identifier: survives restarts and renames, changes on unregister/re-import. **Not** derivable from the base path — imported distros have no GUID in theirs. |
| Default user | per-distro `DefaultUid` | The uid `wsl -d <name>` runs as. `0` means the distro has no non-root user; absent means unreadable, and the two are kept distinct. |
| WSL version per distro | registry `Flags & 0x8` | The per-distro `Version` DWORD is unreliable (reads 2 on WSL1). Flags `0x7` → WSL1, `0xF` → WSL2 — both measured (WSL1 EC2 box + WSL2 metal VM). |
| Installed | `WslService` (Store/MSI) or `LxssManager` (legacy) service key | `System32\wsl.exe` is **not** a signal — it ships with stock Windows even when WSL is disabled. |
| Package version | `Uninstall\...` `DisplayVersion` for "Windows Subsystem for Linux" | Floors to `unknown`. |
| Actively used | `wsl.exe --list --running --quiet` | The only subprocess; UTF-16LE output decoded defensively. Registry carries no runtime state. Skipped entirely unless a WSL service is *running* (native SCM query, no process) — that probe **starts** `WslService` when stopped, so on an idle machine it would wake a service to learn nothing. |

Presence is tri-state (`yes` / `no` / `unknown`): a probe that cannot read the registry reports `unknown` rather than a false `no`. Gated behind the `wsl-detection` feature flag until the backend consumes the payload. Limitation: users whose hive is not loaded (never signed in this boot) are not counted.

---

## Adding New Detections

Want to add detection for a new tool, IDE, or framework? See [docs/adding-detections.md](docs/adding-detections.md) or open a [New Detection issue](.github/ISSUE_TEMPLATE/new_detection.yml).
