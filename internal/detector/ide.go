package detector

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type ideSpec struct {
	AppName      string
	IDEType      string
	Vendor       string
	AppPath      string   // macOS: /Applications/X.app
	BinaryPath   string   // macOS: relative to AppPath
	WinPaths     []string // Windows: candidate install dirs (may contain %ENVVAR% and glob patterns)
	WinBinary    string   // Windows: binary relative to install dir
	LinuxPaths   []string // Linux: candidate install dirs (may contain ~ and glob patterns)
	LinuxBinary  string   // Linux: binary name to search in PATH (LookPath)
	VersionFlag  string
	RegistryName string // Windows: override for registry search if DisplayName differs from AppName
}

// registrySearchName returns the name to use for registry searches.
func (s ideSpec) registrySearchName() string {
	if s.RegistryName != "" {
		return s.RegistryName
	}
	return s.AppName
}

var ideDefinitions = []ideSpec{
	{
		AppName: "Visual Studio Code", IDEType: "vscode", Vendor: "Microsoft",
		AppPath: "/Applications/Visual Studio Code.app", BinaryPath: "Contents/Resources/app/bin/code",
		WinPaths: []string{`%PROGRAMFILES%\Microsoft VS Code`, `%LOCALAPPDATA%\Programs\Microsoft VS Code`}, WinBinary: `bin\code.cmd`,
		LinuxPaths: []string{"/usr/share/code", "/usr/lib/code", "/snap/code/current/usr/share/code"}, LinuxBinary: "code",
		VersionFlag: "--version",
	},
	{
		AppName: "Cursor", IDEType: "cursor", Vendor: "Cursor",
		AppPath: "/Applications/Cursor.app", BinaryPath: "Contents/Resources/app/bin/cursor",
		// Use the .cmd console wrapper, not Cursor.exe (GUI binary that briefly opens a window)
		WinPaths: []string{`%LOCALAPPDATA%\Programs\cursor`}, WinBinary: `resources\app\bin\cursor.cmd`,
		LinuxPaths: []string{"/usr/share/cursor", "/opt/Cursor", "~/.local/share/cursor"}, LinuxBinary: "cursor",
		VersionFlag: "--version",
	},
	{
		AppName: "Windsurf", IDEType: "windsurf", Vendor: "Codeium",
		AppPath: "/Applications/Windsurf.app", BinaryPath: "Contents/MacOS/Windsurf",
		// Use the .cmd console wrapper to avoid launching the GUI
		WinPaths: []string{`%LOCALAPPDATA%\Programs\Windsurf`}, WinBinary: `resources\app\bin\windsurf.cmd`,
		LinuxPaths: []string{"/opt/Windsurf", "/usr/share/windsurf", "~/.local/share/windsurf"}, LinuxBinary: "windsurf",
		VersionFlag: "--version",
	},
	{
		AppName: "Antigravity", IDEType: "antigravity", Vendor: "Google",
		AppPath: "/Applications/Antigravity.app", BinaryPath: "Contents/MacOS/Antigravity",
		// Use the .cmd console wrapper to avoid launching the GUI
		WinPaths: []string{`%LOCALAPPDATA%\Programs\Antigravity`}, WinBinary: `resources\app\bin\antigravity.cmd`,
		LinuxPaths: []string{"/opt/Antigravity", "/usr/share/antigravity"}, LinuxBinary: "antigravity",
		VersionFlag: "--version",
	},
	{
		AppName: "Zed", IDEType: "zed", Vendor: "Zed",
		AppPath: "/Applications/Zed.app", BinaryPath: "Contents/MacOS/zed",
		WinPaths: []string{`%LOCALAPPDATA%\Zed`}, WinBinary: "zed.exe",
		LinuxPaths:  []string{"~/.local/zed.app", "/usr/lib/zed"},
		LinuxBinary: "zed",
	},
	{
		AppName: "Claude", IDEType: "claude_desktop", Vendor: "Anthropic",
		AppPath:  "/Applications/Claude.app",
		WinPaths: []string{`%LOCALAPPDATA%\Programs\Claude`},
	},
	{
		AppName: "Microsoft Copilot", IDEType: "microsoft_copilot_desktop", Vendor: "Microsoft",
		AppPath:  "/Applications/Copilot.app",
		WinPaths: []string{`%LOCALAPPDATA%\Programs\Copilot`},
	},
	// JetBrains IDEs — version extracted via product-info.json (macOS + Windows + Linux)
	// or Info.plist fallback (macOS) or registry fallback (Windows).
	// Windows paths use glob patterns because folder names include the version
	// (e.g., "IntelliJ IDEA 2024.3.2").
	// Linux paths include /opt (manual tar.gz), /snap (snap), and Toolbox locations.
	{
		AppName: "IntelliJ IDEA", IDEType: "intellij_idea", Vendor: "JetBrains",
		AppPath:     "/Applications/IntelliJ IDEA.app",
		WinPaths:    []string{`%PROGRAMFILES%\JetBrains\IntelliJ IDEA 2*`},
		LinuxPaths:  []string{"/opt/idea-IU-*", "/snap/intellij-idea-ultimate/current", "~/.local/share/JetBrains/Toolbox/apps/IDEA-U/ch-0/*"},
		LinuxBinary: "idea",
	},
	{
		AppName: "IntelliJ IDEA CE", IDEType: "intellij_idea_ce", Vendor: "JetBrains",
		AppPath:     "/Applications/IntelliJ IDEA CE.app",
		WinPaths:    []string{`%PROGRAMFILES%\JetBrains\IntelliJ IDEA Community Edition *`},
		LinuxPaths:  []string{"/opt/idea-IC-*", "/snap/intellij-idea-community/current", "~/.local/share/JetBrains/Toolbox/apps/IDEA-C/ch-0/*"},
		LinuxBinary: "idea",
	},
	{
		AppName: "PyCharm", IDEType: "pycharm", Vendor: "JetBrains",
		AppPath:     "/Applications/PyCharm.app",
		WinPaths:    []string{`%PROGRAMFILES%\JetBrains\PyCharm 2*`},
		LinuxPaths:  []string{"/opt/pycharm-*", "/snap/pycharm-professional/current", "~/.local/share/JetBrains/Toolbox/apps/PyCharm-P/ch-0/*"},
		LinuxBinary: "pycharm",
	},
	{
		AppName: "PyCharm CE", IDEType: "pycharm_ce", Vendor: "JetBrains",
		AppPath:     "/Applications/PyCharm CE.app",
		WinPaths:    []string{`%PROGRAMFILES%\JetBrains\PyCharm Community Edition *`},
		LinuxPaths:  []string{"/opt/pycharm-community-*", "/snap/pycharm-community/current", "~/.local/share/JetBrains/Toolbox/apps/PyCharm-C/ch-0/*"},
		LinuxBinary: "pycharm",
	},
	{
		AppName: "WebStorm", IDEType: "webstorm", Vendor: "JetBrains",
		AppPath:     "/Applications/WebStorm.app",
		WinPaths:    []string{`%PROGRAMFILES%\JetBrains\WebStorm *`},
		LinuxPaths:  []string{"/opt/webstorm-*", "/snap/webstorm/current", "~/.local/share/JetBrains/Toolbox/apps/WebStorm/ch-0/*"},
		LinuxBinary: "webstorm",
	},
	{
		AppName: "GoLand", IDEType: "goland", Vendor: "JetBrains",
		AppPath:     "/Applications/GoLand.app",
		WinPaths:    []string{`%PROGRAMFILES%\JetBrains\GoLand *`},
		LinuxPaths:  []string{"/opt/goland-*", "/snap/goland/current", "~/.local/share/JetBrains/Toolbox/apps/GoLand/ch-0/*"},
		LinuxBinary: "goland",
	},
	{
		AppName: "Rider", IDEType: "rider", Vendor: "JetBrains",
		AppPath:      "/Applications/Rider.app",
		WinPaths:     []string{`%PROGRAMFILES%\JetBrains\JetBrains Rider *`},
		RegistryName: "JetBrains Rider",
		LinuxPaths:   []string{"/opt/rider-*", "/snap/rider/current", "~/.local/share/JetBrains/Toolbox/apps/Rider/ch-0/*"},
		LinuxBinary:  "rider",
	},
	{
		AppName: "PhpStorm", IDEType: "phpstorm", Vendor: "JetBrains",
		AppPath:     "/Applications/PhpStorm.app",
		WinPaths:    []string{`%PROGRAMFILES%\JetBrains\PhpStorm *`},
		LinuxPaths:  []string{"/opt/phpstorm-*", "/snap/phpstorm/current", "~/.local/share/JetBrains/Toolbox/apps/PhpStorm/ch-0/*"},
		LinuxBinary: "phpstorm",
	},
	{
		AppName: "RubyMine", IDEType: "rubymine", Vendor: "JetBrains",
		AppPath:     "/Applications/RubyMine.app",
		WinPaths:    []string{`%PROGRAMFILES%\JetBrains\RubyMine *`},
		LinuxPaths:  []string{"/opt/rubymine-*", "/snap/rubymine/current", "~/.local/share/JetBrains/Toolbox/apps/RubyMine/ch-0/*"},
		LinuxBinary: "rubymine",
	},
	{
		AppName: "CLion", IDEType: "clion", Vendor: "JetBrains",
		AppPath:     "/Applications/CLion.app",
		WinPaths:    []string{`%PROGRAMFILES%\JetBrains\CLion *`},
		LinuxPaths:  []string{"/opt/clion-*", "/snap/clion/current", "~/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/*"},
		LinuxBinary: "clion",
	},
	{
		AppName: "DataGrip", IDEType: "datagrip", Vendor: "JetBrains",
		AppPath:     "/Applications/DataGrip.app",
		WinPaths:    []string{`%PROGRAMFILES%\JetBrains\DataGrip *`},
		LinuxPaths:  []string{"/opt/datagrip-*", "/snap/datagrip/current", "~/.local/share/JetBrains/Toolbox/apps/DataGrip/ch-0/*"},
		LinuxBinary: "datagrip",
	},
	{
		AppName: "Fleet", IDEType: "fleet", Vendor: "JetBrains",
		AppPath:     "/Applications/Fleet.app",
		LinuxPaths:  []string{"~/.local/share/JetBrains/Toolbox/apps/Fleet/ch-0/*"},
		LinuxBinary: "fleet",
	},
	{
		AppName: "Android Studio", IDEType: "android_studio", Vendor: "Google",
		AppPath:     "/Applications/Android Studio.app",
		WinPaths:    []string{`%PROGRAMFILES%\Android\Android Studio`},
		LinuxPaths:  []string{"/opt/android-studio", "/usr/local/android-studio", "~/.local/share/JetBrains/Toolbox/apps/AndroidStudio/ch-0/*"},
		LinuxBinary: "studio.sh",
	},
	// Other IDEs
	{
		AppName: "Eclipse", IDEType: "eclipse", Vendor: "Eclipse Foundation",
		AppPath:     "/Applications/Eclipse.app",
		WinPaths:    []string{`%PROGRAMFILES%\eclipse`, `C:\eclipse`, `%USERPROFILE%\eclipse\*\eclipse`},
		LinuxPaths:  []string{"/opt/eclipse", "/usr/lib/eclipse", "/snap/eclipse/current", "~/eclipse/*/eclipse"},
		LinuxBinary: "eclipse",
	},
	{AppName: "Xcode", IDEType: "xcode", Vendor: "Apple", AppPath: "/Applications/Xcode.app"},
}

// IDEDetector detects installed IDEs and AI desktop apps.
type IDEDetector struct {
	exec executor.Executor
}

func NewIDEDetector(exec executor.Executor) *IDEDetector {
	return &IDEDetector{exec: exec}
}

func (d *IDEDetector) Detect(ctx context.Context) []model.IDE {
	var results []model.IDE

	for _, spec := range ideDefinitions {
		switch d.exec.GOOS() {
		case model.PlatformWindows:
			if ide, ok := d.detectWindows(ctx, spec); ok {
				results = append(results, ide)
			}
		case model.PlatformDarwin:
			if ide, ok := d.detectDarwin(ctx, spec); ok {
				results = append(results, ide)
			}
		default: // linux and other unix
			if ide, ok := d.detectLinux(ctx, spec); ok {
				results = append(results, ide)
			}
		}
	}

	return results
}

func (d *IDEDetector) detectDarwin(ctx context.Context, spec ideSpec) (model.IDE, bool) {
	if !d.exec.DirExists(spec.AppPath) {
		return model.IDE{}, false
	}

	version := "unknown"

	// Try version from binary
	if spec.BinaryPath != "" && spec.VersionFlag != "" {
		binaryFull := filepath.Join(spec.AppPath, spec.BinaryPath)
		if d.exec.FileExists(binaryFull) {
			version = runVersionCmd(ctx, d.exec, binaryFull, spec.VersionFlag)
		}
	}

	// Fallback: product-info.json (JetBrains IDEs)
	if version == "unknown" {
		version = readProductInfoVersion(d.exec, filepath.Join(spec.AppPath, "Contents", "Resources", "product-info.json"))
	}

	// Fallback: Info.plist
	if version == "unknown" {
		version = readPlistVersion(ctx, d.exec, filepath.Join(spec.AppPath, "Contents", "Info.plist"))
	}

	return model.IDE{
		IDEType: spec.IDEType, Version: version, InstallPath: spec.AppPath,
		Vendor: spec.Vendor, IsInstalled: true,
	}, true
}

func (d *IDEDetector) detectLinux(ctx context.Context, spec ideSpec) (model.IDE, bool) {
	homeDir := getHomeDir(d.exec)

	// Phase 1: Check known install directories
	for _, linuxPath := range spec.LinuxPaths {
		resolved := expandTilde(linuxPath, homeDir)
		installDir, ok := d.resolveInstallDir(resolved)
		if !ok {
			continue
		}

		version := d.resolveLinuxVersion(ctx, spec, installDir)
		return model.IDE{
			IDEType: spec.IDEType, Version: version, InstallPath: installDir,
			Vendor: spec.Vendor, IsInstalled: true,
		}, true
	}

	// Phase 2: PATH fallback — find the binary via LookPath
	if spec.LinuxBinary != "" {
		binPath, err := d.exec.LookPath(spec.LinuxBinary)
		if err == nil {
			version := "unknown"
			if spec.VersionFlag != "" {
				version = runVersionCmd(ctx, d.exec, binPath, spec.VersionFlag)
			}
			return model.IDE{
				IDEType: spec.IDEType, Version: version, InstallPath: binPath,
				Vendor: spec.Vendor, IsInstalled: true,
			}, true
		}
	}

	// Phase 3: .desktop file fallback — discovers IDEs installed at non-standard paths.
	// Equivalent to Windows registry lookup: .desktop files are registered by package
	// managers, snap, flatpak, and even manual installs that add app launcher entries.
	if spec.LinuxBinary != "" {
		if installDir, ok := d.discoverViaDesktopFile(spec, homeDir); ok {
			version := d.resolveLinuxVersion(ctx, spec, installDir)
			return model.IDE{
				IDEType: spec.IDEType, Version: version, InstallPath: installDir,
				Vendor: spec.Vendor, IsInstalled: true,
			}, true
		}
	}

	return model.IDE{}, false
}

// resolveLinuxVersion determines the IDE version on Linux.
// Prefers the binary within installDir to avoid version mismatch with a different
// install found via PATH. Falls back to PATH lookup, then metadata files.
func (d *IDEDetector) resolveLinuxVersion(ctx context.Context, spec ideSpec, installDir string) string {
	if spec.LinuxBinary != "" && spec.VersionFlag != "" {
		// Try binary inside the detected install directory first
		for _, relBin := range []string{
			filepath.Join("bin", spec.LinuxBinary),
			spec.LinuxBinary,
		} {
			localBin := filepath.Join(installDir, relBin)
			if d.exec.FileExists(localBin) {
				if v := runVersionCmd(ctx, d.exec, localBin, spec.VersionFlag); v != "unknown" {
					return v
				}
			}
		}

		// Fall back to PATH (may be a different install, but better than unknown)
		if binPath, err := d.exec.LookPath(spec.LinuxBinary); err == nil {
			if v := runVersionCmd(ctx, d.exec, binPath, spec.VersionFlag); v != "unknown" {
				return v
			}
		}
	}

	// product-info.json at the root of the install dir (JetBrains, some Electron apps)
	if v := readProductInfoVersion(d.exec, filepath.Join(installDir, "product-info.json")); v != "unknown" {
		return v
	}

	// .eclipseproduct at the root (Eclipse)
	if v := readEclipseProductVersion(d.exec, filepath.Join(installDir, ".eclipseproduct")); v != "unknown" {
		return v
	}

	return "unknown"
}

func (d *IDEDetector) detectWindows(ctx context.Context, spec ideSpec) (model.IDE, bool) {
	// Phase 1: Try hardcoded paths (fast, no registry)
	for _, winPath := range spec.WinPaths {
		resolved := resolveEnvPath(d.exec, winPath)

		installDir, ok := d.resolveInstallDir(resolved)
		if !ok {
			continue
		}

		version := d.resolveWindowsVersion(ctx, spec, installDir)
		return model.IDE{
			IDEType: spec.IDEType, Version: version, InstallPath: installDir,
			Vendor: spec.Vendor, IsInstalled: true,
		}, true
	}

	// Phase 2: Registry fallback — discover install path from Uninstall keys.
	// Catches IDEs installed at non-standard paths (e.g., D:\Tools\VSCode).
	if installDir, version, ok := d.discoverViaRegistry(ctx, spec); ok {
		return model.IDE{
			IDEType: spec.IDEType, Version: version, InstallPath: installDir,
			Vendor: spec.Vendor, IsInstalled: true,
		}, true
	}

	return model.IDE{}, false
}

// resolveWindowsVersion determines the IDE version using multiple strategies.
func (d *IDEDetector) resolveWindowsVersion(ctx context.Context, spec ideSpec, installDir string) string {
	version := d.resolveWindowsVersionFromDir(ctx, spec, installDir)
	if version == "unknown" {
		version = readRegistryVersion(ctx, d.exec, spec.registrySearchName())
	}
	return version
}

// resolveWindowsVersionFromDir tries binary, product-info.json, and .eclipseproduct.
// Does NOT query the registry (caller handles that to avoid redundant queries).
func (d *IDEDetector) resolveWindowsVersionFromDir(ctx context.Context, spec ideSpec, installDir string) string {
	version := "unknown"

	if spec.WinBinary != "" && spec.VersionFlag != "" {
		binaryFull := filepath.Join(installDir, spec.WinBinary)
		if d.exec.FileExists(binaryFull) {
			version = runVersionCmd(ctx, d.exec, binaryFull, spec.VersionFlag)
		}
	}

	if version == "unknown" {
		version = readProductInfoVersion(d.exec, filepath.Join(installDir, "product-info.json"))
	}

	if version == "unknown" {
		version = readEclipseProductVersion(d.exec, filepath.Join(installDir, ".eclipseproduct"))
	}

	return version
}

// discoverViaRegistry attempts to find an IDE's install location from Windows
// Uninstall registry keys. This is a fallback for IDEs installed at non-standard paths.
func (d *IDEDetector) discoverViaRegistry(ctx context.Context, spec ideSpec) (string, string, bool) {
	info := readRegistryInstallInfo(ctx, d.exec, spec.registrySearchName())

	if info.InstallLocation == "" {
		return "", "", false
	}

	if !d.exec.DirExists(info.InstallLocation) {
		return "", "", false
	}

	// Resolve version from the discovered directory
	version := d.resolveWindowsVersionFromDir(ctx, spec, info.InstallLocation)

	// Use registry DisplayVersion as final fallback (avoids redundant registry query)
	if version == "unknown" && info.Version != "" {
		version = info.Version
	}

	return info.InstallLocation, version, true
}

// resolveInstallDir resolves a Windows path to an install directory.
// Supports glob patterns (e.g., "C:\Program Files\JetBrains\GoLand *")
// for IDEs that embed version numbers in folder names.
// When multiple matches exist, returns the most recently modified directory
// (more reliable than lexicographic sort which fails for "2024.9" vs "2024.10").
func (d *IDEDetector) resolveInstallDir(resolved string) (string, bool) {
	if !strings.ContainsAny(resolved, "*?[") {
		if d.exec.DirExists(resolved) {
			return resolved, true
		}
		return "", false
	}

	matches, err := d.exec.Glob(resolved)
	if err != nil || len(matches) == 0 {
		return "", false
	}

	// Filter to directories and pick the most recently modified one
	var newest string
	var newestTime int64
	for _, m := range matches {
		if !d.exec.DirExists(m) {
			continue
		}
		info, err := d.exec.Stat(m)
		if err != nil {
			// Can't stat — still consider it as a candidate
			if newest == "" {
				newest = m
			}
			continue
		}
		mtime := info.ModTime().Unix()
		if mtime > newestTime {
			newestTime = mtime
			newest = m
		}
	}

	if newest == "" {
		return "", false
	}
	return newest, true
}

// runVersionCmd runs a binary with a version flag and extracts the first line.
func runVersionCmd(ctx context.Context, exec executor.Executor, binary, flag string) string {
	stdout, _, _, err := exec.RunWithTimeout(ctx, 10*time.Second, binary, flag)
	if err != nil {
		return "unknown"
	}
	lines := strings.SplitN(stdout, "\n", 2)
	if len(lines) > 0 {
		v := strings.TrimSpace(lines[0])
		if v != "" {
			return v
		}
	}
	return "unknown"
}

// readProductInfoVersion reads the "version" field from a JetBrains product-info.json file.
// Returns "unknown" if the file does not exist or cannot be parsed.
func readProductInfoVersion(exec executor.Executor, filePath string) string {
	data, err := exec.ReadFile(filePath)
	if err != nil {
		return "unknown"
	}
	var info struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &info); err != nil || info.Version == "" {
		return "unknown"
	}
	return info.Version
}

// readEclipseProductVersion reads the "version" property from an .eclipseproduct file.
// The file uses Java properties format (key=value per line).
func readEclipseProductVersion(exec executor.Executor, filePath string) string {
	data, err := exec.ReadFile(filePath)
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "version=") {
			v := strings.TrimPrefix(line, "version=")
			if v != "" {
				return v
			}
		}
	}
	return "unknown"
}

// readPlistVersion reads CFBundleShortVersionString from an Info.plist (macOS).
func readPlistVersion(ctx context.Context, exec executor.Executor, plistPath string) string {
	if !exec.FileExists(plistPath) {
		return "unknown"
	}
	stdout, _, _, err := exec.Run(ctx, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", plistPath)
	if err == nil {
		v := strings.TrimSpace(stdout)
		if v != "" {
			return v
		}
	}
	return "unknown"
}

// registryInstallInfo holds version and install path from Windows Uninstall registry keys.
type registryInstallInfo struct {
	Version         string
	InstallLocation string
}

// readRegistryInstallInfo and readRegistryVersion are implemented in
// registry_windows.go (native API) and registry_other.go (stub).

// discoverViaDesktopFile searches XDG .desktop files for an IDE's install location.
// This is the Linux equivalent of the Windows registry fallback — .desktop files are
// created by package managers, snap, flatpak, and manual installs with app launcher entries.
// Each file contains an Exec= line pointing to the real binary path.
func (d *IDEDetector) discoverViaDesktopFile(spec ideSpec, homeDir string) (string, bool) {
	desktopDirs := []string{
		"/usr/share/applications",
		"/usr/local/share/applications",
		filepath.Join(homeDir, ".local", "share", "applications"),
		"/var/lib/flatpak/exports/share/applications",
		"/var/lib/snapd/desktop/applications",
	}

	desktopName := spec.LinuxBinary + ".desktop"

	for _, dir := range desktopDirs {
		desktopPath := filepath.Join(dir, desktopName)
		data, err := d.exec.ReadFile(desktopPath)
		if err != nil {
			continue
		}

		execPath := parseDesktopExec(string(data))
		if execPath == "" {
			continue
		}

		// Resolve the install directory: walk up from the binary to find the app root.
		// e.g., /usr/share/code/bin/code -> /usr/share/code
		// e.g., /opt/Windsurf/bin/windsurf -> /opt/Windsurf
		installDir := resolveInstallDirFromBinary(execPath)
		if d.exec.DirExists(installDir) {
			return installDir, true
		}
	}

	return "", false
}

// parseDesktopExec extracts the binary path from the first Exec= line in a .desktop file.
// Handles wrapper commands like "env VAR=val /snap/bin/code %U" by scanning tokens
// for the first absolute path.
func parseDesktopExec(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Exec=") {
			continue
		}
		execValue := strings.TrimPrefix(line, "Exec=")
		parts := strings.Fields(execValue)

		// Find the first token that looks like an absolute path
		for _, token := range parts {
			// Skip field codes (%F, %U, etc.) and flags (--foo)
			if strings.HasPrefix(token, "%") || strings.HasPrefix(token, "-") {
				continue
			}
			// Skip env var assignments (VAR=val)
			if strings.Contains(token, "=") && !strings.HasPrefix(token, "/") {
				continue
			}
			if strings.HasPrefix(token, "/") {
				return token
			}
		}
	}
	return ""
}

// resolveInstallDirFromBinary walks up from a binary path to find the app root directory.
// Handles two common layouts:
//   - /usr/share/code/bin/code           -> /usr/share/code
//   - /usr/share/cursor/resources/app/bin/cursor -> /usr/share/cursor
func resolveInstallDirFromBinary(binPath string) string {
	dir := filepath.Dir(binPath)
	base := filepath.Base(dir)

	if base != "bin" {
		return dir
	}

	parent := filepath.Dir(dir)

	// Check for resources/app/bin layout (Electron apps like Cursor)
	// /usr/share/cursor/resources/app/bin/cursor -> /usr/share/cursor
	if filepath.Base(parent) == "app" && filepath.Base(filepath.Dir(parent)) == "resources" {
		return filepath.Dir(filepath.Dir(parent))
	}

	// Simple /bin/ layout: /usr/share/code/bin/code -> /usr/share/code
	return parent
}
