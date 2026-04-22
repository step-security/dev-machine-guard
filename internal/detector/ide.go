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
		VersionFlag: "--version",
	},
	{
		AppName: "Cursor", IDEType: "cursor", Vendor: "Cursor",
		AppPath: "/Applications/Cursor.app", BinaryPath: "Contents/Resources/app/bin/cursor",
		// Use the .cmd console wrapper, not Cursor.exe (GUI binary that briefly opens a window)
		WinPaths: []string{`%LOCALAPPDATA%\Programs\cursor`}, WinBinary: `resources\app\bin\cursor.cmd`,
		VersionFlag: "--version",
	},
	{
		AppName: "Windsurf", IDEType: "windsurf", Vendor: "Codeium",
		AppPath: "/Applications/Windsurf.app", BinaryPath: "Contents/MacOS/Windsurf",
		// Use the .cmd console wrapper to avoid launching the GUI
		WinPaths: []string{`%LOCALAPPDATA%\Programs\Windsurf`}, WinBinary: `resources\app\bin\windsurf.cmd`,
		VersionFlag: "--version",
	},
	{
		AppName: "Antigravity", IDEType: "antigravity", Vendor: "Google",
		AppPath: "/Applications/Antigravity.app", BinaryPath: "Contents/MacOS/Antigravity",
		// Use the .cmd console wrapper to avoid launching the GUI
		WinPaths: []string{`%LOCALAPPDATA%\Programs\Antigravity`}, WinBinary: `resources\app\bin\antigravity.cmd`,
		VersionFlag: "--version",
	},
	{
		AppName: "Zed", IDEType: "zed", Vendor: "Zed",
		AppPath: "/Applications/Zed.app", BinaryPath: "Contents/MacOS/zed",
		WinPaths: []string{`%LOCALAPPDATA%\Zed`}, WinBinary: "zed.exe",
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
	// JetBrains IDEs — version extracted via product-info.json (macOS + Windows)
	// or Info.plist fallback (macOS) or registry fallback (Windows).
	// Windows paths use glob patterns because folder names include the version
	// (e.g., "IntelliJ IDEA 2024.3.2").
	{
		AppName: "IntelliJ IDEA", IDEType: "intellij_idea", Vendor: "JetBrains",
		AppPath:  "/Applications/IntelliJ IDEA.app",
		WinPaths: []string{`%PROGRAMFILES%\JetBrains\IntelliJ IDEA 2*`},
	},
	{
		AppName: "IntelliJ IDEA CE", IDEType: "intellij_idea_ce", Vendor: "JetBrains",
		AppPath:  "/Applications/IntelliJ IDEA CE.app",
		WinPaths: []string{`%PROGRAMFILES%\JetBrains\IntelliJ IDEA Community Edition *`},
	},
	{
		AppName: "PyCharm", IDEType: "pycharm", Vendor: "JetBrains",
		AppPath:  "/Applications/PyCharm.app",
		WinPaths: []string{`%PROGRAMFILES%\JetBrains\PyCharm 2*`},
	},
	{
		AppName: "PyCharm CE", IDEType: "pycharm_ce", Vendor: "JetBrains",
		AppPath:  "/Applications/PyCharm CE.app",
		WinPaths: []string{`%PROGRAMFILES%\JetBrains\PyCharm Community Edition *`},
	},
	{
		AppName: "WebStorm", IDEType: "webstorm", Vendor: "JetBrains",
		AppPath:  "/Applications/WebStorm.app",
		WinPaths: []string{`%PROGRAMFILES%\JetBrains\WebStorm *`},
	},
	{
		AppName: "GoLand", IDEType: "goland", Vendor: "JetBrains",
		AppPath:  "/Applications/GoLand.app",
		WinPaths: []string{`%PROGRAMFILES%\JetBrains\GoLand *`},
	},
	{
		AppName: "Rider", IDEType: "rider", Vendor: "JetBrains",
		AppPath:      "/Applications/Rider.app",
		WinPaths:     []string{`%PROGRAMFILES%\JetBrains\JetBrains Rider *`},
		RegistryName: "JetBrains Rider",
	},
	{
		AppName: "PhpStorm", IDEType: "phpstorm", Vendor: "JetBrains",
		AppPath:  "/Applications/PhpStorm.app",
		WinPaths: []string{`%PROGRAMFILES%\JetBrains\PhpStorm *`},
	},
	{
		AppName: "RubyMine", IDEType: "rubymine", Vendor: "JetBrains",
		AppPath:  "/Applications/RubyMine.app",
		WinPaths: []string{`%PROGRAMFILES%\JetBrains\RubyMine *`},
	},
	{
		AppName: "CLion", IDEType: "clion", Vendor: "JetBrains",
		AppPath:  "/Applications/CLion.app",
		WinPaths: []string{`%PROGRAMFILES%\JetBrains\CLion *`},
	},
	{
		AppName: "DataGrip", IDEType: "datagrip", Vendor: "JetBrains",
		AppPath:  "/Applications/DataGrip.app",
		WinPaths: []string{`%PROGRAMFILES%\JetBrains\DataGrip *`},
	},
	{
		AppName: "Fleet", IDEType: "fleet", Vendor: "JetBrains",
		AppPath: "/Applications/Fleet.app",
	},
	{
		AppName: "Android Studio", IDEType: "android_studio", Vendor: "Google",
		AppPath:  "/Applications/Android Studio.app",
		WinPaths: []string{`%PROGRAMFILES%\Android\Android Studio`},
	},
	// Other IDEs
	{
		AppName: "Eclipse", IDEType: "eclipse", Vendor: "Eclipse Foundation",
		AppPath:  "/Applications/Eclipse.app",
		WinPaths: []string{`%PROGRAMFILES%\eclipse`, `C:\eclipse`, `%USERPROFILE%\eclipse\*\eclipse`},
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
		if d.exec.GOOS() == "windows" {
			if ide, ok := d.detectWindows(ctx, spec); ok {
				results = append(results, ide)
			}
		} else {
			if ide, ok := d.detectDarwin(ctx, spec); ok {
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

// readRegistryInstallInfo searches Windows Uninstall registry keys and extracts
// both DisplayVersion and InstallLocation for the given app name.
func readRegistryInstallInfo(ctx context.Context, exec executor.Executor, appName string) registryInstallInfo {
	for _, root := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	} {
		stdout, _, _, err := exec.Run(ctx, "reg", "query", root, "/s", "/f", appName, "/d")
		if err != nil {
			continue
		}

		var info registryInstallInfo
		for _, line := range strings.Split(stdout, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "DisplayVersion") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					info.Version = parts[len(parts)-1]
				}
			}
			if strings.Contains(line, "InstallLocation") {
				// InstallLocation may contain spaces, so split on REG_SZ and trim
				parts := strings.SplitN(line, "REG_SZ", 2)
				if len(parts) == 2 {
					loc := strings.TrimSpace(parts[1])
					if loc != "" {
						info.InstallLocation = loc
					}
				}
			}
		}

		if info.Version != "" || info.InstallLocation != "" {
			return info
		}
	}
	return registryInstallInfo{}
}

// readRegistryVersion searches Windows Uninstall registry keys for DisplayVersion.
func readRegistryVersion(ctx context.Context, exec executor.Executor, appName string) string {
	info := readRegistryInstallInfo(ctx, exec, appName)
	if info.Version != "" {
		return info.Version
	}
	return "unknown"
}
