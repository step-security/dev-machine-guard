package detector

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type ideSpec struct {
	AppName     string
	IDEType     string
	Vendor      string
	AppPath     string   // macOS: /Applications/X.app
	BinaryPath  string   // macOS: relative to AppPath
	WinPaths    []string // Windows: candidate install dirs (may contain %ENVVAR%)
	WinBinary   string   // Windows: binary relative to install dir
	VersionFlag string
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
		WinPaths: []string{`%LOCALAPPDATA%\Programs\cursor`}, WinBinary: "Cursor.exe",
		VersionFlag: "--version",
	},
	{
		AppName: "Windsurf", IDEType: "windsurf", Vendor: "Codeium",
		AppPath: "/Applications/Windsurf.app", BinaryPath: "Contents/MacOS/Windsurf",
		WinPaths: []string{`%LOCALAPPDATA%\Programs\Windsurf`}, WinBinary: "Windsurf.exe",
		VersionFlag: "--version",
	},
	{
		AppName: "Antigravity", IDEType: "antigravity", Vendor: "Google",
		AppPath: "/Applications/Antigravity.app", BinaryPath: "Contents/MacOS/Antigravity",
		WinPaths: []string{`%LOCALAPPDATA%\Programs\Antigravity`}, WinBinary: "Antigravity.exe",
		VersionFlag: "--version",
	},
	{
		AppName: "Zed", IDEType: "zed", Vendor: "Zed",
		AppPath: "/Applications/Zed.app", BinaryPath: "Contents/MacOS/zed",
		WinPaths: []string{`%LOCALAPPDATA%\Zed`}, WinBinary: "zed.exe",
	},
	{
		AppName: "Claude", IDEType: "claude_desktop", Vendor: "Anthropic",
		AppPath: "/Applications/Claude.app",
		WinPaths: []string{`%LOCALAPPDATA%\Programs\Claude`},
	},
	{
		AppName: "Microsoft Copilot", IDEType: "microsoft_copilot_desktop", Vendor: "Microsoft",
		AppPath: "/Applications/Copilot.app",
		WinPaths: []string{`%LOCALAPPDATA%\Programs\Copilot`},
	},
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
	for _, winPath := range spec.WinPaths {
		resolved := resolveEnvPath(d.exec, winPath)
		if !d.exec.DirExists(resolved) {
			continue
		}

		version := "unknown"

		// Try version from binary
		if spec.WinBinary != "" && spec.VersionFlag != "" {
			binaryFull := filepath.Join(resolved, spec.WinBinary)
			if d.exec.FileExists(binaryFull) {
				version = runVersionCmd(ctx, d.exec, binaryFull, spec.VersionFlag)
			}
		}

		// Fallback: registry
		if version == "unknown" {
			version = readRegistryVersion(ctx, d.exec, spec.AppName)
		}

		return model.IDE{
			IDEType: spec.IDEType, Version: version, InstallPath: resolved,
			Vendor: spec.Vendor, IsInstalled: true,
		}, true
	}
	return model.IDE{}, false
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

// readRegistryVersion searches Windows Uninstall registry keys for DisplayVersion.
func readRegistryVersion(ctx context.Context, exec executor.Executor, appName string) string {
	for _, root := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	} {
		stdout, _, _, err := exec.Run(ctx, "reg", "query", root, "/s", "/f", appName, "/d")
		if err != nil {
			continue
		}
		// Parse "DisplayVersion    REG_SZ    x.y.z" from reg query output
		for _, line := range strings.Split(stdout, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "DisplayVersion") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					return parts[len(parts)-1]
				}
			}
		}
	}
	return "unknown"
}
