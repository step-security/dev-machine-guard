//go:build !windows

package detector

import (
	"context"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// readRegistryInstallInfo uses exec.Run("reg", ...) when not compiled for Windows.
// This path is used by mock-based tests that simulate Windows via SetGOOS("windows").
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

// readRegistryVersion uses the exec-based fallback on non-Windows.
func readRegistryVersion(ctx context.Context, exec executor.Executor, appName string) string {
	info := readRegistryInstallInfo(ctx, exec, appName)
	if info.Version != "" {
		return info.Version
	}
	return "unknown"
}
