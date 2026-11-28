//go:build !windows

package detector

import (
	"context"
	"fmt"
	"strconv"
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

// readKiroCLIRegistry is the non-Windows twin of the native reader: one
// `reg query HKCU\SOFTWARE\Kiro\CLI` whose InstallPath / ProductVersion lines
// are parsed. Only mock-based tests running with SetGOOS("windows") reach it.
func readKiroCLIRegistry(ctx context.Context, exec executor.Executor) (installPath, productVersion string, ok bool) {
	stdout, _, _, err := exec.Run(ctx, "reg", "query", `HKCU\SOFTWARE\Kiro\CLI`)
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "REG_SZ" {
			continue
		}
		value := strings.TrimSpace(strings.SplitN(strings.TrimSpace(line), "REG_SZ", 2)[1])
		switch fields[0] {
		case "InstallPath":
			installPath = value
		case "ProductVersion":
			productVersion = value
		}
	}
	if installPath == "" {
		return "", "", false
	}
	return installPath, productVersion, true
}

// readRegistryValue is the non-Windows twin of the native reader: one
// `reg query <key> /v <name>` whose value line is parsed. A failed query is
// absent; DWORD and QWORD values come back as decimal text. Only mock-based
// tests running with SetGOOS("windows") reach it.
func readRegistryValue(ctx context.Context, exec executor.Executor, path, name string) (value string, found bool, err error) {
	stdout, _, exitCode, err := exec.Run(ctx, "reg", "query", path, "/v", name)
	if err != nil || exitCode != 0 {
		return "", false, nil
	}
	for _, line := range strings.Split(stdout, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), name)
		fields := strings.Fields(rest)
		if !ok || len(fields) == 0 || !strings.HasPrefix(rest, " ") && !strings.HasPrefix(rest, "\t") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), fields[0]))
		switch fields[0] {
		case "REG_SZ", "REG_EXPAND_SZ":
			return data, true, nil
		case "REG_DWORD", "REG_QWORD":
			n, err := strconv.ParseUint(data, 0, 64)
			if err != nil {
				return "", true, err
			}
			return strconv.FormatUint(n, 10), true, nil
		}
		return "", true, fmt.Errorf("registry value type %s", fields[0])
	}
	return "", false, nil
}
