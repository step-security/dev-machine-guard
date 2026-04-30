//go:build windows

package detector

import (
	"context"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"golang.org/x/sys/windows/registry"
)

// readRegistryInstallInfo searches Windows Uninstall registry keys and extracts
// DisplayVersion and InstallLocation for the given app name.
// Uses native Windows registry API instead of shelling out to reg.exe.
func readRegistryInstallInfo(_ context.Context, _ executor.Executor, appName string) registryInstallInfo {
	roots := []struct {
		key  registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}

	lowerAppName := strings.ToLower(appName)

	for _, root := range roots {
		k, err := registry.OpenKey(root.key, root.path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}

		subkeys, err := k.ReadSubKeyNames(-1)
		_ = k.Close()
		if err != nil {
			continue
		}

		for _, subkey := range subkeys {
			sk, err := registry.OpenKey(root.key, root.path+`\`+subkey, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			displayName, _, _ := sk.GetStringValue("DisplayName")
			if !strings.Contains(strings.ToLower(displayName), lowerAppName) {
				_ = sk.Close()
				continue
			}

			var info registryInstallInfo
			info.Version, _, _ = sk.GetStringValue("DisplayVersion")
			info.InstallLocation, _, _ = sk.GetStringValue("InstallLocation")
			_ = sk.Close()

			if info.Version != "" || info.InstallLocation != "" {
				return info
			}
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
