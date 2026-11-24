//go:build windows

package detector

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

// readKiroCLIRegistry reads the Kiro CLI installer's own key,
// HKCU\SOFTWARE\Kiro\CLI, returning InstallPath and ProductVersion. ok is
// false when the key or InstallPath is absent. HKCU only: Windows scans always
// run as the interactive user (NewUserAwareExecutor returns the plain executor
// on Windows and a SYSTEM-context inline scan is refused), so HKCU is the
// scanned user's hive by construction. Uninstall rows are deliberately not
// consulted — the CLI's row carries an empty InstallLocation, and its
// "Kiro CLI" DisplayName substring-matches the "Kiro" IDE.
func readKiroCLIRegistry(_ context.Context, _ executor.Executor) (installPath, productVersion string, ok bool) {
	return readKiroCLIKey(registry.CURRENT_USER, `SOFTWARE\Kiro\CLI`)
}

// readKiroCLIKey is readKiroCLIRegistry with the key injectable, so the native
// test can point it at a scratch key instead of the real installer's.
func readKiroCLIKey(root registry.Key, path string) (installPath, productVersion string, ok bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", "", false
	}
	defer func() { _ = k.Close() }()
	installPath, _, err = k.GetStringValue("InstallPath")
	if err != nil || installPath == "" {
		return "", "", false
	}
	productVersion, _, _ = k.GetStringValue("ProductVersion")
	return installPath, productVersion, true
}

// readRegistryValue reads one value under an HKLM\ or HKCU\ key path. found is
// false when the key or value does not exist; err is set when the value exists
// but cannot be read as text. Strings come back as written, DWORD and QWORD
// values as decimal text. The 64-bit view is used, as policy readers do.
func readRegistryValue(_ context.Context, _ executor.Executor, path, name string) (value string, found bool, err error) {
	root := registry.LOCAL_MACHINE
	sub, ok := strings.CutPrefix(path, `HKLM\`)
	if !ok {
		root = registry.CURRENT_USER
		if sub, ok = strings.CutPrefix(path, `HKCU\`); !ok {
			return "", false, nil
		}
	}
	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", false, nil
		}
		return "", true, err
	}
	defer func() { _ = k.Close() }()
	_, valType, err := k.GetValue(name, nil)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", false, nil
		}
		return "", true, err
	}
	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		value, _, err = k.GetStringValue(name)
	case registry.DWORD, registry.QWORD:
		var n uint64
		n, _, err = k.GetIntegerValue(name)
		value = strconv.FormatUint(n, 10)
	default:
		err = fmt.Errorf("registry value type %d", valType)
	}
	return value, true, err
}
