//go:build windows

package devicepolicy

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// windowsPolicyKeyPath is the VS Code policy key path, relative to a registry
// root. VS Code reads policies from Software\Policies\Microsoft\<productName>;
// the stable build's productName is "VSCode". vscode-policy-watcher consults
// HKLM first and falls back to HKCU when HKLM has no policy, so a user-scope
// GPO / user-targeted Intune policy in HKCU governs VS Code too — the probe
// must check both roots. Both are user-readable (only writes are ACL'd), so
// no elevation is needed.
const windowsPolicyKeyPath = `SOFTWARE\Policies\Microsoft\VSCode`

// registryProbe is one (hive, path) location to check, with a display name
// for log detail.
type registryProbe struct {
	root registry.Key
	name string
	path string
}

// ProbeManagedPolicy reports whether an AllowedExtensions value of ANY
// registry type exists under the VS Code policy key in HKLM or HKCU. Type
// does not matter: VS Code's policy service claims the setting as soon as the
// value exists, so a wrong-typed value still outranks user settings.
func ProbeManagedPolicy() (bool, string) {
	return probeRegistryLocations([]registryProbe{
		{registry.LOCAL_MACHINE, "HKLM", windowsPolicyKeyPath},
		{registry.CURRENT_USER, "HKCU", windowsPolicyKeyPath},
	})
}

// probeRegistryLocations checks the locations in order (mirroring the
// watcher's HKLM-then-HKCU precedence) and reports the first hit.
func probeRegistryLocations(locs []registryProbe) (bool, string) {
	for _, l := range locs {
		if managed, detail := probeRegistry(l); managed {
			return true, detail
		}
	}
	return false, ""
}

// probeRegistry is the single-location presence check, parameterized so tests
// can stage a disposable key under HKCU instead of touching real policy paths.
func probeRegistry(loc registryProbe) (bool, string) {
	k, err := registry.OpenKey(loc.root, loc.path, registry.QUERY_VALUE)
	if err != nil {
		// Key absent (no policy) or unreadable (cannot decide → not managed).
		return false, ""
	}
	defer k.Close()

	// GetValue with a nil buffer asks only for existence/metadata. Any error
	// other than ErrNotExist still proves the value exists or the key is
	// unreadable; only a clean not-exists reads as unmanaged.
	if _, _, err := k.GetValue(allowedExtensionsName, nil); err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, ""
		}
	}
	return true, loc.name + `\` + loc.path + ` [` + allowedExtensionsName + `]`
}
