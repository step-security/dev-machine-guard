//go:build windows

package devicepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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

// ProbeManagedPolicy reports whether an AllowedExtensions or
// ExtensionGalleryServiceUrl value of a type VS Code honors (REG_SZ or
// REG_MULTI_SZ) exists under the VS Code policy key in HKLM or HKCU. A value of
// any other type is dropped by vscode-policy-watcher (nullopt) and does not
// outrank user settings, so it does not count as managed.
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

	// A value counts as managed only when its type is one VS Code honors (REG_SZ
	// or REG_MULTI_SZ). A value of any other type is dropped by
	// vscode-policy-watcher (nullopt) and does not outrank user settings, so skip
	// it and keep scanning the remaining names (and, via the caller, hives). The
	// first honored value wins (AllowedExtensions preferred in the detail).
	for _, name := range managedPolicyNames() {
		if _, valtype, err := k.GetValue(name, nil); isHonoredStringType(valtype, err) {
			return true, loc.name + `\` + loc.path + ` [` + name + `]`
		}
	}
	return false, ""
}

// isHonoredStringType reports whether a GetValue(name, nil) result denotes a
// present value of a type VS Code honors for a string/object policy (REG_SZ or
// REG_MULTI_SZ). A nil probe buffer sets valtype and returns ErrShortBuffer (or
// nil); a clean ErrNotExist — or any other error — is not a honored value.
func isHonoredStringType(valtype uint32, err error) bool {
	if err != nil && !errors.Is(err, registry.ErrShortBuffer) {
		return false
	}
	return valtype == registry.SZ || valtype == registry.MULTI_SZ
}

// keyStatus classifies one registry lookup for a single policy value.
type keyStatus int

const (
	keyAbsent     keyStatus = iota // value not set at this hive
	keyFound                       // value present and read as a supported string type
	keyUnreadable                  // value present but not a type VS Code honors, or unreadable
)

// ProbeManagedContent reads the VS Code managed-policy values from the registry
// for the verify-only path. Each value is resolved with its own HKLM-then-HKCU
// fallback (values may live in different hives), reading only the string types
// VS Code's policy watcher honors.
func ProbeManagedContent() (bool, map[string]json.RawMessage, error) {
	return probeRegistryContent([]registryProbe{
		{registry.LOCAL_MACHINE, "HKLM", windowsPolicyKeyPath},
		{registry.CURRENT_USER, "HKCU", windowsPolicyKeyPath},
	})
}

// probeRegistryContent resolves each policy value independently over locs. A
// value present at the effective hive but of an unsupported type — or otherwise
// unreadable — is a verification_failed for that key (never a silent absence);
// an unsupported HKLM value never masks a valid HKCU one.
func probeRegistryContent(locs []registryProbe) (bool, map[string]json.RawMessage, error) {
	raw := map[string]string{}
	for _, name := range []string{allowedExtensionsName, galleryServiceURLName} {
		v, st := resolveRegistryPolicy(name, locs)
		switch st {
		case keyFound:
			raw[name] = v
		case keyUnreadable:
			return false, nil, fmt.Errorf("devicepolicy: %s present but not a readable string policy", name)
		case keyAbsent:
			// MDM did not set this key; leave it out of observed.
		}
	}
	return buildObserved(raw)
}

// resolveRegistryPolicy reads one policy value across the hives in order and
// returns the first readable string value (keyFound). If no hive holds a
// readable value but at least one held a present-but-unsupported/unreadable
// value, it returns keyUnreadable; otherwise keyAbsent.
func resolveRegistryPolicy(name string, locs []registryProbe) (string, keyStatus) {
	sawUnreadable := false
	for _, l := range locs {
		v, st := readRegistryStringValue(l.root, l.path, name)
		switch st {
		case keyFound:
			return v, keyFound
		case keyUnreadable:
			sawUnreadable = true // must not mask a valid value in a later hive
		case keyAbsent:
		}
	}
	if sawUnreadable {
		return "", keyUnreadable
	}
	return "", keyAbsent
}

// readRegistryStringValue reads one value at one hive, accepting only the
// registry types vscode-policy-watcher honors for a string/object policy: REG_SZ
// and REG_MULTI_SZ (its StringPolicy supportedTypes). REG_EXPAND_SZ and every
// other type are dropped by VS Code (RegistryPolicy returns nullopt), so
// reporting one would claim a value VS Code does not apply — they map to
// keyUnreadable, never keyFound. A missing key or value is keyAbsent; a present
// value of an unhonored type, or a read error on a present value, is
// keyUnreadable (never a silent absence).
func readRegistryStringValue(root registry.Key, path, name string) (string, keyStatus) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		// Key absent at this hive (no policy) or unreadable; treat as absent here
		// and let the other hive decide.
		return "", keyAbsent
	}
	defer k.Close()

	// Gate on the exact type: GetStringValue also accepts REG_EXPAND_SZ, which VS
	// Code does not, so query the type ourselves rather than trust the getter. A
	// nil probe buffer sets valtype and returns ErrShortBuffer (or nil); only a
	// clean not-exists reads as absent.
	_, valtype, err := k.GetValue(name, nil)
	switch {
	case errors.Is(err, registry.ErrNotExist):
		return "", keyAbsent
	case err != nil && !errors.Is(err, registry.ErrShortBuffer):
		return "", keyUnreadable
	}

	switch valtype {
	case registry.SZ:
		if s, _, gErr := k.GetStringValue(name); gErr == nil {
			return s, keyFound
		}
		return "", keyUnreadable
	case registry.MULTI_SZ:
		if lines, _, gErr := k.GetStringsValue(name); gErr == nil {
			return strings.Join(lines, "\n"), keyFound
		}
		return "", keyUnreadable
	default:
		// REG_EXPAND_SZ, REG_DWORD, REG_BINARY, … — not a type VS Code honors.
		return "", keyUnreadable
	}
}
