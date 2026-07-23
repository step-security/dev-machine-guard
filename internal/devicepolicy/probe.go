package devicepolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// allowedExtensionsName is VS Code's registered POLICY name for the
// `extensions.allowed` setting — the registry value name on Windows, the JSON
// key in /etc/vscode/policy.json on Linux, and the plist key in macOS managed
// preferences. Policy locations are keyed by policy name; the user settings
// file the agent writes is keyed by the setting id
// (allowedExtensionsSettingKey). The probes below only ever READ policy
// locations: a policy present there outranks user settings inside VS Code, so
// the agent yields (mdm_managed) instead of writing a settings value that
// would be ignored.
const allowedExtensionsName = "AllowedExtensions"

// galleryServiceURLName is VS Code's registered POLICY name for the
// `extensions.gallery.serviceUrl` setting — the registry value name on Windows,
// the JSON key in /etc/vscode/policy.json on Linux, and the plist key in macOS
// managed preferences. Like allowedExtensionsName it is the POLICY name probed
// read-only at OS policy locations, NOT the setting id the agent writes
// (galleryServiceURLSettingKey).
const galleryServiceURLName = "ExtensionGalleryServiceUrl"

// managedPolicyNames are the VS Code POLICY names whose presence makes the
// agent yield the whole ide_extension category (mdm_managed). An MDM/admin
// policy for EITHER key means a higher-precedence surface owns this category,
// so the agent never half-owns it alongside an MDM. Presence-only, not a value
// comparison. Order is the reporting preference for the log detail.
func managedPolicyNames() []string {
	return []string{allowedExtensionsName, galleryServiceURLName}
}

// ProbeManagedPolicy (probe_<os>.go) reports whether an MDM/admin-managed VS
// Code policy (AllowedExtensions or ExtensionGalleryServiceUrl) is present at
// this OS's policy location, plus a human-readable location for logs.
// Read-only, never elevated, and best-effort: an unreadable location reads as
// "not managed" — enforcement must not be blocked by a probe that cannot
// decide.

// jsonFileHasKey reports whether the JSON object file at path contains key as
// a top-level member. Falls back to a byte scan for `"key"` when the file is
// not a parseable JSON object (an MDM may have written something lenient) —
// over-detecting yields a safe mdm_managed, under-detecting would fight the
// MDM. A missing or unreadable file is false.
func jsonFileHasKey(path, key string) bool {
	// #nosec G304 -- path is a package constant policy location, never
	// external input.
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &m); err == nil {
		_, ok := m[key]
		return ok
	}
	return bytes.Contains(b, []byte(`"`+key+`"`))
}

// fileMentionsKey reports whether the file at path contains key's bytes at
// all. Used for formats not worth parsing for a presence check (macOS managed
// preferences are usually binary plists, which store key names as plain ASCII
// runs, so a byte scan detects them in both binary and XML encodings).
func fileMentionsKey(path, key string) bool {
	// #nosec G304 -- path is a package constant policy location (or a glob
	// expansion under it), never external input.
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Contains(b, []byte(key))
}

// buildObserved converts OS-managed policy values keyed by policy name (the
// inner text each per-OS reader unwrapped) into the observed bag keyed by VS
// Code setting id. AllowedExtensions is a stringified JSON object, parsed back
// to an object; the gallery URL is wrapped as a JSON string. A malformed value
// is an error, not a silent omission. present is true when at least one key was
// observed.
func buildObserved(raw map[string]string) (present bool, observed map[string]json.RawMessage, err error) {
	observed = make(map[string]json.RawMessage, len(raw))
	if s, ok := raw[allowedExtensionsName]; ok {
		v, err := parseAllowedExtensionsValue(s)
		if err != nil {
			return false, nil, err
		}
		observed[allowedExtensionsSettingKey] = v
	}
	if s, ok := raw[galleryServiceURLName]; ok {
		v, err := galleryURLValue(s)
		if err != nil {
			return false, nil, err
		}
		observed[galleryServiceURLSettingKey] = v
	}
	return len(observed) > 0, observed, nil
}

// parseAllowedExtensionsValue parses the AllowedExtensions inner JSON text into
// compacted extensions.allowed object bytes. It must be a JSON object; anything
// else is a malformed value and errors.
func parseAllowedExtensionsValue(s string) (json.RawMessage, error) {
	raw := json.RawMessage(s)
	if !json.Valid(raw) {
		return nil, fmt.Errorf("devicepolicy: %s is not valid JSON", allowedExtensionsName)
	}
	if !isJSONObject(raw) {
		return nil, fmt.Errorf("devicepolicy: %s is not a JSON object", allowedExtensionsName)
	}
	c, err := compactJSON(raw)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(c), nil
}

func galleryURLValue(s string) (json.RawMessage, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("devicepolicy: encode %s: %w", galleryServiceURLName, err)
	}
	return json.RawMessage(b), nil
}
