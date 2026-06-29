package devicepolicy

import (
	"bytes"
	"encoding/json"
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

// ProbeManagedPolicy (probe_<os>.go) reports whether an MDM/admin-managed
// AllowedExtensions policy is present at this OS's policy location, plus a
// human-readable location for logs. Read-only, never elevated, and
// best-effort: an unreadable location reads as "not managed" — enforcement
// must not be blocked by a probe that cannot decide.

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
