//go:build linux

package devicepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// linuxPolicyFilePath is VS Code's managed-policy file on Linux, read by its
// FilePolicyService. World-readable when an MDM/admin creates it, so the probe
// needs no elevation.
const linuxPolicyFilePath = "/etc/vscode/policy.json"

// ProbeManagedPolicy reports whether an AllowedExtensions or
// ExtensionGalleryServiceUrl policy exists in the Linux policy file.
func ProbeManagedPolicy() (bool, string) {
	return probeLinuxPolicyFile(linuxPolicyFilePath)
}

// probeLinuxPolicyFile is ProbeManagedPolicy parameterized over the policy-file
// path so tests can stage a fixture instead of touching /etc.
func probeLinuxPolicyFile(path string) (bool, string) {
	for _, name := range managedPolicyNames() {
		if jsonFileHasKey(path, name) {
			return true, path + " [" + name + "]"
		}
	}
	return false, ""
}

// ProbeManagedContent reads the values of the Linux VS Code managed-policy file
// for the verify-only path.
func ProbeManagedContent() (bool, map[string]json.RawMessage, error) {
	return probeLinuxPolicyContent(linuxPolicyFilePath)
}

// probeLinuxPolicyContent reads path (…/policy.json) and extracts the two VS
// Code policy values. An absent file is a clean "not managed"; a present-but-
// unreadable or non-JSON file is an error, never a silent absence.
// AllowedExtensions is accepted as a stringified JSON object (as exported) or a
// direct object (hand-authored); the gallery URL as a JSON string.
func probeLinuxPolicyContent(path string) (bool, map[string]json.RawMessage, error) {
	// #nosec G304 -- path is the package-constant policy location (or a test
	// fixture), never external input.
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, fmt.Errorf("devicepolicy: read %s: %w", path, err)
	}
	if isJSONNull(b) {
		// A literal `null` document unmarshals into an empty map with no error; it
		// is malformed policy evidence, not "no policy present".
		return false, nil, fmt.Errorf("devicepolicy: %s is a null document, not a policy object", path)
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &m); err != nil {
		return false, nil, fmt.Errorf("devicepolicy: %s is not valid JSON: %w", path, err)
	}
	raw := map[string]string{}
	if v, ok := m[allowedExtensionsName]; ok {
		s, err := allowedInnerText(v)
		if err != nil {
			return false, nil, err
		}
		raw[allowedExtensionsName] = s
	}
	if v, ok := m[galleryServiceURLName]; ok {
		s, err := jsonStringValue(v, galleryServiceURLName)
		if err != nil {
			return false, nil, err
		}
		raw[galleryServiceURLName] = s
	}
	return buildObserved(raw)
}

// allowedInnerText returns the inner JSON text of an AllowedExtensions value: a
// direct object is used as-is (tolerating a hand-authored file), a JSON string
// is decoded to its contents (the exported shape). buildObserved rejects any
// non-object result.
func allowedInnerText(raw json.RawMessage) (string, error) {
	if isJSONNull(raw) {
		return "", fmt.Errorf("devicepolicy: %s is null, not a JSON object or string", allowedExtensionsName)
	}
	if isJSONObject(raw) {
		return string(raw), nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("devicepolicy: %s is neither a JSON object nor a JSON string", allowedExtensionsName)
	}
	return s, nil
}

// jsonStringValue decodes raw as a JSON string, erroring on any other JSON type.
// A JSON null is rejected explicitly: json.Unmarshal leaves the empty string
// with no error, which would turn malformed evidence into an empty URL.
func jsonStringValue(raw json.RawMessage, name string) (string, error) {
	if isJSONNull(raw) {
		return "", fmt.Errorf("devicepolicy: %s is null, not a JSON string", name)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("devicepolicy: %s is not a JSON string: %w", name, err)
	}
	return s, nil
}

// isJSONNull reports whether raw is the JSON null literal. Callers pass
// syntactically valid JSON, so a leading `n` can only be null.
func isJSONNull(raw json.RawMessage) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		}
		return b == 'n'
	}
	return false
}
