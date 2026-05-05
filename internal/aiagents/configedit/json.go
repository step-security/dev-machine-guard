// Package configedit provides byte-preserving edits of user-owned
// JSON and TOML settings files. Standard encoding/json round-trips
// rewrite key order, drop comments (TOML), and renormalize whitespace.
// configedit performs path-targeted edits backed by tidwall/gjson and
// tidwall/sjson for JSON, plus a narrow regex+mask patcher for the
// codex_hooks TOML feature flag.
//
// Scope is intentionally narrow: only what the claudecode and codex
// adapters need.
package configedit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// NormalizeJSONObject returns the input bytes if they parse as a JSON
// object. Empty/whitespace-only input is treated as `{}`. Any other
// shape (array, scalar, malformed) is rejected.
func NormalizeJSONObject(data []byte) ([]byte, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return []byte(`{}`), nil
	}
	if !gjson.ValidBytes(data) {
		return nil, fmt.Errorf("configedit: invalid JSON")
	}
	if !gjson.ParseBytes(data).IsObject() {
		return nil, fmt.Errorf("configedit: root JSON value must be an object")
	}
	return data, nil
}

// EscapePathKey escapes characters that have special meaning in
// gjson/sjson path syntax so a literal key like "first.name" can be
// used as a single path component.
func EscapePathKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch c {
		case '\\', '.', '*', '?':
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// Path joins parts into a gjson/sjson path, escaping each part.
func Path(parts ...string) string {
	escaped := make([]string, len(parts))
	for i, p := range parts {
		escaped[i] = EscapePathKey(p)
	}
	return strings.Join(escaped, ".")
}

// SetRaw sets the value at path to raw via sjson and validates the
// result is still well-formed JSON.
func SetRaw(data []byte, path string, raw string) ([]byte, error) {
	out, err := sjson.SetRawBytes(data, path, []byte(raw))
	if err != nil {
		return nil, fmt.Errorf("configedit: sjson set: %w", err)
	}
	if !json.Valid(out) {
		return nil, fmt.Errorf("configedit: sjson produced invalid JSON")
	}
	return out, nil
}

// Delete removes the value at path via sjson and validates the result.
func Delete(data []byte, path string) ([]byte, error) {
	out, err := sjson.DeleteBytes(data, path)
	if err != nil {
		return nil, fmt.Errorf("configedit: sjson delete: %w", err)
	}
	if !json.Valid(out) {
		return nil, fmt.Errorf("configedit: sjson produced invalid JSON")
	}
	return out, nil
}

// RawArray joins already-valid raw JSON elements into a JSON array
// literal. Empty input yields `[]`.
func RawArray(items []string) string {
	if len(items) == 0 {
		return `[]`
	}
	return `[` + strings.Join(items, `,`) + `]`
}

// MarshalRawJSON marshals v to a compact raw JSON string suitable for
// passing to SetRaw / RawArray.
func MarshalRawJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
