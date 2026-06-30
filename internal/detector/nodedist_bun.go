package detector

import (
	"encoding/json"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// parseBunLock extracts installed packages from a text bun.lock.
//
// bun.lock is JSONC (JSON with // and /* */ comments and trailing commas), so
// it is sanitised to strict JSON before unmarshalling. The `packages` object
// maps a dependency name to an entry whose first array element is the resolved
// "name@version" string (older entries may instead be an object with a
// `version` field). The binary bun.lockb is NOT handled here — the caller
// falls back to the node_modules walk for those. Directness comes from the
// project's declared deps (directNames).
func (d *NodeDistDetector) parseBunLock(data []byte, directNames map[string]struct{}) []model.NodePackage {
	var lf struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(stripJSONC(data), &lf); err != nil {
		d.log.Debug("node disk scan: bun.lock parse failed: %v", err)
		return nil
	}
	out := make([]model.NodePackage, 0, len(lf.Packages))
	for key, raw := range lf.Packages {
		name, version := decodeBunEntry(key, raw)
		if name == "" || version == "" {
			continue
		}
		_, direct := directNames[name]
		out = append(out, model.NodePackage{Name: name, Version: version, IsDirect: direct})
	}
	return out
}

// decodeBunEntry resolves one packages-map entry to name and version. The
// canonical shape is an array whose first element is "name@version"; a legacy
// object shape carries {"version": "..."} and falls back to the map key for
// the name.
func decodeBunEntry(key string, raw json.RawMessage) (name, version string) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		var spec string
		if json.Unmarshal(arr[0], &spec) == nil {
			if n, v := splitAtVersion(spec); v != "" {
				return n, v
			}
		}
	}
	var obj struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Version != "" {
		return key, obj.Version
	}
	return "", ""
}

// splitAtVersion splits a "name@version" spec, treating the first '@' after any
// @scope as the boundary ("@scope/pkg@1.2.3" -> "@scope/pkg", "1.2.3").
func splitAtVersion(s string) (name, version string) {
	searchFrom := 0
	if strings.HasPrefix(s, "@") {
		searchFrom = 1
	}
	if at := strings.IndexByte(s[searchFrom:], '@'); at >= 0 {
		pos := searchFrom + at
		return s[:pos], s[pos+1:]
	}
	return s, ""
}

// stripJSONC removes // line comments, /* */ block comments, and trailing
// commas from JSONC, yielding strict JSON. Comment markers inside string
// literals are preserved (string state is tracked, honouring backslash
// escapes). Trailing commas are dropped by erasing any comma that is followed
// only by whitespace before a closing } or ]. This is a minimal sanitiser
// sufficient for bun.lock, not a general JSONC implementation.
func stripJSONC(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inString := false
	escaped := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			if i < len(in) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++ // land on '/'; loop's i++ steps past it
		case c == ',':
			// Drop a trailing comma: skip ahead past whitespace; if the next
			// non-space byte closes an object/array, omit the comma.
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\n' || in[j] == '\r') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue // skip the comma
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
