package configaudit

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// parseYarnBerry parses `.yarnrc.yml`. Nested maps flatten to dotted keys
// so a single YarnEntry slice carries both flavors, e.g.
//
//	npmScopes:
//	  "@step-security":
//	    npmAuthToken: ${COMPANY_TOKEN}
//
// → `npmScopes.@step-security.npmAuthToken = ${COMPANY_TOKEN}`.
func parseYarnBerry(data []byte) ([]model.YarnEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	flat := flattenYarnBerry("", root)

	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]model.YarnEntry, 0, len(keys))
	for _, k := range keys {
		v := flat[k]
		out = append(out, buildYarnEntry(k, v, true, 0))
	}
	return out, nil
}

// flattenYarnBerry returns dotted-path leaves from a yaml.v3 decoded tree.
// Arrays serialize as `[a, b, c]`.
func flattenYarnBerry(prefix string, node map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range node {
		key := joinYarnKey(prefix, k)
		switch typed := v.(type) {
		case map[string]any:
			for kk, vv := range flattenYarnBerry(key, typed) {
				out[kk] = vv
			}
		default:
			out[key] = stringifyYarnValue(typed)
		}
	}
	return out
}

func joinYarnKey(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// stringifyYarnValue renders a YAML scalar or array. Arrays → `[a, b]`,
// nil → "", everything else → fmt %v.
func stringifyYarnValue(v any) string {
	switch typed := v.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, stringifyYarnValue(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprintf("%v", typed)
	}
}

// yarnBerryAuthSuffixes: leaf-key names that denote credentials, typically
// nested under `npmScopes.*` / `npmRegistries.*`.
var yarnBerryAuthSuffixes = []string{
	"npmauthtoken",
	"npmauthident",
	"password",
}

func isYarnBerryAuthKey(key string) bool {
	last := key
	if idx := strings.LastIndex(key, "."); idx >= 0 {
		last = key[idx+1:]
	}
	last = strings.ToLower(last)
	for _, s := range yarnBerryAuthSuffixes {
		if last == s {
			return true
		}
	}
	return false
}
