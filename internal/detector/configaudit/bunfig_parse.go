package configaudit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// parseBunfig parses a bunfig.toml payload into ordered BunSections. Each
// nested TOML table becomes a section keyed by its dotted path; scalar leaves
// hang off the nearest enclosing section.
//
// Parser is tolerant: a malformed file returns ([], error) and the caller
// surfaces the error as ParseError on the file record without dropping the
// rest of the audit.
func parseBunfig(data []byte) ([]model.BunSection, error) {
	var root map[string]any
	if err := toml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("toml: %w", err)
	}

	sections := map[string]*model.BunSection{
		"": {Name: ""},
	}
	walkBunfig(sections, "", root)

	// Stable order: top-level "" first, then nested sections in dotted-path order.
	order := make([]string, 0, len(sections))
	for k := range sections {
		order = append(order, k)
	}
	sort.Strings(order)

	out := make([]model.BunSection, 0, len(sections))
	for _, name := range order {
		s := sections[name]
		// Skip the root-bucket only if it has no scalar entries (otherwise we
		// drop top-level keys that don't live inside a [section] header).
		if name == "" && len(s.Entries) == 0 {
			continue
		}
		out = append(out, *s)
	}
	return out, nil
}

// walkBunfig descends through the decoded TOML tree, lifting scalars into
// the section keyed by their dotted ancestor path and recursing into nested
// tables (and tables-of-tables, surfaced as map[string]any by go-toml/v2).
func walkBunfig(sections map[string]*model.BunSection, prefix string, node map[string]any) {
	for k, v := range node {
		switch typed := v.(type) {
		case map[string]any:
			nested := joinSection(prefix, k)
			if _, ok := sections[nested]; !ok {
				sections[nested] = &model.BunSection{Name: nested}
			}
			walkBunfig(sections, nested, typed)
		default:
			s, ok := sections[prefix]
			if !ok {
				s = &model.BunSection{Name: prefix}
				sections[prefix] = s
			}
			s.Entries = append(s.Entries, buildBunEntry(k, typed))
		}
	}
}

func joinSection(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// buildBunEntry classifies a TOML key/value into an NPMRCEntry. Auth keys
// (token / password / username) under [install.scopes.*] / [install.registry]
// are detected and redacted; env-ref substrings (`${VAR}`) are preserved.
//
// go-toml/v2 does not cheaply expose per-key line numbers, so LineNum stays
// 0 for bun entries — documented on BunSection.
func buildBunEntry(key string, value any) model.NPMRCEntry {
	raw := stringifyBunValue(value)
	isAuth := isBunAuthKey(key)
	envRefVars, isEnvRef := extractEnvRefs(raw)

	display := raw
	if isAuth && !isEnvRef && raw != "" {
		display = redactSecret(raw)
	}

	return model.NPMRCEntry{
		Key:          key,
		DisplayValue: display,
		IsAuth:       isAuth,
		IsEnvRef:     isEnvRef,
		EnvRefVars:   envRefVars,
		ValueSHA256:  hashValue(raw),
		Quoted:       true, // TOML strings are always quoted; non-strings stringified
	}
}

// stringifyBunValue renders any TOML scalar (string, bool, int, float, array)
// into a printable form. Arrays render `["a", "b"]`; everything else uses
// fmt's %v.
func stringifyBunValue(v any) string {
	switch typed := v.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, stringifyBunValue(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprintf("%v", typed)
	}
}

// bunAuthKeys are the leaf names that indicate a credential. Lowercase
// comparison; matched on the last segment only since bun nests creds under
// dotted section paths (install.scopes.@foo.token).
var bunAuthKeys = map[string]bool{
	"token":    true,
	"password": true,
	"username": true,
}

func isBunAuthKey(key string) bool {
	return bunAuthKeys[strings.ToLower(key)]
}
