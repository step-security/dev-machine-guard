package detector

import (
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// parseYarnLock extracts installed packages from a yarn.lock (Yarn Classic v1
// and Yarn Berry v2+). The format is a custom indented block list:
//
//	"lodash@^4.17.0":            # header: one or more "name@range" descriptors
//	  version "4.17.21"          #   classic: version is a quoted field
//	"@scope/pkg@npm:^1.0.0":     # berry: protocol-qualified descriptor
//	  version: 1.2.3             #   berry: version is a bare YAML scalar
//
// A header sits at column 0 and ends with ':'; its body is indented. We take
// the package name from the (first) descriptor and pair it with the entry's
// version. Directness comes from the project's declared deps (directNames),
// since yarn.lock itself does not record it.
func (d *NodeDistDetector) parseYarnLock(data []byte, directNames map[string]struct{}) []model.NodePackage {
	var out []model.NodePackage
	curName := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' { // header (column 0)
			curName = ""
			if strings.HasSuffix(line, ":") {
				curName = yarnNameFromHeader(strings.TrimSuffix(line, ":"))
			}
			continue
		}
		// Body line. __metadata is a berry bookkeeping block, not a package.
		if curName == "" || curName == "__metadata" {
			continue
		}
		version, ok := yarnVersionField(strings.TrimSpace(line))
		if !ok {
			continue
		}
		// Skip the local workspace marker berry emits for first-party packages.
		if version == "0.0.0-use.local" {
			curName = ""
			continue
		}
		_, direct := directNames[curName]
		out = append(out, model.NodePackage{Name: curName, Version: version, IsDirect: direct})
		curName = "" // one version per entry; ignore later fields in the block
	}
	return out
}

// yarnNameFromHeader extracts the package name from a yarn.lock entry header.
// Headers may list several comma-separated descriptors and may be quoted; the
// name is everything before the version specifier, where the boundary is the
// first '@' after any @scope. Examples:
//
//	"lodash@^4.17.0, lodash@^4.17.21"  -> lodash
//	"@scope/pkg@npm:^1.0.0"            -> @scope/pkg
func yarnNameFromHeader(header string) string {
	h := strings.Trim(strings.TrimSpace(header), `"`)
	if i := strings.Index(h, ", "); i >= 0 { // first of multiple descriptors
		h = h[:i]
	}
	h = strings.Trim(strings.TrimSpace(h), `"`)
	searchFrom := 0
	if strings.HasPrefix(h, "@") {
		searchFrom = 1
	}
	if at := strings.IndexByte(h[searchFrom:], '@'); at >= 0 {
		return h[:searchFrom+at]
	}
	return h
}

// yarnVersionField parses a body line's version field, accepting both the
// classic quoted form (`version "4.17.21"`) and the berry bare form
// (`version: 4.17.21`). Returns ok=false for any other body line.
func yarnVersionField(t string) (string, bool) {
	if !strings.HasPrefix(t, "version") {
		return "", false
	}
	rest := strings.TrimSpace(t[len("version"):])
	rest = strings.TrimSpace(strings.TrimPrefix(rest, ":"))
	rest = strings.Trim(rest, `"`)
	if rest == "" {
		return "", false
	}
	return rest, true
}
