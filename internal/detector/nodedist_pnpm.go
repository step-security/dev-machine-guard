package detector

import (
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// parsePnpmLock extracts installed packages from a pnpm-lock.yaml.
//
// It is a deliberate line scanner, not a YAML unmarshal: pnpm lockfiles are
// large and we only need the top-level `packages:` block's keys. Each key
// encodes name@version across pnpm's lockfile generations:
//
//	v9:      foo@1.2.3:            @scope/foo@1.2.3:
//	v6:      /foo@1.2.3:           /foo@1.2.3(react@18.0.0):   /@scope/foo@1.2.3:
//	v5:      /foo/1.2.3:           /@scope/foo/1.2.3:
//
// Only keys at exactly two-space indent inside `packages:` are entries; nested
// fields (resolution, engines, …) sit at four+ spaces and are ignored, and
// sibling top-level blocks (importers:, snapshots:, settings:) end the scan of
// the packages block. Directness is taken from the project's declared deps
// (directNames), since the resolved `packages:` block does not mark it.
func (d *NodeDistDetector) parsePnpmLock(data []byte, directNames map[string]struct{}) []model.NodePackage {
	var out []model.NodePackage
	inPackages := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		body := line[indent:]

		if indent == 0 {
			// A new top-level block: we're in `packages:` only while this is it.
			inPackages = strings.HasPrefix(body, "packages:")
			continue
		}
		if !inPackages || indent != 2 || !strings.HasSuffix(body, ":") {
			continue
		}
		key := strings.Trim(strings.TrimSuffix(body, ":"), `'"`)
		name, version := parsePnpmPackageKey(key)
		if name == "" || version == "" {
			continue
		}
		_, direct := directNames[name]
		out = append(out, model.NodePackage{Name: name, Version: version, IsDirect: direct})
	}
	return out
}

// parsePnpmPackageKey splits a pnpm packages-block key into name and version,
// handling the leading slash (v5/v6), the @scope prefix, peer-dependency
// suffixes ("(react@18.0.0)" in v6/v9, "_react@18.0.0" in v5), and the legacy
// slash separator ("/foo/1.2.3"). The first '@' after any scope is the
// name/version boundary; absent one, a trailing "/version" is assumed.
func parsePnpmPackageKey(key string) (name, version string) {
	key = strings.TrimPrefix(key, "/")
	if i := strings.IndexByte(key, '('); i >= 0 { // strip "(peer@x)" suffix
		key = key[:i]
	}
	if key == "" {
		return "", ""
	}
	searchFrom := 0
	if key[0] == '@' { // skip the scope '@' so the version '@' is found
		searchFrom = 1
	}
	if at := strings.IndexByte(key[searchFrom:], '@'); at >= 0 {
		pos := searchFrom + at
		name, version = key[:pos], key[pos+1:]
	} else if sl := strings.LastIndexByte(key, '/'); sl >= 0 {
		name, version = key[:sl], key[sl+1:] // legacy v5 "name/version"
	} else {
		return "", ""
	}
	if i := strings.IndexByte(version, '_'); i >= 0 { // strip "_peer@x" (v5)
		version = version[:i]
	}
	return name, version
}
