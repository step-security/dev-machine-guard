package detector

import (
	"encoding/json"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// npmLock is the union of the two package-lock.json / npm-shrinkwrap.json
// shapes. lockfileVersion 1 uses the nested `dependencies` tree; versions 2
// and 3 use the flat `packages` map keyed by install path. A v2 lockfile
// carries both for backwards compatibility, so `packages` is preferred when
// present (it is authoritative and avoids double-counting the tree).
type npmLock struct {
	Packages     map[string]npmLockPkg   `json:"packages"`     // v2/v3
	Dependencies map[string]npmLockDepV1 `json:"dependencies"` // v1
}

type npmLockPkg struct {
	Version string `json:"version"`
	Name    string `json:"name"` // set for aliased installs; key is authoritative otherwise
	Link    bool   `json:"link"` // true for workspace symlinks — not an installed version
}

type npmLockDepV1 struct {
	Version      string                  `json:"version"`
	Dependencies map[string]npmLockDepV1 `json:"dependencies"`
}

// parsePackageLock parses an npm lockfile into installed packages.
//
// Directness is taken from directNames (the project's declared deps), NOT from
// lockfile structure: npm hoists transitive packages to the top of
// node_modules, so install-path depth (and the v1 tree's top level) marks
// hoisted transitives as direct. Matching declared deps mirrors the tree
// top-level that `npm ls` — the command path we are replacing — reports as
// direct.
func (d *NodeDistDetector) parsePackageLock(data []byte, directNames map[string]struct{}) []model.NodePackage {
	var lf npmLock
	if err := json.Unmarshal(data, &lf); err != nil {
		d.log.Debug("node disk scan: package-lock parse failed: %v", err)
		return nil
	}
	if len(lf.Packages) > 0 {
		return npmPackagesFromV2(lf.Packages, directNames)
	}
	if len(lf.Dependencies) > 0 {
		var out []model.NodePackage
		collectNpmV1(lf.Dependencies, directNames, &out)
		return out
	}
	return nil
}

// npmPackagesFromV2 flattens the v2/v3 `packages` map. Keys are install paths:
//   - ""                                  → the project root (skipped)
//   - "node_modules/foo"                  → a hoisted/top-level install
//   - "node_modules/a/node_modules/b"     → a nested install
//   - "packages/ui"                       → a workspace member (no node_modules
//     segment; skipped — it's first-party, not an installed dependency)
func npmPackagesFromV2(packages map[string]npmLockPkg, directNames map[string]struct{}) []model.NodePackage {
	out := make([]model.NodePackage, 0, len(packages))
	for key, p := range packages {
		if key == "" || p.Link || !strings.Contains(key, "node_modules/") {
			continue
		}
		name := nameFromPackagesKey(key, p.Name)
		if name == "" || p.Version == "" {
			continue
		}
		_, direct := directNames[name]
		out = append(out, model.NodePackage{Name: name, Version: p.Version, IsDirect: direct})
	}
	return out
}

// nameFromPackagesKey extracts the package name from a v2/v3 install-path key,
// preferring the explicit `name` field (set for aliased installs). For the key
// it takes the segment(s) after the LAST node_modules, preserving an @scope.
func nameFromPackagesKey(key, explicit string) string {
	if explicit != "" {
		return explicit
	}
	idx := strings.LastIndex(key, "node_modules/")
	if idx == -1 {
		return ""
	}
	tail := key[idx+len("node_modules/"):]
	if strings.HasPrefix(tail, "@") {
		// Scoped: keep "@scope/name", drop any deeper path.
		segs := strings.SplitN(tail, "/", 3)
		if len(segs) < 2 {
			return ""
		}
		return segs[0] + "/" + segs[1]
	}
	if i := strings.IndexByte(tail, '/'); i >= 0 {
		return tail[:i]
	}
	return tail
}

// collectNpmV1 walks the lockfileVersion-1 nested dependency tree, emitting one
// record per node. Directness is by declared-dep membership (see
// parsePackageLock), not tree position — the v1 tree mirrors the hoisted
// node_modules layout, so a top-level node can still be a transitive package.
// An entry without a concrete version is skipped but still recursed into.
func collectNpmV1(deps map[string]npmLockDepV1, directNames map[string]struct{}, out *[]model.NodePackage) {
	for name, dep := range deps {
		if dep.Version != "" {
			_, direct := directNames[name]
			*out = append(*out, model.NodePackage{Name: name, Version: dep.Version, IsDirect: direct})
		}
		if len(dep.Dependencies) > 0 {
			collectNpmV1(dep.Dependencies, directNames, out)
		}
	}
}
