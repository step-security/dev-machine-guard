package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// walkNodeModules is the fallback when no parseable lockfile exists: it reads
// every installed package's own package.json under <projectDir>/node_modules
// and reports the actual installed name@version. A package is marked direct
// when its name appears in the project's declared dependencies.
//
// This covers npm / yarn-classic (real nested node_modules) and pnpm (whose
// real package dirs live under node_modules/.pnpm/<store>/node_modules/<pkg>);
// the "last node_modules segment" rule in isNodeModulesPackagePath matches all
// of them. yarn-berry PnP installs have no node_modules and rely on the
// yarn.lock parser instead.
func (d *NodeDistDetector) walkNodeModules(projectDir string) []model.NodePackage {
	directNames := d.directDepNames(projectDir)
	return d.scanModulesTree(filepath.Join(projectDir, "node_modules"),
		func(name, _ string) bool { _, ok := directNames[name]; return ok })
}

// scanModulesTree reads every installed package's package.json under a
// node_modules root and reports name@version. isDirect decides directness per
// package from its name and full path (project scans key on declared deps;
// global scans key on top-level position — see ScanGlobalModules). The walk
// never follows directory symlinks (filepath.WalkDir does not), so pnpm's
// symlink farm is read via the real .pnpm store dirs, not by chasing links out
// of the tree.
func (d *NodeDistDetector) scanModulesTree(root string, isDirect func(name, path string) bool) []model.NodePackage {
	if !d.exec.DirExists(root) {
		return nil
	}
	var pkgs []model.NodePackage
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if d.skipper.ShouldSkip(path, root) {
				return filepath.SkipDir
			}
			// .bin holds symlinked CLI shims; .cache is npm's build cache.
			// Neither contains installed-package metadata.
			if name := entry.Name(); name == ".bin" || name == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "package.json" || !isNodeModulesPackagePath(path) {
			return nil
		}
		data, ok := d.readBounded(path)
		if !ok {
			return nil
		}
		name, version := packageJSONNameVersion(data)
		if name == "" || version == "" {
			return nil
		}
		pkgs = append(pkgs, model.NodePackage{Name: name, Version: version, IsDirect: isDirect(name, path)})
		return nil
	})
	return pkgs
}

// ScanGlobalModules reads a global node_modules directory (e.g. an npm prefix's
// lib/node_modules, or pnpm's global store), reporting installed packages. A
// package is direct when it sits immediately under the global root (a package
// the user installed with `-g`); anything below a further node_modules is a
// transitive dependency of one of those.
func (d *NodeDistDetector) ScanGlobalModules(nmRoot string) []model.NodePackage {
	clean := filepath.Clean(nmRoot)
	return d.scanModulesTree(clean, func(_, path string) bool {
		rel := strings.TrimPrefix(filepath.ToSlash(path), filepath.ToSlash(clean))
		return !strings.Contains(rel, "node_modules/")
	})
}

// isNodeModulesPackagePath reports whether a package.json path is a package
// root inside node_modules — i.e. the path tail after the LAST "node_modules"
// segment is exactly <pkg>/package.json or @scope/<pkg>/package.json. This
// rejects package.json files nested deeper inside a package's own source/test
// fixtures (which are not installed dependencies), while accepting both
// hoisted and pnpm-store layouts. Using the last segment handles nesting like
// node_modules/a/node_modules/b and node_modules/.pnpm/x@1/node_modules/x.
func isNodeModulesPackagePath(path string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	nmIdx := -1
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "node_modules" {
			nmIdx = i
			break
		}
	}
	if nmIdx == -1 {
		return false
	}
	tail := parts[nmIdx+1:] // segments after the last node_modules, incl. "package.json"
	switch len(tail) {
	case 2: // <pkg>/package.json — must NOT be a scope dir
		return tail[1] == "package.json" && !strings.HasPrefix(tail[0], "@")
	case 3: // @scope/<pkg>/package.json
		return tail[2] == "package.json" && strings.HasPrefix(tail[0], "@")
	default:
		return false
	}
}

// packageJSONNameVersion extracts the name and version from a package.json.
// Both are required for a usable inventory record; a private/workspace
// package.json missing either is treated as not-a-package by the caller.
func packageJSONNameVersion(data []byte) (name, version string) {
	var pj struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return "", ""
	}
	return strings.TrimSpace(pj.Name), strings.TrimSpace(pj.Version)
}

// parsePackageJSONDepMaps returns the four dependency maps a package.json can
// declare. Order is irrelevant — callers only use the union of key names to
// decide directness.
func parsePackageJSONDepMaps(data []byte) []map[string]string {
	var pj struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil
	}
	return []map[string]string{pj.Dependencies, pj.DevDependencies, pj.OptionalDependencies, pj.PeerDependencies}
}
