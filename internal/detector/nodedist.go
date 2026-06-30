// Disk-based Node.js package discovery.
//
// NodeDistDetector inventories installed Node packages by parsing on-disk
// lockfiles (package-lock.json / npm-shrinkwrap.json, pnpm-lock.yaml,
// yarn.lock, bun.lock) and, as a fallback, node_modules/**/package.json —
// instead of running `npm ls` / `yarn list` / `pnpm ls` / `bun pm ls`.
//
// Why parse instead of exec:
//   - Robust: no dependency on a working PM binary, correct PATH under
//     launchd/systemd, network access, or a non-broken interpreter. A
//     package manager that errors or hangs can't drop a project to zero.
//   - Complete: lockfiles carry the FULL resolved graph; the command path
//     truncated transitive deps at --depth=3.
//   - Read-only: never executes project code (no postinstall, no PnP loader).
//
// Output is intentionally minimal — {name, version, is_direct} — matching
// exactly what the backend persists (DeviceNPMPackageUsageInfo). The lockfile
// is the source of truth for the resolved set and for direct-vs-transitive;
// callers gate on an actual install (node_modules / PnP present) so a project
// that was never installed isn't reported.
//
// Security context: all reads go through the Executor (so the user-aware
// executor and test mocks both apply) and are size-bounded via maxLockfileSize
// before the bytes are pulled into memory. The node_modules walk uses
// filepath.WalkDir directly (matching nodeproject.go) and never follows
// directory symlinks, so a symlinked dependency can't redirect the walk out of
// the project tree.
package detector

import (
	"path/filepath"
	"sort"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// maxLockfileSize bounds a single lockfile / package.json read. Real lockfiles
// for large monorepos run into the low tens of MiB; this ceiling only guards
// against a pathological or hostile file exhausting memory.
const maxLockfileSize = 64 << 20 // 64 MiB

// NodeDistDetector parses installed Node packages from disk, with no
// package-manager subprocess.
type NodeDistDetector struct {
	exec        executor.Executor
	log         *progress.Logger
	skipper     *tcc.Skipper
	maxFileSize int64
}

func NewNodeDistDetector(exec executor.Executor) *NodeDistDetector {
	return &NodeDistDetector{exec: exec, log: progress.NewNoop(), maxFileSize: maxLockfileSize}
}

// WithSkipper attaches a TCC skipper so the node_modules fallback walk skips
// macOS-protected directories. A nil skipper is a no-op. Returns the detector
// for chaining.
func (d *NodeDistDetector) WithSkipper(s *tcc.Skipper) *NodeDistDetector {
	d.skipper = s
	return d
}

// WithLogger attaches a progress logger. A nil logger falls back to the no-op
// default. Returns the detector for chaining.
func (d *NodeDistDetector) WithLogger(log *progress.Logger) *NodeDistDetector {
	if log != nil {
		d.log = log
	}
	return d
}

// ScanProject returns the packages installed for a project, parsed from disk.
//
// pm is the package manager already detected for the project (see
// DetectProjectPM). It selects which lockfile parser to try first; if that
// lockfile is absent or unparseable, ScanProject falls back to walking
// node_modules. The result is de-duplicated by (name, version) and sorted by
// name then version for stable output.
func (d *NodeDistDetector) ScanProject(projectDir, pm string) []model.NodePackage {
	var pkgs []model.NodePackage

	switch pm {
	case "bun":
		pkgs = d.parseFirstPresent(projectDir, d.parseBunLock, "bun.lock")
	case "pnpm":
		pkgs = d.parseFirstPresent(projectDir, d.parsePnpmLock, "pnpm-lock.yaml")
	case "yarn", "yarn-berry":
		pkgs = d.parseFirstPresent(projectDir, d.parseYarnLock, "yarn.lock")
	default: // "npm" and anything unrecognised
		pkgs = d.parseFirstPresent(projectDir, d.parsePackageLock, "package-lock.json", "npm-shrinkwrap.json")
	}

	// Fallback: no parseable lockfile (e.g. bun.lockb binary format, a yarn
	// PnP project whose yarn.lock we couldn't read, or a tree installed
	// without a lockfile). Read whatever is actually on disk in node_modules.
	if len(pkgs) == 0 {
		pkgs = d.walkNodeModules(projectDir)
	}

	return dedupSortPackages(pkgs)
}

// lockfileParser parses one lockfile's bytes into packages. directNames carries
// the project's declared direct dependencies (from package.json), used by
// parsers whose lockfile format does not itself encode directness.
type lockfileParser func(data []byte, directNames map[string]struct{}) []model.NodePackage

// parseFirstPresent reads direct-dependency names once, then tries each
// candidate lockfile name in priority order, returning the first that parses
// to a non-empty package set.
func (d *NodeDistDetector) parseFirstPresent(projectDir string, parse lockfileParser, candidates ...string) []model.NodePackage {
	directNames := d.directDepNames(projectDir)
	for _, name := range candidates {
		data, ok := d.readBounded(filepath.Join(projectDir, name))
		if !ok {
			continue
		}
		if pkgs := parse(data, directNames); len(pkgs) > 0 {
			return pkgs
		}
	}
	return nil
}

// readBounded reads path through the executor, rejecting files larger than the
// size cap. The size is checked via Stat before the read so a pathological
// file is never pulled into memory; the post-read length check is a race-safety
// fallback (the file can grow between Stat and ReadFile). Returns ok=false for
// a missing, oversized, or unreadable file.
func (d *NodeDistDetector) readBounded(path string) (data []byte, ok bool) {
	if d.maxFileSize > 0 {
		if info, err := d.exec.Stat(path); err == nil && info.Size() > d.maxFileSize {
			d.log.Debug("node disk scan: %s exceeds %d bytes — skipping", path, d.maxFileSize)
			return nil, false
		}
	}
	b, err := d.exec.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if d.maxFileSize > 0 && int64(len(b)) > d.maxFileSize {
		d.log.Debug("node disk scan: %s exceeds %d bytes — skipping", path, d.maxFileSize)
		return nil, false
	}
	return b, true
}

// directDepNames returns the set of dependency names declared directly in the
// project's package.json (dependencies + devDependencies + optional + peer).
// Used to mark is_direct for lockfile formats (yarn, bun) and the node_modules
// walk that don't otherwise distinguish direct from transitive. Returns an
// empty (non-nil) set when package.json is missing or unparseable, so callers
// can treat "not found" as "not direct" without nil checks.
func (d *NodeDistDetector) directDepNames(projectDir string) map[string]struct{} {
	out := make(map[string]struct{})
	data, ok := d.readBounded(filepath.Join(projectDir, "package.json"))
	if !ok {
		return out
	}
	for _, m := range parsePackageJSONDepMaps(data) {
		for name := range m {
			out[name] = struct{}{}
		}
	}
	return out
}

// dedupSortPackages collapses duplicate (name, version) pairs — the same
// package can be reachable via multiple paths in a lockfile — and sorts by name
// then version for deterministic output. When duplicates disagree on
// directness, direct wins (a package that is a direct dependency anywhere is
// reported as direct).
func dedupSortPackages(pkgs []model.NodePackage) []model.NodePackage {
	if len(pkgs) == 0 {
		return nil
	}
	type key struct{ name, version string }
	idx := make(map[key]int, len(pkgs))
	out := make([]model.NodePackage, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		k := key{p.Name, p.Version}
		if i, ok := idx[k]; ok {
			if p.IsDirect {
				out[i].IsDirect = true
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out
}
