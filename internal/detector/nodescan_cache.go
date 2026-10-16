package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/paths"
)

// scanCacheVersion is bumped when the on-disk format changes. A loaded entry
// from a previous version is silently discarded — the next run pays a fresh
// scan rather than risking a misinterpreted cached body.
const scanCacheVersion = 2

// scanCacheEntry is one project's cached scan result keyed by directory. The
// three mtimes (package.json, lockfile, node_modules) are the invalidation
// signals: if any post-dates LastScanUnix the cache is stale and the PM CLI
// must run fresh. AgentVersion pins the entry to the binary that produced it
// so post-upgrade runs always re-scan.
type scanCacheEntry struct {
	PackageManager   string               `json:"package_manager"`
	LastScanUnix     int64                `json:"last_scan_unix"`
	PackageJSONMtime int64                `json:"package_json_mtime"`
	LockfileMtime    int64                `json:"lockfile_mtime"`
	NodeModulesMtime int64                `json:"node_modules_mtime"`
	AgentVersion     string               `json:"agent_version"`
	CachedResult     model.NodeScanResult `json:"cached_result"`
}

type scanCache struct {
	Version  int                       `json:"version"`
	Projects map[string]scanCacheEntry `json:"projects"`
}

func newScanCache() *scanCache {
	return &scanCache{Version: scanCacheVersion, Projects: map[string]scanCacheEntry{}}
}

// scanCacheFile returns the cache path under paths.Home(). Returns "" when
// Home is disabled — caller must treat "" as "cache disabled, scan everything".
// Override with STEPSEC_NODE_SCAN_CACHE for tests.
func scanCacheFile(exec executor.Executor) string {
	if override := exec.Getenv("STEPSEC_NODE_SCAN_CACHE"); override != "" {
		return override
	}
	home := paths.Home()
	if home == "" {
		return ""
	}
	return filepath.Join(home, "node-scan-cache.json")
}

// loadScanCache reads the cache file. Returns an empty cache on any failure
// (missing, parse error, schema mismatch) so a corrupt cache only forces a
// full scan, never breaks a run.
func loadScanCache(path string) *scanCache {
	if path == "" {
		return newScanCache()
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return newScanCache()
	}
	var c scanCache
	if err := json.Unmarshal(data, &c); err != nil || c.Version != scanCacheVersion {
		return newScanCache()
	}
	if c.Projects == nil {
		c.Projects = map[string]scanCacheEntry{}
	}
	return &c
}

func (c *scanCache) save(path string) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".node-scan-cache-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

// lockfileFor returns the path of the PM's lockfile in projectDir, or "" if
// the expected lockfile isn't present. Used as one of the cache invalidation
// signals.
func lockfileFor(exec executor.Executor, projectDir, pm string) string {
	var names []string
	switch pm {
	case "npm":
		names = []string{"package-lock.json"}
	case "yarn", "yarn-berry":
		names = []string{"yarn.lock"}
	case "pnpm":
		names = []string{"pnpm-lock.yaml"}
	case "bun":
		names = []string{"bun.lock", "bun.lockb"}
	default:
		return ""
	}
	for _, n := range names {
		p := filepath.Join(projectDir, n)
		if exec.FileExists(p) {
			return p
		}
	}
	return ""
}

// mtimeOr0 returns the file's mtime in unix seconds, or 0 if it can't be
// stat'd. Used both for cache writes (capture current state) and cache reads
// (compare to LastScanUnix).
func mtimeOr0(exec executor.Executor, path string) int64 {
	if path == "" {
		return 0
	}
	info, err := exec.Stat(path)
	if err != nil {
		return 0
	}
	return info.ModTime().Unix()
}

// cacheValidFor reports whether the cached entry can be reused for projectDir.
// Three guards:
//   - PM unchanged (lockfile detection must agree with the cached entry)
//   - Agent version unchanged (defensive against parsing-format drift)
//   - All three mtimes ≤ LastScanUnix (package.json, lockfile, node_modules).
//     The node_modules check catches `rm -rf node_modules/foo` cases where
//     the lockfile alone doesn't move.
//
// `bypass` short-circuits to false. The caller passes true during forced
// full syncs so the wire-shipped bodies match what the PM CLI sees right now.
func cacheValidFor(
	exec executor.Executor, entry scanCacheEntry,
	projectDir, pm, agentVersion string, bypass bool,
) bool {
	if bypass {
		return false
	}
	if entry.PackageManager != pm {
		return false
	}
	if entry.AgentVersion != agentVersion {
		return false
	}
	lockPath := lockfileFor(exec, projectDir, pm)
	if lockPath == "" {
		// No lockfile means there's nothing reliable to mtime-check; always re-scan.
		return false
	}
	pkgMt := mtimeOr0(exec, filepath.Join(projectDir, "package.json"))
	lockMt := mtimeOr0(exec, lockPath)
	nmMt := mtimeOr0(exec, filepath.Join(projectDir, "node_modules"))
	return pkgMt <= entry.LastScanUnix &&
		lockMt <= entry.LastScanUnix &&
		nmMt <= entry.LastScanUnix
}

// scanWorkerCount returns how many concurrent project scans to dispatch.
// min(NumCPU, 8) by default. Override with STEPSEC_NODE_SCAN_WORKERS.
func scanWorkerCount(exec executor.Executor) int {
	if v := exec.Getenv("STEPSEC_NODE_SCAN_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	return n
}
