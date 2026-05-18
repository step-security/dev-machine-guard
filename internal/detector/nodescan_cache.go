package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

const scanCacheVersion = 1

// cacheEntry is one project's cached scan result, used to skip re-running
// `npm/yarn/pnpm/bun ls` when neither package.json nor the lockfile has been
// modified since LastScanUnix.
type cacheEntry struct {
	PackageManager string               `json:"package_manager"`
	LastScanUnix   int64                `json:"last_scan_unix"`
	CachedResult   model.NodeScanResult `json:"cached_result"`
}

type scanCache struct {
	Version  int                   `json:"version"`
	Projects map[string]cacheEntry `json:"projects"`
}

func newScanCache() *scanCache {
	return &scanCache{Version: scanCacheVersion, Projects: map[string]cacheEntry{}}
}

// scanCachePath returns the on-disk path for the per-project scan cache.
// Override with STEPSEC_NODE_SCAN_CACHE for tests / non-root runs.
func scanCachePath(exec executor.Executor) string {
	if override := exec.Getenv("STEPSEC_NODE_SCAN_CACHE"); override != "" {
		return override
	}
	if exec.GOOS() == "windows" {
		return filepath.Join(`C:\ProgramData\StepSecurity\dev-machine-guard`, "scan-cache.json")
	}
	return "/var/lib/stepsecurity/dev-machine-guard/scan-cache.json"
}

// loadScanCache reads the cache file. Returns an empty cache on miss or any
// parse error — a corrupt cache must never break a scan, only force a full one.
func loadScanCache(path string) *scanCache {
	data, err := os.ReadFile(path)
	if err != nil {
		return newScanCache()
	}
	var c scanCache
	if err := json.Unmarshal(data, &c); err != nil || c.Version != scanCacheVersion {
		return newScanCache()
	}
	if c.Projects == nil {
		c.Projects = map[string]cacheEntry{}
	}
	return &c
}

// save writes the cache atomically (write to tmp, rename).
func (c *scanCache) save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".scan-cache-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
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

// lockfileFor returns the path of the lockfile for the given package manager
// in projectDir, or "" if no expected lockfile is present.
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

// mtimeOr0 returns the file's mtime in unix seconds, or 0 if it can't be stat'd.
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

// scanWorkerCount returns the number of concurrent project scans to dispatch.
// Defaults to min(NumCPU, 8). Override with STEPSEC_NODE_SCAN_WORKERS.
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
