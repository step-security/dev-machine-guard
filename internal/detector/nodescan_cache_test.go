package detector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestScanCache_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-scan-cache.json")

	c := newScanCache()
	c.Projects["/app"] = scanCacheEntry{
		PackageManager:   "npm",
		LastScanUnix:     1700000000,
		PackageJSONMtime: 1700000000,
		LockfileMtime:    1700000000,
		NodeModulesMtime: 1700000000,
		AgentVersion:     buildinfo.Version,
		CachedResult: model.NodeScanResult{
			ProjectPath:     "/app",
			PackageManager:  "npm",
			RawStdoutBase64: "eyJkZXBzIjpbXX0=",
			ExitCode:        0,
		},
	}
	if err := c.save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded := loadScanCache(path)
	if loaded.Version != scanCacheVersion {
		t.Errorf("version: got %d, want %d", loaded.Version, scanCacheVersion)
	}
	entry, ok := loaded.Projects["/app"]
	if !ok {
		t.Fatal("missing /app entry after reload")
	}
	if entry.LastScanUnix != 1700000000 || entry.PackageManager != "npm" {
		t.Errorf("entry mismatch: %+v", entry)
	}
}

func TestScanCache_MissReturnsEmpty(t *testing.T) {
	c := loadScanCache(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if c == nil || c.Projects == nil {
		t.Fatal("expected non-nil empty cache on miss")
	}
	if len(c.Projects) != 0 {
		t.Errorf("expected empty projects map on miss, got %d entries", len(c.Projects))
	}
}

func TestScanCache_CorruptReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-scan-cache.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := loadScanCache(path)
	if len(c.Projects) != 0 {
		t.Errorf("expected empty cache after corrupt read, got %d entries", len(c.Projects))
	}
}

func TestScanCache_WrongVersionReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-scan-cache.json")
	if err := os.WriteFile(path, []byte(`{"version":999,"projects":{"/a":{"package_manager":"npm","last_scan_unix":1}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c := loadScanCache(path)
	if len(c.Projects) != 0 {
		t.Errorf("expected empty cache on version mismatch, got %d entries", len(c.Projects))
	}
}

func TestLockfileFor(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile(filepath.Join("/proj-npm", "package-lock.json"), []byte{})
	mock.SetFile(filepath.Join("/proj-yarn", "yarn.lock"), []byte{})
	mock.SetFile(filepath.Join("/proj-pnpm", "pnpm-lock.yaml"), []byte{})
	mock.SetFile(filepath.Join("/proj-bun", "bun.lockb"), []byte{})

	cases := []struct {
		dir, pm, want string
	}{
		{"/proj-npm", "npm", filepath.Join("/proj-npm", "package-lock.json")},
		{"/proj-yarn", "yarn", filepath.Join("/proj-yarn", "yarn.lock")},
		{"/proj-yarn", "yarn-berry", filepath.Join("/proj-yarn", "yarn.lock")},
		{"/proj-pnpm", "pnpm", filepath.Join("/proj-pnpm", "pnpm-lock.yaml")},
		{"/proj-bun", "bun", filepath.Join("/proj-bun", "bun.lockb")},
		{"/missing", "npm", ""},
		{"/proj-npm", "unknown", ""},
	}
	for _, c := range cases {
		got := lockfileFor(mock, c.dir, c.pm)
		if got != c.want {
			t.Errorf("lockfileFor(%q,%q): got %q, want %q", c.dir, c.pm, got, c.want)
		}
	}
}

func TestCacheValidFor_HitWhenMtimesUnchanged(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFileMtime(filepath.Join("/p", "package.json"), 100)
	mock.SetFileMtime(filepath.Join("/p", "package-lock.json"), 100)
	mock.SetFileMtime(filepath.Join("/p", "node_modules"), 100)

	entry := scanCacheEntry{PackageManager: "npm", LastScanUnix: 200, AgentVersion: buildinfo.Version}
	if !cacheValidFor(mock, entry, "/p", "npm", buildinfo.Version, false) {
		t.Error("expected hit when all mtimes <= LastScanUnix")
	}
}

func TestCacheValidFor_MissWhenLockfileNewer(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFileMtime(filepath.Join("/p", "package.json"), 100)
	mock.SetFileMtime(filepath.Join("/p", "package-lock.json"), 300) // newer than LastScanUnix
	mock.SetFileMtime(filepath.Join("/p", "node_modules"), 100)

	entry := scanCacheEntry{PackageManager: "npm", LastScanUnix: 200, AgentVersion: buildinfo.Version}
	if cacheValidFor(mock, entry, "/p", "npm", buildinfo.Version, false) {
		t.Error("expected miss when lockfile mtime > LastScanUnix")
	}
}

func TestCacheValidFor_MissWhenNodeModulesNewer(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFileMtime(filepath.Join("/p", "package.json"), 100)
	mock.SetFileMtime(filepath.Join("/p", "package-lock.json"), 100)
	mock.SetFileMtime(filepath.Join("/p", "node_modules"), 300) // user did `rm -rf node_modules/foo`

	entry := scanCacheEntry{PackageManager: "npm", LastScanUnix: 200, AgentVersion: buildinfo.Version}
	if cacheValidFor(mock, entry, "/p", "npm", buildinfo.Version, false) {
		t.Error("expected miss when node_modules mtime > LastScanUnix (rm -rf node_modules/foo case)")
	}
}

func TestCacheValidFor_MissWhenNoLockfile(t *testing.T) {
	// Project without a lockfile — nothing to mtime-check authoritatively.
	mock := executor.NewMock()
	mock.SetFileMtime(filepath.Join("/p", "package.json"), 100)

	entry := scanCacheEntry{PackageManager: "npm", LastScanUnix: 200, AgentVersion: buildinfo.Version}
	if cacheValidFor(mock, entry, "/p", "npm", buildinfo.Version, false) {
		t.Error("expected miss when no lockfile present (can't trust mtimes)")
	}
}

func TestCacheValidFor_MissOnAgentVersionDrift(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFileMtime(filepath.Join("/p", "package.json"), 100)
	mock.SetFileMtime(filepath.Join("/p", "package-lock.json"), 100)
	mock.SetFileMtime(filepath.Join("/p", "node_modules"), 100)

	entry := scanCacheEntry{PackageManager: "npm", LastScanUnix: 200, AgentVersion: "1.10.0"}
	if cacheValidFor(mock, entry, "/p", "npm", "1.13.0", false) {
		t.Error("expected miss on agent version drift")
	}
}

func TestCacheValidFor_MissOnPMChange(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFileMtime(filepath.Join("/p", "yarn.lock"), 100)
	mock.SetFileMtime(filepath.Join("/p", "package.json"), 100)
	mock.SetFileMtime(filepath.Join("/p", "node_modules"), 100)

	entry := scanCacheEntry{PackageManager: "npm", LastScanUnix: 200, AgentVersion: buildinfo.Version}
	if cacheValidFor(mock, entry, "/p", "yarn", buildinfo.Version, false) {
		t.Error("expected miss when cached PM differs from current detection")
	}
}

func TestCacheValidFor_BypassShortCircuits(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFileMtime(filepath.Join("/p", "package.json"), 100)
	mock.SetFileMtime(filepath.Join("/p", "package-lock.json"), 100)
	mock.SetFileMtime(filepath.Join("/p", "node_modules"), 100)

	entry := scanCacheEntry{PackageManager: "npm", LastScanUnix: 200, AgentVersion: buildinfo.Version}
	if cacheValidFor(mock, entry, "/p", "npm", buildinfo.Version, true) {
		t.Error("bypass=true must always miss")
	}
}

func TestPruneCacheToDiscovered_KeepsOnlyDiscovered(t *testing.T) {
	c := newScanCache()
	c.Projects["/a"] = scanCacheEntry{}
	c.Projects["/b"] = scanCacheEntry{}
	c.Projects["/c"] = scanCacheEntry{}

	pruneCacheToDiscovered(c, []projectEntry{{dir: "/a"}, {dir: "/c"}})

	if _, ok := c.Projects["/a"]; !ok {
		t.Error("/a should be kept")
	}
	if _, ok := c.Projects["/b"]; ok {
		t.Error("/b should be pruned (not discovered)")
	}
	if _, ok := c.Projects["/c"]; !ok {
		t.Error("/c should be kept")
	}
}

func TestScanWorkerCount_HonorsEnvOverride(t *testing.T) {
	mock := executor.NewMock()
	mock.SetEnv("STEPSEC_NODE_SCAN_WORKERS", "3")
	if got := scanWorkerCount(mock); got != 3 {
		t.Errorf("expected 3 workers from env, got %d", got)
	}
}

func TestScanWorkerCount_DefaultPositive(t *testing.T) {
	mock := executor.NewMock()
	if got := scanWorkerCount(mock); got < 1 {
		t.Errorf("default worker count must be >= 1, got %d", got)
	}
}
