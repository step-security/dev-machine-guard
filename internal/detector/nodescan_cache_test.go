package detector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestScanCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan-cache.json")

	c := newScanCache()
	c.Projects["/app"] = cacheEntry{
		PackageManager: "npm",
		LastScanUnix:   1700000000,
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
	if entry.CachedResult.RawStdoutBase64 != "eyJkZXBzIjpbXX0=" {
		t.Errorf("cached result lost: %+v", entry.CachedResult)
	}
}

func TestScanCache_MissReturnsEmpty(t *testing.T) {
	c := loadScanCache(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if c == nil || c.Projects == nil {
		t.Fatal("expected non-nil empty cache on miss")
	}
	if len(c.Projects) != 0 {
		t.Errorf("expected empty projects map, got %d entries", len(c.Projects))
	}
}

func TestScanCache_CorruptReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan-cache.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := loadScanCache(path)
	if len(c.Projects) != 0 {
		t.Errorf("expected empty cache after corrupt read, got %d entries", len(c.Projects))
	}
}

func TestScanCache_WrongVersionReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan-cache.json")
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

