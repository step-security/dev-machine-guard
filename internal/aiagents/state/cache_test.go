package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// withTempCache redirects CachePath to a tempdir for the duration of
// the test. Returns the absolute path the cache will be written to.
func withTempCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, CacheFilename)
	prev := cachePathOverride
	cachePathOverride = p
	t.Cleanup(func() { cachePathOverride = prev })
	return p
}

func TestReadMissingFileReturnsDefault(t *testing.T) {
	withTempCache(t)
	s, ok := Read()
	if ok {
		t.Fatal("Read of missing file should report ok=false")
	}
	if !s.Hooks.Enabled {
		t.Fatal("missing-file Read must yield Default (enabled)")
	}
}

func TestWriteThenReadRoundTrip(t *testing.T) {
	withTempCache(t)
	in := State{
		SchemaVersion: SchemaVersion,
		FetchedAt:     time.Date(2026, 5, 14, 8, 0, 0, 0, time.UTC),
		Source:        SourcePoll,
		Hooks:         Hooks{Enabled: false},
	}
	if err := Write(in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, ok := Read()
	if !ok {
		t.Fatal("Read after Write should report ok=true")
	}
	if out.Hooks.Enabled != false || out.Source != SourcePoll {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if !out.FetchedAt.Equal(in.FetchedAt) {
		t.Fatalf("FetchedAt drift: got %v want %v", out.FetchedAt, in.FetchedAt)
	}
}

func TestReadMalformedReturnsDefault(t *testing.T) {
	path := withTempCache(t)
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, ok := Read()
	if ok {
		t.Fatal("malformed file should report ok=false")
	}
	if !s.Hooks.Enabled {
		t.Fatal("malformed Read must yield Default (enabled)")
	}
}

func TestWriteFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits not meaningful on Windows")
	}
	path := withTempCache(t)
	if err := Write(Default()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != cacheFileMode {
		t.Fatalf("mode = %o, want %o", got, cacheFileMode)
	}
}

func TestWriteReplacesExistingFile(t *testing.T) {
	path := withTempCache(t)
	if err := os.WriteFile(path, []byte(`{"hooks":{"enabled":true}}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	next := Default()
	next.Hooks.Enabled = false
	if err := Write(next); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, ok := Read()
	if !ok || out.Hooks.Enabled {
		t.Fatalf("expected disabled after rewrite, got %+v (ok=%v)", out, ok)
	}
}

func TestReadForwardCompatMissingSchemaVersion(t *testing.T) {
	path := withTempCache(t)
	raw := map[string]any{"hooks": map[string]any{"enabled": false}}
	b, _ := json.Marshal(raw)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, ok := Read()
	if !ok {
		t.Fatal("legacy-shape file should still parse")
	}
	if out.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version should default to %d, got %d", SchemaVersion, out.SchemaVersion)
	}
	if out.Hooks.Enabled {
		t.Fatal("legacy disabled value should round-trip")
	}
}
