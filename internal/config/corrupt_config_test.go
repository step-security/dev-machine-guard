package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func seedRaw(t *testing.T, data string) string {
	t.Helper()
	path := WriteConfigFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A truncated config.json must never be overwritten by a read-modify-write:
// persisting would replace it with an empty config and drop api_key/customer_id.
func TestPersistMaxExecutionDuration_CorruptConfigUntouched(t *testing.T) {
	withHome(t)
	const truncated = `{"customer_id":"acme","api_endpoint":"https://api","api_key":"k`
	path := seedRaw(t, truncated)

	err := PersistMaxExecutionDuration("2h")
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("err = %v, want ErrConfigInvalid", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, []byte(truncated)) {
		t.Errorf("corrupt config was rewritten: %q", got)
	}
}

func TestLoad_SurfacesParseError(t *testing.T) {
	withHome(t)
	seedRaw(t, `{"customer_id":`)
	Load()
	t.Cleanup(func() { loadErr = nil })
	if err := LoadError(); !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("LoadError() = %v, want ErrConfigInvalid", err)
	}
}

func TestLoad_MissingFileIsNotAnError(t *testing.T) {
	withHome(t)
	Load()
	if err := LoadError(); err != nil {
		t.Errorf("LoadError() = %v, want nil", err)
	}
}

// save writes via temp+rename: no temp files linger on success, and a failed
// write leaves the previous file intact.
func TestSave_Atomic(t *testing.T) {
	withHome(t)
	if err := save(&ConfigFile{CustomerID: "acme", APIKey: "k", APIEndpoint: "https://api"}); err != nil {
		t.Fatal(err)
	}
	path := WriteConfigFilePath()
	dir := filepath.Dir(path)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "config.json" {
			t.Errorf("unexpected leftover %q", e.Name())
		}
	}

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root POSIX read-only dir")
	}
	before, _ := os.ReadFile(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := save(&ConfigFile{CustomerID: "other"}); err == nil {
		t.Fatal("save into read-only dir succeeded; want error")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Errorf("failed save modified config: %q", after)
	}
	entries, _ = os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("partial temp file left: %q", e.Name())
		}
	}
}
