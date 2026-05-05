package atomicfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPickMode_NoExistingFile(t *testing.T) {
	dir := t.TempDir()
	got := PickMode(filepath.Join(dir, "nope"), 0o600)
	if got != 0o600 {
		t.Errorf("PickMode on missing file = %o, want fallback 0o600", got)
	}
}

func TestPickMode_PreservesExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	got := PickMode(path, 0o644)
	if got != 0o640 {
		t.Errorf("PickMode = %o, want existing mode 0o640", got)
	}
}

func TestTakeBackup_NoSource(t *testing.T) {
	dir := t.TempDir()
	got, err := TakeBackup(filepath.Join(dir, "missing"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("expected empty backup path for missing source, got %q", got)
	}
}

func TestTakeBackup_ProducesCorrectShape(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(src, []byte(`{"old":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stamp := time.Date(2026, 5, 5, 12, 34, 56, 0, time.UTC)
	got, err := TakeBackup(src, stamp)
	if err != nil {
		t.Fatal(err)
	}
	want := src + ".dmg-backup.20260505T123456"
	if got != want {
		t.Errorf("backup path = %q, want %q", got, want)
	}

	// Backup contents must match the source.
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"old":true}` {
		t.Errorf("backup content mismatch: %q", string(data))
	}
}

func TestWriteAtomic_FreshInstall_NoBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	res, err := WriteAtomic(path, []byte("{}"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if res.BackupPath != "" {
		t.Errorf("expected no backup on fresh install, got %q", res.BackupPath)
	}
	if res.Path != path {
		t.Errorf("Path = %q, want %q", res.Path, path)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{}" {
		t.Errorf("file content = %q, want %q", string(got), "{}")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %o, want 0o600", info.Mode().Perm())
	}
}

func TestWriteAtomic_OverwriteWithBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := WriteAtomic(path, []byte("NEW"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if res.BackupPath == "" {
		t.Fatal("expected a backup path when target file pre-existed")
	}
	if !strings.Contains(res.BackupPath, ".dmg-backup.") {
		t.Errorf("backup path missing rebrand: %q", res.BackupPath)
	}

	gotNew, _ := os.ReadFile(path)
	if string(gotNew) != "NEW" {
		t.Errorf("target file = %q, want %q", string(gotNew), "NEW")
	}
	gotOld, _ := os.ReadFile(res.BackupPath)
	if string(gotOld) != "OLD" {
		t.Errorf("backup file = %q, want %q", string(gotOld), "OLD")
	}
}

func TestWriteAtomic_CreatesParentDirsAndReportsThem(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c", "settings.json")

	res, err := WriteAtomic(deep, []byte("{}"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	wantCreated := []string{
		filepath.Join(dir, "a"),
		filepath.Join(dir, "a", "b"),
		filepath.Join(dir, "a", "b", "c"),
	}
	if len(res.CreatedDirs) != len(wantCreated) {
		t.Fatalf("CreatedDirs = %v, want %v", res.CreatedDirs, wantCreated)
	}
	for i, w := range wantCreated {
		if res.CreatedDirs[i] != w {
			t.Errorf("CreatedDirs[%d] = %q, want %q", i, res.CreatedDirs[i], w)
		}
	}

	if _, err := os.Stat(deep); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestWriteAtomic_DoesNotReportPreexistingParents(t *testing.T) {
	dir := t.TempDir()
	// dir already exists; writing directly under it should report nothing.
	path := filepath.Join(dir, "hooks.json")
	res, err := WriteAtomic(path, []byte("{}"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.CreatedDirs) != 0 {
		t.Errorf("expected empty CreatedDirs when parent existed, got %v", res.CreatedDirs)
	}
}

