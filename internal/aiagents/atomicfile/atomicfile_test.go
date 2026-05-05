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
	want := src + ".dmg-20260505T123456.bak"
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
	if !strings.Contains(res.BackupPath, ".dmg-") || !strings.HasSuffix(res.BackupPath, ".bak") {
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

// listBackups returns every backup sibling of src that the rotation
// considers part of the pool (.dmg-*.bak + legacy .dmg-backup.*).
// Anything else in the directory is ignored.
func listBackups(t *testing.T, src string) []string {
	t.Helper()
	var out []string
	for _, pattern := range []string{src + ".dmg-*.bak", src + ".dmg-backup.*"} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m...)
	}
	return out
}

// writeBackupAt creates a backup file at path with mtime set to ts. The
// content is irrelevant; rotation sorts by mtime, not contents.
func writeBackupAt(t *testing.T, path string, ts time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func TestTakeBackup_PrunesPastCap(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(src, []byte("CURRENT"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Five pre-existing backups with strictly increasing mtimes. Names
	// embed the same stamps so debugging output is readable, but the
	// prune sorts by mtime, not by name.
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		ts := base.Add(time.Duration(i) * time.Hour)
		writeBackupAt(t, src+BackupPrefix+ts.Format(BackupStampLayout)+BackupExt, ts)
	}

	// New backup is taken "now" (later than all pre-existing mtimes).
	now := base.Add(24 * time.Hour)
	got, err := TakeBackup(src, now)
	if err != nil {
		t.Fatal(err)
	}

	survivors := listBackups(t, src)
	if len(survivors) != MaxBackups {
		t.Fatalf("expected %d survivors after prune, got %d: %v", MaxBackups, len(survivors), survivors)
	}

	// Survivors must include the freshly-taken one + the two
	// most-recent pre-existing backups (hours +3 and +4).
	want := map[string]bool{
		got: true,
		src + BackupPrefix + base.Add(3*time.Hour).Format(BackupStampLayout) + BackupExt: true,
		src + BackupPrefix + base.Add(4*time.Hour).Format(BackupStampLayout) + BackupExt: true,
	}
	for _, s := range survivors {
		if !want[s] {
			t.Errorf("unexpected survivor %q", s)
		}
		delete(want, s)
	}
	for missing := range want {
		t.Errorf("expected survivor missing: %q", missing)
	}
}

func TestTakeBackup_PruneAcrossLegacyAndNewFormats(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(src, []byte("CURRENT"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Two legacy + two new-form, all older than the upcoming TakeBackup.
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	legacyOldest := src + ".dmg-backup." + base.Format(BackupStampLayout)
	writeBackupAt(t, legacyOldest, base)
	legacyNewer := src + ".dmg-backup." + base.Add(time.Hour).Format(BackupStampLayout)
	writeBackupAt(t, legacyNewer, base.Add(time.Hour))
	newOlder := src + BackupPrefix + base.Add(2*time.Hour).Format(BackupStampLayout) + BackupExt
	writeBackupAt(t, newOlder, base.Add(2*time.Hour))
	newNewest := src + BackupPrefix + base.Add(3*time.Hour).Format(BackupStampLayout) + BackupExt
	writeBackupAt(t, newNewest, base.Add(3*time.Hour))

	now := base.Add(24 * time.Hour)
	got, err := TakeBackup(src, now)
	if err != nil {
		t.Fatal(err)
	}

	survivors := listBackups(t, src)
	if len(survivors) != MaxBackups {
		t.Fatalf("expected %d survivors, got %d: %v", MaxBackups, len(survivors), survivors)
	}
	// Newest 3 = the just-taken one + newNewest + newOlder. Both
	// legacy entries (older mtimes) must be pruned, demonstrating
	// the cap holds across the format rename.
	survSet := map[string]bool{}
	for _, s := range survivors {
		survSet[s] = true
	}
	for _, want := range []string{got, newNewest, newOlder} {
		if !survSet[want] {
			t.Errorf("expected survivor missing: %q", want)
		}
	}
	for _, gone := range []string{legacyOldest, legacyNewer} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("expected legacy backup pruned: %q (stat err=%v)", gone, err)
		}
	}
}

func TestTakeBackup_DoesNotTouchUnrelatedSiblings(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(src, []byte("CURRENT"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Four pre-existing DMG backups so the prune is forced to delete one.
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	for i := range 4 {
		ts := base.Add(time.Duration(i) * time.Hour)
		writeBackupAt(t, src+BackupPrefix+ts.Format(BackupStampLayout)+BackupExt, ts)
	}

	// Files the rotation must NOT touch: a different tool's backup, a
	// user-named sibling, and a file with a different stem.
	anchor := src + ".anchor-backup.20260501T120000"
	userKeep := src + ".user-keep"
	otherStem := filepath.Join(dir, "other.json.dmg-20260501T120000.bak")
	for _, p := range []string{anchor, userKeep, otherStem} {
		if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := TakeBackup(src, base.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Survivors of the DMG pool: cap honored.
	if got := len(listBackups(t, src)); got != MaxBackups {
		t.Errorf("DMG backup count after prune: got %d, want %d", got, MaxBackups)
	}
	// Unrelated files must all still exist.
	for _, p := range []string{anchor, userKeep, otherStem} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("unrelated sibling pruned: %q: %v", p, err)
		}
	}
}

func TestTakeBackup_NoOpUnderCap(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(src, []byte("CURRENT"), 0o600); err != nil {
		t.Fatal(err)
	}

	// One pre-existing backup; combined with the new one we'll be at 2,
	// still under MaxBackups.
	pre := src + BackupPrefix + "20260501T120000" + BackupExt
	writeBackupAt(t, pre, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))

	got, err := TakeBackup(src, time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	survivors := listBackups(t, src)
	if len(survivors) != 2 {
		t.Fatalf("expected 2 survivors when under cap, got %d: %v", len(survivors), survivors)
	}
	survSet := map[string]bool{}
	for _, s := range survivors {
		survSet[s] = true
	}
	if !survSet[pre] {
		t.Errorf("pre-existing backup pruned despite under-cap: %q", pre)
	}
	if !survSet[got] {
		t.Errorf("freshly-taken backup missing: %q", got)
	}
}
