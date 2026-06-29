package devicepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/atomicfile"
)

const samplePolicyObject = `{"github.copilot":true,"ms-python.python":"1.2.3"}`

// sampleSettings exercises every JSONC feature the writer must preserve:
// line + block comments, trailing commas (object and nested), irregular
// whitespace, and unrelated keys before and after where the policy lands.
const sampleSettings = `// StepSecurity test fixture — user settings
{
	/* appearance */
	"workbench.colorTheme": "Solarized Dark", // user's favorite
	"editor.fontSize":   14,
	"files.exclude": {
		"**/.git": true,
	},

	// telemetry opt-out
	"telemetry.telemetryLevel": "off",
}
`

// preservedFragments are exact byte sequences from sampleSettings that must
// survive any single-key edit untouched.
var preservedFragments = []string{
	"// StepSecurity test fixture — user settings",
	"/* appearance */",
	`"workbench.colorTheme": "Solarized Dark", // user's favorite`,
	`"editor.fontSize":   14,`,
	"\"files.exclude\": {\n\t\t\"**/.git\": true,\n\t},",
	"// telemetry opt-out",
	// No trailing comma asserted: when the policy key is removed from the end
	// of the object, hujson also drops the separator comma after this (then
	// last) member — separator syntax is part of the touched region.
	`"telemetry.telemetryLevel": "off"`,
}

func newTestSettingsWriter(t *testing.T) (*settingsWriter, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "User", "settings.json")
	return newSettingsWriterAt(path), path
}

func writeSettingsFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertFragmentsPreserved(t *testing.T, got string) {
	t.Helper()
	for _, frag := range preservedFragments {
		if !strings.Contains(got, frag) {
			t.Errorf("fragment lost after edit:\n%q\n--- file now:\n%s", frag, got)
		}
	}
}

func TestSettingsWriteAddsKeyPreservingFile(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)

	rb, err := w.Write(samplePolicyObject)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rb != samplePolicyObject {
		t.Fatalf("readback = %q, want %q", rb, samplePolicyObject)
	}

	after := readFileString(t, path)
	assertFragmentsPreserved(t, after)

	// The file must remain valid JSONC holding both old and new keys.
	got, present, err := w.Read()
	if err != nil || !present || got != samplePolicyObject {
		t.Fatalf("Read = (%q, %v, %v), want (%q, true, nil)", got, present, err, samplePolicyObject)
	}
}

func TestSettingsWriteReplacesExistingKeyOnly(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	fixture := strings.Replace(sampleSettings,
		"\t// telemetry opt-out",
		"\t/* managed below */\n\t\"extensions.allowed\": { \"old.ext\": true /* stale */ },\n\n\t// telemetry opt-out", 1)
	writeSettingsFixture(t, path, fixture)

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write: %v", err)
	}
	after := readFileString(t, path)
	assertFragmentsPreserved(t, after)
	if strings.Contains(after, "old.ext") {
		t.Fatalf("stale policy value survived the replace:\n%s", after)
	}
	got, present, err := w.Read()
	if err != nil || !present || got != samplePolicyObject {
		t.Fatalf("Read = (%q, %v, %v), want (%q, true, nil)", got, present, err, samplePolicyObject)
	}
}

// TestSettingsWriteLeavesRecoverableBackup pins the safety net for editing a
// file the user owns: before overwriting settings.json the writer (through
// atomicfile) drops a sibling `<path>.dmg-<stamp>.bak` holding the EXACT prior
// bytes, so a botched write is always recoverable. A single write yields
// exactly one backup; retention beyond that (the MaxBackups=3 cap and prune
// ordering) is atomicfile's own concern — and can't be exercised through Write
// here because the stamp has second granularity, so sub-second writes collide
// on one filename. atomicfile_test.go covers the cap with an injectable clock.
func TestSettingsWriteLeavesRecoverableBackup(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write: %v", err)
	}

	backups, err := filepath.Glob(path + atomicfile.BackupPrefix + "*" + atomicfile.BackupExt)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("want exactly 1 backup after one write, got %d: %v", len(backups), backups)
	}
	// The backup must be the pre-write file verbatim — the point is a usable
	// rollback, not merely some file ending in .bak.
	if got := readFileString(t, backups[0]); got != sampleSettings {
		t.Fatalf("backup is not the original file:\nbackup:\n%s\n--- want:\n%s", got, sampleSettings)
	}
	// Sanity: the live file took the new key (we backed up the OLD content, and
	// the write still landed).
	if got, present, err := w.Read(); err != nil || !present || got != samplePolicyObject {
		t.Fatalf("live file Read = (%q, %v, %v), want %q", got, present, err, samplePolicyObject)
	}
}

// TestSettingsWriteCreatingFileMakesNoBackup is the boundary of the rule above:
// a first-ever write (no settings.json yet) has nothing to preserve, so it must
// NOT leave a phantom .bak. Locks the behavior so nobody later "fixes"
// TakeBackup to error on a missing source.
func TestSettingsWriteCreatingFileMakesNoBackup(t *testing.T) {
	w, path := newTestSettingsWriter(t)

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write: %v", err)
	}
	backups, err := filepath.Glob(path + atomicfile.BackupPrefix + "*" + atomicfile.BackupExt)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("first-write should make no backup, got %v", backups)
	}
}

func TestSettingsWriteIsByteIdempotent(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	first := readFileString(t, path)
	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if second := readFileString(t, path); second != first {
		t.Fatalf("second identical Write changed the file:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestSettingsWriteCreatesMissingFileAndDirs(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	// No fixture: neither the User dir nor the file exists.

	rb, err := w.Write(samplePolicyObject)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rb != samplePolicyObject {
		t.Fatalf("readback = %q, want %q", rb, samplePolicyObject)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFileString(t, path)), &m); err != nil {
		t.Fatalf("created file is not plain JSON: %v", err)
	}
	if _, ok := m[allowedExtensionsSettingKey]; !ok || len(m) != 1 {
		t.Fatalf("created file should hold exactly the policy key, got %v", m)
	}
}

func TestSettingsWriteTreatsBlankFileAsEmptyObject(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, "\n  \n")

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write on blank file: %v", err)
	}
	got, present, err := w.Read()
	if err != nil || !present || got != samplePolicyObject {
		t.Fatalf("Read = (%q, %v, %v), want (%q, true, nil)", got, present, err, samplePolicyObject)
	}
}

func TestSettingsReadCompactsFormattedValue(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, `{
	"extensions.allowed": {
		// allow-list managed elsewhere
		"github.copilot": true,
		"ms-python.python": "1.2.3",
	},
}`)
	got, present, err := w.Read()
	if err != nil || !present {
		t.Fatalf("Read = (%q, %v, %v), want present", got, present, err)
	}
	want := `{"github.copilot":true,"ms-python.python":"1.2.3"}`
	if got != want {
		t.Fatalf("Read = %q, want compacted %q", got, want)
	}
}

func TestSettingsReadAbsent(t *testing.T) {
	w, path := newTestSettingsWriter(t)

	// Missing file.
	if got, present, err := w.Read(); err != nil || present || got != "" {
		t.Fatalf("Read(missing file) = (%q, %v, %v), want absent", got, present, err)
	}
	// File without the key.
	writeSettingsFixture(t, path, sampleSettings)
	if got, present, err := w.Read(); err != nil || present || got != "" {
		t.Fatalf("Read(no key) = (%q, %v, %v), want absent", got, present, err)
	}
}

func TestSettingsClearRemovesOnlyTheKey(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)
	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	after := readFileString(t, path)
	assertFragmentsPreserved(t, after)
	if strings.Contains(after, allowedExtensionsSettingKey) {
		t.Fatalf("policy key survived Clear:\n%s", after)
	}
	if _, present, err := w.Read(); err != nil || present {
		t.Fatalf("key still present after Clear (err=%v)", err)
	}
}

func TestSettingsClearAbsentIsNoOp(t *testing.T) {
	w, path := newTestSettingsWriter(t)

	// Missing file: Clear must not create it.
	if err := w.Clear(); err != nil {
		t.Fatalf("Clear(missing file): %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Clear created the settings file")
	}

	// File without the key: Clear must not rewrite it.
	writeSettingsFixture(t, path, sampleSettings)
	if err := w.Clear(); err != nil {
		t.Fatalf("Clear(no key): %v", err)
	}
	if got := readFileString(t, path); got != sampleSettings {
		t.Fatalf("Clear rewrote a file it had no key in:\n%s", got)
	}
}

func TestSettingsUnsalvageableFileIsNeverTouched(t *testing.T) {
	const broken = `{"editor.fontSize": 14, <<<garbage` // not JSONC

	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, broken)

	if _, _, err := w.Read(); err == nil {
		t.Fatal("Read on unparseable file: want error")
	}
	if _, err := w.Write(samplePolicyObject); err == nil {
		t.Fatal("Write on unparseable file: want error")
	}
	if err := w.Clear(); err == nil {
		t.Fatal("Clear on unparseable file: want error")
	}
	if got := readFileString(t, path); got != broken {
		t.Fatalf("unparseable file was modified:\n%s", got)
	}
}

func TestSettingsRootNotObjectIsNeverTouched(t *testing.T) {
	const arrayRoot = `[1, 2, 3] // valid JSONC, wrong shape`

	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, arrayRoot)

	if _, err := w.Write(samplePolicyObject); err == nil {
		t.Fatal("Write on non-object root: want error")
	}
	if got := readFileString(t, path); got != arrayRoot {
		t.Fatalf("non-object file was modified:\n%s", got)
	}
}

func TestSettingsWriteRejectsNonObjectValue(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)

	for _, bad := range []string{`"a string"`, `[1,2]`, `42`, `not json at all`, ``} {
		if _, err := w.Write(bad); err == nil {
			t.Errorf("Write(%q): want error", bad)
		}
	}
	if got := readFileString(t, path); got != sampleSettings {
		t.Fatalf("rejected value still modified the file:\n%s", got)
	}
}

func TestSettingsWriteFailureLeavesFileUntouched(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory write-permission semantics differ on Windows")
	}
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)

	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if _, err := w.Write(samplePolicyObject); err == nil {
		t.Fatal("Write into read-only dir: want error")
	}
	_ = os.Chmod(dir, 0o755)
	if got := readFileString(t, path); got != sampleSettings {
		t.Fatalf("failed write modified the file:\n%s", got)
	}
}

func TestSettingsPathPerOS(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		t.Setenv("APPDATA", `C:\Users\dev\AppData\Roaming`)
		got, ok := settingsPath()
		want := filepath.Join(`C:\Users\dev\AppData\Roaming`, "Code", "User", "settings.json")
		if !ok || got != want {
			t.Fatalf("settingsPath = (%q, %v), want (%q, true)", got, ok, want)
		}
		t.Setenv("APPDATA", "")
		if _, ok := settingsPath(); ok {
			t.Fatal("settingsPath with empty %APPDATA%: want ok=false")
		}
	case "darwin":
		got, ok := settingsPath()
		want := filepath.Join("Library", "Application Support", "Code", "User", "settings.json")
		if !ok || !strings.HasSuffix(got, want) {
			t.Fatalf("settingsPath = (%q, %v), want suffix %q", got, ok, want)
		}
	case "linux":
		t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-test")
		got, ok := settingsPath()
		want := filepath.Join("/tmp/xdg-test", "Code", "User", "settings.json")
		if !ok || got != want {
			t.Fatalf("settingsPath = (%q, %v), want (%q, true)", got, ok, want)
		}
		t.Setenv("XDG_CONFIG_HOME", "")
		got, ok = settingsPath()
		if !ok || !strings.HasSuffix(got, filepath.Join(".config", "Code", "User", "settings.json")) {
			t.Fatalf("settingsPath without XDG = (%q, %v), want ~/.config suffix", got, ok)
		}
	default:
		if _, ok := settingsPath(); ok {
			t.Fatalf("settingsPath on %s: want ok=false", runtime.GOOS)
		}
	}
}
