package devicepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestConfigureCacheTargetWithoutWindowsUserPreservesState(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	restorePath := SetCachePathForTest(path)
	t.Cleanup(restorePath)
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "keep"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	mock.SetLoggedInUserError(errors.New("session 0"))
	if target, restore, err := ConfigureCacheTarget(mock, nil); err == nil || restore != nil || target != nil {
		t.Fatalf("ConfigureCacheTarget returned target=%t, restore=%t, err=%v; want no target error", target != nil, restore != nil, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("state changed without an active target user")
	}
}

func TestConfiguredCacheRejectsRedirectedStateParent(t *testing.T) {
	homeDir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(homeDir, ".stepsecurity")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u.HomeDir = homeDir
	normalizeSecureTestUser(t, u)
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	target, restore, err := ConfigureCacheTarget(secureTestExecutor{Executor: mock, user: u}, nil)
	if err == nil || target != nil || restore != nil {
		t.Fatalf("ConfigureCacheTarget returned target=%t restore=%t err=%v, want redirected-parent refusal", target != nil, restore != nil, err)
	}
	if _, err := os.Stat(filepath.Join(outside, CacheFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("redirected state path was modified: %v", err)
	}
}

// ownRec / npmOwnRec build the one-entry WrittenSettings record used by the
// single-value IDE and npm lanes.
func ownRec(value string) map[string]string {
	return map[string]string{allowedExtensionsSettingKey: value}
}

func npmOwnRec(value string) map[string]string {
	return map[string]string{NPMOwnedKey: value}
}

func TestAppliedTargetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	restore := SetCachePathForTest(filepath.Join(dir, CacheFilename))
	defer restore()

	want := AppliedTargetState{
		AppliedHash:     "sha256:abc",
		WrittenSettings: ownRec(samplePolicy),
		FetchedAt:       time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC),
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, want); err != nil {
		t.Fatalf("WriteAppliedState: %v", err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok {
		t.Fatal("ReadAppliedState ok=false after write")
	}
	if got.AppliedHash != want.AppliedHash || got.WrittenSettings[allowedExtensionsSettingKey] != want.WrittenSettings[allowedExtensionsSettingKey] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// On disk it is the schema-versioned wrapper keyed by category then target.
	raw, err := os.ReadFile(CachePath())
	if err != nil {
		t.Fatal(err)
	}
	var f AppliedStateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("on-disk file is not a valid AppliedStateFile: %v", err)
	}
	if f.SchemaVersion != CacheSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", f.SchemaVersion, CacheSchemaVersion)
	}
	cat, ok := f.Categories[CategoryIDEExtension]
	if !ok {
		t.Fatalf("category %q missing from on-disk wrapper: %+v", CategoryIDEExtension, f)
	}
	if _, ok := cat.Targets[TargetVSCode]; !ok {
		t.Fatalf("target %q missing under category %q: %+v", TargetVSCode, CategoryIDEExtension, f)
	}
}

func TestReadAbsentFileOwnsNothing(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), "nope.json"))
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("absent cache should yield ok=false")
	}
}

func TestReadCorruptFileOwnsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("corrupt cache should yield ok=false (owns nothing)")
	}
}

func TestReadFutureSchemaOwnsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// A wrapper written by a newer agent: a schema beyond what this build
	// understands. It decodes fine, but its metadata may mean something else, so
	// the reader must refuse it rather than drive ownership/drift off it.
	future := `{"schema_version":999,"categories":{"ide_extension":{"targets":{"vscode":{"applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}}}`
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("future schema_version must be unreadable (ok=false) so the agent owns nothing")
	}
}

func TestReadMissingSchemaReadsAsCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// No schema_version field (legacy or hand-written) but the wrapper shape:
	// read it, normalized to the current version — not rejected.
	noVer := `{"categories":{"ide_extension":{"targets":{"vscode":{"applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}}}`
	if err := os.WriteFile(path, []byte(noVer), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok {
		t.Fatal("missing schema_version should read as current, not be rejected")
	}
	if got.AppliedHash != "sha256:x" {
		t.Fatalf("applied_hash = %q, want sha256:x", got.AppliedHash)
	}
}

func TestReadAbsentCategoryOwnsNothing(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()
	// The file exists and holds one category; a DIFFERENT category owns nothing.
	if err := WriteAppliedState("other_category", TargetVSCode, AppliedTargetState{WrittenSettings: ownRec("x")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("a category with no entry should yield ok=false even when the file exists")
	}
}

func TestReadAbsentTargetOwnsNothing(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()
	// The category exists with a vscode target; a DIFFERENT target owns nothing.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, "jetbrains"); ok {
		t.Fatal("a target with no entry should yield ok=false even when the category exists")
	}
	// Sanity: the populated target still reads.
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok {
		t.Fatal("the populated target must still read ok=true")
	}
}

func TestWritePreservesOtherCategories(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	other := AppliedTargetState{AppliedHash: "sha256:OTHER", WrittenSettings: ownRec("other-value")}
	if err := WriteAppliedState("other_category", TargetVSCode, other); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:H", WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	// Writing ide_extension must not disturb other_category.
	got, ok := ReadAppliedState("other_category", TargetVSCode)
	if !ok || got.AppliedHash != other.AppliedHash || got.WrittenSettings[allowedExtensionsSettingKey] != other.WrittenSettings[allowedExtensionsSettingKey] {
		t.Fatalf("other category not preserved across a sibling write: got %+v ok=%v", got, ok)
	}
}

func TestWritePreservesOtherTargets(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	// Two targets under the SAME category. Rewriting one must not disturb the other.
	jb := AppliedTargetState{AppliedHash: "sha256:JB", WrittenSettings: ownRec("jetbrains-value")}
	if err := WriteAppliedState(CategoryIDEExtension, "jetbrains", jb); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:VS", WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	// Rewrite vscode again — the sibling jetbrains target must still stand.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:VS2", WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, "jetbrains")
	if !ok || got.AppliedHash != jb.AppliedHash || got.WrittenSettings[allowedExtensionsSettingKey] != jb.WrittenSettings[allowedExtensionsSettingKey] {
		t.Fatalf("sibling target not preserved across a same-category write: got %+v ok=%v", got, ok)
	}
	if vs, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok || vs.AppliedHash != "sha256:VS2" {
		t.Fatalf("vscode target should hold the latest write: got %+v ok=%v", vs, ok)
	}
}

func TestWriteRefusesFutureSchemaFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	future := `{"schema_version":999,"categories":{"future_only":{"targets":{"vscode":{"applied_hash":"sha256:z","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}}}` + "\n"
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()

	err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenSettings: ownRec(samplePolicy)})
	if !errors.Is(err, errFutureSchema) {
		t.Fatalf("write over a future-schema file must refuse with errFutureSchema, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != future {
		t.Fatalf("future-schema file must be left byte-identical; got %q", string(after))
	}
}

func TestClearRemovesTargetAndPreservesSiblingCategory(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	if err := WriteAppliedState("keep_me", TargetVSCode, AppliedTargetState{WrittenSettings: ownRec("keep")}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("ClearAppliedState: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("cleared target should be gone")
	}
	if got, ok := ReadAppliedState("keep_me", TargetVSCode); !ok || got.WrittenSettings[allowedExtensionsSettingKey] != "keep" {
		t.Fatalf("untouched category must survive a sibling clear: got %+v ok=%v", got, ok)
	}
}

func TestClearRemovesOnlyTargetWithinCategory(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	// Two targets under one category; clearing one must leave the other — and the
	// category itself — intact. Clearing the last target then drops the category.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, "jetbrains", AppliedTargetState{WrittenSettings: ownRec("jb")}); err != nil {
		t.Fatal(err)
	}
	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("ClearAppliedState vscode: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("cleared vscode target should be gone")
	}
	if got, ok := ReadAppliedState(CategoryIDEExtension, "jetbrains"); !ok || got.WrittenSettings[allowedExtensionsSettingKey] != "jb" {
		t.Fatalf("sibling jetbrains target must survive a vscode clear: got %+v ok=%v", got, ok)
	}
	// On disk the category must still exist (it still has the jetbrains target).
	raw, err := os.ReadFile(CachePath())
	if err != nil {
		t.Fatal(err)
	}
	var f AppliedStateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Categories[CategoryIDEExtension]; !ok {
		t.Fatalf("category must remain while a target survives: %+v", f)
	}
	// Clearing the last remaining target drops the now-empty category.
	if err := ClearAppliedState(CategoryIDEExtension, "jetbrains"); err != nil {
		t.Fatalf("ClearAppliedState jetbrains: %v", err)
	}
	if _, err := os.Stat(CachePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("last target clear must remove the state file, stat error = %v", err)
	}
}

func TestClearReclaimsEmptyTargetRecord(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	// An empty-ownership entry, as a preflight leaves when its settings write
	// then fails: present in the file but with no value/hash.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{FetchedAt: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState("keep_me", TargetVSCode, AppliedTargetState{WrittenSettings: ownRec("keep")}); err != nil {
		t.Fatal(err)
	}
	// The empty entry is still a present key (ok=true) — the reconciler's
	// entry-exists drop is what reclaims it.
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok {
		t.Fatal("empty-ownership entry should be a present key")
	}
	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("ClearAppliedState: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("empty target record should be reclaimed by clear")
	}
	if got, ok := ReadAppliedState("keep_me", TargetVSCode); !ok || got.WrittenSettings[allowedExtensionsSettingKey] != "keep" {
		t.Fatalf("sibling category must survive: got %+v ok=%v", got, ok)
	}
}

func TestClearRefusesFutureSchemaFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	future := `{"schema_version":999,"categories":{"future_only":{"targets":{"vscode":{"applied_hash":"sha256:z"}}}}}` + "\n"
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()

	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); !errors.Is(err, errFutureSchema) {
		t.Fatalf("clear over a future-schema file must refuse with errFutureSchema, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != future {
		t.Fatalf("future-schema file must be left byte-identical; got %q", string(after))
	}
}

func TestClearAbsentFileIsNoOp(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()
	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("clearing an absent file should be a no-op, got %v", err)
	}
}

func TestLegacySingleObjectReadsAsOwnsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// The pre-refactor single-object shape (also schema_version 1). It parses as
	// a wrapper with no "categories" key → empty map → owns nothing → one
	// harmless re-apply. We deliberately do NOT migrate it.
	legacy := `{"schema_version":1,"category":"ide_extension","applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("legacy single-object file should read as owns-nothing (no migration)")
	}
}

func TestOldCategoryShapeReadsAsOwnsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// The pre-target category-keyed shape: categories.<cat> carried the ownership
	// fields directly, with no "targets" map. Under the target-aware reader this
	// decodes to a nil Targets map → owns nothing → one harmless re-apply. Not
	// migrated (pre-GA, no rollback support).
	old := `{"schema_version":1,"categories":{"ide_extension":{"applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("pre-target category-only file should read as owns-nothing (no migration)")
	}
}

func TestAppliedTargetWrittenSettingsRoundTrip(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	want := AppliedTargetState{
		AppliedHash: "sha256:abc",
		WrittenSettings: map[string]string{
			allowedExtensionsSettingKey: samplePolicy,
			galleryServiceURLSettingKey: `"https://mkt.example/api/v1"`,
		},
		FetchedAt: time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC),
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, want); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok {
		t.Fatal("ok=false after write")
	}
	for key, wantVal := range want.WrittenSettings {
		if got.WrittenSettings[key] != wantVal {
			t.Fatalf("WrittenSettings[%s] not round-tripped: got %+v", key, got.WrittenSettings)
		}
	}
}

func TestAppliedTargetEmptyOwnershipOmitsField(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	restore := SetCachePathForTest(path)
	defer restore()

	// A record that owns nothing (the preflight writability probe writes exactly
	// this) must omit written_settings on disk and read back as a nil map. This is
	// the only shape that omits it now that WrittenSettings is the sole ownership
	// field: a single-value lane records one entry, so its record always carries it.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{
		AppliedHash: "sha256:H",
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "written_settings") {
		t.Fatalf("a record owning nothing must omit written_settings:\n%s", raw)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok || got.WrittenSettings != nil {
		t.Fatalf("WrittenSettings must be nil when nothing is owned, got %+v ok=%v", got.WrittenSettings, ok)
	}
}

func TestAppliedTargetSingleValueRecordsOneEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	restore := SetCachePathForTest(path)
	defer restore()

	// The single-value lanes (the ~/.npmrc block writer, and the degraded VS Code
	// writer) record ownership as exactly ONE written_settings entry keyed by their
	// own ownership key. This is the shape the retired written_value field used to
	// hold, so the collapse must not change what round-trips.
	if err := WriteAppliedState(CategoryPackageConfig, TargetNPM, AppliedTargetState{
		AppliedHash: "sha256:N", WrittenSettings: npmOwnRec("registry=https://x.example/javascript"),
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadAppliedState(CategoryPackageConfig, TargetNPM)
	if !ok {
		t.Fatal("ok=false after write")
	}
	if len(got.WrittenSettings) != 1 || got.WrittenSettings[NPMOwnedKey] != "registry=https://x.example/javascript" {
		t.Fatalf("single-value record = %+v, want exactly one %s entry", got.WrittenSettings, NPMOwnedKey)
	}
}

func TestPackageConfigPyPIComponentOwnershipRoundTrip(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	want := AppliedTargetState{
		AppliedHash:     "sha256:pypi",
		WrittenSettings: map[string]string{"component": PyPICredentialOwnershipValue},
	}
	if err := WriteAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget, want); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget)
	if !ok || got.WrittenSettings["component"] != PyPICredentialOwnershipValue {
		t.Fatalf("credential component = %+v ok=%v, want %q", got, ok, PyPICredentialOwnershipValue)
	}
	if _, ok := ReadAppliedState(CategoryPackageConfig, TargetPyPI); ok {
		t.Fatal("component ownership must not create a public pypi target record")
	}
}

// TestAppliedTargetLegacyWrittenValueReadsAsUnowned pins the no-migrator
// decision: a state file written before the collapse carries only the retired
// written_value key, which decodes into no WrittenSettings entry — so the target
// reads as "owns nothing" and the next enforce re-converges and re-records it. No
// production devices exist, so nothing is owed beyond not crashing.
func TestAppliedTargetLegacyWrittenValueReadsAsUnowned(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	restore := SetCachePathForTest(path)
	defer restore()

	legacy := `{"schema_version":1,"categories":{"ide_extension":{"targets":{"vscode":` +
		`{"applied_hash":"sha256:OLD","written_value":"{\"*\":false}","fetched_at":"2026-07-01T00:00:00Z"}}}}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok {
		t.Fatal("a legacy record must still decode (ok=true), just own nothing")
	}
	if got.AppliedHash != "sha256:OLD" {
		t.Fatalf("applied_hash = %q, want the legacy hash preserved", got.AppliedHash)
	}
	if len(got.WrittenSettings) != 0 {
		t.Fatalf("legacy written_value must not decode into ownership, got %+v", got.WrittenSettings)
	}
	if len(ownedKeys(got, ok)) != 0 {
		t.Fatal("ownedKeys over a legacy record must be empty (owns nothing)")
	}
}

// ---------------------------------------------------------------------------
// One state file for every category
// ---------------------------------------------------------------------------

// npmRec / ideRec are the two categories' records as they coexist in the file.
func npmRec(hash, value string) AppliedTargetState {
	return AppliedTargetState{AppliedHash: hash, WrittenSettings: npmOwnRec(value), FetchedAt: time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)}
}

func ideRec(hash, value string) AppliedTargetState {
	return AppliedTargetState{AppliedHash: hash, WrittenSettings: ownRec(value), FetchedAt: time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)}
}

func TestNPMAndIDEShareOneStateFile(t *testing.T) {
	// package_config/npm and ide_extension/vscode are two entries in ONE file —
	// there is no per-category state file. Each is written through the same
	// accessors, each preserves the other, and the file keeps the schema-versioned
	// category→target shape and 0600 mode for both.
	dir := t.TempDir()
	path := filepath.Join(dir, CacheFilename)
	restore := SetCachePathForTest(path)
	defer restore()

	if err := WriteAppliedState(CategoryPackageConfig, TargetNPM, npmRec("sha256:N", "npm-block")); err != nil {
		t.Fatalf("write npm: %v", err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, ideRec("sha256:V", "vscode-value")); err != nil {
		t.Fatalf("write ide: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f AppliedStateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("on-disk file is not an AppliedStateFile: %v (%s)", err, raw)
	}
	if f.SchemaVersion != CacheSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", f.SchemaVersion, CacheSchemaVersion)
	}
	if got, ok := f.Categories[CategoryPackageConfig].Targets[TargetNPM]; !ok || got.WrittenSettings[NPMOwnedKey] != "npm-block" {
		t.Fatalf("categories.%s.targets.%s = %+v ok=%v", CategoryPackageConfig, TargetNPM, got, ok)
	}
	if got, ok := f.Categories[CategoryIDEExtension].Targets[TargetVSCode]; !ok || got.WrittenSettings[allowedExtensionsSettingKey] != "vscode-value" {
		t.Fatalf("categories.%s.targets.%s = %+v ok=%v", CategoryIDEExtension, TargetVSCode, got, ok)
	}
	// Exactly one JSON state file in the directory — no sibling per-category file.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var jsonFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			jsonFiles = append(jsonFiles, e.Name())
		}
	}
	if len(jsonFiles) != 1 || jsonFiles[0] != CacheFilename {
		t.Fatalf("state directory holds %v, want only %s", jsonFiles, CacheFilename)
	}
	// The file carries a device auth token in the npm record, so it must stay
	// owner-only. Windows has no permission bits to assert.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != cacheFileMode {
			t.Fatalf("state file mode = %o, want %o", info.Mode().Perm(), cacheFileMode)
		}
	}
}

func TestWritingOneCategoryPreservesTheOther(t *testing.T) {
	// Symmetric preservation: whichever category writes second (and third, on a
	// rewrite) must leave the other's record byte-for-byte intact.
	cases := []struct {
		name             string
		first, second    string
		firstTgt, secTgt string
		firstRec, secRec AppliedTargetState
		firstKey, secKey string
		firstVal, secVal string
	}{
		{
			name: "npm write preserves ide", first: CategoryIDEExtension, firstTgt: TargetVSCode,
			second: CategoryPackageConfig, secTgt: TargetNPM,
			firstRec: ideRec("sha256:V", "vscode-value"), secRec: npmRec("sha256:N", "npm-block"),
			firstKey: allowedExtensionsSettingKey, firstVal: "vscode-value",
			secKey: NPMOwnedKey, secVal: "npm-block",
		},
		{
			name: "ide write preserves npm", first: CategoryPackageConfig, firstTgt: TargetNPM,
			second: CategoryIDEExtension, secTgt: TargetVSCode,
			firstRec: npmRec("sha256:N", "npm-block"), secRec: ideRec("sha256:V", "vscode-value"),
			firstKey: NPMOwnedKey, firstVal: "npm-block",
			secKey: allowedExtensionsSettingKey, secVal: "vscode-value",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
			defer restore()

			if err := WriteAppliedState(tc.first, tc.firstTgt, tc.firstRec); err != nil {
				t.Fatalf("write %s: %v", tc.first, err)
			}
			if err := WriteAppliedState(tc.second, tc.secTgt, tc.secRec); err != nil {
				t.Fatalf("write %s: %v", tc.second, err)
			}
			// A rewrite of the second category is the case that would clobber a
			// read-modify-write that dropped what it did not know about.
			if err := WriteAppliedState(tc.second, tc.secTgt, tc.secRec); err != nil {
				t.Fatalf("rewrite %s: %v", tc.second, err)
			}
			got, ok := ReadAppliedState(tc.first, tc.firstTgt)
			if !ok || got.AppliedHash != tc.firstRec.AppliedHash || got.WrittenSettings[tc.firstKey] != tc.firstVal {
				t.Fatalf("%s/%s not preserved: got %+v ok=%v", tc.first, tc.firstTgt, got, ok)
			}
			if got, ok := ReadAppliedState(tc.second, tc.secTgt); !ok || got.WrittenSettings[tc.secKey] != tc.secVal {
				t.Fatalf("%s/%s = %+v ok=%v, want its own record", tc.second, tc.secTgt, got, ok)
			}
		})
	}
}

func TestClearingOneCategoryLeavesTheOther(t *testing.T) {
	// Unassignment of one category is scoped to its own (category, target) — an npm
	// offboarding must not revoke the agent's record of the VS Code policy it still
	// enforces, and the reverse.
	cases := []struct {
		name             string
		clearCat, clrTgt string
		keepCat, keepTgt string
		keepKey, keepVal string
	}{
		{"clear npm", CategoryPackageConfig, TargetNPM, CategoryIDEExtension, TargetVSCode, allowedExtensionsSettingKey, "vscode-value"},
		{"clear ide", CategoryIDEExtension, TargetVSCode, CategoryPackageConfig, TargetNPM, NPMOwnedKey, "npm-block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), CacheFilename)
			restore := SetCachePathForTest(path)
			defer restore()

			if err := WriteAppliedState(CategoryPackageConfig, TargetNPM, npmRec("sha256:N", "npm-block")); err != nil {
				t.Fatal(err)
			}
			if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, ideRec("sha256:V", "vscode-value")); err != nil {
				t.Fatal(err)
			}
			if err := ClearAppliedState(tc.clearCat, tc.clrTgt); err != nil {
				t.Fatalf("clear %s: %v", tc.clearCat, err)
			}
			if _, ok := ReadAppliedState(tc.clearCat, tc.clrTgt); ok {
				t.Fatalf("%s/%s must be gone after its clear", tc.clearCat, tc.clrTgt)
			}
			got, ok := ReadAppliedState(tc.keepCat, tc.keepTgt)
			if !ok || got.WrittenSettings[tc.keepKey] != tc.keepVal {
				t.Fatalf("%s/%s must survive: got %+v ok=%v", tc.keepCat, tc.keepTgt, got, ok)
			}
			// The cleared category is dropped from the file (it had one target); the
			// surviving one is still there, so the file itself stays.
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var f AppliedStateFile
			if err := json.Unmarshal(raw, &f); err != nil {
				t.Fatal(err)
			}
			if _, ok := f.Categories[tc.clearCat]; ok {
				t.Fatalf("category %s should be dropped once its last target is cleared: %s", tc.clearCat, raw)
			}
			if _, ok := f.Categories[tc.keepCat]; !ok {
				t.Fatalf("category %s must remain: %s", tc.keepCat, raw)
			}
		})
	}
}

func TestClearRemovesCorruptFile(t *testing.T) {
	// A corrupt state file can still hold a token-bearing written_settings entry —
	// the ~/.npmrc record carries the device auth token. A clear is an unassignment
	// or offboarding, so it must not report success while those bytes survive.
	// Nothing interpretable is lost: an unparseable file already reads as "owns
	// nothing" for every category.
	path := filepath.Join(t.TempDir(), CacheFilename)
	corrupt := `{ broken "written_settings": "ssabc123::dev:SERIAL-1` // invalid JSON, token-shaped bytes
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()

	if err := ClearAppliedState(CategoryPackageConfig, TargetNPM); err != nil {
		t.Fatalf("clearing a corrupt file must succeed, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a corrupt state file must be removed by a clear, stat err = %v", err)
	}
}

// --- Unreadable, as opposed to absent or corrupt -----------------------------
//
// "Could not read it" is not "there is nothing in it". A present-but-unreadable
// state file may hold live ownership records for OTHER categories, and on POSIX
// no read permission still leaves it rewritable and unlinkable through a writable
// parent — so a mutation that treats it as recreatable destroys those records
// sight unseen, and (before the split) reported success while doing it. The two
// realistic sources are a mode/ownership mismatch between a root or
// SYSTEM-context run and a user-context one over the same home, and plain I/O
// failure.

// seedUnreadableState writes a state file holding an ide_extension record, then
// makes it unreadable. Returns the path and its exact bytes for an
// unchanged-after check. Skips when the platform or the caller's privileges make
// "unreadable" unachievable: Windows os.Chmod only toggles the read-only
// attribute, and root bypasses the permission bits entirely.
func seedUnreadableState(t *testing.T) (path string, before []byte) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("os.Chmod on Windows cannot revoke read access")
	}
	path = filepath.Join(t.TempDir(), CacheFilename)
	restore := SetCachePathForTest(path)
	t.Cleanup(restore)

	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, ideRec("sha256:V", "vscode-value")); err != nil {
		t.Fatalf("seeding the ide record: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 000: %v", err)
	}
	// Restore a readable mode before TempDir cleanup, and let the assertions read.
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := os.ReadFile(path); err == nil {
		t.Skip("the file is still readable at mode 000 (running as root)")
	}
	return path, before
}

// assertStateFileUnchanged re-reads the file (restoring a readable mode first)
// and fails unless its bytes are exactly what was seeded.
func assertStateFileUnchanged(t *testing.T, path string, before []byte) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the state file is gone or still unreadable: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("the state file was rewritten.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok || got.WrittenSettings[allowedExtensionsSettingKey] != "vscode-value" {
		t.Fatalf("the ide ownership record did not survive: %+v ok=%v", got, ok)
	}
}

func TestWriteRefusesUnreadableFile(t *testing.T) {
	// A write for one category must not recreate a file it could not read: doing so
	// replaces every sibling category's record with nothing. It must fail instead —
	// the reconciler then classifies write_failed rather than reporting a success
	// that quietly cost the IDE lane its ownership.
	path, before := seedUnreadableState(t)

	err := WriteAppliedState(CategoryPackageConfig, TargetNPM, npmRec("sha256:N", "npm-block"))
	if err == nil {
		t.Fatal("a write against an unreadable state file must return an error, got nil")
	}
	if !strings.Contains(err.Error(), CacheFilename) {
		t.Errorf("the error should name the file it could not read, got %v", err)
	}
	assertStateFileUnchanged(t, path, before)
}

func TestClearRefusesUnreadableFile(t *testing.T) {
	// The clear path is the dangerous one: removeStateFile unlinks through the
	// parent directory, which succeeds on a file the process cannot read. An
	// unassignment of package_config would take the IDE lane's ownership with it and
	// still report done.
	path, before := seedUnreadableState(t)

	err := ClearAppliedState(CategoryPackageConfig, TargetNPM)
	if err == nil {
		t.Fatal("a clear against an unreadable state file must return an error, got nil")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("the state file must still exist, stat err = %v", statErr)
	}
	assertStateFileUnchanged(t, path, before)
}

// TestMarkerClearStillRemovesBlockWithUnreadableState pins the non-Windows side
// of the Windows-only clear gate: the token-bearing block is still removed, and
// only the record drop reports the unreadable store.
func TestMarkerClearStillRemovesBlockWithUnreadableState(t *testing.T) {
	path, before := seedUnreadableState(t)
	w := &fakeWriter{value: "block", present: true}
	r, _ := newNPMRec(t, EffectivePolicy{Category: CategoryPackageConfig, Target: TargetNPM, Clear: true}, w, &npmStore{path: path})

	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("clear with an unreadable state file must report the failed record drop")
	}
	if w.clears != 1 || w.present {
		t.Fatalf("managed block clears=%d present=%v, want removed once", w.clears, w.present)
	}
	assertStateFileUnchanged(t, path, before)
}

func TestUnreadableFileStillReadsAsOwnsNothing(t *testing.T) {
	// Only the mutating accessors changed. A plain read keeps its no-error contract
	// and reports owning nothing, which is the safe direction: the reconciler then
	// re-applies the policy and refuses to clear a value it has no record of writing.
	seedUnreadableState(t)

	if got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatalf("an unreadable file must read as owning nothing, got %+v", got)
	}
}

func TestConcurrentCategoryWritesLoseNeither(t *testing.T) {
	// Two lanes converging at once — an npm cycle and an IDE cycle — must each end
	// up recorded. This is the lost-update the read-modify-write locking exists to
	// prevent: without it, one lane reads the file, the other writes, and the first
	// one's rename drops the second's category.
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	const rounds = 40
	writes := []struct {
		cat, tgt string
		rec      AppliedTargetState
	}{
		{CategoryPackageConfig, TargetNPM, npmRec("sha256:N", "npm-block")},
		{CategoryIDEExtension, TargetVSCode, ideRec("sha256:V", "vscode-value")},
	}
	errs := make(chan error, len(writes)*rounds)
	var wg sync.WaitGroup
	for _, w := range writes {
		wg.Add(1)
		go func(cat, tgt string, rec AppliedTargetState) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if err := WriteAppliedState(cat, tgt, rec); err != nil {
					errs <- err
					return
				}
			}
		}(w.cat, w.tgt, w.rec)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write failed: %v", err)
	}

	if got, ok := ReadAppliedState(CategoryPackageConfig, TargetNPM); !ok || got.WrittenSettings[NPMOwnedKey] != "npm-block" {
		t.Fatalf("npm record lost to a concurrent IDE write: %+v ok=%v", got, ok)
	}
	if got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok || got.WrittenSettings[allowedExtensionsSettingKey] != "vscode-value" {
		t.Fatalf("ide record lost to a concurrent npm write: %+v ok=%v", got, ok)
	}
}

func TestStateLockExcludesASecondHolder(t *testing.T) {
	// What makes the read-modify-write safe between separate agent PROCESSES. A
	// second open file description on the lock path is exactly what another process
	// would hold, and it must not be able to take the lock while this one has it.
	if !stateLockSupported {
		t.Skip("no advisory locking on this platform")
	}
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	held := make(chan struct{})
	proceed := make(chan struct{})
	released := make(chan struct{})
	go func() {
		defer close(released)
		_ = withStateLock(func() error {
			close(held)
			<-proceed
			return nil
		})
	}()
	<-held

	f, err := os.OpenFile(stateLockPath(), os.O_CREATE|os.O_RDWR, cacheFileMode)
	if err != nil {
		t.Fatalf("opening the lock file: %v", err)
	}
	defer func() { _ = f.Close() }()

	ok, err := tryLockHandle(f)
	if err != nil {
		t.Fatalf("tryLockHandle: %v", err)
	}
	if ok {
		unlockHandle(f)
		t.Fatal("a second holder took the lock while it was held")
	}

	close(proceed)
	<-released

	// Released — the same handle can take it now, so the lock is not leaked.
	ok, err = tryLockHandle(f)
	if err != nil {
		t.Fatalf("tryLockHandle after release: %v", err)
	}
	if !ok {
		t.Fatal("the lock was not released")
	}
	unlockHandle(f)
}

// holdStateLockUntilCleanup takes the state lock in a background goroutine and
// keeps it until the test ends, with the wait budget shrunk so the contending
// caller reaches its timeout fast. Returns once the lock is genuinely held.
func holdStateLockUntilCleanup(t *testing.T) {
	t.Helper()
	if !stateLockSupported {
		t.Skip("no advisory locking on this platform")
	}
	prevWait, prevDelay := stateLockWait, stateLockRetryDelay
	stateLockWait, stateLockRetryDelay = 20*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { stateLockWait, stateLockRetryDelay = prevWait, prevDelay })

	held := make(chan struct{})
	proceed := make(chan struct{})
	released := make(chan struct{})
	go func() {
		defer close(released)
		if err := withStateLock(func() error {
			close(held)
			<-proceed
			return nil
		}); err != nil {
			t.Errorf("the holder itself failed to take the lock: %v", err)
			close(held)
		}
	}()
	<-held
	t.Cleanup(func() { close(proceed); <-released })
}

func TestStateWriteFailsWhenAPeerHoldsTheLock(t *testing.T) {
	// FAIL CLOSED. A peer still holding the lock after the whole wait budget is a
	// concurrent writer PROVEN to exist, which is the one situation in which
	// proceeding can drop another category's ownership record — the invariant the
	// single shared file rests on. The write is abandoned instead; the caller
	// classifies write_failed, rolls its own file change back and retries next cycle.
	// A reported, recoverable failure beats silently losing a sibling's record.
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()
	holdStateLockUntilCleanup(t)

	err := WriteAppliedState(CategoryPackageConfig, TargetNPM, npmRec("sha256:N", "npm-block"))
	if err == nil {
		t.Fatal("a write must fail while a peer holds the lock, got nil")
	}
	if !errors.Is(err, errStateLockBusy) {
		t.Errorf("error should identify lock contention, got %v", err)
	}
	// Nothing was written: the read-modify-write never ran.
	if got, ok := ReadAppliedState(CategoryPackageConfig, TargetNPM); ok {
		t.Fatalf("the refused write still landed: %+v", got)
	}
}

func TestStateClearFailsWhenAPeerHoldsTheLock(t *testing.T) {
	// The clear path fails closed for the same reason, and it is the one with teeth:
	// a clear that proceeded unlocked could rewrite the file from a snapshot taken
	// before a peer's write, resurrecting a record the peer had just dropped or
	// dropping one it had just added.
	path := filepath.Join(t.TempDir(), CacheFilename)
	restore := SetCachePathForTest(path)
	defer restore()
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, ideRec("sha256:V", "vscode-value")); err != nil {
		t.Fatalf("seeding the ide record: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	holdStateLockUntilCleanup(t)

	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err == nil {
		t.Fatal("a clear must fail while a peer holds the lock, got nil")
	} else if !errors.Is(err, errStateLockBusy) {
		t.Errorf("error should identify lock contention, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the state file must survive a refused clear: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("a refused clear rewrote the file.\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestStateLockWaitAbsorbsSlowRenames(t *testing.T) {
	// The budget is not a latency knob: the critical section is microseconds, so
	// anything short enough to be tripped by an antivirus-serialized rename or a slow
	// network home would convert routine slowness into a reported enforcement
	// failure now that acquisition fails closed. Pinned so a future trim is a
	// deliberate act.
	if stateLockWait < 10*time.Second {
		t.Fatalf("stateLockWait = %s, want at least 10s", stateLockWait)
	}
}

func TestNoCategoryScopedStateFileAnywhereInTheTree(t *testing.T) {
	// The dedicated package_config store is gone for good: nothing in the module may
	// name or create a per-category state file again. Scanning the source is what
	// catches a re-introduction that no behavioral test would see until it shipped.
	root := moduleRoot(t)
	// Assembled from fragments so this scanner does not match its own source.
	needles := []string{"package-config" + "-state", "packageConfigState" + "Basename", "NewStateStore" + "For"}
	var hits []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == "vendor" || name == "specs" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for _, needle := range needles {
			if strings.Contains(string(b), needle) {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, rel+" contains "+needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(hits) != 0 {
		t.Fatalf("category-scoped state must not come back:\n%s", strings.Join(hits, "\n"))
	}
}

// moduleRoot walks up from the package directory to the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the package directory")
		}
		dir = parent
	}
}
