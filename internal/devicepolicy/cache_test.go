package devicepolicy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppliedTargetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	restore := SetCachePathForTest(filepath.Join(dir, CacheFilename))
	defer restore()

	want := AppliedTargetState{
		AppliedHash:  "sha256:abc",
		WrittenValue: samplePolicy,
		FetchedAt:    time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC),
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, want); err != nil {
		t.Fatalf("WriteAppliedState: %v", err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok {
		t.Fatal("ReadAppliedState ok=false after write")
	}
	if got.AppliedHash != want.AppliedHash || got.WrittenValue != want.WrittenValue {
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
	if err := WriteAppliedState("other_category", TargetVSCode, AppliedTargetState{WrittenValue: "x"}); err != nil {
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
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenValue: samplePolicy}); err != nil {
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

	other := AppliedTargetState{AppliedHash: "sha256:OTHER", WrittenValue: "other-value"}
	if err := WriteAppliedState("other_category", TargetVSCode, other); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:H", WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	// Writing ide_extension must not disturb other_category.
	got, ok := ReadAppliedState("other_category", TargetVSCode)
	if !ok || got.AppliedHash != other.AppliedHash || got.WrittenValue != other.WrittenValue {
		t.Fatalf("other category not preserved across a sibling write: got %+v ok=%v", got, ok)
	}
}

func TestWritePreservesOtherTargets(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	// Two targets under the SAME category. Rewriting one must not disturb the other.
	jb := AppliedTargetState{AppliedHash: "sha256:JB", WrittenValue: "jetbrains-value"}
	if err := WriteAppliedState(CategoryIDEExtension, "jetbrains", jb); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:VS", WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	// Rewrite vscode again — the sibling jetbrains target must still stand.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:VS2", WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, "jetbrains")
	if !ok || got.AppliedHash != jb.AppliedHash || got.WrittenValue != jb.WrittenValue {
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

	err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenValue: samplePolicy})
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

	if err := WriteAppliedState("keep_me", TargetVSCode, AppliedTargetState{WrittenValue: "keep"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("ClearAppliedState: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("cleared target should be gone")
	}
	if got, ok := ReadAppliedState("keep_me", TargetVSCode); !ok || got.WrittenValue != "keep" {
		t.Fatalf("untouched category must survive a sibling clear: got %+v ok=%v", got, ok)
	}
}

func TestClearRemovesOnlyTargetWithinCategory(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	// Two targets under one category; clearing one must leave the other — and the
	// category itself — intact. Clearing the last target then drops the category.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, "jetbrains", AppliedTargetState{WrittenValue: "jb"}); err != nil {
		t.Fatal(err)
	}
	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("ClearAppliedState vscode: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("cleared vscode target should be gone")
	}
	if got, ok := ReadAppliedState(CategoryIDEExtension, "jetbrains"); !ok || got.WrittenValue != "jb" {
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
	raw, err = os.ReadFile(CachePath())
	if err != nil {
		t.Fatal(err)
	}
	f = AppliedStateFile{}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Categories[CategoryIDEExtension]; ok {
		t.Fatalf("category should be dropped once its last target is cleared: %+v", f)
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
	if err := WriteAppliedState("keep_me", TargetVSCode, AppliedTargetState{WrittenValue: "keep"}); err != nil {
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
	if got, ok := ReadAppliedState("keep_me", TargetVSCode); !ok || got.WrittenValue != "keep" {
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
		AppliedHash:  "sha256:abc",
		WrittenValue: samplePolicy,
		WrittenSettings: map[string]string{
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
	if got.WrittenSettings[galleryServiceURLSettingKey] != want.WrittenSettings[galleryServiceURLSettingKey] {
		t.Fatalf("WrittenSettings not round-tripped: got %+v", got.WrittenSettings)
	}
}

func TestAppliedTargetNoWrittenSettingsOmitsField(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	restore := SetCachePathForTest(path)
	defer restore()

	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{
		AppliedHash: "sha256:H", WrittenValue: samplePolicy,
	}); err != nil {
		t.Fatal(err)
	}
	// A single-key writer's record (npm: one opaque WrittenValue, no managed
	// multi-key map) must omit written_settings on disk.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "written_settings") {
		t.Fatalf("single-key record must omit written_settings:\n%s", raw)
	}
	// And it reads back as a nil map (owns no managed multi-key state).
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok || got.WrittenSettings != nil {
		t.Fatalf("WrittenSettings must be nil for a single-key record, got %+v ok=%v", got.WrittenSettings, ok)
	}
}
