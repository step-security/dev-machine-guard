package devicepolicy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppliedCategoryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	restore := SetCachePathForTest(filepath.Join(dir, CacheFilename))
	defer restore()

	want := AppliedCategoryState{
		AppliedHash:  "sha256:abc",
		WrittenValue: samplePolicy,
		FetchedAt:    time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC),
	}
	if err := WriteAppliedState(CategoryIDEExtension, want); err != nil {
		t.Fatalf("WriteAppliedState: %v", err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension)
	if !ok {
		t.Fatal("ReadAppliedState ok=false after write")
	}
	if got.AppliedHash != want.AppliedHash || got.WrittenValue != want.WrittenValue {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// On disk it is the schema-versioned wrapper keyed by category.
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
	if _, ok := f.Categories[CategoryIDEExtension]; !ok {
		t.Fatalf("category %q missing from on-disk wrapper: %+v", CategoryIDEExtension, f)
	}
}

func TestReadAbsentFileOwnsNothing(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), "nope.json"))
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension); ok {
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
	if _, ok := ReadAppliedState(CategoryIDEExtension); ok {
		t.Fatal("corrupt cache should yield ok=false (owns nothing)")
	}
}

func TestReadFutureSchemaOwnsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// A wrapper written by a newer agent: a schema beyond what this build
	// understands. It decodes fine, but its category metadata may mean something
	// else, so the reader must refuse it rather than drive ownership/drift off it.
	future := `{"schema_version":999,"categories":{"ide_extension":{"applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}`
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension); ok {
		t.Fatal("future schema_version must be unreadable (ok=false) so the agent owns nothing")
	}
}

func TestReadMissingSchemaReadsAsCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// No schema_version field (legacy or hand-written) but the wrapper shape:
	// read it, normalized to the current version — not rejected.
	noVer := `{"categories":{"ide_extension":{"applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}`
	if err := os.WriteFile(path, []byte(noVer), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	got, ok := ReadAppliedState(CategoryIDEExtension)
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
	if err := WriteAppliedState("other_category", AppliedCategoryState{WrittenValue: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension); ok {
		t.Fatal("a category with no entry should yield ok=false even when the file exists")
	}
}

func TestWritePreservesOtherCategories(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	other := AppliedCategoryState{AppliedHash: "sha256:OTHER", WrittenValue: "other-value"}
	if err := WriteAppliedState("other_category", other); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, AppliedCategoryState{AppliedHash: "sha256:H", WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	// Writing ide_extension must not disturb other_category.
	got, ok := ReadAppliedState("other_category")
	if !ok || got.AppliedHash != other.AppliedHash || got.WrittenValue != other.WrittenValue {
		t.Fatalf("other category not preserved across a sibling write: got %+v ok=%v", got, ok)
	}
}

func TestWriteRefusesFutureSchemaFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	future := `{"schema_version":999,"categories":{"future_only":{"applied_hash":"sha256:z","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}` + "\n"
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()

	err := WriteAppliedState(CategoryIDEExtension, AppliedCategoryState{WrittenValue: samplePolicy})
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

func TestClearRemovesOnlyTargetCategory(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	if err := WriteAppliedState("keep_me", AppliedCategoryState{WrittenValue: "keep"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, AppliedCategoryState{WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	if err := ClearAppliedState(CategoryIDEExtension); err != nil {
		t.Fatalf("ClearAppliedState: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension); ok {
		t.Fatal("cleared category should be gone")
	}
	if got, ok := ReadAppliedState("keep_me"); !ok || got.WrittenValue != "keep" {
		t.Fatalf("untouched category must survive a sibling clear: got %+v ok=%v", got, ok)
	}
}

func TestClearReclaimsEmptyCategoryRecord(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	// An empty-ownership entry, as a preflight leaves when its settings write
	// then fails: present in the file but with no value/hash.
	if err := WriteAppliedState(CategoryIDEExtension, AppliedCategoryState{FetchedAt: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState("keep_me", AppliedCategoryState{WrittenValue: "keep"}); err != nil {
		t.Fatal(err)
	}
	// The empty entry is still a present key (ok=true) — the reconciler's
	// entry-exists drop is what reclaims it.
	if _, ok := ReadAppliedState(CategoryIDEExtension); !ok {
		t.Fatal("empty-ownership entry should be a present key")
	}
	if err := ClearAppliedState(CategoryIDEExtension); err != nil {
		t.Fatalf("ClearAppliedState: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension); ok {
		t.Fatal("empty category record should be reclaimed by clear")
	}
	if got, ok := ReadAppliedState("keep_me"); !ok || got.WrittenValue != "keep" {
		t.Fatalf("sibling category must survive: got %+v ok=%v", got, ok)
	}
}

func TestClearRefusesFutureSchemaFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	future := `{"schema_version":999,"categories":{"future_only":{"applied_hash":"sha256:z"}}}` + "\n"
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()

	if err := ClearAppliedState(CategoryIDEExtension); !errors.Is(err, errFutureSchema) {
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
	if err := ClearAppliedState(CategoryIDEExtension); err != nil {
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
	if _, ok := ReadAppliedState(CategoryIDEExtension); ok {
		t.Fatal("legacy single-object file should read as owns-nothing (no migration)")
	}
}
