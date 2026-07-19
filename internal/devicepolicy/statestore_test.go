package devicepolicy

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newFileStore(t *testing.T) *fileStateStore {
	t.Helper()
	dir := t.TempDir()
	return &fileStateStore{
		dir:  dir,
		path: filepath.Join(dir, packageConfigStateBasename+".json"),
	}
}

func TestFileStateStoreRoundTrip(t *testing.T) {
	s := newFileStore(t)
	if _, ok := s.Read(CategoryPackageConfig, TargetNPM); ok {
		t.Fatal("an empty store must read absent")
	}
	want := AppliedTargetState{
		AppliedHash:  "sha256:N",
		WrittenValue: "managed-block",
		FetchedAt:    time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
	}
	if err := s.Write(CategoryPackageConfig, TargetNPM, want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, ok := s.Read(CategoryPackageConfig, TargetNPM)
	if !ok || got.AppliedHash != want.AppliedHash || got.WrittenValue != want.WrittenValue || !got.FetchedAt.Equal(want.FetchedAt) {
		t.Fatalf("Read = %+v ok=%v, want %+v", got, ok, want)
	}
	// The file is created 0600 (not group/other-accessible). POSIX-only: Windows
	// has no permission bits, so Chmod can't set 0600 and Stat reports 0666 for any
	// writable file.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(s.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != cacheFileMode {
			t.Fatalf("file mode = %o, want %o", info.Mode().Perm(), cacheFileMode)
		}
	}
	if err := s.Drop(CategoryPackageConfig, TargetNPM); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	if _, ok := s.Read(CategoryPackageConfig, TargetNPM); ok {
		t.Fatal("a dropped record must read absent")
	}
}

func TestFileStateStorePreservesSiblings(t *testing.T) {
	// The read-modify-write must preserve every other category/target — the same
	// guarantee the shared cache makes, applied to this category's own file.
	s := newFileStore(t)
	npm := AppliedTargetState{AppliedHash: "sha256:N", WrittenValue: "npm-block"}
	ide := AppliedTargetState{AppliedHash: "sha256:V", WrittenValue: "vscode-value"}
	if err := s.Write(CategoryPackageConfig, TargetNPM, npm); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(CategoryIDEExtension, TargetVSCode, ide); err != nil {
		t.Fatal(err)
	}
	if err := s.Drop(CategoryPackageConfig, TargetNPM); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Read(CategoryPackageConfig, TargetNPM); ok {
		t.Fatal("the dropped npm record must be gone")
	}
	got, ok := s.Read(CategoryIDEExtension, TargetVSCode)
	if !ok || got.WrittenValue != "vscode-value" {
		t.Fatalf("the sibling record must survive, got %+v ok=%v", got, ok)
	}
}

func TestFileStateStoreRefusesFutureSchema(t *testing.T) {
	// An older agent meeting a NEWER agent's state file must not overwrite it:
	// Read yields "owns nothing", and Write/Drop refuse rather than clobber
	// metadata they can't interpret. The file stays byte-identical.
	dir := t.TempDir()
	path := filepath.Join(dir, packageConfigStateBasename+".json")
	future := `{"schema_version":999,"categories":{"package_config":{"targets":` +
		`{"npm":{"applied_hash":"sha256:z","written_value":"blk","fetched_at":"2026-07-01T00:00:00Z"}}}}}` + "\n"
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &fileStateStore{dir: dir, path: path}

	if _, ok := s.Read(CategoryPackageConfig, TargetNPM); ok {
		t.Fatal("a future-schema file must read as absent")
	}
	if err := s.Write(CategoryPackageConfig, TargetNPM, AppliedTargetState{WrittenValue: "x"}); err != errFutureSchema {
		t.Fatalf("Write err = %v, want errFutureSchema", err)
	}
	if err := s.Drop(CategoryPackageConfig, TargetNPM); err != errFutureSchema {
		t.Fatalf("Drop err = %v, want errFutureSchema", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != future {
		t.Fatalf("a future-schema file must be left byte-identical, got %q", string(after))
	}
}

func TestFileStateStoreRecreatesCorruptFile(t *testing.T) {
	// A corrupt (non-JSON-object) file reads as absent and is recreated cleanly on
	// the next write — never surfaced as an error.
	dir := t.TempDir()
	path := filepath.Join(dir, packageConfigStateBasename+".json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &fileStateStore{dir: dir, path: path}
	if _, ok := s.Read(CategoryPackageConfig, TargetNPM); ok {
		t.Fatal("a corrupt file must read as absent")
	}
	if err := s.Write(CategoryPackageConfig, TargetNPM, AppliedTargetState{WrittenValue: "blk"}); err != nil {
		t.Fatalf("Write over a corrupt file must recreate it, got %v", err)
	}
	got, ok := s.Read(CategoryPackageConfig, TargetNPM)
	if !ok || got.WrittenValue != "blk" {
		t.Fatalf("record after recreate = %+v ok=%v", got, ok)
	}
}

func TestFileStateStoreDropAbsentIsNoOp(t *testing.T) {
	s := newFileStore(t)
	// No file yet.
	if err := s.Drop(CategoryPackageConfig, TargetNPM); err != nil {
		t.Fatalf("dropping from an absent store must be a no-op, got %v", err)
	}
	// A file that exists but holds no such record.
	if err := s.Write(CategoryPackageConfig, TargetNPM, AppliedTargetState{WrittenValue: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Drop(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("dropping an absent record must be a no-op, got %v", err)
	}
	if _, ok := s.Read(CategoryPackageConfig, TargetNPM); !ok {
		t.Fatal("the existing record must be untouched")
	}
}

func TestFileStateStoreDropRemovesCorruptFile(t *testing.T) {
	// A corrupt state file can still carry token-bearing WrittenValue bytes. Drop
	// (offboarding) must not report success while leaving those bytes on disk — it
	// removes the file so no stale credential survives the clear. (Contrast an
	// absent file, which stays a no-op — nothing to remove.)
	dir := t.TempDir()
	path := filepath.Join(dir, packageConfigStateBasename+".json")
	corrupt := `{ broken "written_value": "ssabc123::dev:S1` // invalid JSON, token-shaped bytes
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &fileStateStore{dir: dir, path: path}
	if err := s.Drop(CategoryPackageConfig, TargetNPM); err != nil {
		t.Fatalf("Drop over a corrupt file must succeed, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Drop must remove a corrupt state file, stat err = %v", err)
	}
}

func TestNewStateStoreForPlacement(t *testing.T) {
	// Placement depends on whether the process is a POSIX root daemon. Assert the
	// branch that matches this test process's euid so the test is host-portable.
	u := &user.User{Uid: "501", HomeDir: filepath.Join(t.TempDir(), "home")}
	s, ok := NewStateStoreFor(u).(*fileStateStore)
	if !ok {
		t.Fatal("NewStateStoreFor must return a *fileStateStore")
	}
	base := filepath.Base(s.path)
	if os.Geteuid() == 0 {
		// Root daemon → machine-owned dir + ONE record file per target uid.
		if !strings.HasPrefix(s.path, "/Library/Application Support/StepSecurity") &&
			!strings.HasPrefix(s.path, "/var/lib/stepsecurity") {
			t.Fatalf("root-mode path must be machine-owned, got %q", s.path)
		}
		if base != packageConfigStateBasename+"-501.json" {
			t.Fatalf("root-mode file must be per-uid, got %q", base)
		}
	} else {
		// User mode → under the target user's ~/.stepsecurity.
		wantDir := filepath.Join(u.HomeDir, ".stepsecurity")
		if s.dir != wantDir {
			t.Fatalf("user-mode dir = %q, want %q", s.dir, wantDir)
		}
		if base != packageConfigStateBasename+".json" {
			t.Fatalf("user-mode file = %q, want %q", base, packageConfigStateBasename+".json")
		}
	}
}

func TestNewStateStoreForNonNumericUIDIsUserMode(t *testing.T) {
	// A non-numeric uid (a Windows SID, or an unresolved identity) cannot select a
	// per-uid machine file, so placement falls back to user mode — proven by the
	// user-mode basename regardless of euid.
	u := &user.User{Uid: "S-1-5-21-abc", HomeDir: filepath.Join(t.TempDir(), "home")}
	s, ok := NewStateStoreFor(u).(*fileStateStore)
	if !ok {
		t.Fatal("NewStateStoreFor must return a *fileStateStore")
	}
	if base := filepath.Base(s.path); base != packageConfigStateBasename+".json" {
		t.Fatalf("a non-numeric uid must yield the user-mode file, got %q", base)
	}
}
