package rungate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func withTempState(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run-gate-state.json")
	restore := SetStatePathForTest(path)
	t.Cleanup(restore)
	return path
}

func TestStampLastFullRunCreatesAndUpdates(t *testing.T) {
	path := withTempState(t)
	now := time.Unix(1_753_160_800, 0)

	if err := StampLastFullRun(now); err != nil {
		t.Fatalf("StampLastFullRun on absent file: %v", err)
	}
	st, ok := readState()
	if !ok || st.LastFullRunAt != now.Unix() || st.SchemaVersion != StateSchemaVersion {
		t.Fatalf("state after stamp = %+v ok=%v, want LastFullRunAt=%d schema=%d", st, ok, now.Unix(), StateSchemaVersion)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat state file: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("state file mode = %v, want 0600", info.Mode().Perm())
		}
	}

	later := now.Add(4 * time.Hour)
	if err := StampLastFullRun(later); err != nil {
		t.Fatalf("StampLastFullRun update: %v", err)
	}
	st, _ = readState()
	if st.LastFullRunAt != later.Unix() {
		t.Fatalf("LastFullRunAt = %d, want %d", st.LastFullRunAt, later.Unix())
	}
}

func TestStampAndRecordPreserveEachOther(t *testing.T) {
	withTempState(t)
	now := time.Unix(1_753_160_800, 0)

	if err := StampLastFullRun(now); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	d := Directive{Mode: ModeSkip, Reason: "not_due", GatingEnabled: true, EffectiveIntervalMinutes: 240}
	if err := recordCheckin("SER123", d, now.Add(time.Minute)); err != nil {
		t.Fatalf("recordCheckin: %v", err)
	}

	st, ok := readState()
	if !ok {
		t.Fatal("state unreadable after both writes")
	}
	if st.LastFullRunAt != now.Unix() {
		t.Errorf("recordCheckin clobbered LastFullRunAt: %d", st.LastFullRunAt)
	}
	if st.DeviceID != "SER123" || !st.GatingEnabled || st.EffectiveIntervalMinutes != 240 {
		t.Errorf("check-in fields not persisted: %+v", st)
	}

	if err := StampLastFullRun(now.Add(2 * time.Hour)); err != nil {
		t.Fatalf("second stamp: %v", err)
	}
	st, _ = readState()
	if st.DeviceID != "SER123" || st.EffectiveIntervalMinutes != 240 || st.DirectiveFetchedAt != now.Add(time.Minute).Unix() {
		t.Errorf("stamp clobbered check-in fields: %+v", st)
	}
}

func TestFutureSchemaRefusal(t *testing.T) {
	path := withTempState(t)
	future := `{"schema_version": 99, "device_id": "FROM-THE-FUTURE", "last_full_run_at": 42}` + "\n"
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatalf("seed future file: %v", err)
	}

	if _, ok := readState(); ok {
		t.Fatal("readState must treat a future-schema file as unusable")
	}
	if err := StampLastFullRun(time.Unix(1_753_160_800, 0)); err == nil {
		t.Fatal("StampLastFullRun must refuse to overwrite a future-schema file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if string(b) != future {
		t.Fatalf("future-schema file was modified:\n%s", b)
	}
}

func TestCorruptFileIsRecreated(t *testing.T) {
	path := withTempState(t)
	if err := os.WriteFile(path, []byte("not json{{"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if _, ok := readState(); ok {
		t.Fatal("corrupt file must read as unusable")
	}
	now := time.Unix(1_753_160_800, 0)
	if err := StampLastFullRun(now); err != nil {
		t.Fatalf("stamp over corrupt file: %v", err)
	}
	st, ok := readState()
	if !ok || st.LastFullRunAt != now.Unix() {
		t.Fatalf("state not recreated cleanly: %+v ok=%v", st, ok)
	}
}

func TestNoPathFailsSoft(t *testing.T) {
	// paths.RunGateStateFile() returns "" when Home() is disabled; both
	// primitives must degrade softly so the gate's callers fail open.
	if _, status := loadState(""); status != loadAbsentOrCorrupt {
		t.Fatalf("loadState(\"\") status = %v, want loadAbsentOrCorrupt", status)
	}
	if err := saveState("", State{}); err == nil {
		t.Fatal("saveState(\"\") must error (best-effort caller logs it)")
	}
}
