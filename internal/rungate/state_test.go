package rungate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/heartbeat"
)

func withTempState(t *testing.T) string {
	t.Helper()
	// The gate cache shares last-run.json with the heartbeat breadcrumb.
	path := filepath.Join(t.TempDir(), "last-run.json")
	restore := SetStatePathForTest(path)
	t.Cleanup(restore)
	return path
}

func TestStampLastFullRunCreatesAndUpdates(t *testing.T) {
	path := withTempState(t)
	now := time.Unix(1_753_160_800, 0)

	if err := StampLastFullRun("SER123", now); err != nil {
		t.Fatalf("StampLastFullRun on absent file: %v", err)
	}
	st, ok := readState()
	if !ok || st.LastFullRunAt != now.Unix() {
		t.Fatalf("state after stamp = %+v ok=%v, want LastFullRunAt=%d", st, ok, now.Unix())
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
	if err := StampLastFullRun("SER123", later); err != nil {
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

	if err := StampLastFullRun("SER123", now); err != nil {
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

	if err := StampLastFullRun("SER123", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("second stamp: %v", err)
	}
	st, _ = readState()
	if st.DeviceID != "SER123" || st.EffectiveIntervalMinutes != 240 || st.DirectiveFetchedAt != now.Add(time.Minute).Unix() {
		t.Errorf("stamp clobbered check-in fields: %+v", st)
	}
}

// TestHeartbeatAndGateShareFile is the whole point of folding the cache into
// last-run.json: a heartbeat write at the top of a run must not erase the gate
// cache a prior run left, and the gate write must not erase the breadcrumb.
func TestHeartbeatAndGateShareFile(t *testing.T) {
	path := withTempState(t)
	now := time.Unix(1_753_160_800, 0)

	// A prior run left a check-in cache.
	d := Directive{Mode: ModeSkip, Reason: "not_due", GatingEnabled: true, EffectiveIntervalMinutes: 240}
	if err := recordCheckin("SER123", d, now); err != nil {
		t.Fatalf("recordCheckin: %v", err)
	}
	// This run's heartbeat stamps the breadcrumb first.
	if err := heartbeat.Write(path, "send-telemetry", "one_time"); err != nil {
		t.Fatalf("heartbeat write: %v", err)
	}
	// The gate cache must have survived the breadcrumb write.
	st, ok := readState()
	if !ok || st.DeviceID != "SER123" || st.EffectiveIntervalMinutes != 240 {
		t.Fatalf("heartbeat write erased the gate cache: %+v ok=%v", st, ok)
	}
}

func TestFutureSchemaReadUnusableThenOverwritten(t *testing.T) {
	path := withTempState(t)
	future := `{"schema_version": 99, "run_gate": {"device_id": "FROM-THE-FUTURE", "last_full_run_at": 42}}` + "\n"
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatalf("seed future file: %v", err)
	}

	// A newer-schema file is unusable for the gate decision (fail open)...
	if _, ok := readState(); ok {
		t.Fatal("readState must treat a future-schema file as unusable")
	}
	// ...but is overwritten, not refused: the breadcrumb must always write and
	// the gate cache is fail-open-safe, so we don't preserve unknown schemas.
	now := time.Unix(1_753_160_800, 0)
	if err := StampLastFullRun("SER123", now); err != nil {
		t.Fatalf("StampLastFullRun over future-schema file: %v", err)
	}
	st, ok := readState()
	if !ok || st.LastFullRunAt != now.Unix() || st.DeviceID != "SER123" {
		t.Fatalf("future-schema file not cleanly overwritten: %+v ok=%v", st, ok)
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
	if err := StampLastFullRun("SER123", now); err != nil {
		t.Fatalf("stamp over corrupt file: %v", err)
	}
	st, ok := readState()
	if !ok || st.LastFullRunAt != now.Unix() {
		t.Fatalf("state not recreated cleanly: %+v ok=%v", st, ok)
	}
}

func TestCompletionStampBindsIdentityWithoutCheckin(t *testing.T) {
	withTempState(t)
	old := config.DeviceID
	t.Cleanup(func() { config.DeviceID = old })
	config.DeviceID = ""
	now := time.Now()
	if err := recordCheckin("hardware-A", Directive{GatingEnabled: true, EffectiveIntervalMinutes: 240}, now); err != nil {
		t.Fatal(err)
	}
	if err := StampLastFullRun("hardware-A", now.Add(-5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	config.DeviceID = "custom-B"
	if err := StampLastFullRun("custom-B", now); err != nil {
		t.Fatal(err)
	}
	st, ok := readState()
	if !ok || st.DeviceID != "custom-B" || st.ConfiguredDeviceID != "custom-B" || st.LastFullRunAt != now.Unix() {
		t.Fatalf("completion stamped against wrong identity: %+v", st)
	}
	if st.GatingEnabled || st.EffectiveIntervalMinutes != 0 || st.DirectiveFetchedAt != 0 {
		t.Fatalf("completion retained A's directive: %+v", st)
	}
}
