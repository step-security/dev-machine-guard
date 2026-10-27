package updatestate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

func TestRunRecordsLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs", "1.19.0.json")
	if recs := ReadRuns(path); recs != nil {
		t.Fatalf("missing file = %v", recs)
	}
	if err := MarkRunStarted(path, "x"); err != ErrNoOpenRun {
		t.Fatalf("MarkRunStarted on empty = %v", err)
	}
	if err := AppendRun(path, RunRecord{Version: "bad"}); err == nil {
		t.Fatal("AppendRun accepted a bad version")
	}
	at := time.Date(2026, 10, 19, 1, 2, 3, 0, time.UTC)
	for i := 0; i < 13; i++ {
		id := fmt.Sprintf("run-%d", i)
		if err := AppendRun(path, RunRecord{RunID: id, Version: "1.19.0"}); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if err := MarkRunStarted(path, id); err != nil {
				t.Fatal(err)
			}
		}
		if err := FinalizeRun(path, id, i%3, false, at.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := FinalizeRun(path, "run-12", 0, false, at); err != ErrNoOpenRun {
		t.Fatalf("FinalizeRun with no open record = %v", err)
	}
	recs := ReadRuns(path)
	if len(recs) != MaxRunRecords {
		t.Fatalf("kept %d records, want %d", len(recs), MaxRunRecords)
	}
	first, last := recs[0], recs[len(recs)-1]
	if !first.At.Equal(at.Add(3*time.Minute)) || !last.At.Equal(at.Add(12*time.Minute)) {
		t.Fatalf("kept the wrong window: %v .. %v", first.At, last.At)
	}
	if !last.Started || last.RunID != "run-12" || *last.ExitCode != 0 {
		t.Fatalf("last record %+v", last)
	}
	if err := AppendRun(path, RunRecord{RunID: "run-13", Version: "1.19.0"}); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); ClassifyRun(recs[len(recs)-1]) != RunOpen {
		t.Fatal("new record is not open")
	}
}

// R-F1-1: overlapping launches (hourly + logon on wake) each keep their own
// record, whatever order they start and finish in.
func TestOverlappingRunsMatchByRunID(t *testing.T) {
	at := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	for _, aFirst := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "1.19.0.json")
		for _, id := range []string{"A", "B"} {
			if err := AppendRun(path, RunRecord{RunID: id, Version: "1.19.0"}); err != nil {
				t.Fatal(err)
			}
		}
		finalizeA := func() {
			if err := MarkRunStarted(path, "A"); err != nil {
				t.Fatalf("mark A: %v", err)
			}
			if err := FinalizeRun(path, "A", 0, false, at); err != nil {
				t.Fatalf("finalize A: %v", err)
			}
		}
		finalizeB := func() {
			if err := FinalizeRun(path, "B", 1, false, at); err != nil {
				t.Fatalf("finalize B: %v", err)
			}
		}
		if aFirst {
			finalizeA()
			finalizeB()
		} else {
			finalizeB()
			finalizeA()
		}
		got := map[string]RunVerdict{}
		for _, r := range ReadRuns(path) {
			got[r.RunID] = ClassifyRun(r)
		}
		if got["A"] != RunHealthy || got["B"] != RunNeutral {
			t.Fatalf("aFirst=%v verdicts = %v, want A healthy, B neutral", aFirst, got)
		}
		if err := MarkRunStarted(path, "A"); err != ErrNoOpenRun {
			t.Fatalf("closed record reopened: %v", err)
		}
		if err := MarkRunStarted(path, ""); err != ErrNoOpenRun {
			t.Fatalf("empty run id matched: %v", err)
		}
	}
}

// D13: a record without a run_id, or with one already in the file, could
// never be matched (or would be matched twice), so AppendRun refuses it.
func TestAppendRunRequiresUniqueRunID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.19.0.json")
	if err := AppendRun(path, RunRecord{Version: "1.19.0"}); err == nil {
		t.Fatal("empty run_id accepted")
	}
	if err := AppendRun(path, RunRecord{RunID: "A", Version: "1.19.0"}); err != nil {
		t.Fatal(err)
	}
	if err := AppendRun(path, RunRecord{RunID: "A", Version: "1.19.0"}); err == nil {
		t.Fatal("duplicate run_id accepted")
	}
	if recs := ReadRuns(path); len(recs) != 1 {
		t.Fatalf("records = %+v", recs)
	}
}

func TestReadRunsToleratesGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "1.19.0.json")
	for _, body := range []string{"", "garbage", "[]", `{"records":"x"}`, `{"records":[{"version":1}]}`,
		`{"records":[{"version":"1.19.0","exit_code":"x"}]}`, `{"records":[{"version":"../x"}]}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if recs := ReadRuns(path); recs != nil {
			t.Errorf("ReadRuns(%q) = %+v, want none", body, recs)
		}
	}
	// Garbage is replaced, not appended to.
	if err := AppendRun(path, RunRecord{RunID: "r1", Version: "1.19.0"}); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); len(recs) != 1 {
		t.Fatalf("after append over garbage: %+v", recs)
	}
	// Records with bad versions are dropped individually.
	body := `{"records":[{"version":"1.19.0","started":true,"exit_code":0},{"version":"x"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); len(recs) != 1 || !recs[0].Started {
		t.Fatalf("mixed file: %+v", recs)
	}
	big := make([]byte, maxRunsSize+1)
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); recs != nil {
		t.Fatalf("oversize file read as %d records", len(recs))
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); recs != nil {
		t.Fatal("directory read as records")
	}
}

func TestClassifyRun(t *testing.T) {
	code := func(c int) *int { return &c }
	for _, tc := range []struct {
		name string
		r    RunRecord
		want RunVerdict
	}{
		{"open", RunRecord{}, RunOpen},
		{"open started", RunRecord{Started: true}, RunOpen},
		{"watchdog while open", RunRecord{WatchdogKilled: true}, RunBad},
		{"healthy", RunRecord{Started: true, ExitCode: code(0)}, RunHealthy},
		{"healthy error exit", RunRecord{Started: true, ExitCode: code(1)}, RunHealthy},
		{"panic after start", RunRecord{Started: true, ExitCode: code(2)}, RunBad},
		{"watchdog after start", RunRecord{Started: true, ExitCode: code(0), WatchdogKilled: true}, RunBad},
		{"panic before start", RunRecord{ExitCode: code(2)}, RunBad},
		{"crash before start", RunRecord{ExitCode: code(-1073741819)}, RunBad},
		{"crash code before start", RunRecord{ExitCode: code(3221225477)}, RunBad},
		{"offline or lock held", RunRecord{ExitCode: code(1)}, RunNeutral},
		{"clean exit without marker", RunRecord{ExitCode: code(0)}, RunNeutral},
	} {
		if got := ClassifyRun(tc.r); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// D17: trimming to the last MaxRunRecords evicts the oldest CLOSED records
// first; a record still open (its launch is running) is never evicted, so
// its own finalize/marker still finds it.
func TestTrimNeverEvictsOpenRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.19.0.json")
	at := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	if err := AppendRun(path, RunRecord{RunID: "long-running", Version: "1.19.0"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxRunRecords+3; i++ {
		id := fmt.Sprintf("r%d", i)
		if err := AppendRun(path, RunRecord{RunID: id, Version: "1.19.0"}); err != nil {
			t.Fatal(err)
		}
		if err := FinalizeRun(path, id, 0, false, at); err != nil {
			t.Fatal(err)
		}
	}
	recs := ReadRuns(path)
	if len(recs) != MaxRunRecords || recs[0].RunID != "long-running" || recs[len(recs)-1].RunID != fmt.Sprintf("r%d", MaxRunRecords+2) {
		t.Fatalf("kept %d records: first %q last %q", len(recs), recs[0].RunID, recs[len(recs)-1].RunID)
	}
	if err := MarkRunStarted(path, "long-running"); err != nil {
		t.Fatalf("open record evicted: %v", err)
	}
	if err := FinalizeRun(path, "long-running", 0, false, at); err != nil {
		t.Fatalf("open record evicted: %v", err)
	}
}

// R-F1-8: open records whose bootstrap died (logoff, shutdown, the task
// time limit) are abandoned once older than a scan's maximum life: they
// become Neutral, are evicted first, and the record finalized in the same
// write is never evicted, so a crash still reads as Bad.
func TestStaleOpenRecordsDoNotEvictTheFinalizedOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.20.0.json")
	stale := time.Now().Add(-(abandonAfter + time.Hour))
	dead := deadPID(t)
	for i := 0; i < 12; i++ {
		if err := AppendRun(path, RunRecord{RunID: fmt.Sprintf("dead-%d", i), Version: "1.20.0", StartedAt: stale, OwnerPID: dead}); err != nil {
			t.Fatal(err)
		}
	}
	if err := AppendRun(path, RunRecord{RunID: "crash", Version: "1.20.0"}); err != nil {
		t.Fatal(err)
	}
	if err := FinalizeRun(path, "crash", 2, false, time.Now()); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	recs := ReadRuns(path)
	var crash *RunRecord
	abandoned := 0
	for i := range recs {
		switch {
		case recs[i].RunID == "crash":
			crash = &recs[i]
		case recs[i].Abandoned:
			abandoned++
			if v := ClassifyRun(recs[i]); v != RunNeutral {
				t.Fatalf("abandoned record classified %v", v)
			}
		}
	}
	if crash == nil || ClassifyRun(*crash) != RunBad {
		t.Fatalf("the finalized crash record was lost or not Bad: %+v", recs)
	}
	if len(recs) > MaxRunRecords {
		t.Fatalf("%d records kept, want ≤ %d with no fresh open ones", len(recs), MaxRunRecords)
	}
	// Fresh open records are never evicted and don't count against the cap.
	for i := 0; i < 3; i++ {
		if err := AppendRun(path, RunRecord{RunID: fmt.Sprintf("live-%d", i), Version: "1.20.0"}); err != nil {
			t.Fatal(err)
		}
	}
	recs = ReadRuns(path)
	live := 0
	for _, r := range recs {
		if strings.HasPrefix(r.RunID, "live-") {
			live++
		}
	}
	if live != 3 || len(recs) > MaxRunRecords+3 {
		t.Fatalf("live=%d len=%d", live, len(recs))
	}
}

// deadPID is the pid of a process that has already exited.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := proctest.Command(t, os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}

func recordOf(t *testing.T, path, id string) RunRecord {
	t.Helper()
	for _, r := range ReadRuns(path) {
		if r.RunID == id {
			return r
		}
	}
	t.Fatalf("record %s missing", id)
	return RunRecord{}
}

// R-F1-9: abandonment follows the owning bootstrap's liveness, not the
// wall clock: a laptop asleep for two days doesn't abandon a live run.
func TestAbandonFollowsOwnerLiveness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.20.0.json")
	twoDaysAgo := time.Now().Add(-48 * time.Hour)
	future := time.Now().Add(48 * time.Hour)
	dead := deadPID(t)
	for _, r := range []RunRecord{
		{RunID: "asleep-alive", StartedAt: twoDaysAgo}, // owner = this process (alive)
		{RunID: "fresh-dead", OwnerPID: dead},
		{RunID: "future-dead", StartedAt: future, OwnerPID: dead},
	} {
		r.Version = "1.20.0"
		if err := AppendRun(path, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := AppendRun(path, RunRecord{RunID: "trigger", Version: "1.20.0"}); err != nil {
		t.Fatal(err)
	}
	if r := recordOf(t, path, "asleep-alive"); r.Abandoned {
		t.Fatal("a live owner's old run was abandoned")
	}
	for _, id := range []string{"fresh-dead", "future-dead"} {
		if r := recordOf(t, path, id); !r.Abandoned {
			t.Fatalf("%s: dead owner's run not abandoned", id)
		}
	}
	// A late finalize by the run itself revives it with the real outcome.
	if err := FinalizeRun(path, "fresh-dead", 2, false, time.Now()); err != nil {
		t.Fatalf("late finalize: %v", err)
	}
	if r := recordOf(t, path, "fresh-dead"); r.Abandoned || ClassifyRun(r) != RunBad {
		t.Fatalf("late finalize lost: %+v", r)
	}
	if err := MarkRunStarted(path, "future-dead"); err != nil {
		t.Fatalf("late marker: %v", err)
	}
	if r := recordOf(t, path, "future-dead"); r.Abandoned || !r.Started {
		t.Fatalf("late marker lost: %+v", r)
	}
}

// Without an owner (older records), a future start time counts from when a
// writer first saw it.
func TestAbandonUnknownOwnerFutureStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.20.0.json")
	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339Nano)
	body := `{"records":[{"run_id":"old","version":"1.20.0","start":"` + future + `"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendRun(path, RunRecord{RunID: "t1", Version: "1.20.0"}); err != nil {
		t.Fatal(err)
	}
	r := recordOf(t, path, "old")
	if r.Abandoned || r.FirstSeen.IsZero() {
		t.Fatalf("first sighting: %+v", r)
	}
	// Seen long ago: past the bound now.
	data, _ := os.ReadFile(path)
	stale := time.Now().Add(-(abandonAfter + time.Hour)).UTC().Format(time.RFC3339Nano)
	data = []byte(strings.Replace(string(data), r.FirstSeen.Format(time.RFC3339Nano), stale, 1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendRun(path, RunRecord{RunID: "t2", Version: "1.20.0"}); err != nil {
		t.Fatal(err)
	}
	if r := recordOf(t, path, "old"); !r.Abandoned {
		t.Fatalf("unknown owner, seen long ago: not abandoned: %+v", r)
	}
}

// R-F1-10: the reader never trims: 10 fresh open runs plus a just-finalized
// crash, and the crash is visible.
func TestReadRunsNeverTrims(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.20.0.json")
	for i := 0; i < 10; i++ {
		if err := AppendRun(path, RunRecord{RunID: fmt.Sprintf("live-%d", i), Version: "1.20.0"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := AppendRun(path, RunRecord{RunID: "crash", Version: "1.20.0"}); err != nil {
		t.Fatal(err)
	}
	if err := FinalizeRun(path, "crash", 2, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if r := recordOf(t, path, "crash"); ClassifyRun(r) != RunBad {
		t.Fatalf("crash = %+v", r)
	}
	if n := len(ReadRuns(path)); n != 11 {
		t.Fatalf("reader returned %d records, want 11", n)
	}
}

// FR1-7: the watchdogs count awake time, so any watchdog kill is a real
// hang and Bad, before or after the started marker; kill/crash codes are
// judged before the marker.
func TestKillsAndCrashesAreBadEvenAfterStarted(t *testing.T) {
	two, seventy, seventyFive := 2, 70, 75
	for _, r := range []RunRecord{
		{Started: true, WatchdogKilled: true, ExitCode: &seventyFive},
		{Started: true, ExitCode: &two},
		{Started: true, ExitCode: &seventy},
		{Started: false, ExitCode: &seventyFive},
	} {
		r.Version, r.RunID = "1.20.0", "x"
		if v := ClassifyRun(r); v != RunBad {
			t.Errorf("%+v: verdict %v, want Bad", r, v)
		}
	}
}

// FR1-5: exits caused by the session ending (logoff, shutdown, console
// close) are Neutral; a real crash code is still Bad.
func TestSessionEndExitsAreNeutral(t *testing.T) {
	codes := []int{-1073741510} // 0xC000013A as int32
	for _, u := range []uint32{130, 0xC000013A, 0x40010004} {
		codes = append(codes, int(u)) // uint32 form (wraps on 32-bit hosts)
	}
	for _, code := range codes {
		c := code
		if v := ClassifyRun(RunRecord{Version: "1.20.0", RunID: "x", ExitCode: &c}); v != RunNeutral {
			t.Errorf("exit %#x: verdict %v, want Neutral", code, v)
		}
	}
	crash := int(uint32(0xC0000005))
	if ClassifyRun(RunRecord{Version: "1.20.0", RunID: "x", ExitCode: &crash}) != RunBad {
		t.Fatal("access violation not Bad")
	}
}

// FR1-6: every appended record gets the next per-file sequence number, and
// it keeps counting past trimmed records.
func TestRunSeqIsMonotonic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.20.0.json")
	at := time.Now()
	for i := 1; i <= MaxRunRecords+5; i++ {
		id := fmt.Sprintf("r%d", i)
		if err := AppendRun(path, RunRecord{RunID: id, Version: "1.20.0"}); err != nil {
			t.Fatal(err)
		}
		if err := FinalizeRun(path, id, 0, false, at); err != nil {
			t.Fatal(err)
		}
		if got := recordOf(t, path, id).Seq; got != i {
			t.Fatalf("record %d has seq %d", i, got)
		}
	}
	if MaxRunSeq(path) != MaxRunRecords+5 {
		t.Fatalf("MaxRunSeq = %d", MaxRunSeq(path))
	}
}
