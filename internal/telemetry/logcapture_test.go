package telemetry

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSnapshotBase64_IncludesJustWrittenLine reproduces the console
// log-truncation bug: telemetry.Run writes a progress line and then
// immediately calls SnapshotBase64 to embed the log in the payload. Before
// the drain fix, the just-written line was still in flight in the capture
// pipe and got dropped from the uploaded log, so runs appeared to "stop" at
// whatever line preceded the snapshot (in production, the yarn audit line).
//
// StartCapture swaps the process-global os.Stderr, so this test cannot run in
// parallel with others that write to stderr.
func TestSnapshotBase64_IncludesJustWrittenLine(t *testing.T) {
	// Run several trials: the drop was ~deterministic in the tight
	// write→snapshot sequence, but loop to stay robust to scheduling.
	for i := 0; i < 50; i++ {
		lc := StartCapture()

		// An older line that has had time to drain, mirroring the config-audit
		// block where each audit runs for seconds before the next line.
		fmt.Fprintln(os.Stderr, "Auditing yarn configuration...")
		time.Sleep(time.Millisecond)
		// The line written immediately before the payload snapshot.
		fmt.Fprintln(os.Stderr, "  yarn available: false (flavor=), files discovered: 2")

		snap := lc.SnapshotBase64()
		_ = lc.Finalize()

		decoded, err := base64.StdEncoding.DecodeString(snap)
		if err != nil {
			t.Fatalf("trial %d: decode snapshot: %v", i, err)
		}
		if !strings.Contains(string(decoded), "yarn available: false") {
			t.Fatalf("trial %d: snapshot dropped the just-written line; got:\n%s", i, decoded)
		}
	}
}

// TestSnapshotBase64_StripsSentinel guards that the drain sentinel never
// leaks into the captured output.
func TestSnapshotBase64_StripsSentinel(t *testing.T) {
	lc := StartCapture()
	fmt.Fprintln(os.Stderr, "line one")
	_ = lc.SnapshotBase64() // injects + drains a sentinel
	fmt.Fprintln(os.Stderr, "line two")
	out := lc.Finalize()

	decoded, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	s := string(decoded)
	if strings.Contains(s, snapSentinel) || strings.Contains(s, "DMG_LOGCAPTURE_DRAIN") {
		t.Fatalf("sentinel leaked into captured log:\n%q", s)
	}
	if !strings.Contains(s, "line one") || !strings.Contains(s, "line two") {
		t.Fatalf("captured log missing expected lines:\n%q", s)
	}
}
