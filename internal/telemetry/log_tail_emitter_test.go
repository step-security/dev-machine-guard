package telemetry

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"
)

// stepClock is a deterministic time source for the throttle test.
type stepClock struct{ t time.Time }

func (c *stepClock) now() time.Time          { return c.t }
func (c *stepClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newEmitterWithFakeClock(cap *LogCapture, interval time.Duration, clk *stepClock) *logTailEmitter {
	e := newLogTailEmitter(cap, interval)
	e.now = clk.now
	return e
}

func TestLogTailEmitter_ThrottlesAttachments(t *testing.T) {
	lc := &LogCapture{ring: newRingBuffer(64 * 1024)}
	lc.ring.Write([]byte("first batch of logs\n"))

	clk := &stepClock{t: time.Unix(1_700_000_000, 0)}
	em := newEmitterWithFakeClock(lc, 2*time.Minute, clk)

	// First call after construction MUST attach — there's no prior send
	// timestamp; otherwise the very first heartbeat would miss the tail.
	var snap RunStatusInfo
	em.MaybeAttach(&snap)
	if snap.LogTailGzipBase64 == "" {
		t.Fatalf("first MaybeAttach must attach a tail; got empty field")
	}
	if decoded := decodeTail(t, snap.LogTailGzipBase64); !strings.Contains(decoded, "first batch") {
		t.Fatalf("attached tail missing expected content; got %q", decoded)
	}

	// Within the throttle window, no attachment.
	lc.ring.Write([]byte("second batch (within throttle window)\n"))
	clk.advance(30 * time.Second)
	snap = RunStatusInfo{}
	em.MaybeAttach(&snap)
	if snap.LogTailGzipBase64 != "" {
		t.Fatalf("MaybeAttach within throttle window must skip; attached anyway")
	}

	// After the window, attachment resumes and reflects the latest buffer.
	clk.advance(2 * time.Minute)
	lc.ring.Write([]byte("third batch after window\n"))
	snap = RunStatusInfo{}
	em.MaybeAttach(&snap)
	if snap.LogTailGzipBase64 == "" {
		t.Fatalf("MaybeAttach after throttle window must attach")
	}
	decoded := decodeTail(t, snap.LogTailGzipBase64)
	if !strings.Contains(decoded, "third batch") {
		t.Fatalf("post-window tail must include latest content; got %q", decoded)
	}
}

// ForceAttach must attach the current tail even inside the throttle window —
// the final post-upload snapshot depends on it so the last lines (the upload's
// own output) aren't dropped by the throttle on a sub-2-minute run.
func TestLogTailEmitter_ForceAttachBypassesThrottle(t *testing.T) {
	lc := &LogCapture{ring: newRingBuffer(64 * 1024)}
	lc.ring.Write([]byte("startup output\n"))

	clk := &stepClock{t: time.Unix(1_700_000_000, 0)}
	em := newEmitterWithFakeClock(lc, 2*time.Minute, clk)

	// First MaybeAttach consumes the throttle slot.
	var snap RunStatusInfo
	em.MaybeAttach(&snap)
	if snap.LogTailGzipBase64 == "" {
		t.Fatal("first MaybeAttach should attach")
	}

	// Still within the throttle window: MaybeAttach skips, ForceAttach does not.
	clk.advance(10 * time.Second)
	lc.ring.Write([]byte("upload completed\n"))

	var throttled RunStatusInfo
	em.MaybeAttach(&throttled)
	if throttled.LogTailGzipBase64 != "" {
		t.Fatal("MaybeAttach within the window should skip")
	}

	var forced RunStatusInfo
	em.ForceAttach(&forced)
	if forced.LogTailGzipBase64 == "" {
		t.Fatal("ForceAttach must attach even within the throttle window")
	}
	if decoded := decodeTail(t, forced.LogTailGzipBase64); !strings.Contains(decoded, "upload completed") {
		t.Fatalf("ForceAttach must reflect the latest buffer; got %q", decoded)
	}

	// ForceAttach updated lastSent, so a follow-on MaybeAttach still throttles.
	clk.advance(10 * time.Second)
	var after RunStatusInfo
	em.MaybeAttach(&after)
	if after.LogTailGzipBase64 != "" {
		t.Fatal("MaybeAttach should still be throttled after ForceAttach")
	}
}

func TestLogTailEmitter_NilSafe(t *testing.T) {
	// Nil receiver, nil capture, and nil info should all be no-ops, not panics —
	// for both MaybeAttach and ForceAttach.
	var em *logTailEmitter
	em.MaybeAttach(&RunStatusInfo{}) // nil receiver
	em.ForceAttach(&RunStatusInfo{}) // nil receiver

	em2 := newLogTailEmitter(nil, 2*time.Minute)
	em2.MaybeAttach(&RunStatusInfo{}) // nil capture
	em2.ForceAttach(&RunStatusInfo{}) // nil capture

	em3 := newLogTailEmitter(&LogCapture{ring: newRingBuffer(1024)}, 2*time.Minute)
	em3.MaybeAttach(nil) // nil info
	em3.ForceAttach(nil) // nil info
}

func TestRingBuffer_TailRespectsWraparound(t *testing.T) {
	// Cap is small so we can deterministically wrap.
	r := newRingBuffer(8)
	r.Write([]byte("abcdef")) // not yet full
	if got := string(r.Tail(10)); got != "abcdef" {
		t.Fatalf("Tail before fill: got %q, want %q", got, "abcdef")
	}

	r.Write([]byte("ghij")) // now full + wrapped: total written "abcdefghij", buffer holds "cdefghij"
	if got := string(r.Tail(8)); got != "cdefghij" {
		t.Fatalf("Tail after wrap: got %q, want %q", got, "cdefghij")
	}
	if got := string(r.Tail(3)); got != "hij" {
		t.Fatalf("Tail(3) after wrap: got %q, want %q", got, "hij")
	}
}

func decodeTail(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	return string(out)
}
