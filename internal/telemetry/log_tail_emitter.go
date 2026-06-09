package telemetry

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"sync"
	"time"
)

const (
	// captureTailBytes is how many trailing bytes of the captured stderr
	// stream get shipped on each eligible heartbeat. 256 KB strikes a
	// balance between "enough context to diagnose a hang" and "small
	// enough that backend storage doesn't explode at scale" — typical
	// gzip ratio on agent log lines is ~10x, so on the wire each tail is
	// roughly 25 KB.
	captureTailBytes = 256 * 1024

	// logTailHeartbeatInterval throttles tail attachment. Phase
	// boundaries fire rapidly during fast scans (sub-second) and would
	// otherwise attach a tail to every status_info post. 2 minutes keeps
	// the tail "fresh enough" for diagnosing a stuck device while
	// bounding traffic: at most 30 tails per hour per device.
	logTailHeartbeatInterval = 2 * time.Minute
)

// logTailEmitter attaches a gzip+base64-encoded log tail to RunStatusInfo
// snapshots on a fixed interval. Safe for concurrent use across the
// heartbeat goroutine and the inline phase-boundary callers, which can
// both reach postPhase.
type logTailEmitter struct {
	capture  *LogCapture
	interval time.Duration
	now      func() time.Time

	mu       sync.Mutex
	lastSent time.Time
}

func newLogTailEmitter(capture *LogCapture, interval time.Duration) *logTailEmitter {
	return &logTailEmitter{capture: capture, interval: interval, now: time.Now}
}

// MaybeAttach populates info.LogTailGzipBase64 iff the throttle window has
// elapsed since the last attachment and the capture buffer is non-empty.
// No-op on nil capture (tests, or pre-StartCapture early returns).
func (e *logTailEmitter) MaybeAttach(info *RunStatusInfo) {
	if e == nil || e.capture == nil || info == nil {
		return
	}
	now := e.now()
	e.mu.Lock()
	if !e.lastSent.IsZero() && now.Sub(e.lastSent) < e.interval {
		e.mu.Unlock()
		return
	}
	// Tentatively claim the slot; release if there's nothing to attach so
	// the next caller can try again immediately.
	previous := e.lastSent
	e.lastSent = now
	e.mu.Unlock()

	tail := e.capture.Tail(captureTailBytes)
	if len(tail) == 0 {
		e.mu.Lock()
		e.lastSent = previous
		e.mu.Unlock()
		return
	}

	encoded, err := gzipBase64(tail)
	if err != nil {
		// Compression failure shouldn't happen for in-memory writes; if it
		// does, just drop the tail rather than ship raw bytes — the
		// progress upsert still succeeds with the rest of the snapshot.
		return
	}
	info.LogTailGzipBase64 = encoded
}

// ForceAttach attaches the current tail regardless of the throttle window.
// Used for the single final post-upload snapshot so the run-status row carries
// the most complete tail — including the upload's own output and the
// completion line — which a throttled MaybeAttach would otherwise drop on a
// sub-2-minute run. Updates lastSent so any later MaybeAttach still respects
// the interval. No-op on nil capture / empty buffer.
func (e *logTailEmitter) ForceAttach(info *RunStatusInfo) {
	if e == nil || e.capture == nil || info == nil {
		return
	}
	tail := e.capture.Tail(captureTailBytes)
	if len(tail) == 0 {
		return
	}
	encoded, err := gzipBase64(tail)
	if err != nil {
		return
	}
	e.mu.Lock()
	e.lastSent = e.now()
	e.mu.Unlock()
	info.LogTailGzipBase64 = encoded
}

// gzipBase64 gzips b at default compression and base64-encodes the
// result. Wrapped here rather than inlined so the emitter and tests
// share a single encoding pipeline.
func gzipBase64(b []byte) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		_ = zw.Close()
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
