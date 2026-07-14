package telemetry

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// captureRingCapacity bounds the in-memory log buffer. Older bytes are
// discarded on overflow. Sized to keep memory usage trivial on multi-hour
// stuck runs while still preserving enough recent context for diagnosis:
// 1 MB ≈ several thousand lines of typical agent output.
const captureRingCapacity = 1 << 20 // 1 MB

// snapSentinel is an in-band marker drainPipe injects into the capture pipe
// to force the reader goroutine to catch up before a snapshot reads the ring.
// The reader strips it, so it never reaches the ring buffer or the real
// stderr. The embedded NULs make it something normal agent log output never
// emits, so the partial-match holdback in the reader effectively never fires
// on real data.
const snapSentinel = "\x00\x00__DMG_LOGCAPTURE_DRAIN__\x00\x00"

// drainTimeout bounds how long SnapshotBase64 waits for the reader to drain.
// A snapshot must never block the telemetry upload, so on the (unexpected)
// event the marker isn't acknowledged we fall back to reading the ring as-is
// — strictly no worse than the pre-drain behavior.
const drainTimeout = 2 * time.Second

// LogCapture captures all stderr output during telemetry execution into a
// bounded ring buffer. The buffer's contents are exposed two ways:
//
//   - Tail(n): the last n bytes, used by heartbeat posts to ship a fresh
//     diagnostic slice on every progress upsert.
//   - Finalize(): the entire current buffer, base64-encoded, embedded in
//     the final ExecutionLogs payload.
//
// Behavior change vs. previous unbounded bytes.Buffer: when a run produces
// more than captureRingCapacity bytes of log output (hours-long stuck
// runs, mainly), the OLDEST bytes are dropped and the final payload
// reflects only the most recent ~1 MB. That's a deliberate trade — the
// oldest output is rarely diagnostic for a hang, and the prior unbounded
// buffer could OOM the agent on a runaway scan.
//
// Nesting with internal/progress/filelog: when filelog is active,
// os.Stderr is already the filelog pipe's write end. StartCapture saves
// that value as origErr, swaps os.Stderr to its own pipe, and on
// Finalize restores os.Stderr = origErr — re-enabling the filelog tee.
// Do not change Finalize to assign os.Stderr to the "real" stderr
// directly; that would orphan filelog mid-run and lose the suffix of
// the log file.
type LogCapture struct {
	ring      *ringBuffer
	mu        sync.Mutex
	origErr   *os.File
	pipeRead  *os.File
	pipeWrite *os.File
	done      chan struct{}

	drainMu sync.Mutex    // serialises drainPipe so only one sentinel is in flight
	drainCh chan struct{} // closed by the reader when it consumes the sentinel; guarded by mu
}

// ringBuffer is a fixed-capacity append-only byte sink. Once full, writes
// overwrite the oldest bytes. Safe for single-writer / single-reader; the
// LogCapture mutex enforces that elsewhere.
type ringBuffer struct {
	data  []byte
	start int  // index of the oldest byte when full
	size  int  // current valid byte count (≤ cap(data))
	full  bool // true once size has reached cap(data); start is then meaningful
}

func newRingBuffer(cap int) *ringBuffer { return &ringBuffer{data: make([]byte, cap)} }

func (r *ringBuffer) Write(p []byte) {
	capacity := cap(r.data)
	if capacity == 0 {
		return
	}
	// If the incoming slice is bigger than capacity, keep only the tail —
	// older bytes were going to be overwritten anyway.
	if len(p) > capacity {
		p = p[len(p)-capacity:]
	}
	for _, b := range p {
		if !r.full {
			r.data[r.size] = b
			r.size++
			if r.size == capacity {
				r.full = true
				r.start = 0
			}
			continue
		}
		r.data[r.start] = b
		r.start = (r.start + 1) % capacity
	}
}

// Bytes returns a fresh slice containing all currently buffered bytes in
// write order (oldest first).
func (r *ringBuffer) Bytes() []byte {
	if !r.full {
		out := make([]byte, r.size)
		copy(out, r.data[:r.size])
		return out
	}
	capacity := cap(r.data)
	out := make([]byte, capacity)
	n := copy(out, r.data[r.start:])
	copy(out[n:], r.data[:r.start])
	return out
}

// Tail returns the last n buffered bytes (or all of them if fewer have
// been written). Returns a fresh slice, safe for the caller to retain.
func (r *ringBuffer) Tail(n int) []byte {
	all := r.Bytes()
	if n <= 0 || len(all) == 0 {
		return nil
	}
	if n >= len(all) {
		return all
	}
	return all[len(all)-n:]
}

// StartCapture redirects stderr to a tee that writes to both the original
// stderr and an in-memory ring buffer for later base64 encoding.
func StartCapture() *LogCapture {
	lc := &LogCapture{
		ring:    newRingBuffer(captureRingCapacity),
		origErr: os.Stderr,
		done:    make(chan struct{}),
	}

	r, w, err := os.Pipe()
	if err != nil {
		return lc // fallback: no capture
	}
	lc.pipeRead = r
	lc.pipeWrite = w

	// Redirect stderr to the pipe
	os.Stderr = w

	// Tee: read from pipe, write to both original stderr and ring buffer,
	// while watching for drain sentinels (stripped, never emitted).
	go func() {
		defer close(lc.done)
		sentinel := []byte(snapSentinel)
		buf := make([]byte, 4096)
		var pending []byte // holds a trailing partial-sentinel prefix across reads
		for {
			n, err := r.Read(buf)
			if n > 0 {
				data := append(pending, buf[:n]...)
				pending = nil
				// Emit everything up to each sentinel and signal one drain
				// per sentinel consumed. FIFO ordering guarantees that once
				// the sentinel is consumed, all bytes written before it are
				// already in the ring.
				for {
					idx := bytes.Index(data, sentinel)
					if idx < 0 {
						break
					}
					lc.writeOut(data[:idx])
					data = data[idx+len(sentinel):]
					lc.signalDrain()
				}
				// A sentinel may straddle a read boundary: hold back the
				// longest suffix of data that is a prefix of the sentinel so
				// we neither emit part of it nor miss the match next read.
				keep := trailingSentinelPrefixLen(data, sentinel)
				lc.writeOut(data[:len(data)-keep])
				pending = append(pending, data[len(data)-keep:]...)
			}
			if err != nil {
				lc.writeOut(pending)
				break
			}
		}
	}()

	return lc
}

// writeOut appends p to the ring (under mu) and echoes it to the original
// stderr. The terminal write stays outside the ring lock to match the
// original tee's contention profile.
func (lc *LogCapture) writeOut(p []byte) {
	if len(p) == 0 {
		return
	}
	lc.mu.Lock()
	lc.ring.Write(p)
	lc.mu.Unlock()
	_, _ = lc.origErr.Write(p)
}

// signalDrain wakes the drainPipe caller waiting on the current sentinel.
func (lc *LogCapture) signalDrain() {
	lc.mu.Lock()
	ch := lc.drainCh
	lc.drainCh = nil
	lc.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

// trailingSentinelPrefixLen returns the length of the longest suffix of data
// that is a (strict) prefix of sentinel — the bytes that might complete into
// a sentinel on the next read and so must be held back.
func trailingSentinelPrefixLen(data, sentinel []byte) int {
	max := len(sentinel) - 1
	if max > len(data) {
		max = len(data)
	}
	for k := max; k > 0; k-- {
		if bytes.HasSuffix(data, sentinel[:k]) {
			return k
		}
	}
	return 0
}

// Finalize stops capture and returns the base64-encoded output.
// Safe to call multiple times — subsequent calls return the cached result.
func (lc *LogCapture) Finalize() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.pipeWrite == nil {
		// Already finalized or never started
		return base64.StdEncoding.EncodeToString(lc.ringBytesLocked())
	}

	// Close write end so the reader goroutine exits
	_ = lc.pipeWrite.Close()
	lc.pipeWrite = nil
	lc.mu.Unlock()
	<-lc.done
	lc.mu.Lock()

	// Restore stderr
	os.Stderr = lc.origErr
	_ = lc.pipeRead.Close()

	return base64.StdEncoding.EncodeToString(lc.ringBytesLocked())
}

// SnapshotBase64 returns the base64-encoded buffer contents WITHOUT stopping
// capture, so a caller can embed the session-so-far in the telemetry payload
// while the capture keeps recording (e.g. through the upload that follows).
// The real teardown — closing the pipe and restoring os.Stderr — stays in
// Finalize, which the caller still defers. Safe to call during active capture.
//
// It first drains the capture pipe so lines written immediately before the
// call (e.g. the config-audit progress lines emitted right before the payload
// snapshot in telemetry.Run) are already in the ring. Without the drain, those
// still-in-flight lines are dropped from the uploaded log — the console showed
// runs truncating at whatever line preceded the snapshot.
func (lc *LogCapture) SnapshotBase64() string {
	lc.drainPipe()
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return base64.StdEncoding.EncodeToString(lc.ringBytesLocked())
}

// drainPipe blocks until the reader goroutine has copied every byte written
// to the capture pipe so far into the ring buffer. It works by injecting a
// sentinel and waiting for the reader to consume it; the pipe's FIFO ordering
// then guarantees all earlier bytes are already ringed. Best-effort: it
// returns early (leaving the ring as-is) if capture has stopped, the marker
// can't be written, or the reader doesn't acknowledge within drainTimeout.
func (lc *LogCapture) drainPipe() {
	lc.drainMu.Lock()
	defer lc.drainMu.Unlock()

	lc.mu.Lock()
	w := lc.pipeWrite
	if w == nil {
		// Capture never started or already finalized; the ring is final and
		// no reader is running to acknowledge a sentinel.
		lc.mu.Unlock()
		return
	}
	ch := make(chan struct{})
	lc.drainCh = ch
	lc.mu.Unlock()

	if _, err := w.Write([]byte(snapSentinel)); err != nil {
		lc.mu.Lock()
		lc.drainCh = nil
		lc.mu.Unlock()
		return
	}

	select {
	case <-ch:
	case <-lc.done: // reader exited (e.g. a concurrent Finalize)
	case <-time.After(drainTimeout):
	}
}

// Tail returns the last n captured bytes as a fresh slice. Safe to call
// concurrently with active capture; returns nil if the buffer is empty
// or n ≤ 0. Used by heartbeat posts to ship the most recent diagnostic
// slice without bloating the payload.
func (lc *LogCapture) Tail(n int) []byte {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.ring == nil {
		return nil
	}
	return lc.ring.Tail(n)
}

// Seed writes pre-capture bytes directly into the ring buffer WITHOUT echoing
// them to the live stderr / agent.error.log. Used to fold in the loader
// script's earlier agent.log output so heartbeat tails and the final payload
// include it, even though it was logged before StartCapture redirected stderr.
// Call once, right after StartCapture and before any stderr output, so the
// seeded bytes sit at the head of the buffer.
func (lc *LogCapture) Seed(p []byte) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.ring != nil {
		lc.ring.Write(p)
	}
}

func (lc *LogCapture) ringBytesLocked() []byte {
	if lc.ring == nil {
		return nil
	}
	return lc.ring.Bytes()
}

// Write allows direct writing to the capture buffer (for banner etc.)
// while also writing to stderr.
func (lc *LogCapture) Write(p []byte) (n int, err error) {
	if lc.pipeWrite != nil {
		return lc.pipeWrite.Write(p)
	}
	return lc.origErr.Write(p)
}

// Fprintf is a convenience method.
func (lc *LogCapture) Fprintf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	_, _ = io.WriteString(lc, msg)
}
