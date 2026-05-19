// Package filelog tees the agent's stderr stream to a file on disk so
// that when agent-api is unreachable (network failure, firewall, expired
// credentials), the customer can be asked to share the local log file
// with support.
//
// Mechanism: Start() opens an os.Pipe, swaps os.Stderr for the pipe's
// write end, and spawns a goroutine that reads from the pipe and writes
// to both the original stderr file and the on-disk log file. Stop()
// closes the write end, waits for the goroutine to drain, restores
// os.Stderr, and closes the file. This mirrors the in-memory capture
// already used by internal/telemetry/logcapture.go, with a file in
// place of the bytes.Buffer.
//
// The file is opened with O_APPEND|O_SYNC. O_SYNC matters because
// os.Exit (called from many sites in main.go) skips defers, so the tee
// goroutine may not flush before the process dies — O_SYNC makes each
// individual Write durable at the cost of a few extra ms per run.
//
// Rotation is single-file and per-open: if the existing file exceeds
// maxBytes at Start time, it is renamed to path+".prev" so one prior
// run survives. This is a diagnostic snapshot, not an audit log; the
// 5 MiB cap matches the precedent set by
// internal/aiagents/cli/errlog.go.
//
// In service mode (launchd LaunchAgent, systemd user units, Windows
// Task Scheduler) the OS-level redirect is already writing the agent's
// stderr to a file. StartIfEligible detects this via ShouldSkip
// (os.Stderr.Stat reports a regular file) and returns (nil, nil)
// without opening anything, so the OS redirect remains the sole writer
// and no lines are duplicated.
package filelog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// DefaultMaxBytes is the size cap that triggers single-file rotation at
// Start time. Matches internal/aiagents/cli/errlog.go's MaxErrorLogBytes
// for consistency with the existing on-disk-log convention.
const DefaultMaxBytes int64 = 5 * 1024 * 1024

const (
	fileMode os.FileMode = 0o600
	dirMode  os.FileMode = 0o700
)

// Capture owns the swapped os.Stderr, the pipe ends, the log file, and
// the tee goroutine's lifecycle. A nil receiver is safe to call Stop on
// — that simplifies main.go where StartIfEligible may return nil.
type Capture struct {
	origErr   *os.File
	pipeRead  *os.File
	pipeWrite *os.File
	file      *os.File
	done      chan struct{}
	stopped   atomic.Bool
	stopMu    sync.Mutex
}

// DefaultPath returns the default log-file location:
// ~/.stepsecurity/agent.error.log. Empty string if the home directory
// cannot be resolved; callers treat empty path as "disabled."
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".stepsecurity", "agent.error.log")
}

// ShouldSkip reports whether the in-process file writer should be
// skipped because the given stream is already redirected to a regular
// file by the OS (service mode). Terminals report ModeCharDevice and
// pipes report ModeNamedPipe; only regular files trigger the skip.
//
// Errors from Stat are treated as "no skip" — better to log to a fresh
// file than to log nowhere.
func ShouldSkip(stderr *os.File) bool {
	if stderr == nil {
		return false
	}
	info, err := stderr.Stat()
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

// Start installs the stderr tee, opening (and rotating) the log file
// and swapping os.Stderr in a single best-effort sequence. On any
// failure before os.Stderr is reassigned, the global state is left
// untouched and an error is returned.
//
// path must be non-empty. To install conditionally based on path /
// service-mode detection, use StartIfEligible instead.
func Start(path string, maxBytes int64) (*Capture, error) {
	if path == "" {
		return nil, errors.New("filelog: empty path")
	}

	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, fmt.Errorf("filelog: mkdir parent: %w", err)
	}

	if maxBytes > 0 {
		if info, err := os.Stat(path); err == nil && info.Size() > maxBytes {
			// Best-effort rotation; if the rename fails (cross-device,
			// permissions) we still want to append to the existing file
			// rather than refuse to log.
			_ = os.Rename(path, path+".prev")
		}
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|os.O_SYNC, fileMode)
	if err != nil {
		return nil, fmt.Errorf("filelog: open %s: %w", path, err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("filelog: pipe: %w", err)
	}

	c := &Capture{
		origErr:   os.Stderr,
		pipeRead:  r,
		pipeWrite: w,
		file:      f,
		done:      make(chan struct{}),
	}
	os.Stderr = w

	go c.teeLoop()
	return c, nil
}

// StartIfEligible is the main.go-facing entrypoint. It returns
// (nil, nil) when capture should be skipped (empty path, or
// ShouldSkip(os.Stderr) returns true), and the result of Start
// otherwise. Callers can `defer cap.Stop()` unconditionally because
// Stop on a nil receiver is a no-op.
func StartIfEligible(path string, maxBytes int64) (*Capture, error) {
	if path == "" {
		return nil, nil
	}
	if ShouldSkip(os.Stderr) {
		return nil, nil
	}
	return Start(path, maxBytes)
}

// Stop closes the pipe write end, waits for the tee goroutine to
// finish draining, restores os.Stderr, and closes the file. Idempotent
// and safe to call on a nil receiver.
func (c *Capture) Stop() error {
	if c == nil {
		return nil
	}
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	if !c.stopped.CompareAndSwap(false, true) {
		return nil
	}

	_ = c.pipeWrite.Close()
	<-c.done

	os.Stderr = c.origErr
	_ = c.pipeRead.Close()
	return c.file.Close()
}

func (c *Capture) teeLoop() {
	defer close(c.done)
	dst := io.MultiWriter(c.origErr, c.file)
	buf := make([]byte, 4096)
	for {
		n, err := c.pipeRead.Read(buf)
		if n > 0 {
			// Best-effort: a failed write to dst (file full, disk
			// removed) must not stall the agent.
			_, _ = dst.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}
