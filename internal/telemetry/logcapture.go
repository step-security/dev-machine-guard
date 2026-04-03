package telemetry

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"sync"
)

// LogCapture captures all stderr output during telemetry execution.
// The captured output is base64-encoded and included in the execution_logs payload.
type LogCapture struct {
	buf       bytes.Buffer
	mu        sync.Mutex
	origErr   *os.File
	pipeRead  *os.File
	pipeWrite *os.File
	done      chan struct{}
}

// StartCapture redirects stderr to a tee that writes to both the original
// stderr and an in-memory buffer for later base64 encoding.
func StartCapture() *LogCapture {
	lc := &LogCapture{
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

	// Tee: read from pipe, write to both original stderr and buffer
	go func() {
		defer close(lc.done)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				lc.mu.Lock()
				lc.buf.Write(buf[:n])
				lc.mu.Unlock()
				_, _ = lc.origErr.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	return lc
}

// Finalize stops capture and returns the base64-encoded output.
// Safe to call multiple times — subsequent calls return the cached result.
func (lc *LogCapture) Finalize() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.pipeWrite == nil {
		// Already finalized or never started
		return base64.StdEncoding.EncodeToString(lc.buf.Bytes())
	}

	// Close write end so the reader goroutine exits
	lc.pipeWrite.Close()
	lc.pipeWrite = nil
	lc.mu.Unlock()
	<-lc.done
	lc.mu.Lock()

	// Restore stderr
	os.Stderr = lc.origErr
	lc.pipeRead.Close()

	return base64.StdEncoding.EncodeToString(lc.buf.Bytes())
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
