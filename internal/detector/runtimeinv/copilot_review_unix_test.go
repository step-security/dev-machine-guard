//go:build !windows

package runtimeinv

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// A FIFO named like a runtime must be skipped, not opened (open would block).
func TestFIFOCandidateIsSkipped(t *testing.T) {
	f := newFixture(t)
	if err := syscall.Mkfifo(f.path("bin/node"), 0o755); err != nil {
		if os.MkdirAll(f.path("bin"), 0o755) != nil || syscall.Mkfifo(f.path("bin/node"), 0o755) != nil {
			t.Skip("mkfifo unsupported")
		}
	}
	done := make(chan []string, 1)
	go func() {
		out := f.scan("linux", "", walkRoot{f.root, 3, nil, 0})
		var p []string
		for _, r := range out {
			p = append(p, r.ExecutablePath)
		}
		done <- p
	}()
	select {
	case p := <-done:
		if len(p) != 0 {
			t.Fatalf("FIFO reported as runtime: %v", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("scan blocked on a FIFO")
	}
}
