package filelog

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// withStderr swaps os.Stderr for the duration of the test and restores
// it on cleanup. Centralises the dance so test failures don't leak the
// swap into other tests in the same package run.
func withStderr(t *testing.T, f *os.File) {
	t.Helper()
	orig := os.Stderr
	os.Stderr = f
	t.Cleanup(func() { os.Stderr = orig })
}

func TestDefaultDir(t *testing.T) {
	got := DefaultDir()
	if got == "" {
		t.Skip("home dir unresolved in this environment")
	}
	if !strings.HasSuffix(got, ".stepsecurity") {
		t.Errorf("DefaultDir() = %q, expected suffix .stepsecurity", got)
	}
}

func TestDefaultPath(t *testing.T) {
	got := DefaultPath()
	if got == "" {
		t.Skip("home dir unresolved in this environment")
	}
	if !strings.HasSuffix(got, filepath.Join(".stepsecurity", Filename)) {
		t.Errorf("DefaultPath() = %q, expected suffix .stepsecurity/%s", got, Filename)
	}
}

func TestStartStopWritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.error.log")

	origStderr := os.Stderr
	t.Cleanup(func() { os.Stderr = origStderr })

	cap, err := Start(path, DefaultMaxBytes)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if _, err := fmt.Fprintln(os.Stderr, "hello world"); err != nil {
		t.Fatalf("Fprintln: %v", err)
	}

	if err := cap.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(data, []byte("hello world")) {
		t.Errorf("file missing payload: %q", data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// File mode is best-effort on Windows; only assert on POSIX.
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != fileMode {
			t.Errorf("file mode = %#o, want %#o", mode, fileMode)
		}
	}
}

func TestRotateIfOverCap_OverwritesExistingPrev(t *testing.T) {
	// Regression guard: on Windows, os.Rename fails when the destination
	// already exists, so a stale .prev would block all subsequent
	// rotations. RotateIfOverCap removes the prior .prev first.
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.error.log")
	prevPath := path + ".prev"

	if err := os.WriteFile(prevPath, []byte("STALE prior rotation"), fileMode); err != nil {
		t.Fatalf("seed .prev: %v", err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("y"), 200), fileMode); err != nil {
		t.Fatalf("seed current: %v", err)
	}

	RotateIfOverCap(path, 100)

	got, err := os.ReadFile(prevPath)
	if err != nil {
		t.Fatalf(".prev gone after rotation: %v", err)
	}
	// .prev now holds the FRESH old content (200 bytes of 'y'), not the
	// stale "STALE prior rotation" string.
	if bytes.Equal(got, []byte("STALE prior rotation")) {
		t.Errorf(".prev still has stale content; rotation failed to overwrite")
	}
	if len(got) != 200 {
		t.Errorf(".prev size = %d, want 200 (fresh rotated content)", len(got))
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("original path should be gone after rename: stat err = %v", err)
	}
}

func TestRotateIfOverCap_NoopUnderCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.error.log")
	if err := os.WriteFile(path, []byte("small"), fileMode); err != nil {
		t.Fatalf("seed: %v", err)
	}
	RotateIfOverCap(path, 1024)
	if _, err := os.Stat(path + ".prev"); !os.IsNotExist(err) {
		t.Errorf(".prev unexpectedly created when file was under cap")
	}
}

func TestStartRotatesWhenOverCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.error.log")

	// Pre-populate with content exceeding our cap.
	oldContent := bytes.Repeat([]byte("x"), 200)
	if err := os.WriteFile(path, oldContent, fileMode); err != nil {
		t.Fatalf("seed: %v", err)
	}

	origStderr := os.Stderr
	t.Cleanup(func() { os.Stderr = origStderr })

	cap, err := Start(path, 100) // cap = 100 bytes, seeded with 200
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := cap.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	prev, err := os.ReadFile(path + ".prev")
	if err != nil {
		t.Fatalf("missing .prev after rotation: %v", err)
	}
	if !bytes.Equal(prev, oldContent) {
		t.Errorf(".prev content mismatch: got %d bytes, want %d", len(prev), len(oldContent))
	}

	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing current file after rotation: %v", err)
	}
	if len(cur) != 0 {
		t.Errorf("current file should be empty after rotation, got %d bytes", len(cur))
	}
}

func TestStartReturnsErrOnUnwritableDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0o500 semantics differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}

	dir := t.TempDir()
	readonly := filepath.Join(dir, "ro")
	if err := os.Mkdir(readonly, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(readonly, "child", "agent.error.log")

	origStderr := os.Stderr
	t.Cleanup(func() { os.Stderr = origStderr })

	cap, err := Start(path, DefaultMaxBytes)
	if err == nil {
		t.Fatalf("expected error opening under unwritable dir")
	}
	if cap != nil {
		t.Errorf("expected nil Capture on error, got %v", cap)
	}
	if os.Stderr != origStderr {
		t.Errorf("os.Stderr was mutated despite Start failure")
	}
}

func TestConcurrentWritesIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.error.log")

	origStderr := os.Stderr
	t.Cleanup(func() { os.Stderr = origStderr })

	cap, err := Start(path, DefaultMaxBytes)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	const goroutines = 8
	const linesPer = 100

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range linesPer {
				fmt.Fprintf(os.Stderr, "g%d-line-%03d\n", g, i)
			}
		}(g)
	}
	wg.Wait()

	if err := cap.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for g := range goroutines {
		for i := range linesPer {
			line := fmt.Sprintf("g%d-line-%03d\n", g, i)
			if !bytes.Contains(data, []byte(line)) {
				t.Errorf("missing line: %q", strings.TrimSpace(line))
			}
		}
	}
}

func TestShouldSkipDetectsRegularFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "filelog-skip-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() {
		tmp.Close()
		os.Remove(tmp.Name())
	})
	if !ShouldSkip(tmp) {
		t.Error("regular file should trigger skip")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	if ShouldSkip(r) {
		t.Error("pipe must not trigger skip")
	}

	if ShouldSkip(nil) {
		t.Error("nil must not trigger skip")
	}
}

func TestStartIfEligibleSkipsForRegularFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "agent.error.log")

	fakeStderr, err := os.Create(filepath.Join(dir, "fake-stderr"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { fakeStderr.Close() })
	withStderr(t, fakeStderr)

	cap, err := StartIfEligible(logPath, DefaultMaxBytes)
	if err != nil {
		t.Fatalf("StartIfEligible: %v", err)
	}
	if cap != nil {
		t.Errorf("expected nil Capture when stderr is regular file, got %v", cap)
		_ = cap.Stop()
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("log file should not have been created: stat err = %v", err)
	}
}

func TestStartIfEligibleSkipsForEmptyPath(t *testing.T) {
	cap, err := StartIfEligible("", DefaultMaxBytes)
	if err != nil {
		t.Fatalf("StartIfEligible: %v", err)
	}
	if cap != nil {
		t.Errorf("expected nil Capture for empty path, got %v", cap)
	}
}

func TestStopIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.error.log")

	origStderr := os.Stderr
	t.Cleanup(func() { os.Stderr = origStderr })

	cap, err := Start(path, DefaultMaxBytes)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := cap.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := cap.Stop(); err != nil {
		t.Errorf("second Stop returned error: %v", err)
	}
}

func TestStopOnNilReceiverIsNoOp(t *testing.T) {
	var c *Capture
	if err := c.Stop(); err != nil {
		t.Errorf("Stop on nil receiver returned error: %v", err)
	}
}
