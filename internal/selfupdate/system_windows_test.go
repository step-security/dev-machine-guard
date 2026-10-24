//go:build windows

package selfupdate

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestEnsureConfigACL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if fixed, err := EnsureConfigACL(filepath.Join(t.TempDir(), "missing.json")); err != nil || fixed {
		t.Fatalf("missing file: fixed=%v err=%v", fixed, err)
	}
	// A freshly created temp file inherits a non-protected DACL: drift.
	fixed, err := EnsureConfigACL(p)
	if err != nil || !fixed {
		t.Fatalf("first pass: fixed=%v err=%v", fixed, err)
	}
	if fixed, err := EnsureConfigACL(p); err != nil || fixed {
		t.Fatalf("second pass: fixed=%v err=%v", fixed, err)
	}
	// Users gaining Modify is drift again.
	if out, err := exec.Command("icacls", p, "/grant", "*S-1-5-32-545:M").CombinedOutput(); err != nil {
		t.Skipf("icacls: %v %s", err, out)
	}
	if fixed, err := EnsureConfigACL(p); err != nil || !fixed {
		t.Fatalf("after grant: fixed=%v err=%v", fixed, err)
	}
}

func TestFreeBytesWindows(t *testing.T) {
	if n, err := FreeBytes(t.TempDir()); err != nil || n == 0 {
		t.Fatalf("FreeBytes = %d, %v", n, err)
	}
}
