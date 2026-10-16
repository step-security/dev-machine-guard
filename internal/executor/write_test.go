package executor

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRealWriteFileAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stepsecurity", "device-id")
	r := NewReal()
	for _, want := range []string{"first\n", "second\n"} {
		if err := r.WriteFileAtomic(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != want {
			t.Fatalf("content = %q, %v; want %q", got, err, want)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
	if runtime.GOOS == "windows" {
		return
	}
	fi, _ := os.Stat(path)
	di, _ := os.Stat(filepath.Dir(path))
	if fi.Mode().Perm() != 0o644 || di.Mode().Perm() != 0o755 {
		t.Fatalf("modes = file %v dir %v; want 0644 / 0755", fi.Mode().Perm(), di.Mode().Perm())
	}
}

func TestRealCreateFileOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stepsecurity", "device-id")
	r := NewReal()
	if err := r.CreateFileOnce(path, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateFileOnce(path, []byte("second\n"), 0o644); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second create err = %v, want ErrExist", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "first\n" {
		t.Fatalf("content = %q, %v; want first", got, err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}
