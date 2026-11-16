package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Scratch-only: safe on native Windows without touching ProgramData or HOME.
func TestConfigTransactionScratchLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if ok, err := tryConfigLock(first); err != nil || !ok {
		t.Fatalf("first lock: %v %v", ok, err)
	}
	if ok, err := tryConfigLock(second); err != nil || ok {
		t.Fatalf("contending lock: %v %v", ok, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if ok, err := tryConfigLock(second); err != nil || !ok {
		t.Fatalf("lock after close: %v %v", ok, err)
	}
}
func TestConfigTransactionScratchReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"user_id":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := []byte(`{"user_id":"new"}`)
	if err := writeAtomic(path, replacement, 0o600, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(replacement) {
		t.Fatalf("replace: %s %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("replace leftovers: %+v %v", entries, err)
	}
}
