package heartbeat

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

func TestWriteThenLoadRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last-run.json")

	before := time.Now().Add(-time.Second)
	if err := Write(path, "send-telemetry", "install"); err != nil {
		t.Fatalf("Write: %v", err)
	}

	rec, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if rec == nil {
		t.Fatal("Load returned nil record after Write")
	}
	if rec.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", rec.SchemaVersion, SchemaVersion)
	}
	if rec.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", rec.PID, os.Getpid())
	}
	if rec.Command != "send-telemetry" {
		t.Errorf("Command = %q, want send-telemetry", rec.Command)
	}
	if rec.InvocationMethod != "install" {
		t.Errorf("InvocationMethod = %q, want install", rec.InvocationMethod)
	}
	if rec.AgentVersion != buildinfo.Version {
		t.Errorf("AgentVersion = %q, want %q", rec.AgentVersion, buildinfo.Version)
	}
	if rec.OS == "" {
		t.Error("OS is empty")
	}
	if rec.WrittenAt.Before(before) || rec.WrittenAt.After(time.Now().Add(time.Second)) {
		t.Errorf("WrittenAt %v not within the test window", rec.WrittenAt)
	}
}

func TestWriteEmptyPathIsNoop(t *testing.T) {
	if err := Write("", "send-telemetry", "one_time"); err != nil {
		t.Fatalf("Write(\"\") should be a no-op, got %v", err)
	}
}

func TestWriteOverwritesPreviousRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last-run.json")

	if err := Write(path, "send-telemetry", "one_time"); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	// A second write must atomically replace the first (Windows os.Rename
	// would fail on an existing destination without the pre-remove).
	if err := Write(path, "install", "install"); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	rec, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if rec == nil || rec.Command != "install" {
		t.Fatalf("second Write did not take; got %+v", rec)
	}

	// No leftover temp siblings from the atomic-rename dance.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestLoadMissingFileReturnsNilNil(t *testing.T) {
	rec, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("Load of missing file should not error, got %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil record for missing file, got %+v", rec)
	}
}

func TestLoadSchemaMismatchReturnsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last-run.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":999,"pid":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil for schema mismatch, got %+v", rec)
	}
}

func TestLoadEmptyPathReturnsNilNil(t *testing.T) {
	rec, err := Load("")
	if err != nil || rec != nil {
		t.Errorf("Load(\"\") = (%+v, %v), want (nil, nil)", rec, err)
	}
}
