package state

import "testing"

func TestDefaultIsEnabled(t *testing.T) {
	if !Default().Hooks.Enabled {
		t.Fatal("Default() must be enabled; otherwise first-run after install breaks")
	}
	if Default().SchemaVersion != SchemaVersion {
		t.Fatalf("Default schema_version = %d, want %d", Default().SchemaVersion, SchemaVersion)
	}
}
