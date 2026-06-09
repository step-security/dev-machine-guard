package config

import "testing"

// PersistMaxExecutionDuration is a read-modify-write: it records the loader's
// max-execution value into config.json without disturbing the customer_id /
// api_key / etc. the loader already wrote.
func TestPersistMaxExecutionDuration_RoundTrip(t *testing.T) {
	withHome(t)

	// Seed config.json the way the loader's write_config would (no max-exec
	// field), so we prove Persist preserves the existing fields.
	seed := &ConfigFile{CustomerID: "acme", APIKey: "k", APIEndpoint: "https://api"}
	if err := save(seed); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	if err := PersistMaxExecutionDuration("2h"); err != nil {
		t.Fatalf("PersistMaxExecutionDuration: %v", err)
	}

	got := loadExisting()
	if got.MaxExecutionDuration != "2h" {
		t.Errorf("MaxExecutionDuration = %q, want %q", got.MaxExecutionDuration, "2h")
	}
	if got.CustomerID != "acme" || got.APIKey != "k" || got.APIEndpoint != "https://api" {
		t.Errorf("read-modify-write clobbered existing fields: %+v", got)
	}
}

// An empty value is a no-op (a direct binary install with no loader-exported
// value must not write an empty field that would later parse to the default).
func TestPersistMaxExecutionDuration_EmptyIsNoOp(t *testing.T) {
	withHome(t)
	if err := save(&ConfigFile{CustomerID: "acme"}); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	if err := PersistMaxExecutionDuration(""); err != nil {
		t.Fatalf("empty should be a no-op, got: %v", err)
	}

	if got := loadExisting(); got.MaxExecutionDuration != "" {
		t.Errorf("empty value should not be persisted, got %q", got.MaxExecutionDuration)
	}
}

// Load() must surface a persisted max-execution value into the package var the
// resolver reads on scheduler-fired runs.
func TestLoad_PopulatesMaxExecutionDuration(t *testing.T) {
	withHome(t)
	seed := &ConfigFile{
		CustomerID:           "acme",
		APIKey:               "k",
		APIEndpoint:          "https://api",
		MaxExecutionDuration: "90m",
	}
	if err := save(seed); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	// Load only fills package vars still at their zero value; reset so this
	// test is independent of execution order within the package.
	MaxExecutionDuration = ""
	t.Cleanup(func() { MaxExecutionDuration = "" })

	Load()

	if MaxExecutionDuration != "90m" {
		t.Errorf("Load did not populate MaxExecutionDuration: got %q, want %q", MaxExecutionDuration, "90m")
	}
}
