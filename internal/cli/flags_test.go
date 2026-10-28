package cli

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
)

// flagSamples are valid values for flags whose value is validated.
var flagSamples = map[string]string{
	"--color":       "never",
	"--log-level":   "debug",
	"--auto-update": "false",
}

// sampleArgs is one valid spelling of f.
func sampleArgs(f flagSpec) []string {
	v, ok := flagSamples[f.name]
	if !ok {
		v = "7"
	}
	switch f.kind {
	case flagSwitch:
		return []string{f.name}
	case flagEquals:
		return []string{f.name + "=" + v}
	default:
		return []string{f.name, v}
	}
}

// configKeys are config.json's top-level keys, from ConfigFile's tags.
func configKeys() []string {
	var keys []string
	t := reflect.TypeOf(config.ConfigFile{})
	for i := range t.NumField() {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			keys = append(keys, name)
		}
	}
	return keys
}

// Every config.json setting must be settable by a `configure` flag (the
// AGENTS.md §13 rule): a new ConfigFile field fails here until a flag in
// flagTable saves it.
func TestFlagTable_CoversEveryConfigKey(t *testing.T) {
	saved := map[string]bool{}
	for _, f := range flagTable {
		for _, k := range f.saves {
			saved[k] = true
		}
	}
	keys := configKeys()
	for _, k := range keys {
		if !saved[k] {
			t.Errorf("config key %q has no configure flag in flagTable", k)
		}
	}
	for k := range saved {
		if !slices.Contains(keys, k) {
			t.Errorf("flagTable saves %q, which is not a config.json key", k)
		}
	}
}

// A flag saves only the keys it declares, and a flag that declares none
// saves nothing.
func TestFlagTable_SavesOnlyDeclaredKeys(t *testing.T) {
	for _, f := range flagTable {
		cfg, err := Parse(append([]string{"configure"}, sampleArgs(f)...))
		if err != nil {
			t.Errorf("%s: %v", f.name, err)
			continue
		}
		for k := range cfg.ConfigValues {
			if !slices.Contains(f.saves, k) {
				t.Errorf("%s saved undeclared key %q", f.name, k)
			}
		}
		if len(f.saves) > 0 && len(cfg.ConfigValues) == 0 {
			t.Errorf("%s declares %v but saved nothing", f.name, f.saves)
		}
	}
}

// End to end: for every config.json key, some flag passed to `configure`
// lands it in the saved file.
func TestFlagTable_EveryKeyReachesConfigFile(t *testing.T) {
	persisted := map[string]bool{}
	for _, f := range flagTable {
		if len(f.saves) == 0 {
			continue
		}
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		args := append([]string{"configure", "--customer-id", "c", "--api-endpoint", "https://e", "--api-key", "k"}, sampleArgs(f)...)
		cfg, err := Parse(args)
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		if err := config.RunConfigureNonInteractive(config.NonInteractiveOptions{Values: cfg.ConfigValues}); err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		data, err := os.ReadFile(config.WriteConfigFilePath())
		if err != nil {
			t.Fatal(err)
		}
		var onDisk map[string]json.RawMessage
		if err := json.Unmarshal(data, &onDisk); err != nil {
			t.Fatal(err)
		}
		for _, k := range f.saves {
			if _, ok := onDisk[k]; ok {
				persisted[k] = true
			}
		}
	}
	for _, k := range configKeys() {
		if !persisted[k] {
			t.Errorf("no configure flag writes %q to config.json", k)
		}
	}
}

func TestFlagTable_WellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range flagTable {
		if !strings.HasPrefix(f.name, "--") || strings.Contains(f.name, "=") {
			t.Errorf("bad flag name %q", f.name)
		}
		if seen[f.name] {
			t.Errorf("duplicate flag %s", f.name)
		}
		seen[f.name] = true
		if f.set == nil {
			t.Errorf("%s has no setter", f.name)
		}
		if (f.section == helpHidden) != (f.help == "") {
			t.Errorf("%s: hidden flags have no help and listed flags need one", f.name)
		}
		if f.help != "" && !strings.HasPrefix(strings.TrimSpace(f.help), f.name) {
			t.Errorf("%s: help line does not start with the flag: %q", f.name, f.help)
		}
	}
}
