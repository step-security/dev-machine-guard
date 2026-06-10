package cli

import "testing"

func TestParse_RulesFileAndTelemetryOut(t *testing.T) {
	cfg, err := Parse([]string{"send-telemetry", "--rules-file=/tmp/rules.json", "--telemetry-out=/tmp/out.json"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesFile != "/tmp/rules.json" {
		t.Errorf("RulesFile = %q", cfg.RulesFile)
	}
	if cfg.TelemetryOutFile != "/tmp/out.json" {
		t.Errorf("TelemetryOutFile = %q", cfg.TelemetryOutFile)
	}
}

func TestParse_DevFlagsSeparateValue(t *testing.T) {
	cfg, err := Parse([]string{"--rules-file", "r.json", "--telemetry-out", "o.json"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesFile != "r.json" || cfg.TelemetryOutFile != "o.json" {
		t.Errorf("got RulesFile=%q TelemetryOutFile=%q", cfg.RulesFile, cfg.TelemetryOutFile)
	}
}

func TestParse_DevFlagsMissingValue(t *testing.T) {
	if _, err := Parse([]string{"--rules-file"}); err == nil {
		t.Error("--rules-file without value should error")
	}
	if _, err := Parse([]string{"--telemetry-out"}); err == nil {
		t.Error("--telemetry-out without value should error")
	}
}

func TestParse_DevFlagsEnvVarFallback(t *testing.T) {
	t.Setenv("STEPSECURITY_RULES_FILE", "/env/rules.json")
	t.Setenv("STEPSECURITY_TELEMETRY_OUT", "/env/out.json")
	cfg, err := Parse([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesFile != "/env/rules.json" || cfg.TelemetryOutFile != "/env/out.json" {
		t.Errorf("env fallback failed: RulesFile=%q TelemetryOutFile=%q", cfg.RulesFile, cfg.TelemetryOutFile)
	}
}

func TestParse_FlagBeatsEnvVar(t *testing.T) {
	t.Setenv("STEPSECURITY_RULES_FILE", "/env/rules.json")
	cfg, err := Parse([]string{"--rules-file=/flag/rules.json"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesFile != "/flag/rules.json" {
		t.Errorf("explicit flag should win over env var, got %q", cfg.RulesFile)
	}
}
