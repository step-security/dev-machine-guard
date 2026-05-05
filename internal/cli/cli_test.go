package cli

import (
	"testing"
)

func TestParse_Defaults(t *testing.T) {
	cfg, err := Parse([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputFormat != "pretty" {
		t.Errorf("expected pretty, got %s", cfg.OutputFormat)
	}
	if cfg.ColorMode != "auto" {
		t.Errorf("expected auto, got %s", cfg.ColorMode)
	}
	if cfg.Verbose {
		t.Error("expected verbose=false")
	}
	if cfg.EnableNPMScan != nil {
		t.Error("expected EnableNPMScan=nil")
	}
	if len(cfg.SearchDirs) != 1 || cfg.SearchDirs[0] != "$HOME" {
		t.Errorf("expected [$HOME], got %v", cfg.SearchDirs)
	}
}

func TestParse_JSONFlag(t *testing.T) {
	cfg, err := Parse([]string{"--json"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("expected json, got %s", cfg.OutputFormat)
	}
}

func TestParse_HTMLFlag(t *testing.T) {
	cfg, err := Parse([]string{"--html", "report.html"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputFormat != "html" {
		t.Errorf("expected html, got %s", cfg.OutputFormat)
	}
	if cfg.HTMLOutputFile != "report.html" {
		t.Errorf("expected report.html, got %s", cfg.HTMLOutputFile)
	}
}

func TestParse_HTMLMissingFile(t *testing.T) {
	_, err := Parse([]string{"--html"})
	if err == nil {
		t.Error("expected error for --html without file")
	}
}

func TestParse_Verbose(t *testing.T) {
	cfg, err := Parse([]string{"--verbose"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Verbose {
		t.Error("expected verbose=true")
	}
}

func TestParse_Color(t *testing.T) {
	for _, mode := range []string{"auto", "always", "never"} {
		cfg, err := Parse([]string{"--color=" + mode})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ColorMode != mode {
			t.Errorf("expected %s, got %s", mode, cfg.ColorMode)
		}
	}
}

func TestParse_InvalidColor(t *testing.T) {
	_, err := Parse([]string{"--color=invalid"})
	if err == nil {
		t.Error("expected error for invalid color mode")
	}
}

func TestParse_NPMScan(t *testing.T) {
	cfg, err := Parse([]string{"--enable-npm-scan"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnableNPMScan == nil || !*cfg.EnableNPMScan {
		t.Error("expected EnableNPMScan=true")
	}

	cfg, err = Parse([]string{"--disable-npm-scan"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnableNPMScan == nil || *cfg.EnableNPMScan {
		t.Error("expected EnableNPMScan=false")
	}
}

func TestParse_SearchDirs(t *testing.T) {
	cfg, err := Parse([]string{"--search-dirs", "/tmp", "/opt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SearchDirs) != 2 || cfg.SearchDirs[0] != "/tmp" || cfg.SearchDirs[1] != "/opt" {
		t.Errorf("expected [/tmp /opt], got %v", cfg.SearchDirs)
	}
}

func TestParse_SearchDirsMultiple(t *testing.T) {
	cfg, err := Parse([]string{"--search-dirs", "/a", "/b", "--search-dirs", "/c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SearchDirs) != 3 {
		t.Errorf("expected 3 dirs, got %d: %v", len(cfg.SearchDirs), cfg.SearchDirs)
	}
}

func TestParse_SearchDirsStopsAtFlag(t *testing.T) {
	cfg, err := Parse([]string{"--search-dirs", "/tmp", "--verbose"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SearchDirs) != 1 || cfg.SearchDirs[0] != "/tmp" {
		t.Errorf("expected [/tmp], got %v", cfg.SearchDirs)
	}
	if !cfg.Verbose {
		t.Error("expected verbose=true")
	}
}

func TestParse_SearchDirsMissing(t *testing.T) {
	_, err := Parse([]string{"--search-dirs"})
	if err == nil {
		t.Error("expected error for --search-dirs without args")
	}
}

func TestParse_ConfigureCommand(t *testing.T) {
	cfg, err := Parse([]string{"configure"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command != "configure" {
		t.Errorf("expected configure, got %s", cfg.Command)
	}
}

func TestParse_EnterpriseCommands(t *testing.T) {
	for _, cmd := range []string{"install", "uninstall", "send-telemetry"} {
		cfg, err := Parse([]string{cmd})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Command != cmd {
			t.Errorf("expected %s, got %s", cmd, cfg.Command)
		}
	}
}

func TestParse_UnknownOption(t *testing.T) {
	_, err := Parse([]string{"--bogus"})
	if err == nil {
		t.Error("expected error for unknown option")
	}
}

func TestParse_FlagCombinations(t *testing.T) {
	cfg, err := Parse([]string{"--json", "--verbose", "--color=never"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputFormat != "json" || !cfg.Verbose || cfg.ColorMode != "never" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

// --- AI agent hooks group ---

func TestParse_HooksInstall_NoAgent(t *testing.T) {
	cfg, err := Parse([]string{"hooks", "install"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command != "hooks install" {
		t.Errorf("expected command=`hooks install`, got %q", cfg.Command)
	}
	if cfg.HooksAgent != "" {
		t.Errorf("expected empty HooksAgent (= all detected), got %q", cfg.HooksAgent)
	}
}

func TestParse_HooksInstall_AgentSpaceForm(t *testing.T) {
	cfg, err := Parse([]string{"hooks", "install", "--agent", "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command != "hooks install" || cfg.HooksAgent != "claude-code" {
		t.Errorf("unexpected: cmd=%q agent=%q", cfg.Command, cfg.HooksAgent)
	}
}

func TestParse_HooksInstall_AgentEqualsForm(t *testing.T) {
	cfg, err := Parse([]string{"hooks", "install", "--agent=codex"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HooksAgent != "codex" {
		t.Errorf("expected codex, got %q", cfg.HooksAgent)
	}
}

func TestParse_HooksUninstall(t *testing.T) {
	cfg, err := Parse([]string{"hooks", "uninstall", "--agent", "codex"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command != "hooks uninstall" || cfg.HooksAgent != "codex" {
		t.Errorf("unexpected: cmd=%q agent=%q", cfg.Command, cfg.HooksAgent)
	}
}

func TestParse_HooksMissingSubcommand(t *testing.T) {
	_, err := Parse([]string{"hooks"})
	if err == nil {
		t.Error("expected error for bare `hooks` with no subcommand")
	}
}

func TestParse_HooksUnknownSubcommand(t *testing.T) {
	_, err := Parse([]string{"hooks", "frobnicate"})
	if err == nil {
		t.Error("expected error for unknown hooks subcommand")
	}
}

func TestParse_HooksUnsupportedAgent(t *testing.T) {
	_, err := Parse([]string{"hooks", "install", "--agent", "cursor"})
	if err == nil {
		t.Error("expected error for unsupported agent")
	}
}

func TestParse_HooksAgentMissingValue(t *testing.T) {
	cases := [][]string{
		{"hooks", "install", "--agent"},
		{"hooks", "install", "--agent="},
		{"hooks", "uninstall", "--agent="},
	}
	for _, args := range cases {
		_, err := Parse(args)
		if err == nil {
			t.Errorf("expected error for missing --agent value: %v", args)
		}
	}
}

// DMG global flags must not leak into the hooks group.
func TestParse_HooksRejectsGlobalFlags(t *testing.T) {
	cases := [][]string{
		{"hooks", "install", "--json"},
		{"hooks", "install", "--verbose"},
		{"hooks", "install", "--search-dirs", "/tmp"},
		{"hooks", "install", "--enable-npm-scan"},
		{"hooks", "install", "--color=always"},
		{"hooks", "uninstall", "--pretty"},
	}
	for _, args := range cases {
		_, err := Parse(args)
		if err == nil {
			t.Errorf("expected error rejecting global flag in %v", args)
		}
	}
}

// The `_hook` runtime is intentionally not handled by Parse — main.go
// intercepts it before any init runs to honor the fail-open contract.
// See internal/aiagents/cli/hook_test.go for handler-level tests and
// cmd/stepsecurity-dev-machine-guard/main_test.go for the integration
// test that asserts the binary always exits 0 on `_hook` invocations.
