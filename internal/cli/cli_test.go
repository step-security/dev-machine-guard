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

// Bug 1: --search-dirs greedily consumes single-dash flags and commands

func TestParse_SearchDirsStopsAtCommand_Install(t *testing.T) {
	cfg, err := Parse([]string{"--search-dirs", "/tmp", "install"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command != "install" {
		t.Errorf("expected command=install, got %q (search-dirs consumed it: %v)", cfg.Command, cfg.SearchDirs)
	}
	if len(cfg.SearchDirs) != 1 || cfg.SearchDirs[0] != "/tmp" {
		t.Errorf("expected SearchDirs=[/tmp], got %v", cfg.SearchDirs)
	}
}

func TestParse_SearchDirsRejectsSingleDashFlag(t *testing.T) {
	// --search-dirs -v should error, not silently consume -v as a directory
	_, err := Parse([]string{"--search-dirs", "-v"})
	if err == nil {
		t.Error("expected error when --search-dirs is followed by a flag")
	}
}

func TestParse_SearchDirsStopsAtCommand_Uninstall(t *testing.T) {
	cfg, err := Parse([]string{"--search-dirs", "/opt", "uninstall"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command != "uninstall" {
		t.Errorf("expected command=uninstall, got %q (search-dirs consumed it: %v)", cfg.Command, cfg.SearchDirs)
	}
	if len(cfg.SearchDirs) != 1 || cfg.SearchDirs[0] != "/opt" {
		t.Errorf("expected SearchDirs=[/opt], got %v", cfg.SearchDirs)
	}
}

func TestParse_SearchDirsStopsAtCommand_SendTelemetry(t *testing.T) {
	cfg, err := Parse([]string{"--search-dirs", "/data", "send-telemetry"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command != "send-telemetry" {
		t.Errorf("expected command=send-telemetry, got %q (search-dirs consumed it: %v)", cfg.Command, cfg.SearchDirs)
	}
}

func TestParse_SearchDirsStopsAtCommand_Configure(t *testing.T) {
	cfg, err := Parse([]string{"--search-dirs", "/data", "configure"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command != "configure" {
		t.Errorf("expected command=configure, got %q (search-dirs consumed it: %v)", cfg.Command, cfg.SearchDirs)
	}
}

// Bug 2: --html accepts flags as its filename argument

func TestParse_HTMLRejectsFlag(t *testing.T) {
	_, err := Parse([]string{"--html", "--verbose"})
	if err == nil {
		t.Error("expected error when --html argument looks like a flag, got nil")
	}
}

func TestParse_HTMLRejectsDashFlag(t *testing.T) {
	_, err := Parse([]string{"--html", "-v"})
	if err == nil {
		t.Error("expected error when --html argument is -v, got nil")
	}
}
