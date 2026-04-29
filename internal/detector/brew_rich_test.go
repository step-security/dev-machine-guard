package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestParseBrewInfoJSON_Formulae(t *testing.T) {
	jsonData := `{
		"formulae": [
			{
				"name": "curl",
				"tap": "homebrew/core",
				"desc": "Get a file from an HTTP, HTTPS or FTP server",
				"license": "curl",
				"homepage": "https://curl.se",
				"deprecated": false,
				"installed": [
					{
						"version": "8.4.0",
						"time": 1700000000,
						"installed_as_dependency": false,
						"poured_from_bottle": true
					}
				]
			},
			{
				"name": "openssl@3",
				"tap": "homebrew/core",
				"desc": "Cryptography and SSL/TLS Toolkit",
				"license": "Apache-2.0",
				"homepage": "https://openssl.org",
				"deprecated": false,
				"installed": [
					{
						"version": "3.2.0",
						"time": 1700000100,
						"installed_as_dependency": true,
						"poured_from_bottle": true
					}
				]
			},
			{
				"name": "unused-formula",
				"tap": "homebrew/core",
				"desc": "Not installed",
				"license": "MIT",
				"homepage": "https://example.com",
				"deprecated": false,
				"installed": []
			}
		],
		"casks": []
	}`

	pkgs, err := parseBrewInfoJSON(jsonData, "formula")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 formulae (skipping uninstalled), got %d", len(pkgs))
	}

	curl := pkgs[0]
	if curl.Name != "curl" {
		t.Errorf("expected name curl, got %s", curl.Name)
	}
	if curl.Version != "8.4.0" {
		t.Errorf("expected version 8.4.0, got %s", curl.Version)
	}
	if curl.Tap != "homebrew/core" {
		t.Errorf("expected tap homebrew/core, got %s", curl.Tap)
	}
	if curl.Description != "Get a file from an HTTP, HTTPS or FTP server" {
		t.Errorf("unexpected description: %s", curl.Description)
	}
	if curl.License != "curl" {
		t.Errorf("expected license curl, got %s", curl.License)
	}
	if curl.Homepage != "https://curl.se" {
		t.Errorf("expected homepage https://curl.se, got %s", curl.Homepage)
	}
	if curl.InstallTimeUnix != 1700000000 {
		t.Errorf("expected install time 1700000000, got %d", curl.InstallTimeUnix)
	}
	if curl.InstalledAsDependency {
		t.Error("expected curl not installed as dependency")
	}
	if !curl.PouredFromBottle {
		t.Error("expected curl poured from bottle")
	}

	openssl := pkgs[1]
	if !openssl.InstalledAsDependency {
		t.Error("expected openssl installed as dependency")
	}
}

func TestParseBrewInfoJSON_Casks(t *testing.T) {
	jsonData := `{
		"formulae": [],
		"casks": [
			{
				"token": "firefox",
				"name": ["Mozilla Firefox"],
				"tap": "homebrew/cask",
				"desc": "Web browser",
				"homepage": "https://www.mozilla.org/firefox/",
				"version": "120.0",
				"installed": "120.0",
				"installed_time": 1700000200,
				"deprecated": false,
				"auto_updates": true
			},
			{
				"token": "visual-studio-code",
				"name": ["Microsoft Visual Studio Code"],
				"tap": "homebrew/cask",
				"desc": "Open-source code editor",
				"homepage": "https://code.visualstudio.com/",
				"version": "1.85.0",
				"installed": "",
				"installed_time": 1700000300,
				"deprecated": false,
				"auto_updates": true
			}
		]
	}`

	pkgs, err := parseBrewInfoJSON(jsonData, "cask")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 casks, got %d", len(pkgs))
	}

	ff := pkgs[0]
	if ff.Name != "firefox" {
		t.Errorf("expected name firefox, got %s", ff.Name)
	}
	if ff.Version != "120.0" {
		t.Errorf("expected version 120.0 (from installed field), got %s", ff.Version)
	}
	if ff.Description != "Web browser" {
		t.Errorf("unexpected description: %s", ff.Description)
	}

	// When installed field is empty, falls back to version field
	vscode := pkgs[1]
	if vscode.Version != "1.85.0" {
		t.Errorf("expected version 1.85.0 (fallback from version field), got %s", vscode.Version)
	}
}

func TestParseBrewInfoJSON_InvalidJSON(t *testing.T) {
	_, err := parseBrewInfoJSON("not json", "formula")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBrewDetector_ListFormulaeRich_JSONPath(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")

	jsonData := `{
		"formulae": [
			{
				"name": "curl",
				"tap": "homebrew/core",
				"desc": "Get a file from an HTTP, HTTPS or FTP server",
				"license": "curl",
				"homepage": "https://curl.se",
				"deprecated": false,
				"installed": [{"version": "8.4.0", "time": 1700000000, "installed_as_dependency": false, "poured_from_bottle": true}]
			}
		],
		"casks": []
	}`
	mock.SetCommand(jsonData, "", 0, "brew", "info", "--json=v2", "--installed", "--formula")

	det := NewBrewDetector(mock)
	pkgs := det.ListFormulaeRich(context.Background())

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 formula, got %d", len(pkgs))
	}
	if pkgs[0].Name != "curl" {
		t.Errorf("expected curl, got %s", pkgs[0].Name)
	}
	if pkgs[0].Description != "Get a file from an HTTP, HTTPS or FTP server" {
		t.Errorf("unexpected description: %s", pkgs[0].Description)
	}
	if pkgs[0].License != "curl" {
		t.Errorf("expected license curl, got %s", pkgs[0].License)
	}
}

func TestBrewDetector_ListFormulaeRich_FallbackToReceipts(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")

	// Make the JSON command fail so it falls back
	mock.SetCommand("", "error", 1, "brew", "info", "--json=v2", "--installed", "--formula")

	// Basic list output for fallback
	mock.SetCommand("curl 8.4.0\ngit 2.43.0\n", "", 0, "brew", "list", "--formula", "--versions")

	// Set up Cellar directory and receipts
	mock.SetDir("/opt/homebrew/Cellar")
	mock.SetFile("/opt/homebrew/Cellar/curl/8.4.0/INSTALL_RECEIPT.json", []byte(`{
		"time": 1700000000,
		"installed_as_dependency": false,
		"poured_from_bottle": true,
		"source": {"tap": "homebrew/core"}
	}`))
	mock.SetFile("/opt/homebrew/Cellar/git/2.43.0/INSTALL_RECEIPT.json", []byte(`{
		"time": 1700000100,
		"installed_as_dependency": true,
		"poured_from_bottle": false,
		"source": {"tap": "homebrew/core"}
	}`))

	det := NewBrewDetector(mock)
	pkgs := det.ListFormulaeRich(context.Background())

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 formulae, got %d", len(pkgs))
	}

	// curl should be enriched from receipt
	if pkgs[0].Tap != "homebrew/core" {
		t.Errorf("expected tap homebrew/core, got %s", pkgs[0].Tap)
	}
	if pkgs[0].InstallTimeUnix != 1700000000 {
		t.Errorf("expected install time 1700000000, got %d", pkgs[0].InstallTimeUnix)
	}
	if pkgs[0].InstalledAsDependency {
		t.Error("expected curl not installed as dependency")
	}

	// git should be enriched as dependency
	if !pkgs[1].InstalledAsDependency {
		t.Error("expected git installed as dependency")
	}
	if pkgs[1].PouredFromBottle {
		t.Error("expected git not poured from bottle")
	}
}

func TestBrewDetector_ListCasksRich_JSONPath(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")

	jsonData := `{
		"formulae": [],
		"casks": [
			{
				"token": "firefox",
				"name": ["Mozilla Firefox"],
				"tap": "homebrew/cask",
				"desc": "Web browser",
				"homepage": "https://www.mozilla.org/firefox/",
				"version": "120.0",
				"installed": "120.0",
				"installed_time": 1700000200,
				"deprecated": false,
				"auto_updates": true
			}
		]
	}`
	mock.SetCommand(jsonData, "", 0, "brew", "info", "--json=v2", "--installed", "--cask")

	det := NewBrewDetector(mock)
	pkgs := det.ListCasksRich(context.Background())

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 cask, got %d", len(pkgs))
	}
	if pkgs[0].Name != "firefox" {
		t.Errorf("expected firefox, got %s", pkgs[0].Name)
	}
	if pkgs[0].Description != "Web browser" {
		t.Errorf("unexpected description: %s", pkgs[0].Description)
	}
	if pkgs[0].InstallTimeUnix != 1700000200 {
		t.Errorf("expected install time 1700000200, got %d", pkgs[0].InstallTimeUnix)
	}
}

func TestBrewDetector_ListCasksRich_FallbackToReceipts(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")

	// JSON command fails
	mock.SetCommand("", "error", 1, "brew", "info", "--json=v2", "--installed", "--cask")

	// Basic list output
	mock.SetCommand("firefox 120.0\n", "", 0, "brew", "list", "--cask", "--versions")

	// Caskroom directory and receipt
	mock.SetDir("/opt/homebrew/Caskroom")
	mock.SetFile("/opt/homebrew/Caskroom/firefox/.metadata/INSTALL_RECEIPT.json", []byte(`{
		"time": 1700000200,
		"installed_as_dependency": false,
		"poured_from_bottle": false,
		"source": {"tap": "homebrew/cask"}
	}`))

	det := NewBrewDetector(mock)
	pkgs := det.ListCasksRich(context.Background())

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 cask, got %d", len(pkgs))
	}
	if pkgs[0].Tap != "homebrew/cask" {
		t.Errorf("expected tap homebrew/cask, got %s", pkgs[0].Tap)
	}
	if pkgs[0].InstallTimeUnix != 1700000200 {
		t.Errorf("expected install time 1700000200, got %d", pkgs[0].InstallTimeUnix)
	}
}

func TestBrewDetector_BrewPrefix_UsesDirExists(t *testing.T) {
	mock := executor.NewMock()

	// Only set directory (not file) — this verifies DirExists is used
	mock.SetDir("/opt/homebrew/Cellar")

	det := NewBrewDetector(mock)
	prefix := det.brewPrefix()

	if prefix != "/opt/homebrew" {
		t.Errorf("expected /opt/homebrew, got %q", prefix)
	}
}

func TestBrewDetector_BrewPrefix_CaskroomOnly(t *testing.T) {
	mock := executor.NewMock()

	// Only Caskroom exists (no Cellar) — should still find the prefix
	mock.SetDir("/opt/homebrew/Caskroom")

	det := NewBrewDetector(mock)
	prefix := det.brewPrefix()

	if prefix != "/opt/homebrew" {
		t.Errorf("expected /opt/homebrew, got %q", prefix)
	}
}

func TestBrewDetector_BrewPrefix_NotFound(t *testing.T) {
	mock := executor.NewMock()
	det := NewBrewDetector(mock)
	prefix := det.brewPrefix()

	if prefix != "" {
		t.Errorf("expected empty prefix, got %q", prefix)
	}
}
