package detector

import (
	"context"
	"os"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestValidateEclipseInstall(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")

	installDir := `C:\eclipse`
	mock.SetDir(installDir)
	// filepath.Join on macOS uses "/" between parts but preserves existing "\"
	mock.SetFile(installDir+"/eclipse.ini", []byte{})
	mock.SetDir(installDir + "/plugins")
	mock.SetDir(installDir + "/configuration")

	det := &ExtensionDetector{exec: mock}
	if !det.validateEclipseInstall(installDir) {
		t.Error("expected valid Eclipse install")
	}
}

func TestValidateEclipseInstall_MissingIni(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")

	installDir := `C:\eclipse`
	mock.SetDir(installDir)
	// No eclipse.ini
	mock.SetDir(installDir + `\plugins`)
	mock.SetDir(installDir + `\configuration`)

	det := &ExtensionDetector{exec: mock}
	if det.validateEclipseInstall(installDir) {
		t.Error("expected invalid — missing eclipse.ini")
	}
}

func TestValidateEclipseInstall_BrandedIni(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")

	installDir := `C:\sts`
	mock.SetDir(installDir)
	mock.SetFile(installDir+"/sts.ini", []byte{}) // Spring Tool Suite
	mock.SetDir(installDir + "/plugins")
	mock.SetDir(installDir + "/configuration")

	det := &ExtensionDetector{exec: mock}
	if !det.validateEclipseInstall(installDir) {
		t.Error("expected valid — branded sts.ini should count")
	}
}

func TestParseEclipseBundlesInfo(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/test/bundles.info", []byte(`#encoding=UTF-8
#version=1
org.eclipse.platform,4.39.0,file:/plugins/org.eclipse.platform_4.39.0.jar,4,false
com.anthropic.claudecode.eclipse,2.3.11,file:/plugins/com.anthropic.claudecode.eclipse_2.3.11.jar,4,false
`))

	det := &ExtensionDetector{exec: mock}
	results := det.parseEclipseBundlesInfo("/test/bundles.info")

	if len(results) != 2 {
		t.Fatalf("expected 2 bundles, got %d", len(results))
	}

	if results[0].ID != "org.eclipse.platform" {
		t.Errorf("expected org.eclipse.platform, got %s", results[0].ID)
	}
	if results[0].Source != "bundled" {
		t.Errorf("expected bundled, got %s", results[0].Source)
	}

	if results[1].ID != "com.anthropic.claudecode.eclipse" {
		t.Errorf("expected com.anthropic.claudecode.eclipse, got %s", results[1].ID)
	}
	if results[1].Source != "user_installed" {
		t.Errorf("expected user_installed, got %s", results[1].Source)
	}
}

func TestParseEclipseBundlesInfo_MissingFile(t *testing.T) {
	mock := executor.NewMock()
	det := &ExtensionDetector{exec: mock}
	results := det.parseEclipseBundlesInfo("/nonexistent")
	if len(results) != 0 {
		t.Errorf("expected 0, got %d", len(results))
	}
}

func TestQueryP2InstalledRoots_ParsesOutput(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	// filepath.Join on macOS uses "/" between parts
	eclipsec := `C:\eclipse` + "/eclipsec.exe"
	mock.SetFile(eclipsec, []byte{})

	mock.SetCommand(
		"civerooni.com.putman.feature.feature.group/1.0.0\n"+
			"com.anthropic.claudecode.eclipse.feature.feature.group/2.3.11\n"+
			"org.eclipse.jdt.feature.group/3.20.0\n"+
			"epp.package.java/4.39.0\n"+
			"Operation completed in 2131 ms.\n",
		"", 0,
		eclipsec, "-nosplash",
		"-application", "org.eclipse.equinox.p2.director",
		"-listInstalledRoots",
	)

	det := &ExtensionDetector{exec: mock}
	results := det.queryP2InstalledRoots(context.Background(), `C:\eclipse`)

	if len(results) != 4 {
		t.Fatalf("expected 4 root features, got %d", len(results))
	}

	marketplace := 0
	bundled := 0
	for _, r := range results {
		switch r.Source {
		case "marketplace":
			marketplace++
		case "bundled":
			bundled++
		}
	}

	if marketplace != 2 {
		t.Errorf("expected 2 marketplace, got %d", marketplace)
	}
	if bundled != 2 {
		t.Errorf("expected 2 bundled, got %d", bundled)
	}
}

func TestQueryP2InstalledRoots_SkipsDebugLines(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	eclipsec := `C:\eclipse` + "/eclipsec.exe"
	mock.SetFile(eclipsec, []byte{})

	mock.SetCommand(
		"18:53:22.314 [Start Level] DEBUG org.eclipse.jgit -- some debug\n"+
			"org.eclipse.platform.feature.group/4.39.0\n"+
			"Operation completed in 100 ms.\n",
		"", 0,
		eclipsec, "-nosplash",
		"-application", "org.eclipse.equinox.p2.director",
		"-listInstalledRoots",
	)

	det := &ExtensionDetector{exec: mock}
	results := det.queryP2InstalledRoots(context.Background(), `C:\eclipse`)

	if len(results) != 1 {
		t.Fatalf("expected 1 (debug lines filtered), got %d", len(results))
	}
	if results[0].ID != "org.eclipse.platform.feature.group" {
		t.Errorf("expected org.eclipse.platform.feature.group, got %s", results[0].ID)
	}
}

func TestQueryP2InstalledRoots_NoEclipsec(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	// No eclipsec.exe or eclipse.exe

	det := &ExtensionDetector{exec: mock}
	results := det.queryP2InstalledRoots(context.Background(), `C:\eclipse`)

	if len(results) != 0 {
		t.Errorf("expected 0 when no exe found, got %d", len(results))
	}
}

func TestCollectDropins_DirectJAR(t *testing.T) {
	mock := executor.NewMock()
	dropinsDir := "/eclipse/dropins"
	mock.SetDir(dropinsDir)
	mock.SetDirEntries(dropinsDir, []os.DirEntry{
		executor.MockDirEntry("com.example.plugin_1.0.0.jar", false),
	})

	det := &ExtensionDetector{exec: mock}
	results := det.collectDropins(dropinsDir)

	if len(results) != 1 {
		t.Fatalf("expected 1 dropin, got %d", len(results))
	}
	if results[0].ID != "com.example.plugin" {
		t.Errorf("expected com.example.plugin, got %s", results[0].ID)
	}
	if results[0].Version != "1.0.0" {
		t.Errorf("expected 1.0.0, got %s", results[0].Version)
	}
	if results[0].Source != "dropins" {
		t.Errorf("expected dropins source, got %s", results[0].Source)
	}
}

func TestCollectDropins_Empty(t *testing.T) {
	mock := executor.NewMock()
	det := &ExtensionDetector{exec: mock}
	results := det.collectDropins("/nonexistent")
	if len(results) != 0 {
		t.Errorf("expected 0, got %d", len(results))
	}
}

func TestParseEclipsePluginName(t *testing.T) {
	tests := []struct {
		input   string
		id      string
		version string
	}{
		{"com.github.spotbugs.plugin.eclipse_4.9.8.r202510181643-c1fa7f2", "com.github.spotbugs.plugin.eclipse", "4.9.8.r202510181643-c1fa7f2"},
		{"org.eclipse.jdt.core_3.36.0.v20240103-1234", "org.eclipse.jdt.core", "3.36.0.v20240103-1234"},
		{"simple.plugin_1.0", "simple.plugin", "1.0"},
	}

	for _, tt := range tests {
		ext := parseEclipsePluginName(tt.input)
		if ext == nil {
			t.Errorf("parseEclipsePluginName(%q) returned nil", tt.input)
			continue
		}
		if ext.ID != tt.id {
			t.Errorf("ID: expected %s, got %s", tt.id, ext.ID)
		}
		if ext.Version != tt.version {
			t.Errorf("Version: expected %s, got %s", tt.version, ext.Version)
		}
	}
}

func TestParseEclipsePluginName_Invalid(t *testing.T) {
	invalid := []string{
		"nounderscore",
		"no_version_starts_with_letter",
		"",
	}
	for _, input := range invalid {
		if ext := parseEclipsePluginName(input); ext != nil {
			t.Errorf("parseEclipsePluginName(%q) should return nil, got %+v", input, ext)
		}
	}
}

func TestIsEclipseBundled(t *testing.T) {
	bundled := []string{"org.eclipse.jdt.core", "javax.annotation", "ch.qos.logback.classic", "bcprov"}
	for _, id := range bundled {
		if !isEclipseBundled(id) {
			t.Errorf("%q should be bundled", id)
		}
	}

	notBundled := []string{"com.anthropic.claudecode", "civerooni.com.putman", "my.custom.plugin"}
	for _, id := range notBundled {
		if isEclipseBundled(id) {
			t.Errorf("%q should NOT be bundled", id)
		}
	}
}

// Ensure model.FilterUserInstalledExtensions works correctly
func TestFilterUserInstalledExtensions(t *testing.T) {
	exts := []model.Extension{
		{ID: "bundled1", Source: "bundled"},
		{ID: "marketplace1", Source: "marketplace"},
		{ID: "user1", Source: "user_installed"},
		{ID: "dropin1", Source: "dropins"},
		{ID: "nosource"},
	}

	filtered := model.FilterUserInstalledExtensions(exts)
	if len(filtered) != 4 {
		t.Fatalf("expected 4 (all except bundled), got %d", len(filtered))
	}
	for _, e := range filtered {
		if e.Source == "bundled" {
			t.Errorf("bundled extension should have been filtered: %s", e.ID)
		}
	}
}
