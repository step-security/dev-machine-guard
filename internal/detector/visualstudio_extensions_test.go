package detector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// VSIX v2 (2011 schema): Identity is nested under <Metadata>, name in <DisplayName>.
const vsixManifestV2 = `<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Id="VsVim.Microsoft.e1f4f3a0" Version="2.8.0.0" Language="en-US" Publisher="Jared Parsons" />
    <DisplayName>VsVim</DisplayName>
    <Description>Vim emulation for Visual Studio.</Description>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Community" Version="[17.0,18.0)" />
  </Installation>
</PackageManifest>`

// VSIX v1 (2010 schema): Identity is a direct child of <Vsix>, name in <Name>,
// publisher in <Author>.
const vsixManifestV1 = `<?xml version="1.0" encoding="utf-8"?>
<Vsix Version="1.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2010">
  <Identity Id="MyCompany.LegacyExtension.12345" Version="1.4.2" />
  <Name>Legacy Extension</Name>
  <Author>My Company</Author>
  <Description>An older VSIX manifest format.</Description>
</Vsix>`

func TestParseVSIXManifest_V2(t *testing.T) {
	ext := parseVSIXManifest([]byte(vsixManifestV2))
	if ext == nil {
		t.Fatal("expected a parsed extension, got nil")
	}
	if ext.ID != "VsVim.Microsoft.e1f4f3a0" {
		t.Errorf("ID: got %q", ext.ID)
	}
	if ext.Version != "2.8.0.0" {
		t.Errorf("Version: got %q", ext.Version)
	}
	if ext.Publisher != "Jared Parsons" {
		t.Errorf("Publisher: got %q", ext.Publisher)
	}
	if ext.Name != "VsVim" {
		t.Errorf("Name: got %q", ext.Name)
	}
	if ext.IDEType != "visual_studio" {
		t.Errorf("IDEType: got %q", ext.IDEType)
	}
}

func TestParseVSIXManifest_V1(t *testing.T) {
	ext := parseVSIXManifest([]byte(vsixManifestV1))
	if ext == nil {
		t.Fatal("expected a parsed extension, got nil")
	}
	if ext.ID != "MyCompany.LegacyExtension.12345" {
		t.Errorf("ID: got %q", ext.ID)
	}
	if ext.Version != "1.4.2" {
		t.Errorf("Version: got %q", ext.Version)
	}
	// v1 carries publisher in <Author>.
	if ext.Publisher != "My Company" {
		t.Errorf("Publisher: got %q", ext.Publisher)
	}
	// v1 uses <Name> for the display name.
	if ext.Name != "Legacy Extension" {
		t.Errorf("Name: got %q", ext.Name)
	}
}

func TestParseVSIXManifest_Invalid(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"not xml", "this is not xml at all"},
		{"missing identity id", `<PackageManifest><Metadata><DisplayName>No Id</DisplayName></Metadata></PackageManifest>`},
		{"missing version", `<PackageManifest><Metadata><Identity Id="a.b" Publisher="p"/></Metadata></PackageManifest>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if ext := parseVSIXManifest([]byte(tc.data)); ext != nil {
				t.Errorf("expected nil, got %+v", ext)
			}
		})
	}
}

func TestParseVSIXManifest_DisplayNameFallsBackToID(t *testing.T) {
	manifest := `<PackageManifest><Metadata><Identity Id="pub.ext" Version="1.0.0" Publisher="pub"/></Metadata></PackageManifest>`
	ext := parseVSIXManifest([]byte(manifest))
	if ext == nil {
		t.Fatal("expected a parsed extension, got nil")
	}
	if ext.Name != "pub.ext" {
		t.Errorf("expected Name to fall back to ID, got %q", ext.Name)
	}
}

func TestCollectVSExtensionsFromDir(t *testing.T) {
	mock := executor.NewMock()
	extRoot := `C:\Users\dev\AppData\Local\Microsoft\VisualStudio\17.0_abc\Extensions`
	mock.SetDir(extRoot)
	mock.SetDirEntries(extRoot, []os.DirEntry{
		executor.MockDirEntry("rand1", true),
		executor.MockDirEntry("rand2", true),
		executor.MockDirEntry("noManifest", true),
		executor.MockDirEntry("extensions.configurationchanged", false),
	})
	mock.SetFile(filepath.Join(extRoot, "rand1", "extension.vsixmanifest"), []byte(vsixManifestV2))
	mock.SetFile(filepath.Join(extRoot, "rand2", "extension.vsixmanifest"), []byte(vsixManifestV1))
	// "noManifest" dir has no manifest file -> skipped. The non-dir entry -> skipped.

	det := &ExtensionDetector{exec: mock}
	results := det.collectVSExtensionsFromDir(extRoot, "user_installed")

	if len(results) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(results))
	}
	for _, ext := range results {
		if ext.Source != "user_installed" {
			t.Errorf("%s: expected source user_installed, got %q", ext.ID, ext.Source)
		}
		if ext.InstallPath == "" {
			t.Errorf("%s: expected InstallPath to be set", ext.ID)
		}
	}
}

func TestCollectVSExtensionsFromDir_Missing(t *testing.T) {
	mock := executor.NewMock()
	det := &ExtensionDetector{exec: mock}
	if results := det.collectVSExtensionsFromDir(`C:\nope`, "bundled"); results != nil {
		t.Errorf("expected nil for missing dir, got %v", results)
	}
}

func TestDetectVisualStudioExtensions_NonWindows(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	det := &ExtensionDetector{exec: mock}
	if results := det.DetectVisualStudioExtensions(context.Background()); results != nil {
		t.Errorf("expected nil on non-Windows, got %v", results)
	}
}

func TestDetectVisualStudioExtensions_EndToEnd(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")

	localAppData := `C:\Users\dev\AppData\Local`
	programData := `C:\ProgramData`
	mock.SetEnv("LOCALAPPDATA", localAppData)
	mock.SetEnv("PROGRAMDATA", programData)

	// --- Per-user extension (user_installed) ---
	userRoot := filepath.Join(localAppData, "Microsoft", "VisualStudio", "17.0_abc", "Extensions")
	mock.SetGlob(filepath.Join(localAppData, "Microsoft", "VisualStudio", "*", "Extensions"), []string{userRoot})
	mock.SetDir(userRoot)
	mock.SetDirEntries(userRoot, []os.DirEntry{executor.MockDirEntry("userext", true)})
	mock.SetFile(filepath.Join(userRoot, "userext", "extension.vsixmanifest"), []byte(vsixManifestV2))

	// --- Built-in extension via VS setup instance data (bundled) ---
	stateFile := filepath.Join(programData, "Microsoft", "VisualStudio", "Packages", "_Instances", "abc", "state.json")
	mock.SetGlob(filepath.Join(programData, "Microsoft", "VisualStudio", "Packages", "_Instances", "*", "state.json"), []string{stateFile})
	installPath := `C:\Program Files\Microsoft Visual Studio\2022\Community`
	// Marshal so the Windows backslashes are JSON-escaped, exactly as VS writes state.json.
	stateJSON, _ := json.Marshal(map[string]string{"installationPath": installPath, "installationVersion": "17.0"})
	mock.SetFile(stateFile, stateJSON)
	bundledRoot := filepath.Join(installPath, "Common7", "IDE", "Extensions")
	mock.SetDir(bundledRoot)
	mock.SetDirEntries(bundledRoot, []os.DirEntry{executor.MockDirEntry("builtin", true)})
	mock.SetFile(filepath.Join(bundledRoot, "builtin", "extension.vsixmanifest"), []byte(vsixManifestV1))

	det := &ExtensionDetector{exec: mock}
	results := det.DetectVisualStudioExtensions(context.Background())

	if len(results) != 2 {
		t.Fatalf("expected 2 extensions, got %d: %+v", len(results), results)
	}

	bySource := map[string]model.Extension{}
	for _, ext := range results {
		bySource[ext.Source] = ext
		if ext.IDEType != "visual_studio" {
			t.Errorf("%s: expected ide_type visual_studio, got %q", ext.ID, ext.IDEType)
		}
	}
	if bySource["user_installed"].ID != "VsVim.Microsoft.e1f4f3a0" {
		t.Errorf("user_installed: got %q", bySource["user_installed"].ID)
	}
	if bySource["bundled"].ID != "MyCompany.LegacyExtension.12345" {
		t.Errorf("bundled: got %q", bySource["bundled"].ID)
	}

	// The Windows default filter hides the bundled built-in, leaving only the
	// user-installed extension — same behavior as Eclipse/JetBrains.
	filtered := model.FilterUserInstalledExtensions(results)
	if len(filtered) != 1 || filtered[0].Source != "user_installed" {
		t.Errorf("expected only the user_installed extension after filtering, got %+v", filtered)
	}
}

func TestDetectVisualStudioExtensions_Dedup(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	localAppData := `C:\Users\dev\AppData\Local`
	programData := `C:\ProgramData`
	mock.SetEnv("LOCALAPPDATA", localAppData)
	mock.SetEnv("PROGRAMDATA", programData)

	// Same extension present in both the per-user dir and an all-users dir.
	userRoot := filepath.Join(localAppData, "Microsoft", "VisualStudio", "17.0_abc", "Extensions")
	allUsersRoot := filepath.Join(programData, "Microsoft", "VisualStudio", "17.0", "Extensions")
	mock.SetGlob(filepath.Join(localAppData, "Microsoft", "VisualStudio", "*", "Extensions"), []string{userRoot})
	mock.SetGlob(filepath.Join(programData, "Microsoft", "VisualStudio", "*", "Extensions"), []string{allUsersRoot})

	for _, root := range []string{userRoot, allUsersRoot} {
		mock.SetDir(root)
		mock.SetDirEntries(root, []os.DirEntry{executor.MockDirEntry("dup", true)})
		mock.SetFile(filepath.Join(root, "dup", "extension.vsixmanifest"), []byte(vsixManifestV2))
	}

	det := &ExtensionDetector{exec: mock}
	results := det.DetectVisualStudioExtensions(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 deduped extension, got %d", len(results))
	}
	// User-installed is collected first, so it wins the dedup.
	if results[0].Source != "user_installed" {
		t.Errorf("expected user_installed to win dedup, got %q", results[0].Source)
	}
}
