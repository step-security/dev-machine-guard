package detector

import (
	"context"
	"encoding/xml"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// Classic Visual Studio (Community/Professional/Enterprise) stores extensions
// very differently from VS Code: instead of a "publisher.name-version"
// directory, each extension lives in a randomly named folder containing an
// extension.vsixmanifest XML file that carries its identity. This detector is
// Windows-only and reads those manifests directly.
//
// Locations scanned:
//   - Per-user (user_installed): %LOCALAPPDATA%\Microsoft\VisualStudio\<ver>_<id>\Extensions\<rand>\
//   - All-users (bundled):       %PROGRAMDATA%\Microsoft\VisualStudio\<ver>\Extensions\<rand>\
//   - Install-dir built-ins (bundled): <VSInstallDir>\Common7\IDE\Extensions\...
//
// Built-ins are tagged "bundled" so the existing Windows default filter
// (model.FilterUserInstalledExtensions) hides them unless
// --include-bundled-plugins is set, mirroring Eclipse/JetBrains behavior.

// vsixIdentity holds the <Identity> attributes common to both VSIX schemas.
type vsixIdentity struct {
	ID        string `xml:"Id,attr"`
	Version   string `xml:"Version,attr"`
	Publisher string `xml:"Publisher,attr"`
}

// vsixManifest captures the fields we read from an extension.vsixmanifest.
// It tolerates both VSIX schema versions; encoding/xml matches local element
// names regardless of the differing root element and XML namespace:
//   - v2 (2011): <PackageManifest><Metadata><Identity .../><DisplayName/></Metadata></PackageManifest>
//   - v1 (2010): <Vsix><Identity .../><Name/><Author/></Vsix>
type vsixManifest struct {
	// VSIX v2 (2011): Identity is nested under <Metadata>.
	Metadata struct {
		Identity    vsixIdentity `xml:"Identity"`
		DisplayName string       `xml:"DisplayName"`
	} `xml:"Metadata"`
	// VSIX v1 (2010): Identity is a direct child of the root <Vsix> element.
	Identity vsixIdentity `xml:"Identity"`
	Name     string       `xml:"Name"`
	Author   string       `xml:"Author"`
}

// toExtension normalizes a parsed manifest into a model.Extension, or nil if
// it lacks the minimum identity (Id + Version).
func (m *vsixManifest) toExtension() *model.Extension {
	// VSIX v2 nests Identity under <Metadata>; v1 has it as a direct child.
	identity := m.Metadata.Identity
	if identity.ID == "" {
		identity = m.Identity
	}
	if identity.ID == "" || identity.Version == "" {
		return nil
	}

	publisher := identity.Publisher
	if publisher == "" {
		publisher = m.Author // v1 carries the publisher in <Author>
	}

	name := m.Metadata.DisplayName
	if name == "" {
		name = m.Name // v1 uses <Name>
	}
	if name == "" {
		name = identity.ID
	}

	return &model.Extension{
		ID:        identity.ID,
		Name:      name,
		Version:   identity.Version,
		Publisher: publisher,
		IDEType:   "visual_studio",
	}
}

// DetectVisualStudioExtensions discovers classic Visual Studio extensions.
// Windows-only; returns nil on other platforms.
func (d *ExtensionDetector) DetectVisualStudioExtensions(_ context.Context) []model.Extension {
	if d.exec.GOOS() != model.PlatformWindows {
		return nil
	}

	seen := make(map[string]bool)
	var results []model.Extension

	collect := func(roots []string, source string) {
		for _, root := range roots {
			for _, ext := range d.collectVSExtensionsFromDir(root, source) {
				key := strings.ToLower(ext.ID) + "@" + ext.Version
				if seen[key] {
					continue
				}
				seen[key] = true
				results = append(results, ext)
			}
		}
	}

	// User-installed first so a user copy wins over a bundled duplicate.
	collect(d.visualStudioUserExtensionRoots(), "user_installed")
	collect(d.visualStudioBundledExtensionRoots(), "bundled")

	return results
}

// visualStudioUserExtensionRoots returns the per-user "Extensions" directories,
// one per installed VS instance.
func (d *ExtensionDetector) visualStudioUserExtensionRoots() []string {
	localAppData := d.exec.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return nil
	}
	// Each instance is %LOCALAPPDATA%\Microsoft\VisualStudio\<major>.<minor>_<instanceId>\Extensions
	pattern := filepath.Join(localAppData, "Microsoft", "VisualStudio", "*", "Extensions")
	matches, _ := d.exec.Glob(pattern)
	return matches
}

// visualStudioBundledExtensionRoots returns the all-users / install-dir
// "Extensions" directories. Everything found under these is treated as bundled.
func (d *ExtensionDetector) visualStudioBundledExtensionRoots() []string {
	var roots []string

	// Install-dir built-ins: <VSInstallDir>\Common7\IDE\Extensions
	for _, inst := range discoverVisualStudioInstances(d.exec) {
		roots = append(roots, filepath.Join(inst.InstallPath, "Common7", "IDE", "Extensions"))
	}

	// All-users VSIX: %PROGRAMDATA%\Microsoft\VisualStudio\<ver>\Extensions
	if programData := d.exec.Getenv("PROGRAMDATA"); programData != "" {
		pattern := filepath.Join(programData, "Microsoft", "VisualStudio", "*", "Extensions")
		matches, _ := d.exec.Glob(pattern)
		roots = append(roots, matches...)
	}

	return roots
}

// collectVSExtensionsFromDir scans an "Extensions" root directory. Each
// immediate subdirectory is one installed extension containing an
// extension.vsixmanifest.
func (d *ExtensionDetector) collectVSExtensionsFromDir(extRoot, source string) []model.Extension {
	if !d.exec.DirExists(extRoot) {
		return nil
	}

	entries, err := d.exec.ReadDir(extRoot)
	if err != nil {
		return nil
	}

	var results []model.Extension
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		extPath := filepath.Join(extRoot, entry.Name())
		ext := d.parseVSIXManifestDir(extPath)
		if ext == nil {
			continue
		}

		ext.Source = source
		ext.InstallPath = extPath
		if info, err := d.exec.Stat(extPath); err == nil {
			ext.InstallDate = info.ModTime().Unix()
		}

		results = append(results, *ext)
	}

	return results
}

// parseVSIXManifestDir reads and parses <extPath>/extension.vsixmanifest.
func (d *ExtensionDetector) parseVSIXManifestDir(extPath string) *model.Extension {
	manifestPath := filepath.Join(extPath, "extension.vsixmanifest")
	data, err := d.exec.ReadFile(manifestPath)
	if err != nil {
		return nil
	}
	return parseVSIXManifest(data)
}

// parseVSIXManifest parses extension.vsixmanifest XML bytes into a
// model.Extension, or nil if the content is malformed or lacks an identity.
func parseVSIXManifest(data []byte) *model.Extension {
	var m vsixManifest
	if err := xml.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m.toExtension()
}
