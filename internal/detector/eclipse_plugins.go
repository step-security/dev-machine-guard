package detector

import (
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// eclipseFeatureDirs are Eclipse feature directories to scan.
// Features represent installed plugins/extensions (both bundled and user-installed).
var eclipseFeatureDirs = []string{
	"/Applications/Eclipse.app/Contents/Eclipse/features",
	"/Applications/Eclipse.app/Contents/Eclipse/dropins",
}

// eclipseBundledPrefixes are feature ID prefixes that ship as part of the
// base Eclipse platform. Features matching these are tagged as "bundled".
var eclipseBundledPrefixes = []string{
	"org.eclipse.platform",
	"org.eclipse.rcp",
	"org.eclipse.e4.rcp",
	"org.eclipse.equinox.",
	"org.eclipse.help",
	"org.eclipse.justj.",
	"org.eclipse.oomph.",
	"org.eclipse.epp.package.",
}

// DetectEclipsePlugins scans Eclipse feature directories and returns
// all features tagged as "bundled" or "user_installed".
func (d *ExtensionDetector) DetectEclipsePlugins() []model.Extension {
	var results []model.Extension
	for _, dir := range eclipseFeatureDirs {
		if !d.exec.DirExists(dir) {
			continue
		}
		results = append(results, d.collectEclipseFeatures(dir)...)
	}
	return results
}

// collectEclipseFeatures reads Eclipse features from a directory.
// Each feature is tagged as "bundled" or "user_installed".
func (d *ExtensionDetector) collectEclipseFeatures(featuresDir string) []model.Extension {
	entries, err := d.exec.ReadDir(featuresDir)
	if err != nil {
		return nil
	}

	var results []model.Extension
	for _, entry := range entries {
		name := entry.Name()
		baseName := strings.TrimSuffix(name, ".jar")

		ext := parseEclipsePluginName(baseName)
		if ext == nil {
			continue
		}

		// Tag as bundled or user_installed
		if isEclipseBundled(ext.ID) {
			ext.Source = "bundled"
		} else {
			ext.Source = "user_installed"
		}

		path := filepath.Join(featuresDir, name)
		info, err := d.exec.Stat(path)
		if err == nil {
			ext.InstallDate = info.ModTime().Unix()
		}

		results = append(results, *ext)
	}

	return results
}

func isEclipseBundled(pluginID string) bool {
	for _, prefix := range eclipseBundledPrefixes {
		if strings.HasPrefix(pluginID, prefix) {
			return true
		}
	}
	return false
}

// parseEclipsePluginName parses "id_version" format.
// Example: "com.github.spotbugs.plugin.eclipse_4.9.8.r202510181643-c1fa7f2"
//
//	→ id=com.github.spotbugs.plugin.eclipse, version=4.9.8.r202510181643-c1fa7f2
func parseEclipsePluginName(name string) *model.Extension {
	lastUnderscore := -1
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '_' {
			if i+1 < len(name) && name[i+1] >= '0' && name[i+1] <= '9' {
				lastUnderscore = i
				break
			}
		}
	}

	if lastUnderscore < 1 {
		return nil
	}

	pluginID := name[:lastUnderscore]
	version := name[lastUnderscore+1:]

	if pluginID == "" || version == "" {
		return nil
	}

	publisher := "unknown"
	parts := strings.SplitN(pluginID, ".", 3)
	if len(parts) >= 2 {
		publisher = parts[0] + "." + parts[1]
	}

	return &model.Extension{
		ID:        pluginID,
		Name:      pluginID,
		Version:   version,
		Publisher: publisher,
		IDEType:   "eclipse",
	}
}
