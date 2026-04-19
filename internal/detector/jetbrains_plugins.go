package detector

import (
	"archive/zip"
	"encoding/xml"
	"io"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// jetbrainsProductDir maps a JetBrains product directory prefix to its ide_type.
var jetbrainsProductDir = map[string]string{
	"IntelliJIdea": "intellij_idea",
	"IdeaIC":       "intellij_idea_ce",
	"PyCharm":      "pycharm",
	"PyCharmCE":    "pycharm_ce",
	"WebStorm":     "webstorm",
	"GoLand":       "goland",
	"Rider":        "rider",
	"PhpStorm":     "phpstorm",
	"RubyMine":     "rubymine",
	"CLion":        "clion",
	"DataGrip":     "datagrip",
	"Fleet":        "fleet",
}

// jetbrainsAppBundlePaths maps ide_type to the bundled plugins path inside the .app.
var jetbrainsAppBundlePaths = map[string]string{
	"intellij_idea":    "/Applications/IntelliJ IDEA.app/Contents/plugins",
	"intellij_idea_ce": "/Applications/IntelliJ IDEA CE.app/Contents/plugins",
	"pycharm":          "/Applications/PyCharm.app/Contents/plugins",
	"pycharm_ce":       "/Applications/PyCharm CE.app/Contents/plugins",
	"webstorm":         "/Applications/WebStorm.app/Contents/plugins",
	"goland":           "/Applications/GoLand.app/Contents/plugins",
	"rider":            "/Applications/Rider.app/Contents/plugins",
	"phpstorm":         "/Applications/PhpStorm.app/Contents/plugins",
	"rubymine":         "/Applications/RubyMine.app/Contents/plugins",
	"clion":            "/Applications/CLion.app/Contents/plugins",
	"datagrip":         "/Applications/DataGrip.app/Contents/plugins",
	"fleet":            "/Applications/Fleet.app/Contents/plugins",
	"android_studio":   "/Applications/Android Studio.app/Contents/plugins",
}

// DetectJetBrainsPlugins scans JetBrains and Android Studio plugin directories
// and returns detected plugins as model.Extension entries.
// Bundled plugins (from app bundle) are tagged "bundled".
// User-installed plugins (from ~/Library/Application Support/) are tagged "user_installed".
func (d *ExtensionDetector) DetectJetBrainsPlugins() []model.Extension {
	homeDir := getHomeDir(d.exec)
	var results []model.Extension

	// Bundled plugins: /Applications/<IDE>.app/Contents/plugins/
	for ideType, bundlePath := range jetbrainsAppBundlePaths {
		if d.exec.DirExists(bundlePath) {
			plugins := d.collectJetBrainsPlugins(bundlePath, ideType)
			for i := range plugins {
				plugins[i].Source = "bundled"
			}
			results = append(results, plugins...)
		}
	}

	// User-installed: ~/Library/Application Support/JetBrains/*/plugins/
	jbBase := filepath.Join(homeDir, "Library", "Application Support", "JetBrains")
	results = append(results, d.scanJetBrainsUserPlugins(jbBase, jetbrainsProductDir)...)

	// User-installed: ~/Library/Application Support/Google/AndroidStudio*/plugins/
	googleBase := filepath.Join(homeDir, "Library", "Application Support", "Google")
	results = append(results, d.scanJetBrainsUserPlugins(googleBase, map[string]string{
		"AndroidStudio": "android_studio",
	})...)

	return results
}

// scanJetBrainsUserPlugins scans user-installed plugins from versioned product directories.
func (d *ExtensionDetector) scanJetBrainsUserPlugins(baseDir string, productMap map[string]string) []model.Extension {
	if !d.exec.DirExists(baseDir) {
		return nil
	}

	entries, err := d.exec.ReadDir(baseDir)
	if err != nil {
		return nil
	}

	var results []model.Extension
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()

		ideType := matchProductDir(dirName, productMap)
		if ideType == "" {
			continue
		}

		pluginsDir := filepath.Join(baseDir, dirName, "plugins")
		if !d.exec.DirExists(pluginsDir) {
			continue
		}

		plugins := d.collectJetBrainsPlugins(pluginsDir, ideType)
		for i := range plugins {
			plugins[i].Source = "user_installed"
		}
		results = append(results, plugins...)
	}

	return results
}

// matchProductDir checks if a directory name starts with any known product prefix.
// Longer prefixes are checked first to avoid "PyCharm" matching before "PyCharmCE".
func matchProductDir(dirName string, productMap map[string]string) string {
	bestMatch := ""
	bestLen := 0
	for prefix, ideType := range productMap {
		if strings.HasPrefix(dirName, prefix) && len(prefix) > bestLen {
			bestMatch = ideType
			bestLen = len(prefix)
		}
	}
	return bestMatch
}

// collectJetBrainsPlugins reads plugins from a JetBrains plugins directory.
// Each subdirectory is a plugin; metadata is in META-INF/plugin.xml.
func (d *ExtensionDetector) collectJetBrainsPlugins(pluginsDir, ideType string) []model.Extension {
	entries, err := d.exec.ReadDir(pluginsDir)
	if err != nil {
		return nil
	}

	var results []model.Extension
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pluginDir := filepath.Join(pluginsDir, entry.Name())
		ext := d.parseJetBrainsPlugin(pluginDir, ideType)
		if ext != nil {
			info, err := d.exec.Stat(pluginDir)
			if err == nil {
				ext.InstallDate = info.ModTime().Unix()
			}
			results = append(results, *ext)
		}
	}

	return results
}

// pluginXML represents the relevant fields from META-INF/plugin.xml.
type pluginXML struct {
	XMLName xml.Name `xml:"idea-plugin"`
	ID      string   `xml:"id"`
	Name    string   `xml:"name"`
	Version string   `xml:"version"`
	Vendor  string   `xml:"vendor"`
}

// parseJetBrainsPlugin reads META-INF/plugin.xml from a plugin directory.
// It first checks for a top-level META-INF/plugin.xml, then falls back
// to extracting it from jar files in the lib/ directory.
func (d *ExtensionDetector) parseJetBrainsPlugin(pluginDir, ideType string) *model.Extension {
	xmlPath := filepath.Join(pluginDir, "META-INF", "plugin.xml")
	data, err := d.exec.ReadFile(xmlPath)
	if err != nil {
		data = d.readPluginXMLFromJars(pluginDir)
		if data == nil {
			return nil
		}
	}

	var plugin pluginXML
	if err := xml.Unmarshal(data, &plugin); err != nil {
		return nil
	}

	dirName := filepath.Base(pluginDir)
	id := plugin.ID
	if id == "" {
		id = dirName
	}
	name := plugin.Name
	if name == "" {
		name = dirName
	}
	version := plugin.Version
	if version == "" {
		version = "unknown"
	}
	publisher := plugin.Vendor
	if publisher == "" {
		publisher = "unknown"
	}

	return &model.Extension{
		ID:        id,
		Name:      name,
		Version:   version,
		Publisher: publisher,
		IDEType:   ideType,
	}
}

// readPluginXMLFromJars looks for META-INF/plugin.xml inside jar files
// in the plugin's lib/ directory.
func (d *ExtensionDetector) readPluginXMLFromJars(pluginDir string) []byte {
	libDir := filepath.Join(pluginDir, "lib")
	entries, err := d.exec.ReadDir(libDir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jar") {
			continue
		}
		jarPath := filepath.Join(libDir, entry.Name())
		data := readFileFromZip(jarPath, "META-INF/plugin.xml")
		if data != nil {
			return data
		}
	}
	return nil
}

// readFileFromZip extracts a single file from a zip/jar archive.
func readFileFromZip(zipPath, targetFile string) []byte {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name == targetFile {
			rc, err := f.Open()
			if err != nil {
				return nil
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				return nil
			}
			return data
		}
	}
	return nil
}
