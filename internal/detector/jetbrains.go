package detector

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// jetbrainsProductInfo holds the fields we read from product-info.json.
type jetbrainsProductInfo struct {
	DataDirectoryName string `json:"dataDirectoryName"`
	ProductVendor     string `json:"productVendor"`
}

// JetBrainsPluginDetector collects user-installed plugins from JetBrains-family IDEs.
//
// It reads product-info.json from each detected IDE's install path to obtain
// the dataDirectoryName and productVendor, then scans the platform-specific
// config directory for user-installed plugins:
//
//   - macOS:   ~/Library/Application Support/<vendor>/<dataDirectoryName>/plugins/
//   - Windows: %APPDATA%/<vendor>/<dataDirectoryName>/plugins/
//   - Linux:   ~/.config/<vendor>/<dataDirectoryName>/plugins/ (XDG_CONFIG_HOME respected)
//
// Also checks for custom plugin path overrides in idea.properties.
// Plugin version is extracted from JAR filenames matching <pluginDirName>-<version>.jar.
type JetBrainsPluginDetector struct {
	exec executor.Executor
}

func NewJetBrainsPluginDetector(exec executor.Executor) *JetBrainsPluginDetector {
	return &JetBrainsPluginDetector{exec: exec}
}

// Detect scans for user-installed plugins across all detected JetBrains-family IDEs.
func (d *JetBrainsPluginDetector) Detect(_ context.Context, ides []model.IDE) []model.Extension {
	var results []model.Extension

	for _, ide := range ides {
		pluginsDir := d.resolvePluginsDir(ide)
		if pluginsDir == "" {
			continue
		}

		plugins := d.collectPlugins(pluginsDir, ide.IDEType)
		results = append(results, plugins...)
	}

	return results
}

// resolvePluginsDir reads product-info.json from the IDE's install path,
// then returns the platform-specific user plugins path.
// Returns "" if the IDE doesn't have product-info.json (non-JetBrains IDEs).
//
// Resolution order:
//  1. Check idea.plugins.path in user's idea.properties (custom override)
//  2. Use default: <config-base>/<vendor>/<dataDirectoryName>/plugins/
func (d *JetBrainsPluginDetector) resolvePluginsDir(ide model.IDE) string {
	info := d.readProductInfo(ide.InstallPath)
	if info.DataDirectoryName == "" {
		return ""
	}

	vendor := info.ProductVendor
	if vendor == "" {
		vendor = "JetBrains" // safe default for older installations
	}

	configDir := d.resolveConfigDir(vendor, info.DataDirectoryName)
	if configDir == "" {
		return ""
	}

	// Check for custom plugin path override in idea.properties
	if customPath := d.readCustomPluginsPath(configDir); customPath != "" {
		return customPath
	}

	return filepath.Join(configDir, "plugins")
}

// resolveConfigDir returns the platform-specific JetBrains config directory.
// macOS:   ~/Library/Application Support/<vendor>/<dataDirectoryName>/
// Windows: %APPDATA%/<vendor>/<dataDirectoryName>/ (also checks %LOCALAPPDATA%)
// Linux:   ~/.config/<vendor>/<dataDirectoryName>/ (XDG_CONFIG_HOME respected)
func (d *JetBrainsPluginDetector) resolveConfigDir(vendor, dataDirName string) string {
	if d.exec.GOOS() == model.PlatformWindows {
		// Most JetBrains IDEs use APPDATA; Android Studio uses LOCALAPPDATA
		for _, envVar := range []string{"APPDATA", "LOCALAPPDATA"} {
			base := d.exec.Getenv(envVar)
			if base == "" {
				continue
			}
			dir := filepath.Join(base, vendor, dataDirName)
			if d.exec.DirExists(dir) {
				return dir
			}
		}
		// Fall back to APPDATA even if dir doesn't exist yet
		appData := d.exec.Getenv("APPDATA")
		if appData != "" {
			return filepath.Join(appData, vendor, dataDirName)
		}
		return ""
	}

	homeDir := getHomeDir(d.exec)

	if d.exec.GOOS() == model.PlatformDarwin {
		return filepath.Join(homeDir, "Library", "Application Support", vendor, dataDirName)
	}

	// Linux: respect XDG_CONFIG_HOME, default to ~/.config
	configHome := d.exec.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(homeDir, ".config")
	}
	return filepath.Join(configHome, vendor, dataDirName)
}

// readProductInfo reads dataDirectoryName and productVendor from product-info.json.
// On macOS: <installPath>/Contents/Resources/product-info.json
// On Windows/Linux: <installPath>/product-info.json
func (d *JetBrainsPluginDetector) readProductInfo(installPath string) jetbrainsProductInfo {
	var productInfoPath string
	if d.exec.GOOS() == model.PlatformDarwin {
		productInfoPath = filepath.Join(installPath, "Contents", "Resources", "product-info.json")
	} else {
		productInfoPath = filepath.Join(installPath, "product-info.json")
	}

	data, err := d.exec.ReadFile(productInfoPath)
	if err != nil {
		return jetbrainsProductInfo{}
	}

	var info jetbrainsProductInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return jetbrainsProductInfo{}
	}
	return info
}

// readCustomPluginsPath checks for idea.plugins.path override in idea.properties.
// Returns the custom path if set, or "" if not found/overridden.
func (d *JetBrainsPluginDetector) readCustomPluginsPath(configDir string) string {
	propsPath := filepath.Join(configDir, "idea.properties")
	data, err := d.exec.ReadFile(propsPath)
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		// Skip comments
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if strings.HasPrefix(line, "idea.plugins.path=") {
			path := strings.TrimPrefix(line, "idea.plugins.path=")
			path = strings.TrimSpace(path)
			if path != "" {
				return path
			}
		}
	}

	return ""
}

// collectPlugins lists plugin subdirectories and extracts name/version from each.
func (d *JetBrainsPluginDetector) collectPlugins(pluginsDir, ideType string) []model.Extension {
	if !d.exec.DirExists(pluginsDir) {
		return nil
	}

	entries, err := d.exec.ReadDir(pluginsDir)
	if err != nil {
		return nil
	}

	var results []model.Extension
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pluginName := entry.Name()
		libDir := filepath.Join(pluginsDir, pluginName, "lib")
		version := d.parsePluginVersion(libDir, pluginName)

		ext := model.Extension{
			ID:      pluginName,
			Name:    pluginName,
			Version: version,
			IDEType: ideType,
		}

		// Get install date from plugin directory mtime
		info, err := d.exec.Stat(filepath.Join(pluginsDir, pluginName))
		if err == nil {
			ext.InstallDate = info.ModTime().Unix()
		}

		results = append(results, ext)
	}

	return results
}

// parsePluginVersion finds the main plugin JAR matching <pluginDirName>-<version>.jar
// in the lib/ directory and extracts the version string.
func (d *JetBrainsPluginDetector) parsePluginVersion(libDir, pluginDirName string) string {
	entries, err := d.exec.ReadDir(libDir)
	if err != nil {
		return "unknown"
	}

	prefix := strings.ToLower(pluginDirName + "-")
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".jar") {
			continue
		}

		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, prefix) {
			continue
		}

		// Skip auxiliary JARs (e.g., IdeaVIM-2.27.2-searchableOptions.jar)
		remainder := name[len(pluginDirName)+1 : len(name)-4] // strip prefix + "-" and ".jar"
		if strings.Contains(remainder, "-") {
			continue
		}

		if remainder != "" {
			return remainder
		}
	}

	return "unknown"
}
