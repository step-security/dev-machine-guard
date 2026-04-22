package detector

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// eclipseBundledPrefixes are bundle ID prefixes that ship as part of the
// base Eclipse platform. Bundles matching these are tagged as "bundled".
// eclipseBundledPrefixes identifies bundles that ship as part of the Eclipse
// platform or are standard dependencies. Bundles that do not match these
// prefixes are treated as non-bundled and may be classified into source
// categories such as "marketplace", "user_installed", or "dropins".
var eclipseBundledPrefixes = []string{
	// Eclipse platform
	"org.eclipse.",
	"epp.",
	"configure.",
	// OSGi / Equinox runtime
	"org.osgi.",
	// Apache libraries
	"org.apache.",
	// JVM / standard APIs
	"javax.",
	"jakarta.",
	"com.sun.",
	"com.ibm.icu",
	// Common platform dependencies
	"org.objectweb.",
	"org.sat4j.",
	"org.tukaani.",
	"org.w3c.",
	"org.xml.sax",
	"org.hamcrest",
	"org.junit",
	"org.opentest4j",
	"org.apiguardian",
	"org.commonmark",
	"org.mortbay.",
	"org.jdom",
	"org.jsoup",
	"org.snakeyaml",
	"org.jcodings",
	"org.joni",
	"org.glassfish.",
	"org.gradle.",
	"org.jacoco.",
	// JUnit platform (ships with Eclipse JDT)
	"junit-jupiter",
	"junit-platform",
	"junit-vintage",
	// Crypto / SSH / networking
	"bcpg",
	"bcpkix",
	"bcprov",
	"bcutil",
	"com.jcraft.",
	"net.i2p.crypto",
	"net.bytebuddy",
	// Google / JSON / utilities
	"com.google.gson",
	"com.google.guava",
	"com.googlecode.",
	// Logging
	"ch.qos.logback",
	"slf4j.",
	// Build tooling
	"args4j",
	"biz.aQute.",
	// Other standard Eclipse deps
	"com.sun.xml.",
	"jaxen",
}

// eclipseIniPatterns are .ini filenames for Eclipse-family products.
var eclipseIniPatterns = []string{
	"eclipse.ini",
	"sts.ini",
	"SpringToolSuite.ini",
	"myeclipse.ini",
}

// ---------- macOS detection (unchanged) ----------

var eclipseFeatureDirsDarwin = []string{
	"/Applications/Eclipse.app/Contents/Eclipse/features",
	"/Applications/Eclipse.app/Contents/Eclipse/dropins",
}

// ---------- Public API ----------

// DetectEclipsePlugins scans Eclipse installations for plugins.
// On macOS: scans features/dropins directories.
// On Windows: multi-stage pipeline using detected IDE paths, path probes,
// and drive letter scanning, with validation before reporting.
func (d *ExtensionDetector) DetectEclipsePlugins(ctx context.Context, ides []model.IDE) []model.Extension {
	if d.exec.GOOS() != "windows" {
		var results []model.Extension
		for _, dir := range eclipseFeatureDirsDarwin {
			if d.exec.DirExists(dir) {
				results = append(results, d.collectEclipseFeatures(dir)...)
			}
		}
		return results
	}
	return d.detectEclipsePluginsWindows(ctx, ides)
}

// ---------- Windows multi-stage pipeline ----------

func (d *ExtensionDetector) detectEclipsePluginsWindows(ctx context.Context, ides []model.IDE) []model.Extension {
	// Stage 1+2: Collect candidate paths from detected IDEs + well-known locations
	candidates := d.gatherEclipseCandidates(ides)

	// Stage 4: Validate each candidate
	seen := make(map[string]bool)
	var validInstalls []string
	for _, path := range candidates {
		key := strings.ToLower(filepath.Clean(path))
		if seen[key] {
			continue
		}
		seen[key] = true

		if d.validateEclipseInstall(path) {
			validInstalls = append(validInstalls, path)
		}
	}

	// Stage 6: Enumerate plugins from each validated install
	pluginSeen := make(map[string]bool)
	var results []model.Extension
	for _, installDir := range validInstalls {
		plugins := d.enumerateEclipsePlugins(ctx, installDir)
		for _, p := range plugins {
			dedupKey := p.ID + "@" + p.Version
			if pluginSeen[dedupKey] {
				continue
			}
			pluginSeen[dedupKey] = true
			results = append(results, p)
		}
	}

	return results
}

// gatherEclipseCandidates collects candidate install paths from multiple sources.
func (d *ExtensionDetector) gatherEclipseCandidates(ides []model.IDE) []string {
	var candidates []string

	// Source 1: Detected IDEs (registry-aware — handles custom install paths)
	for _, ide := range ides {
		if ide.IDEType == "eclipse" && ide.InstallPath != "" {
			candidates = append(candidates, ide.InstallPath)
		}
	}

	// Source 2: Well-known path probes
	programFiles := d.exec.Getenv("PROGRAMFILES")
	programFilesX86 := d.exec.Getenv("PROGRAMFILES(X86)")
	userProfile := d.exec.Getenv("USERPROFILE")
	localAppData := d.exec.Getenv("LOCALAPPDATA")

	// Machine-scope
	if programFiles != "" {
		candidates = append(candidates, filepath.Join(programFiles, "eclipse"))
	}
	if programFilesX86 != "" {
		candidates = append(candidates, filepath.Join(programFilesX86, "eclipse"))
	}
	candidates = append(candidates, `C:\eclipse`)

	// STS / vendor variants
	if programFiles != "" {
		candidates = append(candidates, d.globDirs(filepath.Join(programFiles, "sts-*"))...)
	}

	// User-scope: Oomph installer default
	if userProfile != "" {
		eclipseUserDir := filepath.Join(userProfile, "eclipse")
		if d.exec.DirExists(eclipseUserDir) {
			entries, err := d.exec.ReadDir(eclipseUserDir)
			if err == nil {
				for _, e := range entries {
					if e.IsDir() {
						candidates = append(candidates, filepath.Join(eclipseUserDir, e.Name(), "eclipse"))
					}
				}
			}
		}
	}

	// User-scope: LOCALAPPDATA
	if localAppData != "" {
		candidates = append(candidates, d.globDirs(filepath.Join(localAppData, "Programs", "Eclipse*"))...)
		candidates = append(candidates, d.globDirs(filepath.Join(localAppData, "Programs", "Spring*"))...)
	}

	// Drive letter probe: D:\eclipse through Z:\eclipse.
	// Only probe drives that actually exist to avoid slow network drive timeouts.
	for drive := 'D'; drive <= 'Z'; drive++ {
		driveRoot := string(drive) + `:\`
		if !d.exec.DirExists(driveRoot) {
			continue
		}
		candidates = append(candidates, string(drive)+`:\eclipse`)
	}

	return candidates
}

// globDirs expands a glob pattern and returns matching directories.
func (d *ExtensionDetector) globDirs(pattern string) []string {
	matches, err := d.exec.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	var dirs []string
	for _, m := range matches {
		if d.exec.DirExists(m) {
			dirs = append(dirs, m)
		}
	}
	return dirs
}

// validateEclipseInstall checks that a candidate directory is actually an Eclipse install.
// Requires: an .ini file + plugins/ directory + configuration/ directory.
func (d *ExtensionDetector) validateEclipseInstall(installDir string) bool {
	if !d.exec.DirExists(installDir) {
		return false
	}

	// Check for eclipse.ini or branded variant
	hasIni := false
	for _, ini := range eclipseIniPatterns {
		if d.exec.FileExists(filepath.Join(installDir, ini)) {
			hasIni = true
			break
		}
	}
	if !hasIni {
		return false
	}

	// Check for plugins/ and configuration/ directories
	if !d.exec.DirExists(filepath.Join(installDir, "plugins")) {
		return false
	}
	if !d.exec.DirExists(filepath.Join(installDir, "configuration")) {
		return false
	}

	return true
}

// enumerateEclipsePlugins collects plugins from a validated Eclipse install.
// Uses the p2 director API (eclipsec.exe -listInstalledRoots) to get authoritative
// installed features, then enriches with bundles.info for full bundle details.
func (d *ExtensionDetector) enumerateEclipsePlugins(ctx context.Context, installDir string) []model.Extension {
	// Try p2 director first — returns authoritative list of installed root features
	roots := d.queryP2InstalledRoots(ctx, installDir)

	// Build a set of root feature prefixes for marketplace classification.
	// Root features that are NOT org.eclipse.* or epp.* are marketplace-installed.
	marketplaceRoots := make(map[string]bool)
	for _, root := range roots {
		if !strings.HasPrefix(root.ID, "org.eclipse.") && !strings.HasPrefix(root.ID, "epp.") {
			// Strip ".feature.group" suffix to get the base feature ID
			baseID := strings.TrimSuffix(root.ID, ".feature.group")
			baseID = strings.TrimSuffix(baseID, ".feature")
			marketplaceRoots[baseID] = true
		}
	}

	var results []model.Extension
	seen := make(map[string]bool)

	// If we got roots from p2 director, use them for classification
	if len(roots) > 0 {
		// Add root features as extensions
		for _, root := range roots {
			key := root.ID + "@" + root.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			results = append(results, root)
		}

		// Also parse bundles.info for non-root bundles that belong to marketplace features.
		// A bundle belongs to a marketplace feature if its ID starts with any marketplace root prefix.
		bundlesInfo := filepath.Join(installDir, "configuration",
			"org.eclipse.equinox.simpleconfigurator", "bundles.info")
		for _, ext := range d.parseEclipseBundlesInfo(bundlesInfo) {
			key := ext.ID + "@" + ext.Version
			if seen[key] {
				continue
			}
			// Check if this bundle belongs to a marketplace feature
			for prefix := range marketplaceRoots {
				if strings.HasPrefix(ext.ID, prefix) {
					ext.Source = "marketplace"
					seen[key] = true
					results = append(results, ext)
					break
				}
			}
		}
	} else {
		// Fallback: bundles.info parsing (p2 director unavailable)
		bundlesInfo := filepath.Join(installDir, "configuration",
			"org.eclipse.equinox.simpleconfigurator", "bundles.info")
		for _, ext := range d.parseEclipseBundlesInfo(bundlesInfo) {
			key := ext.ID + "@" + ext.Version
			if !seen[key] {
				seen[key] = true
				results = append(results, ext)
			}
		}
	}

	// Also check dropins/
	dropinsDir := filepath.Join(installDir, "dropins")
	for _, ext := range d.collectDropins(dropinsDir) {
		key := ext.ID + "@" + ext.Version
		if !seen[key] {
			seen[key] = true
			results = append(results, ext)
		}
	}

	return results
}

// queryP2InstalledRoots invokes Eclipse's p2 director to get the authoritative
// list of installed root features. Returns nil if eclipsec.exe is not available
// or the command fails. Output format: "feature.id/version" per line.
func (d *ExtensionDetector) queryP2InstalledRoots(ctx context.Context, installDir string) []model.Extension {
	// Find eclipsec.exe (console launcher)
	eclipsec := filepath.Join(installDir, "eclipsec.exe")
	if !d.exec.FileExists(eclipsec) {
		// Try eclipse.exe as fallback (may open a window briefly)
		eclipsec = filepath.Join(installDir, "eclipse.exe")
		if !d.exec.FileExists(eclipsec) {
			return nil
		}
	}

	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 30*time.Second,
		eclipsec, "-nosplash",
		"-application", "org.eclipse.equinox.p2.director",
		"-listInstalledRoots")
	if err != nil || exitCode != 0 {
		return nil
	}

	var results []model.Extension
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip debug/log lines — they contain spaces and timestamps.
		// Valid p2 output lines are "feature.id/version" with no spaces before the "/"
		if strings.Contains(line, " ") {
			continue
		}
		if !strings.Contains(line, "/") {
			continue
		}

		parts := strings.SplitN(line, "/", 2)
		if len(parts) != 2 {
			continue
		}

		featureID := parts[0]
		version := parts[1]
		if featureID == "" || version == "" {
			continue
		}

		source := "bundled"
		if !strings.HasPrefix(featureID, "org.eclipse.") && !strings.HasPrefix(featureID, "epp.") {
			source = "marketplace"
		}

		results = append(results, model.Extension{
			ID:        featureID,
			Name:      featureID,
			Version:   version,
			Publisher: extractPublisher(featureID),
			IDEType:   "eclipse",
			Source:    source,
		})
	}

	return results
}

// parseEclipseBundlesInfo reads an Eclipse bundles.info file.
// Format: id,version,location,startLevel,autoStart (one per line, # comments)
func (d *ExtensionDetector) parseEclipseBundlesInfo(filePath string) []model.Extension {
	data, err := d.exec.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var results []model.Extension
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ",", 5)
		if len(parts) < 2 {
			continue
		}

		pluginID := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		if pluginID == "" || version == "" {
			continue
		}

		publisher := extractPublisher(pluginID)
		source := "user_installed"
		if isEclipseBundled(pluginID) {
			source = "bundled"
		}

		results = append(results, model.Extension{
			ID:        pluginID,
			Name:      pluginID,
			Version:   version,
			Publisher: publisher,
			IDEType:   "eclipse",
			Source:    source,
		})
	}

	return results
}

// collectDropins scans the dropins/ directory for additional plugins.
// Handles direct JARs, directory bundles, and nested eclipse/plugins layouts.
func (d *ExtensionDetector) collectDropins(dropinsDir string) []model.Extension {
	if !d.exec.DirExists(dropinsDir) {
		return nil
	}

	entries, err := d.exec.ReadDir(dropinsDir)
	if err != nil {
		return nil
	}

	var results []model.Extension
	for _, entry := range entries {
		name := entry.Name()

		// Direct JAR: dropins/com.example.plugin_1.0.0.jar
		if !entry.IsDir() && strings.HasSuffix(name, ".jar") {
			if ext := parseEclipsePluginName(strings.TrimSuffix(name, ".jar")); ext != nil {
				ext.Source = "dropins"
				results = append(results, *ext)
			}
			continue
		}

		if !entry.IsDir() {
			continue
		}

		// Directory bundle: dropins/com.example.plugin_1.0.0/
		if ext := parseEclipsePluginName(name); ext != nil {
			ext.Source = "dropins"
			results = append(results, *ext)
			continue
		}

		// Nested layout: dropins/<feature>/eclipse/plugins/ or dropins/<feature>/plugins/
		subPath := filepath.Join(dropinsDir, name)
		for _, nested := range []string{
			filepath.Join(subPath, "eclipse", "plugins"),
			filepath.Join(subPath, "plugins"),
		} {
			if !d.exec.DirExists(nested) {
				continue
			}
			nestedEntries, err := d.exec.ReadDir(nested)
			if err != nil {
				continue
			}
			for _, ne := range nestedEntries {
				baseName := strings.TrimSuffix(ne.Name(), ".jar")
				if ext := parseEclipsePluginName(baseName); ext != nil {
					ext.Source = "dropins"
					results = append(results, *ext)
				}
			}
		}
	}

	return results
}

// ---------- Shared helpers ----------

func isEclipseBundled(pluginID string) bool {
	for _, prefix := range eclipseBundledPrefixes {
		if strings.HasPrefix(pluginID, prefix) {
			return true
		}
	}
	return false
}

func extractPublisher(pluginID string) string {
	parts := strings.SplitN(pluginID, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return "unknown"
}

// collectEclipseFeatures reads Eclipse features from a directory (macOS).
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

// parseEclipsePluginName parses "id_version" format.
// Example: "com.github.spotbugs.plugin.eclipse_4.9.8.r202510181643-c1fa7f2"
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

	return &model.Extension{
		ID:        pluginID,
		Name:      pluginID,
		Version:   version,
		Publisher: extractPublisher(pluginID),
		IDEType:   "eclipse",
	}
}
