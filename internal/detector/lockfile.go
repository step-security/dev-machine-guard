package detector

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// LockfilePackage represents a single resolved package from a lockfile.
type LockfilePackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dev     bool   `json:"dev,omitempty"`
}

// LockfileResult is the JSON structure produced when scanning via lockfile
// instead of spawning a subprocess. It is base64-encoded into
// NodeScanResult.RawStdoutBase64 so the backend can distinguish it from
// raw CLI output via the "source" field.
type LockfileResult struct {
	Source          string            `json:"source"`           // "lockfile"
	LockfileFormat  string            `json:"lockfile_format"`  // "npm-v3", "npm-v2", "npm-v1"
	LockfileVersion int               `json:"lockfile_version"` // 1, 2, or 3
	Packages        []LockfilePackage `json:"packages"`
}

// ---------- npm package-lock.json parsing ----------

// npmLockfile is the top-level structure of package-lock.json.
type npmLockfile struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPkgV3   `json:"packages"`    // v2/v3
	Dependencies    map[string]npmLockDepV1   `json:"dependencies"` // v1
}

// npmLockPkgV3 is a single entry in the v2/v3 "packages" map.
type npmLockPkgV3 struct {
	Version  string `json:"version"`
	Dev      bool   `json:"dev"`
	Optional bool   `json:"optional"`
	Link     bool   `json:"link"`
}

// npmLockDepV1 is a single entry in the v1 "dependencies" map.
type npmLockDepV1 struct {
	Version      string                    `json:"version"`
	Dev          bool                      `json:"dev"`
	Dependencies map[string]npmLockDepV1   `json:"dependencies"`
}

// ParseNPMLockfile parses a package-lock.json (or node_modules/.package-lock.json)
// and returns a flat list of resolved packages.
func ParseNPMLockfile(data []byte) (*LockfileResult, error) {
	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	// v2/v3: use the "packages" map (preferred)
	if lock.LockfileVersion >= 2 || len(lock.Packages) > 0 {
		return parseNPMLockV3(lock)
	}

	// v1: use the "dependencies" map
	if len(lock.Dependencies) > 0 {
		return parseNPMLockV1(lock)
	}

	return &LockfileResult{
		Source:          "lockfile",
		LockfileFormat:  fmt.Sprintf("npm-v%d", lock.LockfileVersion),
		LockfileVersion: lock.LockfileVersion,
		Packages:        nil,
	}, nil
}

func parseNPMLockV3(lock npmLockfile) (*LockfileResult, error) {
	var pkgs []LockfilePackage
	for key, entry := range lock.Packages {
		if key == "" {
			continue // root project entry
		}
		name := extractPackageName(key)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, LockfilePackage{
			Name:    name,
			Version: entry.Version,
			Dev:     entry.Dev,
		})
	}

	format := "npm-v3"
	if lock.LockfileVersion == 2 {
		format = "npm-v2"
	}

	return &LockfileResult{
		Source:          "lockfile",
		LockfileFormat:  format,
		LockfileVersion: lock.LockfileVersion,
		Packages:        pkgs,
	}, nil
}

// extractPackageName extracts the package name from a v2/v3 packages map key.
// Keys look like "node_modules/express" or "node_modules/express/node_modules/qs"
// or "node_modules/@scope/pkg".
func extractPackageName(key string) string {
	normalized := strings.ReplaceAll(key, "\\", "/")
	// Find the last "node_modules/" segment
	const prefix = "node_modules/"
	idx := strings.LastIndex(normalized, prefix)
	if idx < 0 {
		return ""
	}
	return normalized[idx+len(prefix):]
}

func parseNPMLockV1(lock npmLockfile) (*LockfileResult, error) {
	var pkgs []LockfilePackage
	flattenV1Deps(lock.Dependencies, &pkgs)
	return &LockfileResult{
		Source:          "lockfile",
		LockfileFormat:  "npm-v1",
		LockfileVersion: 1,
		Packages:        pkgs,
	}, nil
}

func flattenV1Deps(deps map[string]npmLockDepV1, out *[]LockfilePackage) {
	for name, dep := range deps {
		*out = append(*out, LockfilePackage{
			Name:    name,
			Version: dep.Version,
			Dev:     dep.Dev,
		})
		if len(dep.Dependencies) > 0 {
			flattenV1Deps(dep.Dependencies, out)
		}
	}
}

// ---------- npm global packages via filesystem ----------

// NPMGlobalPrefix returns the npm global prefix directory by reading ~/.npmrc,
// checking the PREFIX env var, or falling back to platform defaults.
// This avoids running "npm config get prefix" as a subprocess.
func NPMGlobalPrefix(homeDir, appDataDir, goos string, readFile func(string) ([]byte, error)) string {
	// 1. Check PREFIX env var (handled by caller if needed)

	// 2. Parse ~/.npmrc for prefix= line
	npmrcPaths := []string{homeDir + "/.npmrc"}
	for _, rc := range npmrcPaths {
		data, err := readFile(rc)
		if err != nil {
			continue
		}
		if prefix := parseNpmrcPrefix(string(data)); prefix != "" {
			return prefix
		}
	}

	// 3. Platform defaults
	switch goos {
	case "windows":
		if appDataDir != "" {
			return appDataDir + `\npm`
		}
		return ""
	default: // darwin, linux
		return "/usr/local"
	}
}

// parseNpmrcPrefix extracts the "prefix" value from .npmrc INI content.
func parseNpmrcPrefix(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "prefix=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "prefix="))
		}
		if strings.HasPrefix(line, "prefix =") {
			return strings.TrimSpace(strings.TrimPrefix(line, "prefix ="))
		}
	}
	return ""
}

// GlobalNodeModulesDir returns the path to global node_modules given a prefix.
func GlobalNodeModulesDir(prefix, goos string) string {
	switch goos {
	case "windows":
		return prefix + `\node_modules`
	default:
		return prefix + "/lib/node_modules"
	}
}

// ---------- yarn.lock v1 parsing ----------
//
// Yarn v1 lockfile uses a custom format (not JSON or YAML):
//
//   "react@^19.0.0", "react@^19.2.5":
//     version "19.2.5"
//     resolved "https://registry.yarnpkg.com/react/-/react-19.2.5.tgz#..."
//     integrity sha512-...
//     dependencies:
//       scheduler "^0.27.0"
//
// Each block starts with a non-indented header of name@range(s), followed by
// indented key-value pairs. We extract version from each block.

// ParseYarnLockV1 parses a yarn.lock v1 file and returns resolved packages.
func ParseYarnLockV1(data []byte) (*LockfileResult, error) {
	content := string(data)
	lines := strings.Split(content, "\n")

	var pkgs []LockfilePackage
	var currentName string

	for _, line := range lines {
		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Non-indented line = new block header
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			currentName = extractYarnV1PackageName(line)
			continue
		}

		// Indented line inside a block — look for "version"
		trimmed := strings.TrimSpace(line)
		if currentName != "" && strings.HasPrefix(trimmed, "version ") {
			version := strings.TrimPrefix(trimmed, "version ")
			version = strings.Trim(version, `"`)
			pkgs = append(pkgs, LockfilePackage{
				Name:    currentName,
				Version: version,
			})
			currentName = "" // only take first version per block
		}
	}

	return &LockfileResult{
		Source:          "lockfile",
		LockfileFormat:  "yarn-v1",
		LockfileVersion: 1,
		Packages:        pkgs,
	}, nil
}

// extractYarnV1PackageName extracts the package name from a yarn.lock v1 header line.
// Header formats:
//
//	"react@^19.0.0":
//	react@^19.0.0:
//	"react-dom@^19.2.5", "react-dom@^19.0.0":
//	"@babel/core@^7.0.0":
func extractYarnV1PackageName(header string) string {
	// Take the first entry (before any comma)
	if idx := strings.Index(header, ","); idx >= 0 {
		header = header[:idx]
	}
	header = strings.TrimSpace(header)
	header = strings.Trim(header, `":`)

	// Find the @ that separates name from version range
	// For scoped packages (@scope/name@range), skip the leading @
	searchFrom := 0
	if strings.HasPrefix(header, "@") {
		searchFrom = 1
	}
	atIdx := strings.Index(header[searchFrom:], "@")
	if atIdx < 0 {
		return ""
	}
	return header[:searchFrom+atIdx]
}

// ---------- pnpm-lock.yaml parsing ----------
//
// pnpm-lock.yaml (v5/v6/v9) structure:
//
//   lockfileVersion: '9.0'
//   importers:
//     .:
//       dependencies:
//         fastify:
//           specifier: ^5.8.4
//           version: 5.8.4
//   packages:
//     '@fastify/ajv-compiler@4.0.5':
//       resolution: {integrity: sha512-...}
//     fastify@5.8.4:
//       resolution: {integrity: sha512-...}
//   snapshots:
//     fastify@5.8.4:
//       dependencies:
//         ...

// pnpmLockfile is the top-level structure of pnpm-lock.yaml.
type pnpmLockfile struct {
	LockfileVersion string                       `yaml:"lockfileVersion"`
	Packages        map[string]pnpmPackageEntry  `yaml:"packages"`
	Importers       map[string]pnpmImporterEntry `yaml:"importers"`
}

type pnpmPackageEntry struct {
	Resolution map[string]string `yaml:"resolution"`
	Dev        bool              `yaml:"dev"`
}

type pnpmImporterEntry struct {
	Dependencies    map[string]pnpmDepRef `yaml:"dependencies"`
	DevDependencies map[string]pnpmDepRef `yaml:"devDependencies"`
}

type pnpmDepRef struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

// ParsePnpmLock parses a pnpm-lock.yaml file and returns resolved packages.
func ParsePnpmLock(data []byte) (*LockfileResult, error) {
	var lock pnpmLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse pnpm-lock.yaml: %w", err)
	}

	var pkgs []LockfilePackage

	// Build a set of dev dependency names from importers for tagging
	devDeps := make(map[string]bool)
	for _, imp := range lock.Importers {
		for name := range imp.DevDependencies {
			devDeps[name] = true
		}
	}

	// Parse packages map — keys are "name@version" or "@scope/name@version"
	for key := range lock.Packages {
		name, version := parsePnpmPackageKey(key)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, LockfilePackage{
			Name:    name,
			Version: version,
			Dev:     devDeps[name],
		})
	}

	// Determine lockfile version number
	lockVer := 0
	if strings.HasPrefix(lock.LockfileVersion, "9") {
		lockVer = 9
	} else if strings.HasPrefix(lock.LockfileVersion, "6") {
		lockVer = 6
	} else if strings.HasPrefix(lock.LockfileVersion, "5") {
		lockVer = 5
	}

	return &LockfileResult{
		Source:          "lockfile",
		LockfileFormat:  fmt.Sprintf("pnpm-v%s", lock.LockfileVersion),
		LockfileVersion: lockVer,
		Packages:        pkgs,
	}, nil
}

// parsePnpmPackageKey extracts name and version from a pnpm packages key.
// Keys look like "express@4.18.2" or "@fastify/ajv-compiler@4.0.5"
// or "/express@4.18.2" (older lockfile versions use leading slash).
func parsePnpmPackageKey(key string) (name, version string) {
	// Strip leading slash (pnpm v5/v6 format)
	key = strings.TrimPrefix(key, "/")

	// For scoped packages: @scope/name@version
	// Find the last @ that separates name from version
	if strings.HasPrefix(key, "@") {
		// Scoped package: find @ after the first /
		slashIdx := strings.Index(key, "/")
		if slashIdx < 0 {
			return "", ""
		}
		atIdx := strings.LastIndex(key[slashIdx:], "@")
		if atIdx < 0 {
			return "", ""
		}
		atIdx += slashIdx
		return key[:atIdx], key[atIdx+1:]
	}

	// Unscoped package: name@version
	atIdx := strings.LastIndex(key, "@")
	if atIdx <= 0 {
		return "", ""
	}
	return key[:atIdx], key[atIdx+1:]
}
