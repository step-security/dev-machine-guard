package detector

import (
	"encoding/json"
	"fmt"
	"strings"
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
