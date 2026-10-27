// Package runtimeinv inventories language runtime installs (node, python,
// php, java, go, ruby, deno, bun, dotnet) on disk, independent of how they
// were installed: version managers, package managers, installers, zips and
// runtimes bundled inside other apps. Discovered binaries are never executed;
// versions come from files the install ships, the PE version resource, or the
// install path.
package runtimeinv

import (
	"regexp"
	"strings"
)

// signature describes one runtime: which executable names identify it and
// which version strategies apply, in order of preference.
type signature struct {
	runtime  string
	matches  func(name string) bool // lowercased base name, ".exe" stripped
	versions []versionStrategy
}

var (
	pythonExeRe = regexp.MustCompile(`^python([23](\.\d+)?)?$`)
	phpExeRe    = regexp.MustCompile(`^php(\d+(\.\d+)?)?$`)
	// Distros install versioned binaries behind the plain name: Fedora's
	// node -> node-22, ruby (a wrapper script) -> ruby-mri.
	nodeExeRe = regexp.MustCompile(`^node(js)?(-?\d+(\.\d+)*)?$`)
	rubyExeRe = regexp.MustCompile(`^ruby(-mri|-?\d+(\.\d+)*)?$`)
)

func exact(names ...string) func(string) bool {
	return func(n string) bool {
		for _, want := range names {
			if n == want {
				return true
			}
		}
		return false
	}
}

// signatures is the runtime table. Adding a runtime means adding a row here
// (plus a version reader if it ships a version file).
var signatures = []signature{
	{runtime: "node", matches: nodeExeRe.MatchString, versions: []versionStrategy{nodeHeaderVersion, peVersionStrategy, pkgOwnerVersion, embeddedVersion(nodeEmbeddedRe), pathVersionStrategy}},
	{runtime: "python", matches: pythonExeRe.MatchString, versions: []versionStrategy{pythonPatchlevelVersion, peVersionStrategy, pkgOwnerVersion, pathVersionStrategy}},
	{runtime: "php", matches: phpExeRe.MatchString, versions: []versionStrategy{phpHeaderVersion, peVersionStrategy, pkgOwnerVersion, pathVersionStrategy}},
	{runtime: "java", matches: exact("java"), versions: []versionStrategy{javaReleaseVersion, peVersionStrategy, pkgOwnerVersion, pathVersionStrategy}},
	{runtime: "go", matches: exact("go"), versions: []versionStrategy{goVersionFile, pkgOwnerVersion, pathVersionStrategy}},
	{runtime: "ruby", matches: rubyExeRe.MatchString, versions: []versionStrategy{rubyConfigVersion, peVersionStrategy, pkgOwnerVersion, pathVersionStrategy}},
	{runtime: "deno", matches: exact("deno"), versions: []versionStrategy{peVersionStrategy, embeddedVersion(denoEmbeddedRe), pathVersionStrategy}},
	{runtime: "bun", matches: exact("bun"), versions: []versionStrategy{peVersionStrategy, embeddedVersion(bunEmbeddedRe), pathVersionStrategy}},
	// dotnet is one host binary serving several side-by-side runtimes; the
	// scanner expands it to one record per shared/Microsoft.NETCore.App/<v>.
	{runtime: "dotnet", matches: exact("dotnet")},
}

// matchSignature returns the signature for a directory entry name, or nil.
// On Windows only .exe files are considered.
func matchSignature(name, goos string) *signature {
	// Names are case-sensitive except on Windows: on macOS the framework
	// library "Python" must not match the "python" interpreter.
	n := name
	if goos == "windows" {
		n = strings.ToLower(n)
		if !strings.HasSuffix(n, ".exe") {
			return nil
		}
		n = strings.TrimSuffix(n, ".exe")
	}
	for i := range signatures {
		if signatures[i].matches(n) {
			return &signatures[i]
		}
	}
	return nil
}
