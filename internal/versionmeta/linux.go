// Linux static version sources: package database, snap manifest, AppImage
// filename. Nothing here launches the tool.

package versionmeta

import (
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const (
	dpkgStatusPath = "/var/lib/dpkg/status"
	dpkgInfoDir    = "/var/lib/dpkg/info"
)

// versionFromDpkg returns the version of the Debian/Ubuntu package that owns
// one of paths. Read straight off the dpkg database, no dpkg-query.
//
// Ownership is proved from the package's own file manifest, never assumed
// from a matching name: a stale `foo` package and a hand-installed
// /usr/local/bin/foo coexist happily and their versions differ. Only packages
// named exactly `base` are considered — scanning every *.list means reading
// thousands of files.
func versionFromDpkg(exec executor.Executor, base string, paths []string) string {
	if base == "" {
		return ""
	}
	if v := dpkgVersionIfOwned(exec, dpkgInfoDir+"/"+base+".list", base, paths); v != "" {
		return v
	}

	// Multi-Arch: same records the file list as `<pkg>:<arch>.list`. Finding
	// those needs a glob over a directory holding tens of thousands of entries
	// on Ubuntu, so it only runs when the plain name missed.
	entries, err := exec.Glob(dpkgInfoDir + "/" + base + ":*.list")
	if err != nil {
		return ""
	}
	for _, manifest := range entries {
		if v := dpkgVersionIfOwned(exec, manifest, base, paths); v != "" {
			return v
		}
	}
	return ""
}

// dpkgVersionIfOwned returns pkg's version if the manifest lists one of paths.
func dpkgVersionIfOwned(exec executor.Executor, manifest, pkg string, paths []string) string {
	data, err := exec.ReadFile(manifest)
	if err != nil {
		return ""
	}
	if !dpkgManifestLists(string(data), paths) {
		return ""
	}
	return dpkgStatusVersion(exec, pkg)
}

// dpkgManifestLists reports whether a `.list` manifest (one absolute path per
// line) names any of paths. dpkg lists a packaged symlink and its target, so
// callers can pass the binary as found and its resolved form.
func dpkgManifestLists(manifest string, paths []string) bool {
	for _, line := range strings.Split(manifest, "\n") {
		line = strings.TrimRight(line, "\r")
		for _, p := range paths {
			if p != "" && line == p {
				return true
			}
		}
	}
	return false
}

// dpkgStatusVersion reads the Version field of pkg's blank-line-delimited
// stanza in /var/lib/dpkg/status. Only "installed" counts: dpkg keeps stanzas
// for purged packages, whose version describes nothing on disk.
func dpkgStatusVersion(exec executor.Executor, pkg string) string {
	data, err := exec.ReadFile(dpkgStatusPath)
	if err != nil {
		return ""
	}
	var name, version string
	var installed bool
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" { // stanza boundary
			if name == pkg && installed {
				return normalizeDebianVersion(version)
			}
			name, version, installed = "", "", false
			continue
		}
		switch {
		case strings.HasPrefix(line, "Package:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		case strings.HasPrefix(line, "Version:"):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Status:"):
			installed = strings.HasSuffix(strings.TrimSpace(line), " installed")
		}
	}
	if name == pkg && installed { // file not newline-terminated
		return normalizeDebianVersion(version)
	}
	return ""
}

// normalizeDebianVersion reduces [epoch:]upstream[-revision] to the upstream
// part, matching what the tool reports about itself: "1:0.3.31-2" -> "0.3.31".
// Per Debian policy the revision is everything after the last hyphen, so this
// is exact rather than heuristic.
func normalizeDebianVersion(v string) string {
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.LastIndex(v, "-"); i > 0 {
		v = v[:i]
	}
	if !isVersionLike(v) {
		return ""
	}
	return v
}

// versionFromAppImage extracts the version from an AppImage filename
// (LM-Studio-0.3.31-x64.AppImage -> 0.3.31). A single-file install has no
// install tree and no package entry, so the filename is the only static
// source. The segments before the version must name the tool, so a symlink
// into someone else's AppImage can't lend its version.
func versionFromAppImage(resolved, base string) string {
	segments := splitPath(resolved)
	name := segments[len(segments)-1]
	if !strings.HasSuffix(strings.ToLower(name), ".appimage") {
		return ""
	}
	stem := name[:len(name)-len(".AppImage")]

	parts := strings.Split(stem, "-")
	for i := 1; i < len(parts); i++ {
		if !isVersionLike(parts[i]) {
			continue
		}
		if matchesTool(strings.Join(parts[:i], "-"), base) {
			return strings.TrimPrefix(parts[i], "v")
		}
	}
	return ""
}

// versionFromSnap reads the version from /snap/<name>/current/meta/snap.yaml.
// The path rules can't reach it: /snap/bin/<name> symlinks to the snap
// wrapper, so resolving it walks away from the install.
//
// That path is definitionally the right snap's manifest, so unlike dpkg no
// ownership proof is needed; `name:` is checked only against the directory it
// came from. The tool name is not compared — `snap run <snap>.<app>` exposes
// apps under names that differ from the snap's own.
func versionFromSnap(exec executor.Executor, binaryPath string) string {
	segments := splitPath(binaryPath)
	if len(segments) < 3 || segments[0] != "snap" || segments[1] != "bin" {
		return ""
	}
	snapName := segments[2]
	if i := strings.Index(snapName, "."); i > 0 {
		snapName = snapName[:i]
	}
	data, err := exec.ReadFile("/snap/" + snapName + "/current/meta/snap.yaml")
	if err != nil {
		return ""
	}

	var name, version string
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "name:"):
			name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "name:")), `"'`)
		case strings.HasPrefix(line, "version:"):
			version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version:")), `"'`)
		}
	}
	if name != snapName || !isVersionLike(version) {
		return ""
	}
	return strings.TrimPrefix(version, "v")
}
