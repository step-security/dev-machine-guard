package runtimeinv

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Version sources reported in RuntimeInstall.VersionSource.
const (
	versionFromFile    = "file"
	versionFromPE      = "pe"
	versionFromPath    = "path"
	versionFromPkg     = "pkg" // OS package database (rpm/dpkg)
	versionFromUnknown = "unknown"
)

// versionResult is what a strategy found; vendor is optional.
type versionResult struct {
	version string
	vendor  string
	source  string
}

// versionStrategy inspects an install (resolved exe path and its root) and
// returns ok=false when it cannot tell.
type versionStrategy func(exec executor.Executor, exe, root string) (versionResult, bool)

// peVersion reads the version resource of a Windows executable. Replaced on
// Windows (pe_windows.go); tests may override it.
var peVersion = func(string) string { return "" }

func peVersionStrategy(_ executor.Executor, exe, _ string) (versionResult, bool) {
	v := cleanVersion(peVersion(exe))
	if v == "" {
		return versionResult{}, false
	}
	return versionResult{version: v, source: versionFromPE}, true
}

var (
	cDefineRe   = regexp.MustCompile(`(?m)^#define[ \t]+(\w+)[ \t]+"?([^"\s]+)"?`)
	keyValueRe  = regexp.MustCompile(`(?m)^(\w+)="?([^"\r\n]*)"?`)
	rbConfigRe  = regexp.MustCompile(`CONFIG\["RUBY_PROGRAM_VERSION"\]\s*=\s*"([^"]+)"`)
	rbPartRe    = regexp.MustCompile(`CONFIG\["(MAJOR|MINOR|TEENY)"\]\s*=\s*"(\d+)"`)
	numericRe   = regexp.MustCompile(`^\d+(\.\d+)*`)
	pathVerRe   = regexp.MustCompile(`(?i)^(?:[a-z]+[-_]?)?v?(\d+\.\d+(?:\.\d+){0,2})`)
	dotnetVerRe = regexp.MustCompile(`^\d+\.\d+\.\d+`)
)

func readDefines(exec executor.Executor, path string) map[string]string {
	data, err := exec.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, m := range cDefineRe.FindAllStringSubmatch(string(data), -1) {
		out[m[1]] = m[2]
	}
	return out
}

// nodeHeaderVersion reads include/node/node_version.h, which official
// tarballs, nvm, fnm, volta and brew installs all ship.
func nodeHeaderVersion(exec executor.Executor, _, root string) (versionResult, bool) {
	d := readDefines(exec, filepath.Join(root, "include", "node", "node_version.h"))
	if d["NODE_MAJOR_VERSION"] == "" || d["NODE_MINOR_VERSION"] == "" || d["NODE_PATCH_VERSION"] == "" {
		return versionResult{}, false
	}
	v := d["NODE_MAJOR_VERSION"] + "." + d["NODE_MINOR_VERSION"] + "." + d["NODE_PATCH_VERSION"]
	return versionResult{version: v, source: versionFromFile}, true
}

// pythonPatchlevelVersion reads PY_VERSION from patchlevel.h:
// include/pythonX.Y/patchlevel.h (POSIX) or include/patchlevel.h (Windows).
func pythonPatchlevelVersion(exec executor.Executor, _, root string) (versionResult, bool) {
	candidates := []string{filepath.Join(root, "include", "patchlevel.h")}
	if ents, err := exec.ReadDir(filepath.Join(root, "include")); err == nil {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "python") {
				candidates = append(candidates, filepath.Join(root, "include", e.Name(), "patchlevel.h"))
			}
		}
	}
	for _, c := range candidates {
		if v := cleanVersion(readDefines(exec, c)["PY_VERSION"]); v != "" {
			return versionResult{version: v, source: versionFromFile}, true
		}
	}
	return versionResult{}, false
}

// phpHeaderVersion reads include/php/main/php_version.h (present with dev headers).
func phpHeaderVersion(exec executor.Executor, _, root string) (versionResult, bool) {
	v := cleanVersion(readDefines(exec, filepath.Join(root, "include", "php", "main", "php_version.h"))["PHP_VERSION"])
	if v == "" {
		return versionResult{}, false
	}
	return versionResult{version: v, source: versionFromFile}, true
}

// javaReleaseVersion reads the JDK/JRE `release` file (JAVA_VERSION, IMPLEMENTOR).
func javaReleaseVersion(exec executor.Executor, _, root string) (versionResult, bool) {
	data, err := exec.ReadFile(filepath.Join(root, "release"))
	if err != nil {
		return versionResult{}, false
	}
	kv := map[string]string{}
	for _, m := range keyValueRe.FindAllStringSubmatch(string(data), -1) {
		kv[m[1]] = strings.TrimSpace(m[2])
	}
	if kv["JAVA_VERSION"] == "" {
		return versionResult{}, false
	}
	return versionResult{version: kv["JAVA_VERSION"], vendor: kv["IMPLEMENTOR"], source: versionFromFile}, true
}

// goVersionFile reads $GOROOT/VERSION ("go1.22.1" on the first line).
func goVersionFile(exec executor.Executor, _, root string) (versionResult, bool) {
	data, err := exec.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return versionResult{}, false
	}
	line, _, _ := strings.Cut(string(data), "\n")
	v := cleanVersion(strings.TrimPrefix(strings.TrimSpace(line), "go"))
	if v == "" {
		return versionResult{}, false
	}
	return versionResult{version: v, source: versionFromFile}, true
}

// rubyConfigVersion reads RUBY_PROGRAM_VERSION from lib/ruby/<abi>/<arch>/rbconfig.rb.
func rubyConfigVersion(exec executor.Executor, _, root string) (versionResult, bool) {
	libRuby := filepath.Join(root, "lib", "ruby")
	abis, err := exec.ReadDir(libRuby)
	if err != nil {
		return versionResult{}, false
	}
	for _, abi := range abis {
		if !abi.IsDir() || !numericRe.MatchString(abi.Name()) {
			continue
		}
		arches, err := exec.ReadDir(filepath.Join(libRuby, abi.Name()))
		if err != nil {
			continue
		}
		for _, arch := range arches {
			if !arch.IsDir() {
				continue
			}
			data, err := exec.ReadFile(filepath.Join(libRuby, abi.Name(), arch.Name(), "rbconfig.rb"))
			if err != nil {
				continue
			}
			if v := rubyVersionFromConfig(data); v != "" {
				return versionResult{version: v, source: versionFromFile}, true
			}
		}
	}
	return versionResult{}, false
}

// rubyVersionFromConfig reads RUBY_PROGRAM_VERSION, which some builds (rbenv,
// ruby-build) leave as "$(MAJOR).$(MINOR).$(TEENY)"; then the parts are used.
func rubyVersionFromConfig(data []byte) string {
	if m := rbConfigRe.FindSubmatch(data); m != nil && !strings.Contains(string(m[1]), "$(") {
		return string(m[1])
	}
	parts := map[string]string{}
	for _, m := range rbPartRe.FindAllSubmatch(data, -1) {
		parts[string(m[1])] = string(m[2])
	}
	if parts["MAJOR"] == "" || parts["MINOR"] == "" || parts["TEENY"] == "" {
		return ""
	}
	return parts["MAJOR"] + "." + parts["MINOR"] + "." + parts["TEENY"]
}

// pkgOwnerVersion asks the Linux package database which package owns a
// distro-installed runtime: distro builds ship no version headers unless the
// -devel package is installed. It runs rpm / dpkg-query, never the runtime.
func pkgOwnerVersion(exec executor.Executor, exe, _ string) (versionResult, bool) {
	if exec.GOOS() != "linux" || attributeSource(exe, "") != "system" {
		return versionResult{}, false
	}
	ctx := context.Background()
	const timeout = 5 * time.Second
	if out, _, code, err := exec.RunWithTimeout(ctx, timeout, "rpm", "-qf", "--queryformat", "%{VERSION}", exe); err == nil && code == 0 {
		if v := cleanVersion(out); v != "" {
			return versionResult{version: v, source: versionFromPkg}, true
		}
	}
	out, _, code, err := exec.RunWithTimeout(ctx, timeout, "dpkg-query", "-S", exe)
	if err != nil || code != 0 {
		return versionResult{}, false
	}
	pkg, _, ok := strings.Cut(strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]), ": ")
	if !ok || pkg == "" || strings.Contains(pkg, ",") { // "diversion by" / multiple owners
		return versionResult{}, false
	}
	out, _, code, err = exec.RunWithTimeout(ctx, timeout, "dpkg-query", "-W", "-f=${Version}", pkg)
	if err != nil || code != 0 {
		return versionResult{}, false
	}
	v := strings.TrimSpace(out)
	if _, after, found := strings.Cut(v, ":"); found { // drop the epoch
		v = after
	}
	if v = cleanVersion(v); v == "" {
		return versionResult{}, false
	}
	return versionResult{version: v, source: versionFromPkg}, true
}

// pathVersionStrategy takes the nearest version-looking path component between
// the executable and two levels above the install root: nvm's v18.20.0,
// Cellar/node/22.1.0, php-8.3.1-Win32-vs16-x64, jdk-21.0.2+13.
func pathVersionStrategy(_ executor.Executor, exe, root string) (versionResult, bool) {
	// A versioned executable name (python3.13, php8.2) is the most specific.
	if m := pathVerRe.FindStringSubmatch(strings.TrimSuffix(filepath.Base(exe), ".exe")); m != nil {
		return versionResult{version: m[1], source: versionFromPath}, true
	}
	stop := filepath.Dir(filepath.Dir(root))
	for d := filepath.Dir(exe); ; d = filepath.Dir(d) {
		if m := pathVerRe.FindStringSubmatch(filepath.Base(d)); m != nil {
			return versionResult{version: m[1], source: versionFromPath}, true
		}
		if d == stop || filepath.Dir(d) == d {
			break
		}
	}
	return versionResult{}, false
}

// cleanVersion keeps the leading dotted-numeric part of a version string and
// drops trailing ".0" padding PE resources add (18.20.0.0 -> 18.20.0).
func cleanVersion(v string) string {
	v = numericRe.FindString(strings.TrimSpace(v))
	for strings.Count(v, ".") > 2 && strings.HasSuffix(v, ".0") {
		v = strings.TrimSuffix(v, ".0")
	}
	return v
}

// detectVersion runs a signature's strategies in order.
func detectVersion(exec executor.Executor, sig *signature, exe, root string) versionResult {
	for _, s := range sig.versions {
		if r, ok := s(exec, exe, root); ok {
			return r
		}
	}
	return versionResult{version: "unknown", source: versionFromUnknown}
}

// dotnetRuntimeVersions lists side-by-side .NET runtimes under a dotnet root.
func dotnetRuntimeVersions(exec executor.Executor, root string) []string {
	ents, err := exec.ReadDir(filepath.Join(root, "shared", "Microsoft.NETCore.App"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && dotnetVerRe.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}
