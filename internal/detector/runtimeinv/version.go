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
type versionStrategy func(ctx context.Context, exec executor.Executor, exe, root string) (versionResult, bool)

// peVersion reads the version resource of a Windows executable. Replaced on
// Windows (pe_windows.go); tests may override it.
var peVersion = func(string) string { return "" }

func peVersionStrategy(_ context.Context, _ executor.Executor, exe, _ string) (versionResult, bool) {
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
	return definesFrom(data)
}

func definesFrom(data []byte) map[string]string {
	out := map[string]string{}
	for _, m := range cDefineRe.FindAllStringSubmatch(string(data), -1) {
		out[m[1]] = m[2]
	}
	return out
}

// nodeHeaderVersion reads include/node/node_version.h, which official
// tarballs, nvm, fnm, volta and brew installs all ship.
func nodeHeaderVersion(_ context.Context, exec executor.Executor, _, root string) (versionResult, bool) {
	d := readDefines(exec, filepath.Join(root, "include", "node", "node_version.h"))
	if d["NODE_MAJOR_VERSION"] == "" || d["NODE_MINOR_VERSION"] == "" || d["NODE_PATCH_VERSION"] == "" {
		return versionResult{}, false
	}
	v := d["NODE_MAJOR_VERSION"] + "." + d["NODE_MINOR_VERSION"] + "." + d["NODE_PATCH_VERSION"]
	return versionResult{version: v, source: versionFromFile}, true
}

// pythonPatchlevelVersion reads PY_VERSION from patchlevel.h:
// include/pythonX.Y/patchlevel.h (POSIX) or include/patchlevel.h (Windows).
func pythonPatchlevelVersion(_ context.Context, exec executor.Executor, exe, root string) (versionResult, bool) {
	// Windows layout: one interpreter per install root.
	if v := cleanVersion(readDefines(exec, filepath.Join(root, "include", "patchlevel.h"))["PY_VERSION"]); v != "" {
		return versionResult{version: v, source: versionFromFile}, true
	}
	// POSIX: include/pythonX.Y[suffix]/. A shared prefix (/usr) can hold
	// several, so use the one matching the interpreter's ABI; with no ABI in
	// the name, only an unambiguous single header is trusted.
	ents, err := exec.ReadDir(filepath.Join(root, "include"))
	if err != nil {
		return versionResult{}, false
	}
	abi := exeABI(exe, pythonABIRe)
	var match []string
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, "python") {
			continue
		}
		if abi == "" || strings.TrimRight(strings.TrimPrefix(n, "python"), "abcdefghijklmnopqrstuvwxyz") == abi {
			match = append(match, filepath.Join(root, "include", n, "patchlevel.h"))
		}
	}
	return singleVersion(exec, match, func(data []byte) string {
		return cleanVersion(definesFrom(data)["PY_VERSION"])
	})
}

// phpHeaderVersion reads include/php/main/php_version.h (present with dev headers).
func phpHeaderVersion(_ context.Context, exec executor.Executor, _, root string) (versionResult, bool) {
	v := cleanVersion(readDefines(exec, filepath.Join(root, "include", "php", "main", "php_version.h"))["PHP_VERSION"])
	if v == "" {
		return versionResult{}, false
	}
	return versionResult{version: v, source: versionFromFile}, true
}

// javaReleaseVersion reads the JDK/JRE `release` file (JAVA_VERSION, IMPLEMENTOR).
func javaReleaseVersion(_ context.Context, exec executor.Executor, _, root string) (versionResult, bool) {
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
func goVersionFile(_ context.Context, exec executor.Executor, _, root string) (versionResult, bool) {
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
func rubyConfigVersion(_ context.Context, exec executor.Executor, exe, root string) (versionResult, bool) {
	// lib/ruby/<X.Y.0>/<arch>/rbconfig.rb. A shared prefix can hold several
	// ABIs: use the one matching the executable (ruby3.3), else only an
	// unambiguous single config.
	libRuby := filepath.Join(root, "lib", "ruby")
	abis, err := exec.ReadDir(libRuby)
	if err != nil {
		return versionResult{}, false
	}
	want := exeABI(exe, rubyABIRe)
	var match []string
	for _, abi := range abis {
		if !abi.IsDir() || !numericRe.MatchString(abi.Name()) {
			continue
		}
		if want != "" && !strings.HasPrefix(abi.Name(), want+".") {
			continue
		}
		arches, err := exec.ReadDir(filepath.Join(libRuby, abi.Name()))
		if err != nil {
			continue
		}
		for _, arch := range arches {
			if arch.IsDir() {
				match = append(match, filepath.Join(libRuby, abi.Name(), arch.Name(), "rbconfig.rb"))
			}
		}
	}
	return singleVersion(exec, match, rubyVersionFromConfig)
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
func pkgOwnerVersion(ctx context.Context, exec executor.Executor, exe, _ string) (versionResult, bool) {
	if exec.GOOS() != "linux" || attributeSource(exe, "") != "system" {
		return versionResult{}, false
	}
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
func pathVersionStrategy(_ context.Context, _ executor.Executor, exe, root string) (versionResult, bool) {
	// Nearest version-looking directory between the exe and two levels above
	// the root: nvm's v18.20.8, Cellar/node/22.1.0, php-8.3.1-Win32, jdk-21.0.2+13.
	dirVer := ""
	stop := filepath.Dir(filepath.Dir(root))
	for d := filepath.Dir(exe); ; d = filepath.Dir(d) {
		if m := pathVerRe.FindStringSubmatch(filepath.Base(d)); m != nil {
			dirVer = m[1]
			break
		}
		if d == stop || filepath.Dir(d) == d {
			break
		}
	}
	// A versioned exe name (python3.12, php8.2) pins major.minor. Prefer the
	// directory's version when it agrees and is more precise (.../3.12.9/bin/python3.12).
	exeVer := ""
	if m := pathVerRe.FindStringSubmatch(strings.TrimSuffix(filepath.Base(exe), ".exe")); m != nil {
		exeVer = m[1]
	}
	switch {
	case dirVer != "" && (exeVer == "" || dirVer == exeVer || strings.HasPrefix(dirVer, exeVer+".")):
		return versionResult{version: dirVer, source: versionFromPath}, true
	case exeVer != "":
		return versionResult{version: exeVer, source: versionFromPath}, true
	}
	return versionResult{}, false
}

var (
	pythonABIRe = regexp.MustCompile(`^python(\d+\.\d+)`)
	rubyABIRe   = regexp.MustCompile(`^ruby-?(\d+\.\d+)`)
)

// exeABI extracts major.minor from a versioned executable name (python3.12,
// ruby3.3); "" when the name carries none (python3, ruby, ruby-mri).
func exeABI(exe string, re *regexp.Regexp) string {
	if m := re.FindStringSubmatch(strings.TrimSuffix(filepath.Base(exe), ".exe")); m != nil {
		return m[1]
	}
	return ""
}

// singleVersion reads the candidate files and returns a version only when
// exactly one distinct version is found: with several installs sharing a
// prefix and no way to tell which is this one, it defers to the next
// strategy (package DB, path) rather than guess.
func singleVersion(exec executor.Executor, paths []string, parse func([]byte) string) (versionResult, bool) {
	found := ""
	for _, p := range paths {
		data, err := exec.ReadFile(p)
		if err != nil {
			continue
		}
		v := parse(data)
		if v == "" {
			continue
		}
		if found != "" && found != v {
			return versionResult{}, false
		}
		found = v
	}
	if found == "" {
		return versionResult{}, false
	}
	return versionResult{version: found, source: versionFromFile}, true
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
func detectVersion(ctx context.Context, exec executor.Executor, sig *signature, exe, root string) versionResult {
	for _, s := range sig.versions {
		if ctx.Err() != nil {
			break
		}
		if r, ok := s(ctx, exec, exe, root); ok {
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
