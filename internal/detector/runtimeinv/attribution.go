package runtimeinv

import (
	"regexp"
	"strings"
)

// normPath lowercases and forward-slashes a path and wraps it in slashes so
// rules can match whole components on every OS ("/cellar/").
func normPath(p string) string {
	return "/" + strings.Trim(strings.ToLower(strings.ReplaceAll(p, `\`, "/")), "/") + "/"
}

// sourceRules map a path fragment to the tool that installed the runtime.
// First match wins, so more specific fragments come first.
var sourceRules = []struct{ fragment, source string }{
	{"/.nvm/versions/", "nvm"},
	{"/appdata/roaming/nvm/", "nvm"}, // nvm-windows default root
	{"/fnm/node-versions/", "fnm"},
	{"/volta/tools/image/", "volta"},
	{"/.volta/tools/image/", "volta"}, // ~/.volta on Linux/macOS
	{"/n/versions/", "n"},
	{"/nodist/", "nodist"},
	{"/pnpm/nodejs/", "pnpm"},
	{"/.asdf/installs/", "asdf"},
	{"/mise/installs/", "mise"},
	{"/.pyenv/versions/", "pyenv"},
	{"/pyenv-win/versions/", "pyenv"},
	{"/uv/python/", "uv"},
	{"/.rye/", "rye"},
	{"/miniconda", "conda"},
	{"/anaconda", "conda"},
	{"/miniforge", "conda"},
	{"/mambaforge", "conda"},
	{"/.sdkman/candidates/", "sdkman"},
	{"/.rbenv/versions/", "rbenv"},
	{"/.rvm/rubies/", "rvm"},
	{"/.goenv/versions/", "goenv"},
	{"/golang.org/toolchain@", "go-toolchain"},
	{"/sdk/go1.", "go-dl"}, // golang.org/dl downloads (~/sdk/go1.x)
	{"/.dotnet/", "dotnet-install"},
	{"/cellar/", "brew"},
	{"/caskroom/", "brew"},
	{"/opt/homebrew/", "brew"},
	{"/home/linuxbrew/", "brew"},
	{"/scoop/apps/", "scoop"},
	{"/chocolatey/", "choco"},
	{"/winget/packages/", "winget"},
	{"/xampp/", "xampp"},
	{"/wamp64/", "wamp"},
	{"/wamp/", "wamp"},
	{"/laragon/", "laragon"},
	{"/snap/", "snap"},
	{"/library/developer/commandlinetools/", "xcode-clt"},
}

// systemPrefixes are distro / OS owned locations (package-managed on Linux).
var systemPrefixes = []string{"/usr/bin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/usr/share/", "/bin/", "/system/"}

// installerFragments are locations official installers write to.
var installerFragments = []string{
	"/library/java/javavirtualmachines/",
	"/library/frameworks/python.framework/",
	"/program files/",
	"/program files (x86)/",
	"/appdata/local/programs/",
	"/.jdks/",
}

// attributeSource names the installer of a runtime from its resolved path.
// nvmHome is NVM_HOME (nvm-windows custom root), may be empty.
func attributeSource(realPath, nvmHome string) string {
	p := normPath(realPath)
	if nvmHome != "" && strings.HasPrefix(p, normPath(nvmHome)) {
		return "nvm"
	}
	for _, r := range sourceRules {
		if strings.Contains(p, r.fragment) {
			return r.source
		}
	}
	for _, pre := range systemPrefixes {
		if strings.HasPrefix(p, pre) {
			return "system"
		}
	}
	for _, f := range installerFragments {
		if strings.Contains(p, f) {
			return "installer"
		}
	}
	return "manual"
}

var (
	appBundleRe  = regexp.MustCompile(`(?i)[/\\]([^/\\]+)\.app[/\\]contents[/\\]`)
	editorExtRe  = regexp.MustCompile(`(?i)[/\\]\.(vscode|vscode-insiders|cursor|windsurf|kiro)[^/\\]*[/\\]extensions[/\\]([^/\\]+)[/\\]`)
	remoteSrvRe  = regexp.MustCompile(`(?i)[/\\]\.(vscode-server|vscode-server-insiders|cursor-server|windsurf-server)[/\\]`)
	jbrRe        = regexp.MustCompile(`(?i)[/\\]([^/\\]+)[/\\]jbr[/\\]`)
	vsNodeRe     = regexp.MustCompile(`(?i)[/\\]microsoft visual studio[/\\]`)
	adobeRe      = regexp.MustCompile(`(?i)[/\\]adobe[/\\]`)
	electronRe   = regexp.MustCompile(`(?i)[/\\]([^/\\]+)[/\\]resources[/\\]app(?:\.asar\.unpacked)?[/\\]`)
	eclipseJreRe = regexp.MustCompile(`(?i)[/\\]plugins[/\\]org\.eclipse\.justj\.`)
)

// launcherDirs are version-manager shim directories: everything in them
// selects a runtime rather than being one. On Windows shims are copies of a
// launcher exe, so they cannot be told apart from runtimes by content.
var launcherDirs = []string{
	"/scoop/shims/", "/chocolatey/bin/", "/program files/volta/", "/volta/bin/", "/.volta/bin/",
	"/.pyenv/shims/", "/pyenv-win/shims/", "/.rbenv/shims/", "/.asdf/shims/", "/mise/shims/", "/nodist/bin/",
}

// inLauncherDir reports a path directly inside a launcher directory.
func inLauncherDir(realPath string) bool {
	dir := normPath(realPath[:max(0, strings.LastIndexAny(realPath, `/\`))])
	for _, d := range launcherDirs {
		if strings.HasSuffix(dir, d) {
			return true
		}
	}
	return false
}

// bundledBy names the application that privately ships this runtime, or ""
// for a standalone install. Bundled runtimes are inventoried but are not
// installs a developer manages.
func bundledBy(realPath string) string {
	if m := appBundleRe.FindStringSubmatch(realPath); m != nil {
		return m[1]
	}
	if m := remoteSrvRe.FindStringSubmatch(realPath); m != nil {
		return m[1]
	}
	if m := editorExtRe.FindStringSubmatch(realPath); m != nil {
		return m[1] + " extension " + m[2]
	}
	if m := jbrRe.FindStringSubmatch(realPath); m != nil {
		return m[1]
	}
	if vsNodeRe.MatchString(realPath) {
		return "Visual Studio"
	}
	if adobeRe.MatchString(realPath) {
		return "Adobe"
	}
	if m := electronRe.FindStringSubmatch(realPath); m != nil {
		return m[1]
	}
	if eclipseJreRe.MatchString(realPath) {
		return "Eclipse"
	}
	return ""
}
