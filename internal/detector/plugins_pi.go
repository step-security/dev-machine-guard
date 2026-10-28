package detector

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Pi coding agent packages and extensions. Pi loads code from saved package
// selections (npm, Git, local) and from entrypoints in its extensions
// directories; a package can also bundle skills, prompt templates and themes.
// Selection follows Pi's own resolution rules, ported here as reads of
// settings, manifests and directory listings. No package manager, Git or Pi
// command is run, and extension code is never read.

// piKinds are Pi's resource kinds, spelled as its settings and manifest keys.
var piKinds = []string{"extensions", "skills", "prompts", "themes"}

var piComponentKinds = map[string]string{
	"extensions": model.PluginComponentExtension,
	"skills":     model.PluginComponentSkill,
	"prompts":    model.PluginComponentPrompt,
	"themes":     model.PluginComponentTheme,
}

var piResourceSuffixes = map[string][]string{
	"extensions": {".ts", ".js"},
	"skills":     {".md"},
	"prompts":    {".md"},
	"themes":     {".json"},
}

var utf8BOM = []byte("\xef\xbb\xbf")

// piAgentRoot is Pi's agent directory for the scanned user: an absolute
// PI_CODING_AGENT_DIR, else ~/.pi/agent. ok is false when an override exists
// that this process cannot resolve; the default is still returned for callers
// that keep their earlier behavior in that case.
func piAgentRoot(exec executor.Executor, home string) (root string, ok bool) {
	root = filepath.Join(home, ".pi", "agent")
	if executor.UserEnvironmentError(exec) != nil {
		return root, false
	}
	dir := exec.Getenv("PI_CODING_AGENT_DIR")
	if dir == "" {
		return root, true
	}
	// A relative override resolves against Pi's working directory, which is unknown here.
	if dir, ok = piNormalizePath(dir, home, exec.GOOS()); !ok || !filepath.IsAbs(dir) {
		return root, false
	}
	return filepath.Clean(dir), true
}

var piShellDriveRE = regexp.MustCompile(`(?i)^/(?:mnt/|cygdrive/)?([a-z])(?:/(.*))?$`)

// piNormalizePath applies Pi's path spellings: Git Bash, Cygwin and WSL drive
// paths on Windows, a leading ~ for the scanned user's home, and file:// URLs.
func piNormalizePath(p, home, goos string) (string, bool) {
	win := goos == model.PlatformWindows
	if win && strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.Contains(p, `\`) {
		if m := piShellDriveRE.FindStringSubmatch(p); m != nil {
			p = strings.ToUpper(m[1]) + `:\` + strings.ReplaceAll(m[2], "/", `\`)
		}
	}
	switch {
	case p == "~":
		return home, true
	case strings.HasPrefix(p, "~/") || win && strings.HasPrefix(p, `~\`):
		return filepath.Join(home, p[2:]), true
	case strings.HasPrefix(p, "file://"):
		u, err := url.Parse(p)
		if err != nil {
			return "", false
		}
		remote := u.Host != "" && u.Host != "localhost"
		if !win {
			return u.Path, !remote
		}
		if remote {
			return `\\` + u.Host + strings.ReplaceAll(u.Path, "/", `\`), true
		}
		file := u.Path
		if len(file) < 3 || file[0] != '/' || file[2] != ':' {
			return "", false
		}
		return strings.ReplaceAll(file[1:], "/", `\`), true
	}
	return p, true
}

// piResolvePath resolves a saved selection against its settings base directory.
func piResolvePath(p, base, home, goos string) (string, bool) {
	p, ok := piNormalizePath(strings.TrimSpace(p), home, goos)
	if !ok || p == "" {
		return "", false
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p), true
	}
	return filepath.Join(base, p), true
}

// piTildeFilters reports whether version is known to expand ~ in resource
// filters, which Pi does from 1.2.
func piTildeFilters(version string) bool {
	v, pre, ok := parseSemver(strings.TrimPrefix(strings.TrimSpace(version), "v"))
	if !ok {
		return false
	}
	return v[0] > 1 || v[0] == 1 && v[1] >= 2 && !(v[1] == 2 && v[2] == 0 && pre != "")
}

// ---------------------------------------------------------------------------
// Settings and sources
// ---------------------------------------------------------------------------

// piLayer is one settings.json: the user's agent settings or one project's
// .pi/settings.json. Relative selections resolve against base.
type piLayer struct {
	scope, project, path, base string
	failed                     bool
	packages                   []piPackage
	extensions                 []string
	extensionsOK               bool
}

// piPackage is one saved package entry. The object form can narrow each kind
// with patterns; a kind absent from filters keeps the package's own selection.
type piPackage struct {
	source   string
	object   bool
	noAuto   bool // autoload:false — only the listed patterns load
	filters  map[string][]string
	position int
}

// piSource is a parsed package source.
type piSource struct {
	kind              string // model.PluginSourceNPM | PluginSourceGit | PluginSourceLocal
	name, version     string // npm
	repo, host, path  string // git
	ref               string // git
	local             string // as written
	identity, display string
}

func (a *piAdapter) layer(scope, project, file, base string) *piLayer {
	l := &piLayer{scope: scope, project: project, path: file, base: base, extensionsOK: true}
	data, absent, code := a.s.readMetadata(a.gd, file)
	if absent {
		return l
	}
	if code != "" {
		l.failed = true
		a.fail(code, file)
		return l
	}
	// Pi treats an empty file as empty settings.
	if len(data) == 0 {
		return l
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(bytes.TrimPrefix(data, utf8BOM), &doc) != nil || doc == nil {
		l.failed = true
		a.fail(model.AgentScanErrParseFailed, file)
		return l
	}
	if raw, ok := doc["packages"]; ok && string(raw) != "null" {
		var rows []json.RawMessage
		if json.Unmarshal(raw, &rows) != nil {
			a.fail(model.AgentScanErrParseFailed, file)
		}
		for i, row := range rows {
			if pkg, ok := piDecodePackage(row); ok {
				pkg.position = i
				l.packages = append(l.packages, pkg)
			} else {
				a.fail(model.AgentScanErrParseFailed, file)
			}
		}
	}
	if raw, ok := doc["extensions"]; ok && string(raw) != "null" {
		if json.Unmarshal(raw, &l.extensions) != nil {
			l.extensions, l.extensionsOK = nil, false
			a.fail(model.AgentScanErrParseFailed, file)
		}
	}
	return l
}

func piDecodePackage(raw json.RawMessage) (piPackage, bool) {
	var source string
	if json.Unmarshal(raw, &source) == nil {
		return piPackage{source: source}, source != ""
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil || json.Unmarshal(obj["source"], &source) != nil || source == "" {
		return piPackage{}, false
	}
	pkg := piPackage{source: source, object: true, filters: map[string][]string{}}
	if auto := jsonBool(obj["autoload"]); auto != nil && !*auto {
		pkg.noAuto = true
	}
	for _, kind := range piKinds {
		value, ok := obj[kind]
		if !ok || string(value) == "null" {
			continue
		}
		patterns := []string{}
		if json.Unmarshal(value, &patterns) != nil {
			return piPackage{}, false
		}
		pkg.filters[kind] = patterns
	}
	return pkg, true
}

var piNPMSpecRE = regexp.MustCompile(`^(@?[^@]+(?:/[^@]+)?)(?:@(.+))?$`)

// parsePiSource classifies a saved package source the way Pi does. identity is
// Pi's own package identity: the npm name, the Git host and path without a ref,
// or the resolved local path.
func (a *piAdapter) parsePiSource(source string, l *piLayer) (piSource, bool) {
	if spec, ok := strings.CutPrefix(source, "npm:"); ok {
		spec = strings.TrimSpace(spec)
		src := piSource{kind: model.PluginSourceNPM, name: spec}
		if m := piNPMSpecRE.FindStringSubmatch(spec); m != nil {
			src.name, src.version = m[1], m[2]
		}
		src.identity, src.display = "npm:"+src.name, src.name
		return src, src.name != ""
	}
	if !piLocalSource(source) {
		if src, ok := parsePiGitSource(source); ok {
			return src, true
		}
	}
	resolved, ok := piResolvePath(source, l.base, a.s.home, a.s.goos)
	if !ok {
		return piSource{}, false
	}
	return piSource{kind: model.PluginSourceLocal, local: resolved, identity: "local:" + resolved, display: filepath.Base(resolved)}, true
}

// piBuiltin reports a selection of an extension that ships inside Pi itself.
func piBuiltin(source string) bool { return strings.HasPrefix(strings.TrimSpace(source), "builtin:") }

func piLocalSource(source string) bool {
	source = strings.TrimSpace(source)
	for _, prefix := range []string{"npm:", "git:", "github:", "http:", "https:", "ssh:", "builtin:"} {
		if strings.HasPrefix(source, prefix) {
			return false
		}
	}
	return true
}

var (
	piSCPRE       = regexp.MustCompile(`^git@([^:]+):(.+)$`)
	piHostedRE    = regexp.MustCompile(`^(github|gitlab|bitbucket):([^/#]+/[^#]+)(?:#(.*))?$`)
	piShorthandRE = regexp.MustCompile(`^[^:@%/\s.-][^:@%/\s]*/[^:@\s/%#]+(?:#(.*))?$`)
	piHostedHosts = map[string]string{"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}
)

// parsePiGitSource parses a Git package source: git: accepts shorthand and
// any URL form, while an unprefixed source needs an explicit protocol.
func parsePiGitSource(source string) (piSource, bool) {
	trimmed := strings.TrimSpace(source)
	raw, prefixed := strings.CutPrefix(trimmed, "git:")
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	if !prefixed && !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "ssh://") && !strings.HasPrefix(lower, "git://") {
		return piSource{}, false
	}
	if prefixed {
		if m := piHostedRE.FindStringSubmatch(raw); m != nil {
			repo, ref := piSplitRef(m[2])
			if m[3] != "" {
				ref = m[3]
			}
			return piBuildGitSource("https://"+piHostedHosts[m[1]]+"/"+repo, piHostedHosts[m[1]], repo, ref)
		}
		if m := piShorthandRE.FindStringSubmatch(raw); m != nil && !strings.Contains(strings.SplitN(raw, "/", 2)[0], ".") {
			repo, ref := piSplitRef(strings.SplitN(raw, "#", 2)[0])
			if m[1] != "" {
				ref = m[1]
			}
			return piBuildGitSource("https://github.com/"+repo, "github.com", repo, ref)
		}
	}
	repo, ref := piSplitRef(raw)
	if m := piSCPRE.FindStringSubmatch(repo); m != nil {
		return piBuildGitSource(repo, m[1], m[2], ref)
	}
	if strings.Contains(repo, "://") {
		u, err := url.Parse(repo)
		if err != nil {
			return piSource{}, false
		}
		return piBuildGitSource(repo, u.Hostname(), strings.TrimLeft(u.Path, "/"), ref)
	}
	host, repoPath, ok := strings.Cut(repo, "/")
	if !ok || !strings.Contains(host, ".") && host != "localhost" {
		return piSource{}, false
	}
	return piBuildGitSource("https://"+repo, host, repoPath, ref)
}

// piSplitRef separates a trailing @ref from a repository path.
func piSplitRef(repo string) (string, string) {
	if m := piSCPRE.FindStringSubmatch(repo); m != nil {
		if p, ref, ok := strings.Cut(m[2], "@"); ok && p != "" && ref != "" {
			return "git@" + m[1] + ":" + p, ref
		}
		return repo, ""
	}
	if strings.Contains(repo, "://") {
		u, err := url.Parse(repo)
		if err != nil {
			return repo, ""
		}
		if p, ref, ok := strings.Cut(strings.TrimLeft(u.Path, "/"), "@"); ok && p != "" && ref != "" {
			u.Path = "/" + p
			return strings.TrimSuffix(u.String(), "/"), ref
		}
		return repo, ""
	}
	host, rest, ok := strings.Cut(repo, "/")
	if !ok {
		return repo, ""
	}
	if p, ref, ok := strings.Cut(rest, "@"); ok && p != "" && ref != "" {
		return host + "/" + p, ref
	}
	return repo, ""
}

func piBuildGitSource(repo, host, repoPath, ref string) (piSource, bool) {
	if strings.HasPrefix(repoPath, "/") {
		return piSource{}, false
	}
	repoPath = strings.TrimLeft(strings.TrimSuffix(repoPath, ".git"), "/")
	if host == "" || len(strings.Split(repoPath, "/")) < 2 || piUnsafeGitPart(host, false) || piUnsafeGitPart(repoPath, true) {
		return piSource{}, false
	}
	return piSource{kind: model.PluginSourceGit, repo: repo, host: host, path: repoPath, ref: ref, identity: "git:" + host + "/" + repoPath, display: host + "/" + repoPath}, true
}

func piUnsafeGitPart(value string, allowSlash bool) bool {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return true
	}
	for _, v := range []string{value, decoded} {
		if strings.ContainsAny(v, "\x00\\") || strings.HasPrefix(v, "/") || !allowSlash && strings.Contains(v, "/") {
			return true
		}
		for seg := range strings.SplitSeq(v, "/") {
			if seg == ".." {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

type piAdapter struct {
	s       *pluginScan
	gd      *SkillsDetector
	root    string
	c       *model.AgentPluginContext
	tildeOK bool
	parents []*piParent
	byPath  map[string]*piParent
	claimed map[string]bool
	users   map[string]*piParent
	skills  map[string]skillMeta
}

// piParent is one installation and its selected resources before it is added.
type piParent struct {
	p        *model.PluginObservation
	root     string // payload directory components are relative to
	manifest string // package.json that declares external targets
	index    map[string]int
}

// piResource is one selected resource file. pointer is the manifest
// declaration that selected a file outside the payload directory.
type piResource struct {
	kind, file, pointer string
	enabled             *bool
	stated              bool
}

func (s *pluginScan) detectPi() *model.AgentPluginContext {
	root, ok := piAgentRoot(s.d.exec, s.home)
	if !ok {
		return s.unresolvedContext(model.AgentPi, root, root)
	}
	gd := s.guarded(root)
	state, _, _ := s.stat(gd, root)
	if state != fileDir && state != fileAbsent {
		return s.unresolvedContext(model.AgentPi, root, root)
	}
	a := &piAdapter{s: s, gd: gd, root: root, tildeOK: piTildeFilters(s.d.agentVersions[model.AgentPi])}
	restore := s.snapshotRetry()
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			restore()
		}
		s.reads = map[string]pluginMetadataStamp{}
		s.sourceChanged = false
		a.c = s.newContext(model.AgentPi, root, root)
		a.run()
		if !s.snapshotChanged() {
			break
		}
		if attempt == 1 {
			a.fail(model.AgentScanErrSourceChanged, filepath.Join(root, "settings.json"))
			for i := range a.c.Plugins {
				degrade(&a.c.Plugins[i].ComponentStatus, model.AgentScanStatusPartial)
			}
			break
		}
	}
	if state == fileAbsent && len(a.c.Plugins) == 0 && len(a.c.Errors) == 0 {
		return nil
	}
	return a.c
}

func (a *piAdapter) fail(code, file string) {
	degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
	scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: file})
}

func piPartial(p *model.PluginObservation, code, file string) {
	degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
	scanError(&p.Errors, model.AgentScanError{Code: code, SourcePath: file, InstanceID: p.InstanceID})
}

// run inventories user selections first so a project's autoload:false entry
// can annotate the user installation it narrows. Configured selections precede
// automatic discovery at each scope, as in Pi, so a payload found both ways is
// one installation.
func (a *piAdapter) run() {
	a.parents, a.byPath, a.claimed, a.users, a.skills = nil, map[string]*piParent{}, map[string]bool{}, map[string]*piParent{}, map[string]skillMeta{}
	layers := []*piLayer{a.layer(model.PluginScopeUser, "", filepath.Join(a.root, "settings.json"), a.root)}
	for _, project := range a.s.projects {
		dir := filepath.Join(project, ".pi")
		layers = append(layers, a.layer(model.PluginScopeProject, project, filepath.Join(dir, "settings.json"), dir))
	}
	for _, l := range layers {
		for _, pkg := range l.packages {
			if len(a.parents) >= maxPluginObs || a.s.ctx.Err() != nil {
				a.fail(model.AgentScanErrLimitExceeded, l.path)
				break
			}
			a.addPackage(l, pkg, layers[0])
		}
		a.savedExtensions(l)
		a.autoExtensions(l)
	}
	for _, pp := range a.parents {
		a.s.addPlugin(a.c, pp.p)
	}
}

// parentKey identifies a physical payload, so a saved alias and the automatic
// discovery of its target are one installation per scope.
func (a *piAdapter) parentKey(scope, project, source string) string {
	if real, err := a.gd.exec.EvalSymlinks(source); err == nil && real != "" {
		source = real
	}
	return scope + "\x00" + a.s.hashPath(project) + "\x00" + a.s.hashPath(source)
}

// newParent starts an installation, or returns nil when the same payload is
// already an installation at this scope.
func (a *piAdapter) newParent(l *piLayer, nativeID, name, source, installPath, evidence string, loc *model.SourceLocator) *piParent {
	key := a.parentKey(l.scope, l.project, source)
	if a.byPath[key] != nil {
		return nil
	}
	if len(nativeID) > maxIDBytes && strings.HasPrefix(nativeID, "local:") {
		// Long local paths keep the family prefix; the installation ID still uses the full path.
		nativeID = "local:" + filepath.Base(source)
	}
	p := newPlugin(nativeID, name, model.PluginInstallDirectory, l.scope)
	p.ProjectPath = l.project
	p.InstallPath, p.SourcePath = installPath, source
	p.InstallationEvidence = evidence
	p.ManifestFormat = model.PluginManifestNone
	p.Source = loc
	p.InstanceID = a.s.instanceID(a.c.ContextID, p)
	pp := &piParent{p: p, root: installPath, index: map[string]int{}}
	a.byPath[key] = pp
	a.parents = append(a.parents, pp)
	return pp
}

// addPackage inventories one saved package entry.
func (a *piAdapter) addPackage(l *piLayer, pkg piPackage, user *piLayer) {
	if piBuiltin(pkg.source) {
		return
	}
	src, ok := a.parsePiSource(pkg.source, l)
	if !ok {
		a.fail(model.AgentScanErrParseFailed, l.path)
		return
	}
	if l.scope == model.PluginScopeProject && pkg.noAuto {
		// A project autoload:false entry narrows the user installation of the
		// same package rather than installing another copy.
		if user.failed {
			a.fail(model.AgentScanErrParseFailed, user.path)
			return
		}
		if base := a.users[src.identity]; base != nil {
			a.applyDelta(base, l, pkg)
			return
		}
	}
	scopeRoot := a.root
	if l.scope == model.PluginScopeProject {
		scopeRoot = l.base
	}
	var payload string
	loc := &model.SourceLocator{Kind: src.kind}
	switch src.kind {
	case model.PluginSourceNPM:
		modules := filepath.Join(scopeRoot, "npm", "node_modules")
		payload = filepath.Join(modules, filepath.FromSlash(src.name))
		if _, inside := relSlash(modules, payload); !inside || payload == modules {
			a.fail(model.AgentScanErrUnsafePath, l.path)
			return
		}
		loc.PackageName, loc.PackageVersion = src.name, src.version
		if strings.Contains(src.version, "://") {
			loc.PackageVersion = sanitizeLocation(src.version)
		}
	case model.PluginSourceGit:
		checkouts := filepath.Join(scopeRoot, "git")
		payload = filepath.Join(checkouts, src.host, filepath.FromSlash(src.path))
		if _, inside := relSlash(checkouts, payload); !inside {
			a.fail(model.AgentScanErrUnsafePath, l.path)
			return
		}
		loc.Location, loc.RequestedRef = sanitizeLocation(src.repo), src.ref
	default:
		payload = src.local
		loc.Location = src.local
	}
	gd := a.s.guarded(a.root, payload)
	state, _, err := a.s.stat(gd, payload)
	installPath := payload
	if state == fileRegular {
		installPath = filepath.Dir(payload)
	}
	pp := a.newParent(l, src.identity, src.display, payload, installPath, model.PluginEvidenceLocalConfig, loc)
	if pp == nil {
		return
	}
	if l.scope == model.PluginScopeUser {
		a.users[src.identity] = pp
	}
	if !a.present(pp, state, err) {
		return
	}
	k := &piCollector{a: a, gd: gd, p: pp.p}
	if state == fileRegular {
		// A single local file is one extension; Pi ignores filters for it.
		if src.kind == model.PluginSourceLocal {
			a.claim(l, payload)
			a.components(pp, l, gd, []piResource{{kind: "extensions", file: payload}})
		}
		return
	}
	if src.kind == model.PluginSourceGit {
		loc.ResolvedRevision = a.gitRevision(gd, payload)
	}
	a.manifestFields(pp, k.manifest(payload))
	if src.kind == model.PluginSourceNPM {
		loc.Location = a.npmRegistry(filepath.Join(scopeRoot, "npm"), src.name, pp.p.ManifestVersion)
	}
	res, any := k.packageResources(payload, pkg)
	if !any && src.kind == model.PluginSourceLocal {
		// A local directory with no resources of its own is loaded as one extension.
		res = []piResource{{kind: "extensions", file: payload}}
	}
	a.components(pp, l, gd, res)
}

// present records whether a configured payload exists. A selection alone is
// never an installation: a missing payload stays visible as not installed.
func (a *piAdapter) present(pp *piParent, state fileState, err error) bool {
	p := pp.p
	switch state {
	case fileDir, fileRegular:
		p.Installed, p.FilesPresent = boolPtr(true), boolPtr(true)
		return true
	case fileAbsent:
		p.Installed, p.FilesPresent = boolPtr(false), boolPtr(false)
		piPartial(p, model.AgentScanErrReadFailed, p.SourcePath)
	case fileRefused:
		piPartial(p, readCode(err), p.SourcePath)
	default:
		piPartial(p, model.AgentScanErrReadFailed, p.SourcePath)
	}
	return false
}

func (a *piAdapter) manifestFields(pp *piParent, m *piManifest) {
	if m == nil {
		return
	}
	pp.p.ManifestPath, pp.manifest = m.path, m.path
	pp.p.ManifestName, pp.p.ManifestVersion = m.name, m.version
	if m.pi != nil {
		pp.p.ManifestFormat = model.PluginManifestPi
	}
}

// npmRegistry is the registry npm recorded in its lock receipts under prefix
// for the installed version of name, or "" when no receipt proves one.
func (a *piAdapter) npmRegistry(prefix, name, version string) string {
	gd := a.s.guarded(a.root, prefix)
	for _, rel := range []string{"node_modules/.package-lock.json", "package-lock.json"} {
		data, _, code := a.s.readMetadata(gd, filepath.Join(prefix, filepath.FromSlash(rel)))
		var lock struct {
			Packages map[string]struct{ Version, Resolved string } `json:"packages"`
		}
		if code != "" || data == nil || json.Unmarshal(data, &lock) != nil {
			continue
		}
		entry, ok := lock.Packages["node_modules/"+name]
		if !ok || version != "" && entry.Version != version {
			continue
		}
		// Tarballs live at <registry>/<name>/-/<file>; some registries escape a scope's slash.
		for _, n := range []string{name, strings.Replace(name, "/", "%2f", 1), strings.Replace(name, "/", "%2F", 1)} {
			if i := strings.Index(entry.Resolved, "/"+n+"/-/"); i > 0 && strings.Contains(entry.Resolved[:i], "://") {
				return sanitizeLocation(entry.Resolved[:i])
			}
		}
	}
	return ""
}

func (a *piAdapter) claim(l *piLayer, file string) {
	a.claimed[a.parentKey(l.scope, l.project, file)] = true
}

// applyDelta records a project's autoload:false patterns as project-scoped
// preferences on the user installation's matching resources. Unmatched
// resources keep the user's selection.
func (a *piAdapter) applyDelta(base *piParent, l *piLayer, pkg piPackage) {
	if base.p.FilesPresent == nil || !*base.p.FilesPresent || base.root != base.p.SourcePath {
		return
	}
	gd := a.s.guarded(a.root, base.root)
	k := &piCollector{a: a, gd: gd, p: base.p}
	man := k.manifest(base.root)
	for _, kind := range piKinds {
		patterns := pkg.filters[kind]
		if len(patterns) == 0 {
			continue
		}
		files := k.manifestFiles(base.root, kind, man, piFallbackWhenEmpty)
		decide := a.decide(base.p, base.root, patterns, func(m *piMatcher) map[string]bool { return m.autoloadDelta(piPaths(files), patterns) })
		for _, f := range files {
			enabled, matched, known := decide(f.path)
			i, ok := base.index[kind+"\x00"+f.path]
			if !matched || !ok {
				continue
			}
			if !known {
				piPartial(base.p, model.AgentScanErrUnsupportedSchema, l.path)
				continue
			}
			c := &base.p.Components[i]
			c.Enablement = append(c.Enablement, model.EnablementObservation{Scope: l.scope, SourcePath: l.path, ProjectPath: l.project, Enabled: enabled})
		}
	}
}

// savedExtensions inventories the settings "extensions" paths: each plain
// entry is one selection, and pattern entries decide which of the files it
// supplies are enabled.
func (a *piAdapter) savedExtensions(l *piLayer) {
	if l.failed || len(l.extensions) == 0 {
		return
	}
	var plain, patterns []string
	for _, entry := range l.extensions {
		if piIsPattern(entry) {
			patterns = append(patterns, entry)
		} else if !piBuiltin(entry) {
			plain = append(plain, entry)
		}
	}
	for _, entry := range plain {
		resolved, ok := piResolvePath(entry, l.base, a.s.home, a.s.goos)
		if !ok {
			a.fail(model.AgentScanErrParseFailed, l.path)
			continue
		}
		gd := a.s.guarded(a.root, resolved)
		state, _, err := a.s.stat(gd, resolved)
		installPath := resolved
		if state == fileRegular {
			installPath = filepath.Dir(resolved)
		}
		pp := a.newParent(l, "local:"+resolved, filepath.Base(resolved), resolved, installPath, model.PluginEvidenceLocalConfig, &model.SourceLocator{Kind: model.PluginSourceLocal, Location: resolved})
		if pp == nil || !a.present(pp, state, err) {
			continue
		}
		k := &piCollector{a: a, gd: gd, p: pp.p}
		files := k.filesFromPaths([]string{resolved}, "extensions")
		if state == fileDir {
			a.manifestFields(pp, k.manifest(resolved))
		}
		decide := a.decide(pp.p, l.base, patterns, func(m *piMatcher) map[string]bool { return m.apply(files, patterns) })
		res := make([]piResource, 0, len(files))
		for _, f := range files {
			r := piResource{kind: "extensions", file: f}
			if len(patterns) > 0 {
				if enabled, _, known := decide(f); known {
					r.enabled, r.stated = boolPtr(enabled), true
				}
			}
			a.claim(l, f)
			res = append(res, r)
		}
		a.claim(l, resolved)
		a.components(pp, l, gd, res)
	}
}

// autoExtensions inventories entrypoints Pi loads from an extensions
// directory: each direct TS/JS file, and each child directory with an
// entrypoint, is one installation.
func (a *piAdapter) autoExtensions(l *piLayer) {
	dir := filepath.Join(l.base, "extensions")
	gd := a.s.guarded(a.root, dir)
	scratch := newPlugin("auto", "auto", model.PluginInstallDirectory, l.scope)
	k := &piCollector{a: a, gd: gd, p: scratch}
	groups := k.extensionGroups(dir)
	if scratch.ComponentStatus != model.AgentScanStatusComplete {
		for _, e := range scratch.Errors {
			a.fail(e.Code, e.SourcePath)
		}
	}
	var overrides []string
	for _, entry := range l.extensions {
		if strings.HasPrefix(entry, "!") || strings.HasPrefix(entry, "+") || strings.HasPrefix(entry, "-") {
			overrides = append(overrides, entry)
		}
	}
	for _, g := range groups {
		if a.claimed[a.parentKey(l.scope, l.project, g.path)] {
			continue
		}
		installPath := g.path
		if g.file {
			installPath = filepath.Dir(g.path)
		}
		pp := a.newParent(l, "local:"+g.path, filepath.Base(g.path), g.path, installPath, model.PluginEvidenceExtensionDirectory, &model.SourceLocator{Kind: model.PluginSourceLocal, Location: g.path})
		if pp == nil {
			continue
		}
		pp.p.Installed, pp.p.FilesPresent = boolPtr(true), boolPtr(true)
		gk := &piCollector{a: a, gd: gd, p: pp.p}
		if !g.file {
			a.manifestFields(pp, gk.manifest(g.path))
		}
		decide := a.decide(pp.p, l.base, overrides, func(m *piMatcher) map[string]bool { return m.overrides(g.files, overrides) })
		res := make([]piResource, 0, len(g.files))
		for _, f := range g.files {
			if a.claimed[a.parentKey(l.scope, l.project, f)] {
				continue
			}
			r := piResource{kind: "extensions", file: f, pointer: g.pointers[f]}
			if !l.extensionsOK {
				// The overrides that decide this file are unreadable.
			} else if len(overrides) > 0 {
				if enabled, _, known := decide(f); known {
					r.enabled, r.stated = boolPtr(enabled), true
				}
			}
			res = append(res, r)
		}
		a.components(pp, l, gd, res)
	}
}

// components emits the selected resources of one installation.
func (a *piAdapter) components(pp *piParent, l *piLayer, gd *SkillsDetector, res []piResource) {
	p := pp.p
	r := &pluginRootScan{s: a.s, gd: gd, p: p, root: pp.root, attr: nestedAttr{agent: model.AgentPi, source: "pi_plugin", vendor: "Pi", scope: nestedScope(p.Scope), projectPath: p.ProjectPath}}
	for _, res := range res {
		if a.s.ctx.Err() != nil {
			piPartial(p, model.AgentScanErrLimitExceeded, pp.root)
			return
		}
		kind := piComponentKinds[res.kind]
		rel, inside := relSlash(pp.root, res.file)
		c := model.PluginComponent{Kind: kind, RelativePath: rel, DefinitionPath: res.file}
		if !inside {
			// A manifest may select a file outside the package; the component
			// names the declaration, and the skill payload keeps the real path.
			if res.pointer == "" || pp.manifest == "" {
				piPartial(p, model.AgentScanErrUnsafePath, res.file)
				continue
			}
			out, _ := filepath.Rel(pp.root, res.file)
			c.RelativePath, c.DeclarationPointer, c.DefinitionPath, c.Name = ".", res.pointer, pp.manifest, filepath.ToSlash(out)
			if resolved, err := gd.exec.EvalSymlinks(pp.manifest); err == nil {
				c.ResolvedDefinitionPath = resolved
			}
		}
		before := len(p.Components)
		switch {
		case kind == model.PluginComponentSkill && inside && filepath.Base(res.file) == "SKILL.md":
			dir := filepath.Dir(res.file)
			relDir, _ := relSlash(pp.root, dir)
			r.skillComponent(dir, relDir, filepath.Base(dir), "")
		case kind == model.PluginComponentSkill:
			a.skill(r, gd, res.file, c)
		default:
			if c.Name == "" {
				c.Name = rel
				if kind != model.PluginComponentExtension {
					c.Name = strings.TrimSuffix(path.Base(rel), path.Ext(rel))
				}
			}
			r.addComponent(c)
		}
		if len(p.Components) == before+1 {
			added := &p.Components[before]
			added.ConfiguredEnabled = res.enabled
			if res.stated && res.enabled != nil {
				added.Enablement = append(added.Enablement, model.EnablementObservation{Scope: l.scope, SourcePath: l.path, ProjectPath: l.project, Enabled: *res.enabled})
			}
			pp.index[res.kind+"\x00"+res.file] = before
		}
	}
}

// skill emits a skill Pi loads from a plain Markdown file, or a SKILL.md a
// manifest selects outside the package. Pi skips a plain file without a
// description: such a file is not a skill.
func (a *piAdapter) skill(r *pluginRootScan, gd *SkillsDetector, file string, c model.PluginComponent) {
	declared := filepath.Base(file) == "SKILL.md"
	resolved, err := gd.exec.EvalSymlinks(file)
	if err != nil || resolved == "" || a.s.d.skipper.WithinProtected(resolved) {
		code := model.AgentScanErrUnsafePath
		if err != nil {
			code = readCode(err)
		}
		if !declared {
			piPartial(r.p, code, file)
			return
		}
		c.Name = filepath.Base(filepath.Dir(file))
		r.componentError(&c, code)
		r.addComponent(c)
		return
	}
	if c.ResolvedDefinitionPath == "" {
		c.ResolvedDefinitionPath = resolved
	}
	var meta skillMeta
	var census *skillCensus
	if declared {
		dir := filepath.Dir(resolved)
		scan, ok := a.s.memo[dir]
		if !ok {
			if !r.takeDefinition() {
				return
			}
			scan = &skillScan{meta: gd.parseSkillMD(resolved), census: gd.census(a.s.ctx, dir)}
			a.s.memo[dir] = scan
		}
		meta, census = scan.meta, scan.census
	} else {
		var ok bool
		if meta, ok = a.skills[resolved]; !ok {
			if !r.takeDefinition() {
				return
			}
			meta = gd.parseSkillMD(resolved)
			a.skills[resolved] = meta
		}
	}
	switch meta.frontmatterError {
	case "unreadable", "file_too_large":
		code := model.AgentScanErrReadFailed
		if meta.frontmatterError == "file_too_large" {
			code = model.AgentScanErrLimitExceeded
		}
		if !declared {
			piPartial(r.p, code, file)
			return
		}
		c.Name = filepath.Base(filepath.Dir(file))
		r.componentError(&c, code)
		r.addComponent(c)
		return
	case "invalid_yaml":
		if !declared {
			return
		}
		c.Name = filepath.Base(filepath.Dir(file))
		r.componentError(&c, model.AgentScanErrParseFailed)
		r.addComponent(c)
		return
	}
	if !declared && strings.TrimSpace(meta.description) == "" {
		return
	}
	name := filepath.Base(filepath.Dir(file))
	rec := model.AgentSkill{
		SkillSlug: name, SkillName: name, Agent: r.attr.agent, Source: r.attr.source,
		Scope: r.attr.scope, ProjectPath: r.attr.projectPath,
		DefinitionKind: model.AgentDefinitionSkill, DefinitionPath: file, CallableNames: []string{},
	}
	applySkillMeta(&rec, meta)
	rec.DefinitionHash = meta.skillMDHash
	if declared {
		rec.SkillDirPath, rec.SkillMDPath = filepath.Dir(resolved), file
		applySkillCensus(&rec, census)
	} else {
		// A plain file is not a SKILL.md, and its directory is not a skill directory.
		rec.SkillMDHash = ""
	}
	if c.Name == "" {
		c.Name = rec.SkillName
	}
	c.Skill = &rec
	r.addComponent(c)
}

// gitRevision reads the commit a managed checkout has, through its HEAD and
// loose or packed refs.
func (a *piAdapter) gitRevision(gd *SkillsDetector, checkout string) string {
	gitDir := filepath.Join(checkout, ".git")
	data, _, code := a.s.readMetadata(gd, filepath.Join(gitDir, "HEAD"))
	if code != "" || data == nil {
		return ""
	}
	sha, ref := parseGitHead(data)
	if sha != "" || !strings.HasPrefix(ref, "refs/") || strings.Contains("/"+ref+"/", "/../") {
		return sha
	}
	if data, _, code := a.s.readMetadata(gd, filepath.Join(gitDir, filepath.FromSlash(ref))); code == "" && data != nil {
		sha, _ = parseGitHead(data)
		return sha
	}
	if data, _, code := a.s.readMetadata(gd, filepath.Join(gitDir, "packed-refs")); code == "" && data != nil {
		return parsePackedRef(data, ref)
	}
	return ""
}

// decide evaluates a filter for each file. Pi 1.2 began expanding ~ in
// filters; unless the installed version is known to, a result that depends on
// that expansion is unknown. Unsupported pattern syntax makes every result
// unknown and the installation partial.
func (a *piAdapter) decide(p *model.PluginObservation, base string, patterns []string, eval func(*piMatcher) map[string]bool) func(string) (enabled, matched, known bool) {
	m := &piMatcher{base: base, home: a.s.home, goos: a.s.goos, tilde: true}
	got := eval(m)
	var alt map[string]bool
	if !a.tildeOK && slicesContainTilde(patterns) {
		other := &piMatcher{base: base, home: a.s.home, goos: a.s.goos}
		alt = eval(other)
		m.unsupported = m.unsupported || other.unsupported
	}
	if m.unsupported {
		piPartial(p, model.AgentScanErrUnsupportedSchema, base)
	}
	return func(f string) (bool, bool, bool) {
		enabled, matched := got[f]
		if m.unsupported {
			return false, matched, false
		}
		if alt != nil {
			if other, otherMatched := alt[f]; other != enabled || otherMatched != matched {
				return false, true, false
			}
		}
		return enabled, matched, true
	}
}

func slicesContainTilde(patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(p, "~") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Resource discovery
// ---------------------------------------------------------------------------

// piCollector walks one payload through a guarded reader, charging the shared
// directory bounds and recording failures on the installation.
type piCollector struct {
	a    *piAdapter
	gd   *SkillsDetector
	p    *model.PluginObservation
	dirs int
	mans map[string]*piManifest
}

// piManifest is the part of package.json Pi reads: string-array resource
// fields of an object "pi" key.
type piManifest struct {
	path, name, version string
	pi                  map[string][]string
}

// piFile is one discovered file and the manifest declaration that selected it.
type piFile struct {
	path, pointer string
}

func piPaths(files []piFile) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.path
	}
	return out
}

func (k *piCollector) manifest(root string) *piManifest {
	if m, ok := k.mans[root]; ok {
		return m
	}
	if k.mans == nil {
		k.mans = map[string]*piManifest{}
	}
	file := filepath.Join(root, "package.json")
	data, absent, code := k.a.s.readMetadata(k.gd, file)
	var m *piManifest
	if code != "" {
		piPartial(k.p, code, file)
	} else if !absent {
		var doc map[string]json.RawMessage
		if json.Unmarshal(bytes.TrimPrefix(data, utf8BOM), &doc) != nil || doc == nil {
			// Pi falls back to convention directories, but a half-written
			// manifest must not read as removed resources.
			piPartial(k.p, model.AgentScanErrParseFailed, file)
		} else {
			m = &piManifest{path: file, name: jsonString(doc["name"]), version: jsonString(doc["version"])}
			var pi map[string]json.RawMessage
			if json.Unmarshal(doc["pi"], &pi) == nil && pi != nil {
				m.pi = map[string][]string{}
				for _, kind := range piKinds {
					var entries []string
					if json.Unmarshal(pi[kind], &entries) == nil && entries != nil {
						m.pi[kind] = entries
					}
				}
			}
		}
	}
	k.mans[root] = m
	return m
}

func (m *piManifest) entries(kind string) ([]string, bool) {
	if m == nil || m.pi == nil {
		return nil, false
	}
	entries, ok := m.pi[kind]
	return entries, ok
}

// Manifest fallbacks differ by caller: a filter treats an empty field as
// absent, an unfiltered object entry honors an empty field, and a plain entry
// with a pi manifest never falls back to conventional directories.
const (
	piFallbackWhenEmpty = iota
	piFallbackWhenAbsent
	piNoFallback
)

// packageResources selects a package's resources the way Pi does for one
// saved entry. any reports whether a plain entry found resources of its own.
func (k *piCollector) packageResources(root string, pkg piPackage) (res []piResource, any bool) {
	man := k.manifest(root)
	if pkg.object {
		for _, kind := range piKinds {
			patterns, filtered := pkg.filters[kind]
			if !pkg.noAuto && !filtered {
				res = append(res, piUnfiltered(kind, k.manifestFiles(root, kind, man, piFallbackWhenAbsent))...)
				continue
			}
			files := k.manifestFiles(root, kind, man, piFallbackWhenEmpty)
			var decide func(string) (bool, bool, bool)
			switch {
			case len(patterns) == 0:
				// autoload:false with nothing listed loads none of the kind, and an
				// empty filter disables every resource of it.
				decide = func(string) (bool, bool, bool) { return false, true, true }
			case pkg.noAuto:
				decide = k.a.decide(k.p, root, patterns, func(m *piMatcher) map[string]bool { return m.autoloadDelta(piPaths(files), patterns) })
			default:
				decide = k.a.decide(k.p, root, patterns, func(m *piMatcher) map[string]bool { return m.apply(piPaths(files), patterns) })
			}
			for _, f := range files {
				r := piResource{kind: kind, file: f.path, pointer: f.pointer}
				// A resource autoload:false does not list is not loaded.
				if enabled, _, known := decide(f.path); known {
					r.enabled, r.stated = boolPtr(enabled), true
				}
				res = append(res, r)
			}
		}
		return res, true
	}
	if man != nil && man.pi != nil {
		for _, kind := range piKinds {
			res = append(res, piUnfiltered(kind, k.manifestFiles(root, kind, man, piNoFallback))...)
		}
		return res, true
	}
	for _, kind := range piKinds {
		dir := filepath.Join(root, kind)
		if st, _, _ := k.a.s.stat(k.gd, dir); st == fileAbsent {
			continue
		}
		any = true
		for _, f := range k.resourceFiles(dir, kind) {
			res = append(res, piResource{kind: kind, file: f})
		}
	}
	return res, any
}

func piUnfiltered(kind string, files []piFile) []piResource {
	res := make([]piResource, len(files))
	for i, f := range files {
		res[i] = piResource{kind: kind, file: f.path, pointer: f.pointer}
	}
	return res
}

// manifestFiles lists a kind's files: the manifest's entries narrowed by its
// own override patterns, else the conventional directory.
func (k *piCollector) manifestFiles(root, kind string, man *piManifest, fallback int) []piFile {
	entries, declared := man.entries(kind)
	useManifest := declared && (len(entries) > 0 || fallback != piFallbackWhenEmpty)
	if !useManifest {
		if fallback == piNoFallback {
			return nil
		}
		var files []piFile
		for _, f := range k.resourceFiles(filepath.Join(root, kind), kind) {
			files = append(files, piFile{path: f})
		}
		return files
	}
	var files []piFile
	seen := map[string]bool{}
	var overrides []string
	for i, entry := range entries {
		if strings.HasPrefix(entry, "!") || strings.HasPrefix(entry, "+") || strings.HasPrefix(entry, "-") {
			overrides = append(overrides, entry)
			continue
		}
		var targets []string
		if strings.ContainsAny(entry, "*?") {
			targets = k.expandGlob(entry, root)
		} else if filepath.IsAbs(entry) {
			targets = []string{filepath.Clean(entry)}
		} else {
			targets = []string{filepath.Join(root, entry)}
		}
		for _, f := range k.filesFromPaths(targets, kind) {
			if !seen[f] {
				seen[f] = true
				files = append(files, piFile{path: f, pointer: "/pi/" + kind + "/" + jsonPointerIndex(i)})
			}
		}
	}
	if len(overrides) == 0 {
		return files
	}
	decide := k.a.decide(k.p, root, overrides, func(m *piMatcher) map[string]bool { return m.apply(piPaths(files), overrides) })
	kept := files[:0]
	for _, f := range files {
		// A file the package's own overrides may or may not exclude is kept, unknown.
		if enabled, _, known := decide(f.path); enabled || !known {
			kept = append(kept, f)
		}
	}
	return kept
}

func jsonPointerIndex(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// filesFromPaths expands selected paths: a file is itself, a directory is the
// kind's resources inside it. Missing paths select nothing.
func (k *piCollector) filesFromPaths(paths []string, kind string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		st, _, err := k.a.s.stat(k.gd, p)
		var files []string
		switch st {
		case fileRegular:
			files = []string{p}
		case fileDir:
			files = k.resourceFiles(p, kind)
		case fileRefused:
			piPartial(k.p, readCode(err), p)
		}
		for _, f := range files {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}

func (k *piCollector) resourceFiles(dir, kind string) []string {
	switch kind {
	case "skills":
		return k.skillEntries(dir, dir, &piIgnore{}, 0)
	case "extensions":
		var out []string
		for _, g := range k.extensionGroups(dir) {
			out = append(out, g.files...)
		}
		return out
	}
	return k.collectFiles(dir, dir, &piIgnore{}, piResourceSuffixes[kind], 0)
}

// enter charges one directory against the walk bounds.
func (k *piCollector) enter(dir string, depth int) bool {
	if k.a.s.ctx.Err() != nil || depth > maxComponentWalkDepth {
		piPartial(k.p, model.AgentScanErrLimitExceeded, dir)
		return false
	}
	k.dirs++
	if k.dirs > maxComponentDirs {
		piPartial(k.p, model.AgentScanErrLimitExceeded, dir)
		return false
	}
	return true
}

func (k *piCollector) list(dir string) []os.DirEntry {
	entries, code := k.a.s.listDir(k.gd, dir)
	if code != "" {
		piPartial(k.p, code, dir)
	}
	return entries
}

// kind follows links through the guard; Windows junctions report ModeIrregular.
func (k *piCollector) kind(full string, e os.DirEntry) (isDir, isFile, ok bool) {
	isJunction := e.Type()&os.ModeIrregular != 0 && k.gd.exec.GOOS() == model.PlatformWindows
	if e.Type()&os.ModeSymlink == 0 && !isJunction {
		return e.IsDir(), e.Type().IsRegular(), true
	}
	st, _, err := k.a.s.stat(k.gd, full)
	switch st {
	case fileDir:
		return true, false, true
	case fileRegular:
		return false, true, true
	case fileRefused:
		piPartial(k.p, readCode(err), full)
	}
	return false, false, false
}

func piRel(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	if rel == "." {
		return ""
	}
	return filepath.ToSlash(rel)
}

func piHidden(name string) bool { return strings.HasPrefix(name, ".") || name == "node_modules" }

// collectFiles lists files with a matching suffix below dir, honoring ignore
// files on the way down.
func (k *piCollector) collectFiles(dir, root string, ig *piIgnore, suffixes []string, depth int) []string {
	if !k.enter(dir, depth) {
		return nil
	}
	k.addIgnoreRules(ig, dir, root)
	entries := k.list(dir)
	var out []string
	for _, name := range sortedEntryNames(entries) {
		if piHidden(name) {
			continue
		}
		full := filepath.Join(dir, name)
		isDir, isFile, ok := k.kind(full, dirEntryByName(entries, name))
		if !ok || k.ignored(ig, piRel(root, full), isDir) {
			continue
		}
		if isDir {
			out = append(out, k.collectFiles(full, root, ig, suffixes, depth+1)...)
		} else if isFile && piHasSuffix(name, suffixes) {
			out = append(out, full)
		}
	}
	return out
}

func piHasSuffix(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// skillEntries finds skills: a directory with SKILL.md is one skill and its
// contents are not searched; a Markdown file directly in the skills root is a
// skill of its own.
func (k *piCollector) skillEntries(dir, root string, ig *piIgnore, depth int) []string {
	if !k.enter(dir, depth) {
		return nil
	}
	k.addIgnoreRules(ig, dir, root)
	entries := k.list(dir)
	if e := dirEntryByName(entries, "SKILL.md"); e != nil {
		full := filepath.Join(dir, "SKILL.md")
		if _, isFile, ok := k.kind(full, e); ok && isFile && !k.ignored(ig, piRel(root, full), false) {
			return []string{full}
		}
	}
	var out []string
	for _, name := range sortedEntryNames(entries) {
		if piHidden(name) {
			continue
		}
		full := filepath.Join(dir, name)
		isDir, isFile, ok := k.kind(full, dirEntryByName(entries, name))
		if !ok {
			continue
		}
		rel := piRel(root, full)
		if isFile && strings.HasSuffix(name, ".md") && dir == root && !k.ignored(ig, rel, false) {
			out = append(out, full)
			continue
		}
		if isDir && !k.ignored(ig, rel, true) {
			out = append(out, k.skillEntries(full, root, ig, depth+1)...)
		}
	}
	return out
}

// piGroup is one automatically discovered extension: a direct file, or a
// directory and the entrypoints it declares.
type piGroup struct {
	path     string
	file     bool
	files    []string
	pointers map[string]string
}

// extensionGroups discovers extensions in dir: the directory's own
// entrypoints if it declares any, else each direct TS/JS file and each child
// directory with entrypoints.
func (k *piCollector) extensionGroups(dir string) []piGroup {
	if st, _, err := k.a.s.stat(k.gd, dir); st != fileDir {
		if st == fileRefused {
			piPartial(k.p, readCode(err), dir)
		}
		return nil
	}
	if g, ok := k.entrypoints(dir); ok {
		return []piGroup{g}
	}
	if !k.enter(dir, 0) {
		return nil
	}
	ig := &piIgnore{}
	k.addIgnoreRules(ig, dir, dir)
	entries := k.list(dir)
	var out []piGroup
	for _, name := range sortedEntryNames(entries) {
		if piHidden(name) {
			continue
		}
		full := filepath.Join(dir, name)
		isDir, isFile, ok := k.kind(full, dirEntryByName(entries, name))
		if !ok || k.ignored(ig, name, isDir) {
			continue
		}
		if isFile && (strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".js")) {
			out = append(out, piGroup{path: full, file: true, files: []string{full}})
		} else if isDir {
			if g, ok := k.entrypoints(full); ok {
				out = append(out, g)
			}
		}
	}
	return out
}

// entrypoints resolves a directory's extension entrypoints: existing
// package.json pi.extensions paths, else index.ts, else index.js.
func (k *piCollector) entrypoints(dir string) (piGroup, bool) {
	g := piGroup{path: dir, pointers: map[string]string{}}
	if entries, _ := k.manifest(dir).entries("extensions"); len(entries) > 0 {
		for i, entry := range entries {
			target := filepath.Join(dir, entry)
			if filepath.IsAbs(entry) {
				target = filepath.Clean(entry)
			}
			if st, _, _ := k.a.s.stat(k.gd, target); st != fileAbsent {
				g.files = append(g.files, target)
				g.pointers[target] = "/pi/extensions/" + jsonPointerIndex(i)
			}
		}
		if len(g.files) > 0 {
			return g, true
		}
	}
	for _, index := range []string{"index.ts", "index.js"} {
		target := filepath.Join(dir, index)
		if st, _, _ := k.a.s.stat(k.gd, target); st != fileAbsent {
			g.files = []string{target}
			return g, true
		}
	}
	return g, false
}

// expandGlob expands a manifest glob below root. Matches inside dot
// directories are dropped, except through "..".
func (k *piCollector) expandGlob(pattern, root string) []string {
	alts, ok := piExpandBraces(filepath.ToSlash(pattern))
	if !ok || piUnsupportedGlob(pattern) {
		piPartial(k.p, model.AgentScanErrUnsupportedSchema, root)
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		rel, err := filepath.Rel(root, p)
		if err != nil || seen[p] {
			return
		}
		for seg := range strings.SplitSeq(filepath.ToSlash(rel), "/") {
			if seg != ".." && seg != "." && strings.HasPrefix(seg, ".") {
				return
			}
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, alt := range alts {
		segs := strings.Split(alt, "/")
		start := root
		if filepath.IsAbs(filepath.FromSlash(alt)) {
			start, segs = segs[0]+string(filepath.Separator), segs[1:]
		}
		k.globWalk(start, segs, 0, add)
	}
	sort.Strings(out)
	return out
}

func (k *piCollector) globWalk(dir string, segs []string, depth int, add func(string)) {
	if len(segs) == 0 {
		add(dir)
		return
	}
	seg := segs[0]
	switch {
	case seg == "" || seg == ".":
		k.globWalk(dir, segs[1:], depth, add)
	case seg == "**":
		k.globWalk(dir, segs[1:], depth, add)
		if !k.enter(dir, depth) {
			return
		}
		for _, e := range k.list(dir) {
			if !strings.HasPrefix(e.Name(), ".") && e.IsDir() {
				k.globWalk(filepath.Join(dir, e.Name()), segs, depth+1, add)
			}
		}
	case !strings.ContainsAny(seg, "*?["):
		next := filepath.Join(dir, seg)
		if len(segs) == 1 {
			if st, _, _ := k.a.s.stat(k.gd, next); st != fileAbsent {
				add(next)
			}
			return
		}
		k.globWalk(next, segs[1:], depth, add)
	default:
		if !k.enter(dir, depth) {
			return
		}
		for _, e := range k.list(dir) {
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if match, err := path.Match(strings.ReplaceAll(seg, "[!", "[^"), e.Name()); err == nil && match {
				k.globWalk(filepath.Join(dir, e.Name()), segs[1:], depth+1, add)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Ignore files
// ---------------------------------------------------------------------------

// piIgnore holds .gitignore/.ignore/.fdignore rules collected on the way down.
// Pi prefixes a nested file's rules with its directory, so a nested rule is
// anchored there.
type piIgnore struct{ rules []piIgnoreRule }

type piIgnoreRule struct {
	negate, dirOnly, anchored bool
	segs                      []string
}

func (k *piCollector) addIgnoreRules(ig *piIgnore, dir, root string) {
	prefix := piRel(root, dir)
	if prefix != "" {
		prefix += "/"
	}
	for _, name := range []string{".gitignore", ".ignore", ".fdignore"} {
		file := filepath.Join(dir, name)
		data, absent, code := k.a.s.readMetadata(k.gd, file)
		if absent {
			continue
		}
		if code != "" {
			piPartial(k.p, code, file)
			continue
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if !ig.add(strings.TrimSuffix(line, "\r"), prefix) {
				piPartial(k.p, model.AgentScanErrUnsupportedSchema, file)
			}
		}
	}
}

func (ig *piIgnore) add(line, prefix string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, `\#`) {
		return true
	}
	rule := piIgnoreRule{}
	pattern := line
	if strings.HasPrefix(pattern, "!") {
		rule.negate, pattern = true, pattern[1:]
	} else if strings.HasPrefix(pattern, `\!`) {
		pattern = pattern[1:]
	}
	pattern = prefix + strings.TrimPrefix(pattern, "/")
	pattern = strings.TrimRight(pattern, " \t")
	pattern, rule.dirOnly = strings.CutSuffix(pattern, "/")
	if pattern == "" {
		return true
	}
	rule.anchored = strings.Contains(pattern, "/")
	rule.segs = strings.Split(pattern, "/")
	for _, seg := range rule.segs {
		if _, err := path.Match(seg, ""); err != nil {
			return false
		}
	}
	ig.rules = append(ig.rules, rule)
	return true
}

func (k *piCollector) ignored(ig *piIgnore, rel string, dir bool) bool {
	ignored := false
	name := []string{path.Base(rel)}
	segs := strings.Split(rel, "/")
	for _, rule := range ig.rules {
		if rule.dirOnly && !dir {
			continue
		}
		target := name
		if rule.anchored {
			target = segs
		}
		if piMatchSegments(rule.segs, target, false) {
			ignored = !rule.negate
		}
	}
	return ignored
}

// ---------------------------------------------------------------------------
// Filter matching
// ---------------------------------------------------------------------------

// piMatcher evaluates Pi resource filters relative to base: glob patterns
// against a file's relative path, name and absolute path, and exact entries
// against its relative and absolute path. A SKILL.md also matches through its
// directory.
type piMatcher struct {
	base, home, goos string
	tilde            bool
	unsupported      bool
}

func piIsPattern(s string) bool {
	return strings.HasPrefix(s, "!") || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") || strings.ContainsAny(s, "*?")
}

func (m *piMatcher) posix(p string) string {
	if m.goos == model.PlatformWindows {
		return strings.ReplaceAll(p, `\`, "/")
	}
	return p
}

func (m *piMatcher) normalize(pattern string) string {
	if !m.tilde && strings.HasPrefix(pattern, "~") {
		return m.posix(pattern)
	}
	normalized, ok := piNormalizePath(pattern, m.home, m.goos)
	if !ok {
		m.unsupported = true
	}
	return m.posix(normalized)
}

func (m *piMatcher) forms(file string) []string {
	forms := []string{m.posix(piRel(m.base, file)), filepath.Base(file), m.posix(file)}
	if filepath.Base(file) == "SKILL.md" {
		dir := filepath.Dir(file)
		forms = append(forms, m.posix(piRel(m.base, dir)), filepath.Base(dir), m.posix(dir))
	}
	return forms
}

func (m *piMatcher) any(file string, patterns []string) bool {
	forms := m.forms(file)
	for _, pattern := range patterns {
		pattern = m.normalize(pattern)
		for _, form := range forms {
			match, ok := piGlobMatch(pattern, form)
			if !ok {
				m.unsupported = true
			}
			if match {
				return true
			}
		}
	}
	return false
}

func (m *piMatcher) exact(file string, patterns []string) bool {
	forms := m.forms(file)
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "./") || strings.HasPrefix(pattern, `.\`) {
			pattern = pattern[2:]
		}
		pattern = m.normalize(pattern)
		for i, form := range forms {
			// Exact entries compare paths, never bare names.
			if i%3 != 1 && pattern == form {
				return true
			}
		}
	}
	return false
}

// apply is Pi's filter: plain patterns include (all when none), !patterns
// exclude, +paths force-include and -paths force-exclude.
func (m *piMatcher) apply(files, patterns []string) map[string]bool {
	var includes, excludes, forceIn, forceOut []string
	for _, p := range patterns {
		switch {
		case strings.HasPrefix(p, "+"):
			forceIn = append(forceIn, p[1:])
		case strings.HasPrefix(p, "-"):
			forceOut = append(forceOut, p[1:])
		case strings.HasPrefix(p, "!"):
			excludes = append(excludes, p[1:])
		default:
			includes = append(includes, p)
		}
	}
	out := make(map[string]bool, len(files))
	for _, f := range files {
		in := len(includes) == 0 || m.any(f, includes)
		if in && len(excludes) > 0 && m.any(f, excludes) {
			in = false
		}
		if !in && len(forceIn) > 0 && m.exact(f, forceIn) {
			in = true
		}
		if in && len(forceOut) > 0 && m.exact(f, forceOut) {
			in = false
		}
		out[f] = in
	}
	return out
}

// overrides decides automatically discovered resources: enabled unless an
// override pattern turns them off.
func (m *piMatcher) overrides(files, patterns []string) map[string]bool {
	var overrides []string
	for _, p := range patterns {
		if strings.HasPrefix(p, "!") || strings.HasPrefix(p, "+") || strings.HasPrefix(p, "-") {
			overrides = append(overrides, p)
		}
	}
	return m.apply(files, overrides)
}

// autoloadDelta applies autoload:false patterns in order; only matched files
// get a value, and a later pattern overrides an earlier one.
func (m *piMatcher) autoloadDelta(files, patterns []string) map[string]bool {
	out := map[string]bool{}
	for _, p := range patterns {
		enabled := !strings.HasPrefix(p, "-") && !strings.HasPrefix(p, "!")
		exact := strings.HasPrefix(p, "+") || strings.HasPrefix(p, "-")
		target := p
		if exact || !enabled {
			target = p[1:]
		}
		for _, f := range files {
			if exact && m.exact(f, []string{target}) || !exact && m.any(f, []string{target}) {
				out[f] = enabled
			}
		}
	}
	return out
}

var (
	piExtglobRE = regexp.MustCompile(`[@!+*?]\(`)
	piBraceRE   = regexp.MustCompile(`\{([^{}]*,[^{}]*)\}`)
	piRangeRE   = regexp.MustCompile(`\{[^{},]*\.\.[^{},]*\}`)
)

func piUnsupportedGlob(pattern string) bool {
	return strings.HasPrefix(pattern, "!") || piExtglobRE.MatchString(pattern) || piRangeRE.MatchString(pattern) || strings.Contains(pattern, "[:")
}

// piGlobMatch is the subset of minimatch Pi filters use: *, **, ?, character
// classes and {a,b} alternatives, where wildcards never match a leading dot.
// ok is false for syntax outside that subset.
func piGlobMatch(pattern, name string) (match, ok bool) {
	if strings.HasPrefix(pattern, "#") {
		return false, true // minimatch treats it as a comment
	}
	if piUnsupportedGlob(pattern) {
		return false, false
	}
	alts, ok := piExpandBraces(pattern)
	if !ok {
		return false, false
	}
	parts := strings.Split(name, "/")
	for _, alt := range alts {
		var segs []string
		for seg := range strings.SplitSeq(strings.ReplaceAll(alt, "[!", "[^"), "/") {
			if seg == "." {
				continue
			}
			if _, err := path.Match(seg, ""); err != nil {
				return false, false
			}
			segs = append(segs, seg)
		}
		if piMatchSegments(segs, parts, true) {
			return true, true
		}
	}
	return false, true
}

func piExpandBraces(p string) ([]string, bool) {
	out := []string{p}
	for i := 0; i < len(out); {
		loc := piBraceRE.FindStringSubmatchIndex(out[i])
		if loc == nil {
			i++
			continue
		}
		if len(out) > 64 {
			return nil, false
		}
		s := out[i]
		var expanded []string
		for part := range strings.SplitSeq(s[loc[2]:loc[3]], ",") {
			expanded = append(expanded, s[:loc[0]]+part+s[loc[1]:])
		}
		out = append(out[:i], append(expanded, out[i+1:]...)...)
	}
	return out, true
}

// piMatchSegments matches path segments, with ** spanning any number of
// segments. dotRule keeps wildcards off dot-prefixed names, as minimatch does.
func piMatchSegments(pat, name []string, dotRule bool) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for i := 0; i <= len(name); i++ {
				if piMatchSegments(pat[1:], name[i:], dotRule) {
					return true
				}
				if i < len(name) && dotRule && strings.HasPrefix(name[i], ".") {
					return false
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if dotRule && strings.HasPrefix(name[0], ".") && !strings.HasPrefix(pat[0], ".") {
			return false
		}
		if match, _ := path.Match(pat[0], name[0]); !match {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}

// ---------------------------------------------------------------------------
// Standalone MCP
// ---------------------------------------------------------------------------

// isPiMCPPath reports whether file is Pi's own mcp.json: the agent root's, or
// a project's .pi/mcp.json.
func isPiMCPPath(file, piRoot string) bool {
	file = filepath.Clean(file)
	if filepath.Base(file) != "mcp.json" {
		return false
	}
	return piRoot != "" && filepath.Dir(file) == filepath.Clean(piRoot) || filepath.Base(filepath.Dir(file)) == ".pi"
}

// filterPiMCP reduces a Pi mcp.json — strict JSON with an optional BOM — to
// each server's redacted command, args and URL plus its enabled flag. Entries
// Pi itself would reject are kept: extensions such as pi-mcp-adapter read the
// same file with their own schema. Only entries that define no command or URL
// are dropped, since they merely override another server's settings.
func filterPiMCP(content []byte) ([]byte, bool) {
	var doc struct {
		Servers map[string]json.RawMessage `json:"mcpServers"`
	}
	if json.Unmarshal(bytes.TrimPrefix(content, utf8BOM), &doc) != nil {
		return nil, false
	}
	servers := map[string]any{}
	for name, raw := range doc.Servers {
		var entry map[string]json.RawMessage
		if json.Unmarshal(raw, &entry) != nil || entry["command"] == nil && entry["url"] == nil && entry["serverUrl"] == nil {
			continue
		}
		kept := map[string]any{}
		for _, key := range []string{"command", "args", "serverUrl", "url"} {
			var value any
			if raw, ok := entry[key]; ok && json.Unmarshal(raw, &value) == nil {
				kept[key] = redact.Value(value)
			}
		}
		if enabled := jsonBool(entry["enabled"]); enabled != nil {
			kept["enabled"] = *enabled
		}
		servers[name] = kept
	}
	if len(servers) == 0 {
		return nil, false
	}
	out, err := json.Marshal(map[string]any{"mcpServers": servers})
	return out, err == nil
}
