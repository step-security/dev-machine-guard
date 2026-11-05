package configaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

var maxSwiftAuditBytes = 256 << 10

const (
	swiftManager       = "swiftpm"
	swiftConfigBytes   = int64(2 << 20)
	swiftSettingLimit  = 256
	swiftListLimit     = 10_000
	swiftDefaultScope  = "[default]"
	swiftLiteralSuffix = ".literal_auth"
)

// swiftSigningEnums are the supported signing keys with an enumerated value.
var swiftSigningEnums = map[string][]string{
	"onUnsigned":                             {"prompt", "error", "warn", "silentAllow"},
	"onUntrustedCertificate":                 {"prompt", "error", "warn", "silentAllow"},
	"validationChecks.certificateExpiration": {"enabled", "disabled"},
	"validationChecks.certificateRevocation": {"strict", "allowSoftFail", "disabled"},
}

// SwiftLibraryGuard admits SwiftPM's macOS state roots under ~/Library, which
// protected refuses wholesale for walks: each root, everything below it, and
// its ancestors so a reader rooted there can reach it. Every other path,
// including a link target elsewhere in ~/Library, stays with protected, and a
// network volume is refused first. It is only for readers rooted at roots;
// it grants no OS permission.
func SwiftLibraryGuard(protected func(string) string, volume func(string) bool, roots []string) func(string) string {
	return func(p string) string {
		p = filepath.Clean(p)
		if volume != nil && volume(p) {
			return model.GoReasonSkippedProtected
		}
		// APFS folds case by default, as protected does.
		key := strings.ToLower(p)
		for _, root := range roots {
			root = strings.ToLower(filepath.Clean(root))
			if key == root || isLexicalAncestor(root, key) || isLexicalAncestor(key, root) {
				return ""
			}
		}
		if protected != nil {
			return protected(p)
		}
		return ""
	}
}

// SwiftURL sanitizes one recorded SwiftPM location for display. Local paths
// and file URLs keep their spelling. Network URLs keep transport, port and
// path case, lowercase scheme and host, drop an HTTP(S) trailing slash and
// drop userinfo, except an SSH username without a password, which is kept
// like an SCP-like location's user. literalAuth reports a
// credential found before sanitizing; ok is false for a query, fragment,
// encoded "@", unknown scheme or malformed value, which must not be used.
func SwiftURL(raw string) (display string, literalAuth, ok bool) {
	if raw == "" || !composerSafeText(raw, 4096) {
		return "", false, false
	}
	if SwiftAbsPath(raw) {
		return raw, false, true
	}
	if !strings.Contains(raw, "://") {
		if strings.ContainsAny(raw, "?# \t\\") {
			return "", false, false
		}
		// Git treats a colon before any slash as SCP-like syntax.
		colon, slash := strings.Index(raw, ":"), strings.Index(raw, "/")
		if colon < 0 || slash >= 0 && slash < colon {
			if strings.Contains(raw, "@") {
				return "", false, false
			}
			return raw, false, true // a registry identity or relative path
		}
		host, path := raw[:colon], raw[colon+1:]
		user, h, hasUser := strings.Cut(host, "@")
		if hasUser {
			if user == "" {
				return "", false, false
			}
			host = h
		}
		if len(host) < 2 || path == "" || strings.Contains(host, "@") || strings.Contains(path, "@") {
			return "", false, false
		}
		if hasUser {
			// An SSH username is not a credential, and a relative path is
			// resolved in that user's home, so it is part of the location.
			return user + "@" + strings.ToLower(host) + ":" + path, false, true
		}
		return strings.ToLower(host) + ":" + path, false, true
	}
	literalAuth = rubyURLCredential(raw)
	// URL parsers disagree on which "@" ends a doubled userinfo.
	authority, _, _ := strings.Cut(raw[strings.Index(raw, "://")+3:], "/")
	if strings.Count(authority, "@") > 1 {
		return "", literalAuth, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return "", literalAuth, false
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "file":
		if u.User != nil || u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
			return "", literalAuth, false
		}
		return raw, false, true
	case "http", "https", "ssh", "git", "git+ssh":
	default:
		return "", literalAuth, false
	}
	path := u.EscapedPath()
	if decoded, err := url.PathUnescape(path); u.Hostname() == "" || err != nil || strings.Contains(decoded, "@") || !composerSafeText(decoded, 4096) {
		return "", literalAuth, false
	}
	if scheme == "http" || scheme == "https" {
		path = strings.TrimSuffix(path, "/")
	}
	user := ""
	if _, password := u.User.Password(); (scheme == "ssh" || scheme == "git+ssh") && u.User != nil && !password {
		// As in SCP-like syntax, an SSH username selects whose home "~"
		// means; only a password is a credential.
		name := u.User.Username()
		if name == "" || strings.ContainsAny(name, "@:/%") || !composerSafeText(name, 256) {
			return "", literalAuth, false
		}
		user = name + "@"
	}
	return scheme + "://" + user + strings.ToLower(u.Host) + path, literalAuth, true
}

// SwiftAbsPath accepts POSIX, drive and UNC absolute paths, so a file
// recorded on Windows reads the same on every scanner platform.
func SwiftAbsPath(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) || len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') && (p[0]|0x20 >= 'a' && p[0]|0x20 <= 'z')
}

// SwiftRegistryScope and SwiftRegistryName follow SwiftPM's registry identity
// rules, restricted to ASCII.
func SwiftRegistryScope(s string) bool {
	if len(s) == 0 || len(s) > 39 || s[0] == '-' || s[len(s)-1] == '-' || strings.Contains(s, "--") {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return !swiftAlnum(r) && r != '-' })
}

func SwiftRegistryName(s string) bool {
	if len(s) == 0 || len(s) > 100 || !swiftAlnum(rune(s[0])) {
		return false
	}
	sep := func(c byte) bool { return c == '-' || c == '_' }
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !swiftAlnum(rune(c)) && !sep(c) || sep(c) && (i == len(s)-1 || sep(s[i+1])) {
			return false
		}
	}
	return true
}

func swiftAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

// SwiftConfigScope comes from the resolved developer, never a login shell.
type SwiftConfigScope struct {
	Username, Home string
	Protected      func(string) string
	// Library guards readers rooted at LibraryRoots (macOS only).
	Library         func(string) string
	LibraryRoots    []string
	Volume          func(string) bool
	ProcessVerified bool
}

// SwiftProjectFiles are a project's configuration files that its directory
// listings found; an empty path was not listed.
type SwiftProjectFiles struct{ Mirrors, Registries, Legacy string }

type swiftProjectConfig struct {
	dir     string
	files   []*model.RubyConfigFile
	partial bool
}

// SwiftConfigSnapshot accumulates SwiftPM configuration observations as
// inventory discovers projects. Leads are verified absolute environment
// paths, not proof that any invocation used them.
type SwiftConfigSnapshot struct {
	// ScratchLeads come from SWIFTPM_BUILD_DIR; CacheLeads from Linux
	// XDG_CACHE_HOME. DotSwiftPM are the bases whose cache alias may exist.
	ScratchLeads, CacheLeads, DotSwiftPM []string
	// InventoryReasons are lead failures that also limit inventory coverage.
	InventoryReasons []string
	exec             executor.Executor
	ctx              context.Context
	scope            SwiftConfigScope
	audit            model.RubyConfigAudit
	files            map[string]*model.RubyConfigFile
	process          *model.RubyConfigFile
	user             []*model.RubyConfigFile // modern before legacy
	projects         map[string]*swiftProjectConfig
	credentials      map[string]bool
	protected        map[string]bool
	partial          bool
	bytes            int
	limited          bool
}

type SwiftConfigDetector struct{ exec executor.Executor }

func NewSwiftConfigDetector(exec executor.Executor) *SwiftConfigDetector {
	return &SwiftConfigDetector{exec: exec}
}

func emptySwiftAudit() model.RubyConfigAudit {
	return model.RubyConfigAudit{SchemaVersion: model.SwiftInventorySchemaVersion, Status: "complete", Reasons: []string{}, Files: []model.RubyConfigFile{},
		Contexts: []model.RubyConfigContext{}, CredentialFiles: []model.SwiftCredentialFile{}, Findings: []model.CargoConfigFinding{}}
}

func (d *SwiftConfigDetector) Detect(ctx context.Context, scope SwiftConfigScope) *SwiftConfigSnapshot {
	a := &SwiftConfigSnapshot{exec: d.exec, ctx: ctx, scope: scope, audit: emptySwiftAudit(), files: map[string]*model.RubyConfigFile{},
		projects: map[string]*swiftProjectConfig{}, credentials: map[string]bool{}, protected: map[string]bool{}}
	a.bytes = swiftAuditSize(a.audit) + 128
	if scope.Username == "" || scope.Home == "" {
		a.Partial("user_unresolved")
		return a
	}
	if ctx.Err() != nil {
		a.Partial("deadline_exceeded")
		return a
	}
	home, goos := scope.Home, d.exec.GOOS()
	netrc := filepath.Join(home, ".netrc")
	a.protect(netrc)
	env := map[string]string{}
	if scope.ProcessVerified {
		keys := []string{"SWIFTPM_BUILD_DIR", "SWIFTPM_MIRROR_CONFIG", "XDG_CONFIG_HOME"}
		if goos == model.PlatformLinux {
			keys = append(keys, "XDG_CACHE_HOME")
		}
		for _, key := range keys {
			v := a.exec.Getenv(key)
			if v == "" {
				continue
			}
			if !filepath.IsAbs(v) || !composerSafeText(v, 4096) {
				// The mirror file is audit-only, build and cache leads are
				// inventory-only, and the config home feeds both.
				if key == "SWIFTPM_MIRROR_CONFIG" || key == "XDG_CONFIG_HOME" {
					a.degrade("path_unresolved")
				}
				if key != "SWIFTPM_MIRROR_CONFIG" && !slices.Contains(a.InventoryReasons, "path_unresolved") {
					a.InventoryReasons = append(a.InventoryReasons, "path_unresolved")
				}
				continue
			}
			env[key] = filepath.Clean(v)
		}
	} else {
		// No process environment of the developer was observed.
		a.Partial("user_unresolved")
	}
	if dir := env["SWIFTPM_BUILD_DIR"]; dir != "" {
		a.ScratchLeads = append(a.ScratchLeads, dir)
	}
	if dir := env["XDG_CACHE_HOME"]; dir != "" {
		a.CacheLeads = append(a.CacheLeads, filepath.Join(dir, "org.swift.swiftpm"))
	}
	dot := filepath.Join(home, ".swiftpm")
	if dir := env["XDG_CONFIG_HOME"]; dir != "" {
		dot = filepath.Join(dir, "swiftpm")
	}
	a.DotSwiftPM = []string{dot}
	// SwiftPM's security state (fingerprints, signing history) is never read,
	// even through a configuration link or a process lead.
	bases := []string{filepath.Join(home, ".swiftpm"), dot}
	if goos == model.PlatformDarwin {
		bases = append(bases, filepath.Join(home, "Library", "org.swift.swiftpm"))
	}
	for _, base := range bases {
		a.protect(filepath.Join(base, "security"))
	}
	if p := env["SWIFTPM_MIRROR_CONFIG"]; p != "" {
		a.process = a.readFile("process", p, a.parseMirrors)
	}
	if goos == model.PlatformDarwin {
		base := filepath.Join(home, "Library", "org.swift.swiftpm")
		a.user = append(a.user, a.readFile("user", filepath.Join(base, "configuration", "mirrors.json"), a.parseMirrors),
			a.readFile("user", filepath.Join(base, "configuration", "registries.json"), a.parseRegistries))
		a.user = append(a.user, a.legacy(base, base)...)
	} else {
		a.user = append(a.user, a.readFile("user", filepath.Join(dot, "configuration", "mirrors.json"), a.parseMirrors),
			a.readFile("user", filepath.Join(dot, "configuration", "registries.json"), a.parseRegistries))
		a.user = append(a.user, a.legacy(filepath.Join(dot, "config"), "")...)
		if fallback := filepath.Join(home, ".swiftpm"); a.key(fallback) != a.key(dot) {
			a.user = append(a.user, a.legacy(filepath.Join(fallback, "configuration"), "")...)
			a.user = append(a.user, a.legacy(filepath.Join(fallback, "config"), "")...)
		}
	}
	a.credential(netrc)
	return a
}

// legacy reads the shared mirrors.json and registries.json in dir only when
// its listing holds them. root is the Library root a reader must use.
func (a *SwiftConfigSnapshot) legacy(dir, root string) []*model.RubyConfigFile {
	if a.ctx.Err() != nil {
		a.Partial("deadline_exceeded")
		return nil
	}
	files := a.exec.GuardedFiles([]string{dir}, a.ContentGuard, 0)
	if root != "" {
		files = a.exec.GuardedFiles([]string{root}, a.LibraryGuard, 0)
	}
	entries, more, err := files.ReadDirLimit(dir, swiftListLimit)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		a.Partial(CargoReadReason(err, dir, a.scope.Volume))
		return nil
	}
	if more {
		a.Partial("entry_limit")
	}
	out := []*model.RubyConfigFile{}
	for _, e := range entries {
		switch e.Name() {
		case "mirrors.json":
			out = append(out, a.readFile("user", filepath.Join(dir, e.Name()), a.parseMirrors))
		case "registries.json":
			out = append(out, a.readFile("user", filepath.Join(dir, e.Name()), a.parseRegistries))
		}
	}
	return out
}

// ContentGuard keeps credential files existence-only, including redirected reads.
func (a *SwiftConfigSnapshot) ContentGuard(path string) string {
	if a.scope.Protected != nil {
		if reason := a.scope.Protected(path); reason != "" {
			return reason
		}
	}
	return a.credentialGuard(path)
}

// protect makes path and everything below it existence-only, at its logical
// and resolved location. Under ~/Library only the approved reader may resolve.
func (a *SwiftConfigSnapshot) protect(path string) {
	a.protected[a.key(path)] = true
	if a.ctx.Err() != nil {
		return
	}
	guard := a.scope.Protected
	if a.libraryRoot(path) != "" {
		if a.scope.Library == nil {
			return // nothing under ~/Library is read either
		}
		guard = a.scope.Library
	}
	if resolved, err := a.exec.GuardedFiles([]string{path}, guard, 0).EvalSymlinks(path); err == nil {
		a.protected[a.key(resolved)] = true
	}
}

func (a *SwiftConfigSnapshot) credentialGuard(path string) string {
	key := a.key(path)
	for p := range a.protected {
		if key == p || isLexicalAncestor(p, key) {
			return "skipped_protected"
		}
	}
	return ""
}

// LibraryGuard is the guard for readers rooted at the ~/Library roots:
// credential paths stay existence-only before the roots are admitted.
func (a *SwiftConfigSnapshot) LibraryGuard(path string) string {
	if reason := a.credentialGuard(path); reason != "" {
		return reason
	}
	if a.scope.Library == nil {
		return "skipped_protected"
	}
	return a.scope.Library(path)
}

// libraryRoot returns the Library root holding p, or "".
func (a *SwiftConfigSnapshot) libraryRoot(p string) string {
	for _, root := range a.scope.LibraryRoots {
		if GoWithinRoots(a.exec.GOOS(), p, []string{root}) {
			return root
		}
	}
	return ""
}

func (a *SwiftConfigSnapshot) key(p string) string { return GoPathKey(a.exec.GOOS(), p) }

func (a *SwiftConfigSnapshot) degrade(reason string) {
	a.audit.Status = "partial"
	if !slices.Contains(a.audit.Reasons, reason) {
		a.audit.Reasons = append(a.audit.Reasons, reason)
	}
}

// Partial marks every context incomplete, as when project discovery was cut short.
func (a *SwiftConfigSnapshot) Partial(reason string) {
	a.partial = true
	a.degrade(reason)
}

func (a *SwiftConfigSnapshot) fileReason(f *model.RubyConfigFile, status, reason string) {
	f.Status = status
	a.limitation(f, reason)
}

// limitation keeps a parseable file present with its supported settings and
// records why its coverage is incomplete.
func (a *SwiftConfigSnapshot) limitation(f *model.RubyConfigFile, reason string) {
	if !slices.Contains(f.Reasons, reason) {
		f.Reasons = append(f.Reasons, reason)
	}
	a.degrade(reason)
}

func (a *SwiftConfigSnapshot) record(scope, path string) *model.RubyConfigFile {
	id := GoSourceID(a.scope.Username, "swift_config_"+scope, path)
	if f := a.files[id]; f != nil {
		return f
	}
	f := &model.RubyConfigFile{SourceID: id, Manager: swiftManager, Scope: scope, Path: path, Status: "absent", Reasons: []string{}, Settings: []model.CargoConfigSetting{}}
	size := swiftAuditSize(f) + 128 // room for later coverage reasons
	if a.limited || a.bytes+size > maxSwiftAuditBytes {
		a.limited = true
		a.degrade("output_size_limit")
		return nil
	}
	a.files[id] = f
	a.bytes += size
	return f
}

func (a *SwiftConfigSnapshot) setting(f *model.RubyConfigFile, key, value string, redacted bool) {
	if !composerSafeText(value, 4096) || len(key) > 512 {
		a.limitation(f, "unsupported_format")
		return
	}
	if slices.ContainsFunc(f.Settings, func(x model.CargoConfigSetting) bool { return x.Key == key && x.Display == value }) {
		return
	}
	if len(f.Settings) >= swiftSettingLimit {
		a.limitation(f, "record_limit")
		return
	}
	setting := model.CargoConfigSetting{Key: key, Display: value, SourceID: f.SourceID, Redacted: redacted}
	size := swiftAuditSize(setting)
	// Reserve the possible finding before admitting its setting.
	for _, finding := range swiftFindings(model.RubyConfigFile{SourceID: f.SourceID, Settings: []model.CargoConfigSetting{setting}}) {
		size += swiftAuditSize(finding)
	}
	if a.limited || a.bytes+size > maxSwiftAuditBytes {
		a.limited = true
		a.limitation(f, "output_size_limit")
		return
	}
	a.bytes += size
	f.Settings = append(f.Settings, setting)
}

// readFile observes one file. A file under a macOS Library root is read only
// through that root's reader; elsewhere a missing file cannot establish its
// own root through a parent symlink.
func (a *SwiftConfigSnapshot) readFile(scope, p string, parse func(*model.RubyConfigFile, []byte)) *model.RubyConfigFile {
	f := a.record(scope, p)
	if f == nil || f.Status != "absent" || len(f.Reasons) > 0 {
		return f
	}
	if a.ctx.Err() != nil {
		a.fileReason(f, "unreadable", "deadline_exceeded")
		return f
	}
	files := a.exec.GuardedFiles([]string{filepath.Dir(p), p}, a.ContentGuard, swiftConfigBytes)
	if root := a.libraryRoot(p); root != "" {
		files = a.exec.GuardedFiles([]string{root}, a.LibraryGuard, swiftConfigBytes)
	}
	info, err := files.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return f
	}
	if err != nil {
		a.readFailure(f, err, p)
		return f
	}
	if !info.Mode().IsRegular() {
		a.fileReason(f, "unsupported", "unsupported_entry")
		return f
	}
	if info.Size() > swiftConfigBytes {
		a.fileReason(f, "unreadable", "size_limit")
		return f
	}
	if a.ctx.Err() != nil {
		a.fileReason(f, "unreadable", "deadline_exceeded")
		return f
	}
	data, err := files.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		a.fileReason(f, "unreadable", "changed_during_scan")
		return f
	}
	if err != nil {
		a.readFailure(f, err, p)
		return f
	}
	f.Status = "present"
	parse(f, data)
	return f
}

func (a *SwiftConfigSnapshot) readFailure(f *model.RubyConfigFile, err error, p string) {
	reason := CargoReadReason(err, p, a.scope.Volume)
	status := "unreadable"
	if reason == "skipped_protected" || reason == "refused_network_volume" {
		status = "skipped_protected"
	}
	a.fileReason(f, status, reason)
}

// SwiftJSON decodes one JSON object and rejects trailing data. Unknown
// fields are allowed: SwiftPM adds optional fields within a schema version.
func SwiftJSON(data []byte, v any) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return errors.New("not an object")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// swiftDisplay renders a URL field and reports a literal credential.
func swiftDisplay(raw string) (display string, redacted, literal bool) {
	display, literal, ok := SwiftURL(raw)
	if !ok {
		return goRedacted, true, literal
	}
	return display, literal, literal
}

func (a *SwiftConfigSnapshot) invalid(f *model.RubyConfigFile) {
	f.Settings = []model.CargoConfigSetting{}
	a.fileReason(f, "invalid", "parse_error")
}

// parseMirrors reads a mirrors file in the modern or legacy location. Like
// SwiftPM it ignores the version and keeps the first mapping of an original.
func (a *SwiftConfigSnapshot) parseMirrors(f *model.RubyConfigFile, data []byte) {
	var doc struct {
		Object *[]struct {
			Original *string `json:"original"`
			Mirror   *string `json:"mirror"`
		} `json:"object"`
	}
	if SwiftJSON(data, &doc) != nil || doc.Object == nil {
		a.invalid(f)
		return
	}
	type row struct {
		original, mirror       string
		originalRed, mirrorRed bool
		originalLit, mirrorLit bool
	}
	rows := []row{}
	seen := map[string]bool{}
	for _, m := range *doc.Object {
		if m.Original == nil || m.Mirror == nil {
			a.invalid(f)
			return
		}
		if seen[*m.Original] {
			continue
		}
		seen[*m.Original] = true
		o, r1, l1 := swiftDisplay(*m.Original)
		d, r2, l2 := swiftDisplay(*m.Mirror)
		rows = append(rows, row{o, d, r1, r2, l1, l2})
	}
	sortKey := func(r row) string {
		return r.original + "\x00" + r.mirror + "\x00" + strconv.FormatBool(r.originalLit) + strconv.FormatBool(r.mirrorLit)
	}
	slices.SortFunc(rows, func(x, y row) int { return strings.Compare(sortKey(x), sortKey(y)) })
	rows = slices.CompactFunc(rows, func(x, y row) bool { return sortKey(x) == sortKey(y) })
	for i, r := range rows {
		prefix := "mirrors." + strconv.Itoa(i) + "."
		a.setting(f, prefix+"original", r.original, r.originalRed)
		a.setting(f, prefix+"mirror", r.mirror, r.mirrorRed)
		if r.originalLit {
			a.setting(f, prefix+"original"+swiftLiteralSuffix, "true", false)
		}
		if r.mirrorLit {
			a.setting(f, prefix+"mirror"+swiftLiteralSuffix, "true", false)
		}
	}
}

// parseRegistries reads registries.json version 1. Authentication keeps only
// the host, type and that it is configured; no credential is ever stored there.
func (a *SwiftConfigSnapshot) parseRegistries(f *model.RubyConfigFile, data []byte) {
	var doc struct {
		Version        *int                       `json:"version"`
		Registries     map[string]json.RawMessage `json:"registries"`
		Authentication map[string]json.RawMessage `json:"authentication"`
		Security       *struct {
			Default           *swiftSecurityEntry           `json:"default"`
			RegistryOverrides map[string]swiftSecurityEntry `json:"registryOverrides"`
			ScopeOverrides    map[string]swiftSecurityEntry `json:"scopeOverrides"`
			PackageOverrides  map[string]swiftSecurityEntry `json:"packageOverrides"`
		} `json:"security"`
	}
	if SwiftJSON(data, &doc) != nil || doc.Version == nil {
		a.invalid(f)
		return
	}
	if *doc.Version != 1 {
		f.Settings = []model.CargoConfigSetting{}
		a.fileReason(f, "unsupported", "unsupported_format")
		return
	}
	if doc.Registries == nil {
		a.invalid(f)
		return
	}
	type registry struct {
		scope, url        string
		redacted, literal bool
	}
	registries := []registry{}
	for scope, raw := range doc.Registries {
		var r struct {
			URL *string `json:"url"`
		}
		if scope != swiftDefaultScope && !SwiftRegistryScope(scope) || SwiftJSON(raw, &r) != nil || r.URL == nil {
			a.invalid(f)
			return
		}
		u, redacted, literal := swiftDisplay(*r.URL)
		registries = append(registries, registry{scope, u, redacted, literal})
	}
	slices.SortFunc(registries, func(x, y registry) int {
		return strings.Compare(x.scope+"\x00"+x.url+"\x00"+strconv.FormatBool(x.literal), y.scope+"\x00"+y.url+"\x00"+strconv.FormatBool(y.literal))
	})
	for i, r := range registries {
		prefix := "registries." + strconv.Itoa(i) + "."
		a.setting(f, prefix+"scope", r.scope, false)
		a.setting(f, prefix+"url", r.url, r.redacted)
		if r.literal {
			a.setting(f, prefix+"url"+swiftLiteralSuffix, "true", false)
		}
	}
	for i, host := range sortedKeys(doc.Authentication) {
		var auth struct {
			Type *string `json:"type"`
		}
		if SwiftJSON(doc.Authentication[host], &auth) != nil || auth.Type == nil {
			a.invalid(f)
			return
		}
		prefix := "authentication." + strconv.Itoa(i) + "."
		display, redacted := swiftHost(host)
		a.setting(f, prefix+"host", display, redacted)
		if *auth.Type == "basic" || *auth.Type == "token" {
			a.setting(f, prefix+"type", *auth.Type, false)
		} else {
			a.limitation(f, "unsupported_format")
		}
		a.setting(f, prefix+"configured", "true", false)
	}
	if s := doc.Security; s != nil {
		if s.Default != nil {
			a.signing(f, "security.default.signing.", s.Default.Signing, true)
		}
		for i, host := range sortedKeys(s.RegistryOverrides) {
			prefix := "security.registry_overrides." + strconv.Itoa(i) + "."
			display, redacted := swiftHost(host)
			a.setting(f, prefix+"host", display, redacted)
			a.signing(f, prefix+"signing.", s.RegistryOverrides[host].Signing, true)
		}
		for i, scope := range sortedKeys(s.ScopeOverrides) {
			prefix := "security.scope_overrides." + strconv.Itoa(i) + "."
			if !SwiftRegistryScope(scope) {
				a.invalid(f)
				return
			}
			a.setting(f, prefix+"scope", scope, false)
			a.signing(f, prefix+"signing.", s.ScopeOverrides[scope].Signing, false)
		}
		for i, pkg := range sortedKeys(s.PackageOverrides) {
			prefix := "security.package_overrides." + strconv.Itoa(i) + "."
			scope, name, ok := strings.Cut(pkg, ".")
			if !ok || !SwiftRegistryScope(scope) || !SwiftRegistryName(name) {
				a.invalid(f)
				return
			}
			a.setting(f, prefix+"package", pkg, false)
			a.signing(f, prefix+"signing.", s.PackageOverrides[pkg].Signing, false)
		}
	}
}

type swiftSecurityEntry struct {
	Signing map[string]json.RawMessage `json:"signing"`
}

// signing emits the supported signing keys. Scope and package overrides
// support only the trust-root keys; SwiftPM ignores their other keys.
func (a *SwiftConfigSnapshot) signing(f *model.RubyConfigFile, prefix string, signing map[string]json.RawMessage, actions bool) {
	values := map[string]json.RawMessage{}
	for k, v := range signing {
		values[k] = v
	}
	if raw, ok := signing["validationChecks"]; ok && actions {
		var checks map[string]json.RawMessage
		if json.Unmarshal(raw, &checks) != nil {
			a.limitation(f, "unsupported_format")
		}
		for k, v := range checks {
			values["validationChecks."+k] = v
		}
	}
	for _, key := range sortedKeys(values) {
		raw := values[key]
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		switch {
		case key == "trustedRootCertificatesPath":
			var p string
			if json.Unmarshal(raw, &p) != nil {
				a.limitation(f, "unsupported_format")
				continue
			}
			display, redacted := p, false
			if !composerSafeText(p, 4096) || strings.ContainsAny(p, "@?#") {
				display, redacted = goRedacted, true
			}
			a.setting(f, prefix+key, display, redacted)
		case key == "includeDefaultTrustedRootCertificates":
			var b bool
			if json.Unmarshal(raw, &b) != nil {
				a.limitation(f, "unsupported_format")
				continue
			}
			a.setting(f, prefix+key, strconv.FormatBool(b), false)
		case actions && swiftSigningEnums[key] != nil:
			var v string
			if json.Unmarshal(raw, &v) != nil || !slices.Contains(swiftSigningEnums[key], v) {
				// An invalid value degrades the file; it never becomes a default.
				a.limitation(f, "unsupported_format")
				continue
			}
			a.setting(f, prefix+key, v, false)
		}
	}
}

// swiftHost keeps a configured host key only when it is a bare host.
func swiftHost(host string) (string, bool) {
	if !composerSafeText(host, 512) || host == "" || strings.ContainsAny(host, "@/?# \\") {
		return goRedacted, true
	}
	return strings.ToLower(host), false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Project observes one project's configuration files, given as the absolute
// paths its directory listings found.
func (a *SwiftConfigSnapshot) Project(dir string, files SwiftProjectFiles) {
	if a.scope.Username == "" {
		return
	}
	p := a.projectConfig(dir)
	if files.Mirrors != "" {
		p.files = append(p.files, a.readFile("project", files.Mirrors, a.parseMirrors))
	}
	if files.Registries != "" {
		p.files = append(p.files, a.readFile("project", files.Registries, a.parseRegistries))
	}
	if files.Legacy != "" {
		p.files = append(p.files, a.readFile("project", files.Legacy, a.parseMirrors))
	}
}

// Unlisted marks a project's context partial when one of its configuration
// folders could not be fully listed.
func (a *SwiftConfigSnapshot) Unlisted(dir, reason string) {
	if a.scope.Username == "" {
		return
	}
	a.projectConfig(dir).partial = true
	a.degrade(reason)
}

func (a *SwiftConfigSnapshot) projectConfig(dir string) *swiftProjectConfig {
	p := a.projects[a.key(dir)]
	if p == nil {
		p = &swiftProjectConfig{dir: dir}
		a.projects[a.key(dir)] = p
	}
	return p
}

func (a *SwiftConfigSnapshot) credential(path string) {
	if a.limited || a.credentials[a.key(path)] {
		return
	}
	a.credentials[a.key(path)] = true
	c := model.SwiftCredentialFile{Path: path, Status: "present", Presence: "present"}
	if a.ctx.Err() != nil {
		c.Status, c.Presence = "unreadable", "unknown"
		a.degrade("deadline_exceeded")
	} else {
		info, err := a.exec.GuardedFiles([]string{path}, a.scope.Protected, 0).Stat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			c.Status, c.Presence = "absent", "absent"
		case err != nil:
			c.Status, c.Presence = "unreadable", "unknown"
			reason := CargoReadReason(err, path, a.scope.Volume)
			if reason == "skipped_protected" || reason == "refused_network_volume" {
				c.Status = "skipped_protected"
			}
			a.degrade(reason)
		case !info.Mode().IsRegular():
			c.Status, c.Presence = "unsupported", "unknown"
			a.degrade("unsupported_entry")
		}
	}
	size := swiftAuditSize(c)
	if a.bytes+size > maxSwiftAuditBytes {
		a.limited = true
		a.degrade("output_size_limit")
		return
	}
	a.audit.CredentialFiles = append(a.audit.CredentialFiles, c)
	a.bytes += size
}

func (a *SwiftConfigSnapshot) context(c model.RubyConfigContext) {
	if a.limited {
		return
	}
	size := swiftAuditSize(c)
	if a.bytes+size > maxSwiftAuditBytes {
		a.limited = true
		a.degrade("output_size_limit")
		return
	}
	a.audit.Contexts = append(a.audit.Contexts, c)
	a.bytes += size
}

// chain lists observed sources highest precedence first: the process mirror
// file, project files, then user files. It describes observed files, not an
// effective merge: mirrors and registries combine by different rules.
func (a *SwiftConfigSnapshot) chain(p *swiftProjectConfig) ([]string, bool) {
	ids := []string{}
	partial := a.partial
	add := func(files ...*model.RubyConfigFile) {
		for _, f := range files {
			if f == nil {
				partial = true
				continue
			}
			if !slices.Contains(ids, f.SourceID) {
				ids = append(ids, f.SourceID)
			}
			if f.Status != "present" && f.Status != "absent" || len(f.Reasons) > 0 {
				partial = true
			}
		}
	}
	if a.process != nil {
		add(a.process)
	}
	if p != nil {
		partial = partial || p.partial
		add(p.files...)
	}
	add(a.user...)
	return ids, partial
}

func (a *SwiftConfigSnapshot) Finish() model.SwiftConfigAudit {
	if a.scope.Username != "" {
		ids, partial := a.chain(nil)
		a.context(model.RubyConfigContext{Manager: swiftManager, ConfigSourceIDs: ids, SelectionStatus: swiftSelection(partial)})
		for _, p := range a.projects {
			ids, partial := a.chain(p)
			a.context(model.RubyConfigContext{Manager: swiftManager, ProjectPath: p.dir, ConfigSourceIDs: ids, SelectionStatus: swiftSelection(partial)})
		}
	}
	for _, f := range a.files {
		// An incomplete source has no current settings or findings.
		if f.Status != "present" {
			f.Settings = []model.CargoConfigSetting{}
		}
		slices.Sort(f.Reasons)
		slices.SortFunc(f.Settings, func(x, y model.CargoConfigSetting) int {
			return strings.Compare(x.Key+"\x00"+x.Display, y.Key+"\x00"+y.Display)
		})
		a.audit.Files = append(a.audit.Files, *f)
		a.audit.Findings = append(a.audit.Findings, swiftFindings(*f)...)
	}
	slices.SortFunc(a.audit.Files, func(x, y model.RubyConfigFile) int {
		return strings.Compare(x.Scope+"\x00"+x.Path, y.Scope+"\x00"+y.Path)
	})
	slices.SortFunc(a.audit.Contexts, func(x, y model.RubyConfigContext) int {
		return strings.Compare(x.ProjectPath+"\x00"+strings.Join(x.ConfigSourceIDs, ","), y.ProjectPath+"\x00"+strings.Join(y.ConfigSourceIDs, ","))
	})
	slices.SortFunc(a.audit.CredentialFiles, func(x, y model.SwiftCredentialFile) int { return strings.Compare(x.Path, y.Path) })
	slices.SortFunc(a.audit.Findings, func(x, y model.CargoConfigFinding) int {
		return strings.Compare(x.Code+"\x00"+x.SourceID+"\x00"+x.Key, y.Code+"\x00"+y.SourceID+"\x00"+y.Key)
	})
	slices.Sort(a.audit.Reasons)
	return a.audit
}

func swiftSelection(partial bool) string {
	if partial {
		return "partial"
	}
	return "observed"
}

// swiftAuditSize includes JSON escaping and the array separator.
func swiftAuditSize(record any) int {
	data, _ := json.Marshal(record)
	return len(data) + 1
}

// swiftFindings derives the catalog from kept settings. Details are fixed
// text and never claim the setting was used.
func swiftFindings(f model.RubyConfigFile) []model.CargoConfigFinding {
	var out []model.CargoConfigFinding
	add := func(code, severity, key, detail string) {
		out = append(out, model.CargoConfigFinding{Code: code, Severity: severity, SourceID: f.SourceID, Key: key, Detail: detail})
	}
	for _, s := range f.Settings {
		parts := strings.Split(s.Key, ".")
		indexed := len(parts) >= 3 && parts[1] != "" && strings.Trim(parts[1], "0123456789") == ""
		field := ""
		if indexed {
			field = parts[0] + "." + strings.Join(parts[2:], ".")
		}
		switch {
		case (field == "registries.url" || field == "mirrors.mirror") && strings.HasPrefix(s.Display, "http://"):
			add("swift-001", "MEDIUM", s.Key, "A configured SwiftPM registry or mirror destination uses an unencrypted HTTP URL.")
		case (field == "registries.url"+swiftLiteralSuffix || field == "mirrors.mirror"+swiftLiteralSuffix || field == "mirrors.original"+swiftLiteralSuffix) && s.Display == "true":
			add("swift-002", "MEDIUM", s.Key, "A configured SwiftPM URL contains a literal credential.")
		case s.Display == "silentAllow" && swiftSigningAction(s.Key):
			add("swift-003", "LOW", s.Key, "Registry signing warnings suppressed; signature validation itself is not disabled.")
		}
	}
	return out
}

// swiftSigningAction reports a warning-action key of the default or a
// registry override; scope and package overrides do not support actions.
func swiftSigningAction(key string) bool {
	action, ok := strings.CutPrefix(key, "security.default.signing.")
	if !ok {
		rest, found := strings.CutPrefix(key, "security.registry_overrides.")
		var index string
		index, action, ok = strings.Cut(rest, ".signing.")
		if !found || !ok || index == "" || strings.Trim(index, "0123456789") != "" {
			return false
		}
	}
	return action == "onUnsigned" || action == "onUntrustedCertificate"
}
