package configaudit

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

var maxRubyAuditBytes = 256 << 10

const rubyConfigBytes int64 = 2 << 20
const rubySettingLimit = 256

var (
	rubyGemNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	rubyTokenPattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	rubyHostPattern    = regexp.MustCompile(`^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z][a-z0-9-]*(?::[0-9]+)?$`)
	rubyIntPattern     = regexp.MustCompile(`^[0-9]{1,9}$`)
	rubyDecimalPattern = regexp.MustCompile(`^[0-9]{1,9}(?:\.[0-9]{1,9})?$`)
)

// RubyGemName is the bounded package-name grammar, with at least one letter.
func RubyGemName(s string) bool {
	return len(s) <= 256 && rubyGemNamePattern.MatchString(s) && strings.ContainsFunc(s, unicode.IsLetter)
}

// RubyToken bounds artifact platforms and group/platform labels.
func RubyToken(s string) bool { return len(s) <= 256 && rubyTokenPattern.MatchString(s) }

// RubyConfigScope comes from the resolved developer, never a login shell.
type RubyConfigScope struct {
	Username, Home  string
	Protected       func(string) string
	Volume          func(string) bool
	ProcessVerified bool
}

// RubyManifestSource is one literal Gemfile source. URL is raw and stays in
// memory; only its sanitized display is serialized.
type RubyManifestSource struct{ Type, URL, Cooldown string }

// RubyManifest is a manifest already read by inventory, so this package
// never parses Ruby. Status uses the file-status vocabulary.
type RubyManifest struct {
	Path, Status string
	Reasons      []string
	Sources      []RubyManifestSource
	Lockfile     string
	NoLockfile   bool
}

// RubyProject is one Bundler project: its root manifest first, then
// manifests it evaluates.
type RubyProject struct {
	Dir       string
	Manifests []RubyManifest
}

// RubyProjectLeads are discovery locations, not a claimed effective config.
// An empty Path means Bundler uses shared gem homes found independently.
type RubyProjectLeads struct {
	Path, CachePath, AppConfig, Lockfile string
	Partial                              bool
}

// RubyConfigSnapshot accumulates RubyGems and Bundler observations as
// inventory discovers interpreter prefixes and projects.
type RubyConfigSnapshot struct {
	GemHomes              []string
	UserCache, UserPlugin string
	Gemfile               string
	exec                  executor.Executor
	ctx                   context.Context
	scope                 RubyConfigScope
	audit                 model.RubyConfigAudit
	files                 map[string]*model.RubyConfigFile
	parsed                map[string]bool
	env                   map[string]string
	leads                 map[string]map[string]string
	literal               map[string]bool
	homes                 map[string]bool
	credentials           map[string]bool
	credentialPaths       map[string]bool
	gemProcess, bundle    *model.RubyConfigFile
	userGemrc, systemrc   []*model.RubyConfigFile
	global                *model.RubyConfigFile
	ignoreConfig          bool
	partial               bool
	systemPartial         bool // interpreter prefixes not fully discovered
	bytes                 int
	limited               bool
}

type RubyConfigDetector struct{ exec executor.Executor }

func NewRubyConfigDetector(exec executor.Executor) *RubyConfigDetector {
	return &RubyConfigDetector{exec: exec}
}

func emptyRubyAudit() model.RubyConfigAudit {
	return model.RubyConfigAudit{SchemaVersion: model.RubyInventorySchemaVersion, Status: "complete", Reasons: []string{}, Files: []model.RubyConfigFile{}, Contexts: []model.RubyConfigContext{}, CredentialFiles: []model.RubyCredentialFile{}, Findings: []model.CargoConfigFinding{}}
}

func (d *RubyConfigDetector) Detect(ctx context.Context, scope RubyConfigScope) *RubyConfigSnapshot {
	a := &RubyConfigSnapshot{exec: d.exec, ctx: ctx, scope: scope, audit: emptyRubyAudit(), files: map[string]*model.RubyConfigFile{}, parsed: map[string]bool{}, env: map[string]string{},
		leads: map[string]map[string]string{}, literal: map[string]bool{}, homes: map[string]bool{}, credentials: map[string]bool{}}
	if scope.Username == "" || scope.Home == "" {
		a.degrade("user_unresolved")
		return a
	}
	if ctx.Err() != nil {
		a.degrade("deadline_exceeded")
		return a
	}
	home := scope.Home
	a.gemProcess, a.bundle = a.record("rubygems", "process", ""), a.record("bundler", "process", "")
	gemrc := []string{}
	if scope.ProcessVerified {
		gemrc = a.processEnv()
	} else {
		a.fileReason(a.gemProcess, "unsupported", "user_unresolved")
		a.fileReason(a.bundle, "unsupported", "user_unresolved")
		a.partial = true
	}
	a.credentialPaths = map[string]bool{}
	for _, p := range []string{
		filepath.Join(home, ".gem", "credentials"),
		filepath.Join(home, ".local", "share", "gem", "credentials"),
		filepath.Join(cmpOr(a.env["XDG_DATA_HOME"], filepath.Join(home, ".local", "share")), "gem", "credentials"),
	} {
		a.credentialPaths[a.key(p)] = true
		if resolved, err := a.exec.GuardedFiles([]string{p}, scope.Protected, 0).EvalSymlinks(p); err == nil {
			a.credentialPaths[a.key(resolved)] = true
		}
	}
	// GEMRC files merge in list order, so the last one has highest precedence.
	for _, p := range slices.Backward(gemrc) {
		a.userGemrc = append(a.userGemrc, a.readFile("rubygems", "user", p, a.parseGemrc))
	}
	user := a.readFile("rubygems", "user", filepath.Join(home, ".gemrc"), a.parseGemrc)
	a.userGemrc = append(a.userGemrc, user)
	// RubyGems falls back to XDG only when ~/.gemrc does not exist; an
	// unreadable ~/.gemrc leaves both candidates possible.
	if user == nil || user.Status == "absent" || user.Status == "unreadable" || user.Status == "skipped_protected" {
		if user == nil || user.Status != "absent" {
			a.partial = true
		}
		configHome := cmpOr(a.env["XDG_CONFIG_HOME"], filepath.Join(home, ".config"))
		a.userGemrc = append(a.userGemrc, a.readFile("rubygems", "user", filepath.Join(configHome, "gem", "gemrc"), a.parseGemrc))
	}
	sysconf := "/etc"
	if d.exec.GOOS() == model.PlatformWindows {
		sysconf = cmpOr(a.env["PROGRAMDATA"], `C:\ProgramData`)
	}
	a.systemrc = append(a.systemrc, a.readFile("rubygems", "system", filepath.Join(sysconf, "gemrc"), a.parseGemrc))
	userHome := cmpOr(a.env["BUNDLE_USER_HOME"], filepath.Join(home, ".bundle"))
	global := filepath.Join(userHome, "config")
	for _, key := range []string{"BUNDLE_USER_CONFIG", "BUNDLE_CONFIG"} {
		if v := a.env[key]; v != "" {
			global = v
		}
	}
	a.global = a.readFile("bundler", "user", global, a.parseBundler)
	a.UserCache = cmpOr(a.env["BUNDLE_USER_CACHE"], filepath.Join(userHome, "cache"))
	a.UserPlugin = cmpOr(a.env["BUNDLE_USER_PLUGIN"], filepath.Join(userHome, "plugin"))
	a.Gemfile = a.env["BUNDLE_GEMFILE"]
	// Existence only; credential contents are never read.
	if a.credential(filepath.Join(home, ".gem", "credentials")) == "absent" {
		a.credential(filepath.Join(cmpOr(a.env["XDG_DATA_HOME"], filepath.Join(home, ".local", "share")), "gem", "credentials"))
	}
	return a
}

func cmpOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// Env returns a verified developer-process root selector as a safe absolute
// path, or "" when unset, unverified or unsafe.
func (a *RubyConfigSnapshot) Env(key string) string { return a.env[key] }

// ContentGuard keeps credential files existence-only, including redirected reads.
func (a *RubyConfigSnapshot) ContentGuard(path string) string {
	if a.scope.Protected != nil {
		if reason := a.scope.Protected(path); reason != "" {
			return reason
		}
	}
	if a.credentialPaths[a.key(path)] {
		return "skipped_protected"
	}
	return ""
}

func (a *RubyConfigSnapshot) key(p string) string { return GoPathKey(a.exec.GOOS(), p) }
func (a *RubyConfigSnapshot) degrade(reason string) {
	a.audit.Status = "partial"
	if !slices.Contains(a.audit.Reasons, reason) {
		a.audit.Reasons = append(a.audit.Reasons, reason)
	}
}
func (a *RubyConfigSnapshot) fileReason(f *model.RubyConfigFile, status, reason string) {
	if f != nil {
		f.Status = status
		if !slices.Contains(f.Reasons, reason) {
			f.Reasons = append(f.Reasons, reason)
		}
	}
	a.degrade(reason)
}
func (a *RubyConfigSnapshot) unresolved() {
	a.partial = true
	a.degrade("path_unresolved")
}

func rubySplitList(goos, v string) []string {
	sep := ":"
	if goos == model.PlatformWindows {
		sep = ";"
	}
	return strings.Split(v, sep)
}

// processEnv reads only allowlisted names. Root selectors are discovery
// leads; credential variables are reduced to presence.
func (a *RubyConfigSnapshot) processEnv() []string {
	e := a.exec
	for _, key := range []string{"GEM_VENDOR", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "RBENV_ROOT", "ASDF_DATA_DIR", "MISE_DATA_DIR", "BUNDLE_GEMFILE", "BUNDLE_CONFIG", "BUNDLE_USER_HOME", "BUNDLE_USER_CONFIG", "BUNDLE_USER_CACHE", "BUNDLE_USER_PLUGIN", "PROGRAMDATA"} {
		if v := e.Getenv(key); v != "" {
			if !filepath.IsAbs(v) || !composerSafeText(v, 4096) {
				a.unresolved()
				continue
			}
			a.env[key] = filepath.Clean(v)
		}
	}
	// A relative app config resolves from each project, so keep it raw.
	if v := e.Getenv("BUNDLE_APP_CONFIG"); v != "" {
		if composerSafeText(v, 4096) {
			a.env["BUNDLE_APP_CONFIG"] = v
		} else {
			a.unresolved()
		}
	}
	if v := a.env["GEM_VENDOR"]; v != "" {
		a.home(v)
	}
	f := a.gemProcess
	if v := e.Getenv("GEM_HOME"); v != "" {
		a.gemHome(f, v)
	}
	if v := e.Getenv("GEM_PATH"); v != "" {
		a.gemPath(f, rubySplitList(e.GOOS(), v))
	}
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		v := e.Getenv(key)
		if v == "" {
			continue
		}
		display, redacted := sanitizeComposerProxy(v)
		if strings.EqualFold(key, "NO_PROXY") {
			display, redacted = v, false
			if !composerNoProxy(v) {
				display, redacted = goRedacted, true
			}
		}
		a.setting(f, strings.ToLower(key), display, redacted)
	}
	if e.Getenv("GEM_HOST_API_KEY") != "" {
		a.setting(f, "auth_configured", "true", true)
	}
	gemrc := []string{}
	if v := e.Getenv("GEMRC"); v != "" {
		// GEMRC both selects and merges user files; which ones applied to a
		// past invocation is not knowable from static files.
		a.partial = true
		for _, p := range rubySplitList(e.GOOS(), v) {
			if p == "" {
				continue
			}
			if !filepath.IsAbs(p) || !composerSafeText(p, 4096) {
				a.unresolved()
				continue
			}
			gemrc = append(gemrc, filepath.Clean(p))
		}
	}
	entries := map[string]string{}
	for _, name := range e.EnvNames("BUNDLE_") {
		// Windows names are case-insensitive; Bundler's keys are uppercase.
		key := name
		if e.GOOS() == model.PlatformWindows {
			key = strings.ToUpper(name)
		}
		// Unknown names are never read: arbitrary keys can hold secrets.
		if rubyBundleKnown(strings.TrimPrefix(key, "BUNDLE_")) {
			entries[key] = e.Getenv(name)
		}
	}
	a.bundleSettings(a.bundle, entries, true)
	a.ignoreConfig = a.leads[a.bundle.SourceID]["ignore_config"] != ""
	for _, p := range []*model.RubyConfigFile{a.gemProcess, a.bundle} {
		if len(p.Settings) > 0 && p.Status == "absent" {
			p.Status = "present"
		}
	}
	return gemrc
}

// home records a supported absolute gem-home lead once.
func (a *RubyConfigSnapshot) home(p string) {
	p = filepath.Clean(p)
	if !a.homes[a.key(p)] {
		a.homes[a.key(p)] = true
		a.GemHomes = append(a.GemHomes, p)
	}
}

func (a *RubyConfigSnapshot) gemHome(f *model.RubyConfigFile, v string) {
	if !composerSafeText(v, 4096) {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	if strings.HasPrefix(v, "~/") || strings.HasPrefix(v, `~\`) {
		v = filepath.Join(a.scope.Home, v[2:])
	}
	if filepath.IsAbs(v) {
		v = filepath.Clean(v)
		a.home(v)
	} else {
		// A relative or dynamic value stays observed but unresolved.
		a.unresolved()
	}
	display, redacted := SanitizeComposerURL(v)
	a.setting(f, "gem_home", display, redacted)
}

func (a *RubyConfigSnapshot) gemPath(f *model.RubyConfigFile, values []string) {
	if len(values) > rubySettingLimit {
		a.fileReason(f, "unsupported", "record_limit")
		return
	}
	paths := []string{}
	for _, v := range values {
		if v == "" {
			continue
		}
		if strings.HasPrefix(v, "~/") || strings.HasPrefix(v, `~\`) {
			v = filepath.Join(a.scope.Home, v[2:])
		}
		if !filepath.IsAbs(v) || !composerSafeText(v, 4096) {
			a.unresolved()
			continue
		}
		v = filepath.Clean(v)
		if display, redacted := SanitizeComposerURL(v); !redacted {
			paths = append(paths, display)
		}
		a.home(v)
	}
	encoded, _ := json.Marshal(paths)
	a.setting(f, "gem_path", string(encoded), false)
}

func (a *RubyConfigSnapshot) record(manager, scope, path string) *model.RubyConfigFile {
	id := GoSourceID(a.scope.Username, "ruby_config_"+manager+"_"+scope, path)
	if f := a.files[id]; f != nil {
		return f
	}
	if a.limited || a.bytes+len(path)+256 > maxRubyAuditBytes {
		a.limited = true
		a.degrade("output_size_limit")
		return nil
	}
	f := &model.RubyConfigFile{SourceID: id, Manager: manager, Scope: scope, Path: path, Status: "absent", Reasons: []string{}, Settings: []model.CargoConfigSetting{}}
	a.files[id] = f
	a.bytes += len(path) + 256
	return f
}

// setting deduplicates identical observations, such as the same proxy in
// both spellings of a case-insensitive Windows environment.
func (a *RubyConfigSnapshot) setting(f *model.RubyConfigFile, key, value string, redacted bool) {
	if f == nil {
		return
	}
	if !composerSafeText(value, 4096) {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	if slices.ContainsFunc(f.Settings, func(s model.CargoConfigSetting) bool { return s.Key == key && s.Display == value }) {
		return
	}
	if len(f.Settings) >= rubySettingLimit {
		a.fileReason(f, "unsupported", "record_limit")
		return
	}
	if a.bytes+len(key)+len(value)+128 > maxRubyAuditBytes {
		a.limited = true
		a.fileReason(f, "unsupported", "output_size_limit")
		return
	}
	a.bytes += len(key) + len(value) + 128
	f.Settings = append(f.Settings, model.CargoConfigSetting{Key: key, Display: value, SourceID: f.SourceID, Redacted: redacted})
}

func (a *RubyConfigSnapshot) readFile(manager, scope, p string, parse func(*model.RubyConfigFile, []byte)) *model.RubyConfigFile {
	if f := a.files[GoSourceID(a.scope.Username, "ruby_config_"+manager+"_"+scope, p)]; f != nil {
		return f
	}
	f := a.record(manager, scope, p)
	if f == nil {
		return nil
	}
	if a.ctx.Err() != nil {
		a.fileReason(f, "unreadable", "deadline_exceeded")
		return f
	}
	// A missing file cannot establish its own root through a parent symlink.
	files := a.exec.GuardedFiles([]string{filepath.Dir(p), p}, a.ContentGuard, rubyConfigBytes)
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
	if info.Size() > rubyConfigBytes {
		a.fileReason(f, "unreadable", "size_limit")
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
	parse(f, data)
	return f
}
func (a *RubyConfigSnapshot) readFailure(f *model.RubyConfigFile, err error, p string) {
	reason := CargoReadReason(err, p, a.scope.Volume)
	status := "unreadable"
	if reason == "skipped_protected" || reason == "refused_network_volume" {
		status = "skipped_protected"
	}
	a.fileReason(f, status, reason)
}

// Prefixes observes each discovered interpreter's compiled sysconfdir gemrc.
// These are bounded candidates, not a claim that every runtime uses each one.
// An incomplete prefix search may have omitted a file, so the audit and the
// RubyGems context are partial; files that were read keep their settings.
func (a *RubyConfigSnapshot) Prefixes(prefixes, incomplete []string) {
	if a.scope.Username == "" {
		return
	}
	for _, reason := range incomplete {
		a.systemPartial = true
		a.degrade(reason)
	}
	for _, p := range prefixes {
		f := a.readFile("rubygems", "system", filepath.Join(p, "etc", "gemrc"), a.parseGemrc)
		if f != nil && !slices.Contains(a.systemrc, f) {
			a.systemrc = append(a.systemrc, f)
		}
	}
}

// rubyYAMLRoot returns root mapping pairs. A merge or aliased key could
// inject relevant settings, so either rejects the file.
func (a *RubyConfigSnapshot) yamlRoot(f *model.RubyConfigFile, data []byte) ([][2]*yaml.Node, bool) {
	var doc yaml.Node
	if !utf8.Valid(data) || yaml.Unmarshal(data, &doc) != nil {
		a.fileReason(f, "invalid", "parse_error")
		return nil, false
	}
	if len(doc.Content) == 0 {
		return nil, true
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || root.Anchor != "" || root.Style&yaml.TaggedStyle != 0 {
		a.fileReason(f, "invalid", "parse_error")
		return nil, false
	}
	var out [][2]*yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		k := root.Content[i]
		if k.Kind != yaml.ScalarNode || k.Value == "<<" || k.Anchor != "" || k.Style&yaml.TaggedStyle != 0 {
			a.fileReason(f, "unsupported", "unsupported_format")
			return nil, false
		}
		out = append(out, [2]*yaml.Node{k, root.Content[i+1]})
	}
	return out, true
}

// rubyYAMLData accepts plain data only. The official line serializers never
// write anchors, aliases, explicit tags or block scalars, so those are not
// interpreted with full-YAML semantics.
func rubyYAMLData(n *yaml.Node, depth int) bool {
	if n == nil || depth > 4 || n.Anchor != "" || n.Kind == yaml.AliasNode || n.Style&(yaml.TaggedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return false
	}
	switch n.Kind {
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!str", "!!int", "!!bool", "!!float", "!!null":
			return true
		}
		return false
	case yaml.SequenceNode, yaml.MappingNode:
		for i, c := range n.Content {
			if n.Kind == yaml.MappingNode && i%2 == 0 && (c.Kind != yaml.ScalarNode || c.Value == "<<") {
				return false
			}
			if !rubyYAMLData(c, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

func rubyScalar(n *yaml.Node) (string, bool) {
	if n.Kind != yaml.ScalarNode {
		return "", false
	}
	if n.ShortTag() == "!!null" {
		return "", true
	}
	return n.Value, true
}

var rubyGemrcKeys = []string{"sources", "gemhome", "gempath", "ssl_verify_mode", "ssl_ca_cert", "ssl_client_cert", "http_proxy", "rubygems_api_key", "s3_source"}

// parseGemrc reads allowlisted keys in string or symbol spelling. Command
// option strings (gem/install/update) can hold secrets and are never read.
func (a *RubyConfigSnapshot) parseGemrc(f *model.RubyConfigFile, data []byte) {
	pairs, ok := a.yamlRoot(f, data)
	if !ok {
		return
	}
	values := map[string]*yaml.Node{}
	for _, kv := range pairs {
		key := strings.TrimPrefix(kv[0].Value, ":")
		if !slices.Contains(rubyGemrcKeys, key) {
			continue
		}
		if values[key] != nil || !rubyYAMLData(kv[1], 0) {
			a.fileReason(f, "unsupported", "unsupported_format")
			return
		}
		values[key] = kv[1]
	}
	f.Status = "present"
	invalid := func() { a.fileReason(f, "invalid", "parse_error") }
	literal := false
	if n := values["sources"]; n != nil {
		if n.Kind != yaml.SequenceNode {
			invalid()
		} else if len(n.Content) > rubySettingLimit {
			a.fileReason(f, "unsupported", "record_limit")
		} else {
			for i, item := range n.Content {
				v, ok := rubyScalar(item)
				if !ok || v == "" {
					invalid()
					continue
				}
				prefix := "sources." + strconv.Itoa(i) + "."
				display, redacted := SanitizeRubyURL(v)
				literal = literal || rubyURLCredential(v)
				a.setting(f, prefix+"type", "registry", false)
				a.setting(f, prefix+"url", display, redacted)
			}
		}
	}
	if n := values["gemhome"]; n != nil {
		if v, ok := rubyScalar(n); ok && v != "" {
			a.gemHome(f, v)
		} else {
			invalid()
		}
	}
	if n := values["gempath"]; n != nil {
		var list []string
		if v, ok := rubyScalar(n); ok {
			list = rubySplitList(a.exec.GOOS(), v)
		} else if n.Kind == yaml.SequenceNode {
			for _, item := range n.Content {
				v, ok := rubyScalar(item)
				if !ok {
					invalid()
				}
				list = append(list, v)
			}
		} else {
			invalid()
		}
		a.gemPath(f, list)
	}
	if n := values["ssl_verify_mode"]; n != nil {
		if v, ok := rubyScalar(n); ok && rubyIntPattern.MatchString(v) {
			i, _ := strconv.Atoi(v)
			a.setting(f, "ssl_verify_mode", strconv.Itoa(i), false)
		} else {
			invalid()
		}
	}
	for _, key := range []string{"ssl_ca_cert", "ssl_client_cert"} {
		if n := values[key]; n != nil {
			// Path only; certificate and key contents are never read.
			if v, ok := rubyScalar(n); ok && v != "" && composerSafeText(v, 4096) {
				display, redacted := SanitizeComposerURL(v)
				a.setting(f, key, display, redacted)
			} else {
				invalid()
			}
		}
	}
	if n := values["http_proxy"]; n != nil {
		v, ok := rubyScalar(n)
		switch {
		case !ok:
			invalid()
		case v == "" || strings.HasPrefix(v, ":"):
			// `:no_proxy` disables the proxy; it is not an endpoint.
		default:
			display, redacted := sanitizeComposerProxy(v)
			a.setting(f, "http_proxy", display, redacted)
			if !strings.Contains(v, "://") {
				v = "http://" + v
			}
			literal = literal || rubyURLCredential(v)
		}
	}
	auth := false
	if n := values["rubygems_api_key"]; n != nil {
		if v, ok := rubyScalar(n); ok && v != "" {
			auth, literal = true, true
		}
	}
	if n := values["s3_source"]; n != nil {
		if n.Kind != yaml.MappingNode {
			invalid()
		} else {
			for i := 1; i < len(n.Content); i += 2 {
				bucket := n.Content[i]
				if bucket.Kind != yaml.MappingNode {
					invalid()
					continue
				}
				for j := 0; j+1 < len(bucket.Content); j += 2 {
					v, ok := rubyScalar(bucket.Content[j+1])
					if !ok || v == "" {
						continue
					}
					switch strings.TrimPrefix(bucket.Content[j].Value, ":") {
					case "secret", "security_token":
						auth, literal = true, true
					case "provider":
						// An external provider configures auth without an embedded secret.
						if v == "env" || v == "instance_profile" {
							auth = true
						}
					}
				}
			}
		}
	}
	if auth || literal {
		a.setting(f, "auth_configured", "true", true)
	}
	if literal {
		a.literal[f.SourceID] = true
	}
}

func (a *RubyConfigSnapshot) parseBundler(f *model.RubyConfigFile, data []byte) {
	pairs, ok := a.yamlRoot(f, data)
	if !ok {
		return
	}
	entries := map[string]string{}
	at := map[int][2]string{}
	for _, kv := range pairs {
		key := kv[0].Value
		if !strings.HasPrefix(key, "BUNDLE_") {
			continue
		}
		v, scalar := rubyScalar(kv[1])
		if _, dup := entries[key]; dup || !scalar || !rubyYAMLData(kv[1], 0) || kv[1].Line != kv[0].Line {
			a.fileReason(f, "unsupported", "unsupported_format")
			return
		}
		entries[key] = v
		at[kv[0].Line] = [2]string{key, v}
	}
	// Bundler reads this file line by line, not as YAML. A relevant line it
	// reads differently (quoted comment, escape, extra space) is unsupported,
	// so `"false" # comment`, which Bundler treats as true, never shows false.
	for i, line := range strings.Split(string(data), "\n") {
		key, value, ok := rubyBundlerLine(strings.TrimSuffix(line, "\r"))
		got, parsed := at[i+1]
		relevant := parsed && rubyBundleKnown(strings.TrimPrefix(got[0], "BUNDLE_")) ||
			ok && strings.HasPrefix(key, "BUNDLE_") && rubyBundleKnown(strings.TrimPrefix(key, "BUNDLE_"))
		if relevant && (!ok || !parsed || got != [2]string{key, value}) {
			a.fileReason(f, "unsupported", "unsupported_format")
			return
		}
	}
	f.Status = "present"
	a.bundleSettings(f, entries, false)
}

var (
	rubyBundleBool = map[string]string{"DEPLOYMENT": "deployment", "FROZEN": "frozen", "PATH__SYSTEM": "path.system", "CACHE_ALL": "cache_all", "CACHE_ALL_PLATFORMS": "cache_all_platforms",
		"GLOBAL_GEM_CACHE": "global_gem_cache", "FORCE_RUBY_PLATFORM": "force_ruby_platform", "DISABLE_SHARED_GEMS": "disable_shared_gems",
		"DISABLE_CHECKSUM_VALIDATION": "disable_checksum_validation", "LOCKFILE_CHECKSUMS": "lockfile_checksums"}
	rubyBundlePath = map[string]string{"PATH": "path", "CACHE_PATH": "cache_path", "GEMFILE": "gemfile", "LOCKFILE": "lockfile", "SSL_CA_CERT": "ssl_ca_cert", "SSL_CLIENT_CERT": "ssl_client_cert"}
	rubyBundleList = map[string]string{"WITH": "with", "WITHOUT": "without", "ONLY": "only"}
	rubyBundleInt  = map[string]string{"SSL_VERIFY_MODE": "ssl_verify_mode", "COOLDOWN": "cooldown"}
)

// rubyBundlerLine mirrors one top-level line of Bundler's YAMLSerializer.load:
// HASH_REGEX with its greedy `#`-free key, one optional space, a quote pair
// only when the line ends with it, then strip_comment. An empty unquoted
// value loads as a nested hash, never a setting.
func rubyBundlerLine(line string) (key, value string, ok bool) {
	rest := strings.TrimLeft(line, " ")
	if (len(line)-len(rest))/2 != 0 {
		return "", "", false
	}
	end := strings.IndexByte(rest, '#')
	if end < 0 {
		end = len(rest)
	}
	colon := -1
	for i := end - 1; i > 0 && colon < 0; i-- {
		if rest[i] == ':' && (i+1 == len(rest) || strings.IndexByte(" \t\r\n\f\v", rest[i+1]) >= 0) {
			colon = i
		}
	}
	if colon < 0 {
		return "", "", false
	}
	value = strings.TrimPrefix(rest[colon+1:], " ")
	quoted := len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0]
	if quoted {
		value = value[1 : len(value)-1]
	}
	if before, _, found := strings.Cut(value, "#"); found && !strings.HasPrefix(value, "#") {
		value = strings.Trim(before, " \t\r\n\f\v\x00")
	}
	if !quoted && value == "" {
		return "", "", false
	}
	return rest[:colon], value, true
}

// rubyBundleDecode applies Bundler's key unescaping in upstream order.
func rubyBundleDecode(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, "___", "-"), "__", "."))
}

// rubyBundleCredential recognizes Bundler's per-host credential keys
// (GEMS__EXAMPLE__COM or a full source URI). Dotted families that are
// settings, not hosts, are excluded before the host test.
func rubyBundleCredential(name string) bool {
	if strings.Contains(name, "://") {
		return true
	}
	for _, family := range []string{"BUILD__", "GEM__", "MIRROR__", "LOCAL__", "PATH__"} {
		if strings.HasPrefix(name, family) {
			return false
		}
	}
	return rubyHostPattern.MatchString(rubyBundleDecode(name))
}

func rubyBundleKnown(name string) bool {
	return name == "IGNORE_CONFIG" || rubyBundleBool[name] != "" || rubyBundlePath[name] != "" || rubyBundleList[name] != "" || rubyBundleInt[name] != "" ||
		strings.HasPrefix(name, "MIRROR__") || strings.HasPrefix(name, "LOCAL__") || rubyBundleCredential(name)
}

// rubyBundleBoolValue follows Bundler's boolean conversion for known keys.
func rubyBundleBoolValue(v string) string {
	switch strings.ToLower(v) {
	case "false", "f", "no", "n", "0", "":
		return "false"
	}
	return "true"
}

// bundleSettings classifies BUNDLE_* keys before decoding, so a host-shaped
// credential key or its value never becomes a display.
func (a *RubyConfigSnapshot) bundleSettings(f *model.RubyConfigFile, entries map[string]string, process bool) {
	if f == nil {
		return
	}
	leads := map[string]string{}
	a.leads[f.SourceID] = leads
	type mirror struct{ url, timeout string }
	mirrors := map[string]*mirror{}
	locals := map[string]string{}
	invalid := func() { a.fileReason(f, "invalid", "parse_error") }
	auth := false
	for _, key := range slices.Sorted(maps.Keys(entries)) {
		name, value := strings.TrimPrefix(key, "BUNDLE_"), entries[key]
		switch {
		case name == "IGNORE_CONFIG":
			// Presence semantics: any value ignores config files.
			leads["ignore_config"] = "true"
			a.setting(f, "ignore_config", "true", false)
		case rubyBundleBool[name] != "":
			leads[rubyBundleBool[name]] = rubyBundleBoolValue(value)
			a.setting(f, rubyBundleBool[name], rubyBundleBoolValue(value), false)
		case rubyBundlePath[name] != "":
			if value == "" || !composerSafeText(value, 4096) {
				invalid()
				continue
			}
			leads[rubyBundlePath[name]] = value
			display, redacted := SanitizeComposerURL(value)
			a.setting(f, rubyBundlePath[name], display, redacted)
		case rubyBundleList[name] != "":
			labels := []string{}
			for _, l := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ':' }) {
				if !RubyToken(l) {
					invalid()
					labels = nil
					break
				}
				if !slices.Contains(labels, l) {
					labels = append(labels, l)
				}
			}
			if labels == nil {
				continue
			}
			if len(labels) > rubySettingLimit {
				a.fileReason(f, "unsupported", "record_limit")
				continue
			}
			encoded, _ := json.Marshal(labels)
			a.setting(f, rubyBundleList[name], string(encoded), false)
		case rubyBundleInt[name] != "":
			if !rubyIntPattern.MatchString(value) {
				invalid()
				continue
			}
			i, _ := strconv.Atoi(value)
			a.setting(f, rubyBundleInt[name], strconv.Itoa(i), false)
		case strings.HasPrefix(name, "MIRROR__"):
			// mirror.<source>[.fallback_timeout][/], per Bundler's MirrorConfig.
			src := strings.TrimSuffix(rubyBundleDecode(strings.TrimPrefix(name, "MIRROR__")), "/")
			src, timeout := strings.CutSuffix(src, ".fallback_timeout")
			if strings.Contains(src, "://") && !strings.HasSuffix(src, "/") {
				src += "/"
			}
			if rubyURLCredential(src) || rubyURLCredential(value) {
				auth = true
			}
			m := mirrors[src]
			if m == nil {
				m = &mirror{}
				mirrors[src] = m
			}
			if !timeout {
				m.url = value
				continue
			}
			switch v := strings.ToLower(value); {
			case v == "true":
				m.timeout = "0.1"
			case v == "false":
				m.timeout = "0"
			case rubyDecimalPattern.MatchString(value):
				m.timeout = value
			default:
				invalid()
			}
		case strings.HasPrefix(name, "LOCAL__"):
			gem := rubyBundleDecode(strings.TrimPrefix(name, "LOCAL__"))
			if !RubyGemName(gem) || value == "" || !composerSafeText(value, 4096) {
				invalid()
				continue
			}
			locals[gem] = value
		case rubyBundleCredential(name):
			// The value is a secret; only its presence is observed.
			if value != "" {
				auth = true
			}
		}
	}
	if len(mirrors) > rubySettingLimit || len(locals) > rubySettingLimit {
		a.fileReason(f, "unsupported", "record_limit")
		return
	}
	for i, src := range slices.Sorted(maps.Keys(mirrors)) {
		m, prefix := mirrors[src], "mirrors."+strconv.Itoa(i)+"."
		display, redacted := src, false
		switch {
		case src == "all":
		case strings.Contains(src, "://"):
			display, redacted = SanitizeRubyURL(src)
		case !rubyHostPattern.MatchString(src):
			display, redacted = goRedacted, true
		}
		a.setting(f, prefix+"source", display, redacted)
		if m.url != "" {
			display, redacted := SanitizeRubyURL(m.url)
			a.setting(f, prefix+"url", display, redacted)
		}
		if m.timeout != "" {
			a.setting(f, prefix+"fallback_timeout", m.timeout, false)
		}
	}
	for i, gem := range slices.Sorted(maps.Keys(locals)) {
		prefix := "local." + strconv.Itoa(i) + "."
		a.setting(f, prefix+"name", gem, false)
		display, redacted := SanitizeComposerURL(locals[gem])
		a.setting(f, prefix+"path", display, redacted)
	}
	if auth {
		a.setting(f, "auth_configured", "true", true)
		// Process credentials are expected injection, not embedded config.
		if !process {
			a.literal[f.SourceID] = true
		}
	}
}

// SanitizeRubyURL is the shared whole-URL redactor, except that SCP-like Git
// remotes are never rewritten to an inequivalent ssh:// URI.
func SanitizeRubyURL(raw string) (string, bool) {
	if !strings.Contains(raw, "://") && strings.Contains(raw, "@") {
		return goRedacted, true
	}
	return SanitizeComposerURL(raw)
}

// rubyURLCredential reports an embedded secret: any HTTP(S) userinfo
// (Bundler sends a lone user as a token) or a password on other schemes. A
// login user on ssh or SCP-like remotes is not a credential; malformed text
// is redacted but not asserted as a credential.
func rubyURLCredential(raw string) bool {
	if !strings.Contains(raw, "://") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return false
	}
	_, password := u.User.Password()
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u.User.Username() != "" || password
	}
	return password
}

// Project observes one Bundler project's manifests and local config and
// selects installation leads with Bundler's Settings#path rule: the first
// level (local, process, global) holding path, path.system or
// disable_shared_gems decides; deployment applies only when none does.
func (a *RubyConfigSnapshot) Project(p RubyProject) RubyProjectLeads {
	out := RubyProjectLeads{Partial: a.partial}
	if a.scope.Username == "" {
		out.Partial = true
		return out
	}
	ids := []string{}
	for _, m := range p.Manifests {
		f := a.record("bundler", "project", m.Path)
		if f == nil {
			out.Partial = true
			continue
		}
		if !a.parsed[f.SourceID] {
			a.parsed[f.SourceID] = true
			f.Status, f.Reasons = m.Status, append([]string{}, m.Reasons...)
			if m.Status == "present" {
				a.manifestSettings(f, m)
			}
		}
		if f.Status != "present" {
			out.Partial = true
		}
		ids = append(ids, f.SourceID)
	}
	appConfig := filepath.Join(p.Dir, ".bundle")
	if v := a.env["BUNDLE_APP_CONFIG"]; v != "" {
		appConfig = v
		if !filepath.IsAbs(v) {
			appConfig = filepath.Join(p.Dir, v)
		}
	}
	out.AppConfig = filepath.Clean(appConfig)
	local := a.readFile("bundler", "project", filepath.Join(out.AppConfig, "config"), a.parseBundler)
	all := []*model.RubyConfigFile{local, a.bundle, a.global}
	levels := all
	if a.ignoreConfig {
		// Ignored files stay observed but are not applicable.
		levels = []*model.RubyConfigFile{a.bundle}
	}
	for _, f := range all {
		if f == nil || f.Status != "present" && f.Status != "absent" {
			out.Partial = true
		}
	}
	value := func(key string) (string, bool) {
		for _, f := range levels {
			if f == nil {
				continue
			}
			if v, ok := a.leads[f.SourceID][key]; ok {
				return v, true
			}
		}
		return "", false
	}
	resolve := func(v string) string {
		if strings.HasPrefix(v, "~/") || strings.HasPrefix(v, `~\`) {
			v = filepath.Join(a.scope.Home, v[2:])
		}
		if !filepath.IsAbs(v) {
			v = filepath.Join(p.Dir, v)
		}
		if !composerSafeText(v, 4096) {
			out.Partial = true
			a.degrade("path_unresolved")
			return ""
		}
		return filepath.Clean(v)
	}
	decided := false
	for _, f := range levels {
		if f == nil {
			continue
		}
		l := a.leads[f.SourceID]
		path, hasPath := l["path"]
		system, hasSystem := l["path.system"]
		shared, hasShared := l["disable_shared_gems"]
		if !hasPath && !hasSystem && !hasShared {
			continue
		}
		decided = true
		// System gems live in shared homes that root discovery already covers.
		if system != "true" && shared != "false" && hasPath {
			out.Path = resolve(path)
		}
		break
	}
	if v, ok := value("deployment"); !decided && ok && v == "true" {
		out.Path = filepath.Join(p.Dir, "vendor", "bundle")
	}
	out.CachePath = filepath.Join(p.Dir, "vendor", "cache")
	if v, ok := value("cache_path"); ok {
		out.CachePath = resolve(v)
	}
	if v, ok := value("lockfile"); ok {
		out.Lockfile = resolve(v)
	}
	chain := append([]string{}, ids...)
	for _, f := range all {
		if f != nil && (f == a.bundle || !a.ignoreConfig) {
			chain = append(chain, f.SourceID)
		}
	}
	if !a.limited {
		selection := "observed"
		if out.Partial {
			selection = "partial"
		}
		a.audit.Contexts = append(a.audit.Contexts, model.RubyConfigContext{Manager: "bundler", ProjectPath: p.Dir, ConfigSourceIDs: chain, SelectionStatus: selection})
		a.bytes += len(p.Dir) + len(chain)*70 + 128
	}
	return out
}

func (a *RubyConfigSnapshot) manifestSettings(f *model.RubyConfigFile, m RubyManifest) {
	if len(m.Sources) > rubySettingLimit {
		a.fileReason(f, "unsupported", "record_limit")
		return
	}
	literal := false
	for i, s := range m.Sources {
		prefix := "sources." + strconv.Itoa(i) + "."
		display, redacted := SanitizeRubyURL(s.URL)
		literal = literal || rubyURLCredential(s.URL)
		a.setting(f, prefix+"type", s.Type, false)
		a.setting(f, prefix+"url", display, redacted)
		if s.Cooldown != "" {
			a.setting(f, prefix+"cooldown", s.Cooldown, false)
		}
	}
	if m.NoLockfile {
		a.setting(f, "lockfile", "false", false)
	} else if m.Lockfile != "" {
		display, redacted := SanitizeComposerURL(m.Lockfile)
		a.setting(f, "lockfile", display, redacted)
	}
	if literal {
		a.setting(f, "auth_configured", "true", true)
		a.literal[f.SourceID] = true
	}
}

func (a *RubyConfigSnapshot) credential(path string) string {
	if a.limited || a.credentials[a.key(path)] {
		return ""
	}
	a.credentials[a.key(path)] = true
	c := model.RubyCredentialFile{Path: path, Status: "present", Presence: "present"}
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
	a.audit.CredentialFiles = append(a.audit.CredentialFiles, c)
	a.bytes += len(path) + 128
	return c.Status
}

func (a *RubyConfigSnapshot) Finish() model.RubyConfigAudit {
	if a.gemProcess != nil {
		// One ambient RubyGems chain; several present system files mean the
		// applicable interpreter is ambiguous.
		ids, present, partial := []string{}, 0, a.partial || a.systemPartial
		for _, f := range append(append([]*model.RubyConfigFile{a.gemProcess}, a.userGemrc...), a.systemrc...) {
			if f == nil {
				partial = true
				continue
			}
			ids = append(ids, f.SourceID)
			if f.Status != "present" && f.Status != "absent" {
				partial = true
			}
			if f.Scope == "system" && f.Status == "present" {
				present++
			}
		}
		a.context("rubygems", ids, partial || present > 1)
		ids, partial = []string{a.bundle.SourceID}, a.partial || a.bundle.Status != "present" && a.bundle.Status != "absent"
		if a.global != nil && !a.ignoreConfig {
			ids = append(ids, a.global.SourceID)
			partial = partial || a.global.Status != "present" && a.global.Status != "absent"
		}
		a.context("bundler", ids, partial)
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
		a.audit.Findings = append(a.audit.Findings, rubyFindings(*f, a.literal[f.SourceID])...)
		for _, r := range f.Reasons {
			a.degrade(r)
		}
	}
	slices.SortFunc(a.audit.Files, func(x, y model.RubyConfigFile) int {
		return strings.Compare(x.Manager+"\x00"+x.Scope+"\x00"+x.Path, y.Manager+"\x00"+y.Scope+"\x00"+y.Path)
	})
	slices.SortFunc(a.audit.Contexts, func(x, y model.RubyConfigContext) int {
		return strings.Compare(x.Manager+"\x00"+x.ProjectPath, y.Manager+"\x00"+y.ProjectPath)
	})
	slices.SortFunc(a.audit.CredentialFiles, func(x, y model.RubyCredentialFile) int { return strings.Compare(x.Path, y.Path) })
	slices.SortFunc(a.audit.Findings, func(x, y model.CargoConfigFinding) int {
		return strings.Compare(x.Code+x.SourceID+x.Key, y.Code+y.SourceID+y.Key)
	})
	slices.Sort(a.audit.Reasons)
	data, _ := json.Marshal(a.audit)
	if len(data) > maxRubyAuditBytes {
		a.audit = emptyRubyAudit()
		a.degrade("output_size_limit")
	}
	return a.audit
}

func (a *RubyConfigSnapshot) context(manager string, ids []string, partial bool) {
	if a.limited {
		return
	}
	selection := "observed"
	if partial {
		selection = "partial"
	}
	a.audit.Contexts = append(a.audit.Contexts, model.RubyConfigContext{Manager: manager, ConfigSourceIDs: ids, SelectionStatus: selection})
	a.bytes += len(ids)*70 + 128
}

// rubyFindings derives 001/002/004 from kept settings. 003 comes from the
// pre-redaction literal-credential flag and never carries secret text.
func rubyFindings(f model.RubyConfigFile, literal bool) []model.CargoConfigFinding {
	var out []model.CargoConfigFinding
	seen := map[string]bool{}
	add := func(code, key, detail string) {
		if !seen[code+"\x00"+key] {
			seen[code+"\x00"+key] = true
			out = append(out, model.CargoConfigFinding{SourceID: f.SourceID, Code: code, Severity: "MEDIUM", Key: key, Detail: detail})
		}
	}
	for _, s := range f.Settings {
		lower := strings.ToLower(s.Display)
		source := strings.HasPrefix(s.Key, "sources.") && strings.HasSuffix(s.Key, ".url")
		mirror := strings.HasPrefix(s.Key, "mirrors.") && (strings.HasSuffix(s.Key, ".source") || strings.HasSuffix(s.Key, ".url"))
		switch {
		case (source || mirror) && strings.HasPrefix(lower, "http://"), source && strings.HasPrefix(lower, "git://"):
			add("ruby-001", s.Key, "Ruby package source uses an unencrypted connection.")
		case s.Key == "ssl_verify_mode" && s.Display == "0":
			add("ruby-002", s.Key, "TLS certificate verification is disabled by Ruby package configuration.")
		case s.Key == "disable_checksum_validation" && s.Display == "true":
			add("ruby-004", s.Key, "Bundler checksum validation is disabled.")
		case s.Key == "auth_configured" && literal && f.Scope != "process":
			add("ruby-003", s.Key, "Credentials are embedded in Ruby package configuration.")
		}
	}
	return out
}
