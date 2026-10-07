package configaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

var maxComposerAuditBytes = 256 << 10

const composerConfigBytes int64 = 2 << 20
const composerSettingLimit = 256
const composerPatternLimit = 256

// ComposerConfigScope comes from the resolved developer, never a login shell.
type ComposerConfigScope struct {
	Username, Home  string
	Protected       func(string) string
	Volume          func(string) bool
	ProcessVerified bool
}

// ComposerPaths contains only locations needed for inventory discovery.
type ComposerPaths struct {
	Vendor, Cache string
	Partial       bool
}

// ComposerConfigSnapshot accumulates observed config as manifests are discovered.
// This permits vendor pruning before descent without a second config-file walk.
type ComposerConfigSnapshot struct {
	Homes                   []string
	Caches                  []string
	Home, AlternateManifest string
	SelectionPartial        bool
	exec                    executor.Executor
	ctx                     context.Context
	scope                   ComposerConfigScope
	audit                   model.ComposerConfigAudit
	files                   map[string]*model.ComposerConfigFile
	paths                   map[string]map[string]string
	env                     map[string]string
	process                 *model.ComposerConfigFile
	credentials             map[string]bool
	bytes                   int
	limited                 bool
}

type ComposerConfigDetector struct{ exec executor.Executor }

func NewComposerConfigDetector(exec executor.Executor) *ComposerConfigDetector {
	return &ComposerConfigDetector{exec: exec}
}

func emptyComposerAudit() model.ComposerConfigAudit {
	return model.ComposerConfigAudit{SchemaVersion: model.ComposerInventorySchemaVersion, Status: "complete", Reasons: []string{}, Files: []model.ComposerConfigFile{}, Contexts: []model.ComposerConfigContext{}, CredentialFiles: []model.CargoCredentialFile{}, Findings: []model.CargoConfigFinding{}}
}

func (d *ComposerConfigDetector) Detect(ctx context.Context, scope ComposerConfigScope) *ComposerConfigSnapshot {
	a := &ComposerConfigSnapshot{exec: d.exec, ctx: ctx, scope: scope, audit: emptyComposerAudit(), files: map[string]*model.ComposerConfigFile{}, paths: map[string]map[string]string{}, env: map[string]string{}, credentials: map[string]bool{}}
	if scope.Username == "" || scope.Home == "" {
		a.degrade("user_unresolved")
		return a
	}
	if ctx.Err() != nil {
		a.degrade("deadline_exceeded")
		return a
	}
	a.process = a.record("process", "")
	if a.process == nil {
		a.SelectionPartial = true
		return a
	}
	if scope.ProcessVerified {
		for _, key := range []string{"COMPOSER_HOME", "COMPOSER", "COMPOSER_VENDOR_DIR", "COMPOSER_BIN_DIR", "COMPOSER_CACHE_DIR", "COMPOSER_CAFILE", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
			value := d.exec.Getenv(key)
			if value == "" {
				continue
			}
			display, redacted := value, false
			switch {
			case strings.HasSuffix(strings.ToLower(key), "proxy"):
				if strings.EqualFold(key, "NO_PROXY") {
					if !composerNoProxy(value) {
						display, redacted = goRedacted, true
					}
				} else {
					display, redacted = sanitizeComposerProxy(value)
				}
			default:
				if !composerSafeText(value, 4096) || !filepath.IsAbs(value) || strings.ContainsAny(value, "\x00\n\r") {
					a.fileReason(a.process, "unsupported", "path_unresolved")
					a.SelectionPartial = true
					continue
				}
				a.env[key] = filepath.Clean(value)
				display, redacted = SanitizeComposerURL(value)
			}
			a.setting(a.process, key, display, redacted)
		}
		if d.exec.Getenv("COMPOSER_AUTH") != "" {
			a.setting(a.process, "auth_configured", "true", true)
		}
		if len(a.process.Settings) > 0 && a.process.Status == "absent" {
			a.process.Status = "present"
		}
	} else {
		a.fileReason(a.process, "unsupported", "user_unresolved")
		a.SelectionPartial = true
	}
	// Cache roots are exclusions even when no project has been read yet.
	// These variables are observed only in the verified developer process.
	if scope.ProcessVerified {
		for _, key := range []string{"XDG_CACHE_HOME", "LOCALAPPDATA"} {
			value := d.exec.Getenv(key)
			if value == "" {
				continue
			}
			if !filepath.IsAbs(value) || !composerSafeText(value, 4096) {
				a.SelectionPartial = true
				a.degrade("path_unresolved")
				continue
			}
			if key == "XDG_CACHE_HOME" && d.exec.GOOS() != model.PlatformWindows {
				a.Caches = append(a.Caches, filepath.Join(value, "composer"))
			}
			if key == "LOCALAPPDATA" && d.exec.GOOS() == model.PlatformWindows {
				a.Caches = append(a.Caches, filepath.Join(value, "Composer"))
			}
		}
		if value := a.env["COMPOSER_CACHE_DIR"]; value != "" {
			a.Caches = append(a.Caches, value)
		}
	}
	a.resolveHomes()
	a.AlternateManifest = a.env["COMPOSER"]
	if a.Home != "" {
		a.global(a.Home)
	} else {
		f := a.record("user", "")
		a.fileReason(f, "unsupported", "path_unresolved")
	}
	return a
}

func (a *ComposerConfigSnapshot) key(p string) string { return GoPathKey(a.exec.GOOS(), p) }
func (a *ComposerConfigSnapshot) degrade(reason string) {
	a.audit.Status = "partial"
	if !slices.Contains(a.audit.Reasons, reason) {
		a.audit.Reasons = append(a.audit.Reasons, reason)
	}
}
func (a *ComposerConfigSnapshot) fileReason(f *model.ComposerConfigFile, status, reason string) {
	if f != nil {
		f.Status = status
		if !slices.Contains(f.Reasons, reason) {
			f.Reasons = append(f.Reasons, reason)
		}
	}
	a.degrade(reason)
}
func (a *ComposerConfigSnapshot) reason(err error, p string) string {
	return CargoReadReason(err, p, a.scope.Volume)
}

func (a *ComposerConfigSnapshot) probeDir(p string) (bool, bool) {
	if a.ctx.Err() != nil {
		a.degrade("deadline_exceeded")
		return false, false
	}
	info, err := a.exec.GuardedFiles([]string{p}, a.scope.Protected, 0).Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, true
	}
	if err != nil {
		a.degrade(a.reason(err, p))
		return false, false
	}
	return info.IsDir(), true
}
func (a *ComposerConfigSnapshot) resolveHomes() {
	home := a.scope.Home
	candidates := []string{filepath.Join(home, ".composer")}
	if a.exec.GOOS() == model.PlatformWindows {
		appdata := filepath.Join(home, "AppData", "Roaming")
		if a.scope.ProcessVerified {
			if v := a.exec.Getenv("APPDATA"); v != "" {
				if filepath.IsAbs(v) && composerSafeText(v, 4096) {
					appdata = v
				} else {
					a.SelectionPartial = true
					a.degrade("path_unresolved")
				}
			}
		}
		candidates = []string{filepath.Join(appdata, "Composer")}
	} else {
		xdg := a.scope.ProcessVerified && a.exec.HasEnvPrefix("XDG_")
		if !xdg {
			systemXDG := "/etc/xdg"
			if a.exec.GOOS() == model.PlatformDarwin {
				// /etc is a symlink on macOS; guard the physical missing-path probe.
				systemXDG = "/private/etc/xdg"
			}
			exists, known := a.probeDir(systemXDG)
			xdg = exists
			if !known {
				a.SelectionPartial = true
			}
		}
		xdgHome := filepath.Join(home, ".config", "composer")
		if a.scope.ProcessVerified {
			if v := a.exec.Getenv("XDG_CONFIG_HOME"); v != "" {
				if filepath.IsAbs(v) && composerSafeText(v, 4096) {
					xdgHome = filepath.Join(v, "composer")
				} else {
					a.SelectionPartial = true
					a.degrade("path_unresolved")
				}
			}
		}
		if xdg {
			candidates = append([]string{xdgHome}, candidates...)
		}
		// Inactive conventional homes remain inventory candidates, not active config.
		a.Homes = append(a.Homes, filepath.Join(home, ".config", "composer"))
	}
	a.Home = candidates[0]
	for _, p := range candidates {
		exists, known := a.probeDir(p)
		if !known {
			a.SelectionPartial = true
		}
		if exists {
			a.Home = p
			break
		}
	}
	a.Homes = append(a.Homes, candidates...)
	if v := a.env["COMPOSER_HOME"]; v != "" {
		a.Home = v
		a.Homes = append(a.Homes, v)
	} else if a.scope.ProcessVerified && a.exec.Getenv("COMPOSER_HOME") != "" {
		a.Home = ""
	}
	seen := map[string]bool{}
	out := []string{}
	for _, p := range a.Homes {
		if !seen[a.key(p)] {
			out = append(out, p)
			seen[a.key(p)] = true
		}
	}
	a.Homes = out
}

func (a *ComposerConfigSnapshot) record(scope, path string) *model.ComposerConfigFile {
	id := GoSourceID(a.scope.Username, "composer_config_"+scope, path)
	if f := a.files[id]; f != nil {
		return f
	}
	if a.limited || a.bytes+len(path)+256 > maxComposerAuditBytes {
		a.limited = true
		a.degrade("output_size_limit")
		return nil
	}
	f := &model.ComposerConfigFile{SourceID: id, Scope: scope, Path: path, Status: "absent", Reasons: []string{}, Settings: []model.CargoConfigSetting{}}
	a.files[id] = f
	a.bytes += len(path) + 256
	return f
}
func (a *ComposerConfigSnapshot) setting(f *model.ComposerConfigFile, key, value string, redacted bool) {
	if f == nil {
		return
	}
	if !composerSafeText(value, 4096) {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	if len(f.Settings) >= composerSettingLimit {
		a.fileReason(f, "unsupported", "record_limit")
		return
	}
	if a.bytes+len(key)+len(value)+128 > maxComposerAuditBytes {
		a.limited = true
		a.fileReason(f, "unsupported", "output_size_limit")
		return
	}
	a.bytes += len(key) + len(value) + 128
	f.Settings = append(f.Settings, model.CargoConfigSetting{Key: key, Display: value, SourceID: f.SourceID, Redacted: redacted})
}

func (a *ComposerConfigSnapshot) global(home string) *model.ComposerConfigFile {
	p := filepath.Join(home, "config.json")
	id := GoSourceID(a.scope.Username, "composer_config_user", p)
	if f := a.files[id]; f != nil {
		return f
	}
	f := a.record("user", p)
	if f == nil {
		return nil
	}
	if a.ctx.Err() != nil {
		a.fileReason(f, "unreadable", "deadline_exceeded")
		return f
	}
	files := a.exec.GuardedFiles([]string{p}, a.scope.Protected, composerConfigBytes)
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
	if info.Size() > composerConfigBytes {
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
	a.parse(f, data)
	return f
}
func (a *ComposerConfigSnapshot) readFailure(f *model.ComposerConfigFile, err error, p string) {
	reason := a.reason(err, p)
	status := "unreadable"
	if reason == "skipped_protected" || reason == "refused_network_volume" {
		status = "skipped_protected"
	}
	a.fileReason(f, status, reason)
}

// Project uses the manifest bytes already read by inventory. Inactive homes
// get their own global config, never another home's settings.
func (a *ComposerConfigSnapshot) Project(manifest string, data []byte, status string, reasons []string, globalHome string) ComposerPaths {
	p := filepath.Dir(manifest)
	selected := a.Home
	if globalHome != "" {
		selected = globalHome
	}
	global := a.globalFor(selected)
	f := a.record("project", manifest)
	if f != nil {
		f.Status = status
		f.Reasons = slices.Clone(reasons)
		if f.Reasons == nil {
			f.Reasons = []string{}
		}
		if status == "present" {
			a.parse(f, data)
		}
	}
	result := ComposerPaths{Partial: a.SelectionPartial || f == nil || global == nil}
	values := map[string]string{"home": selected, "vendor-dir": "vendor", "bin-dir": "{$vendor-dir}/bin"}
	if a.exec.GOOS() == model.PlatformDarwin {
		values["cache-dir"] = filepath.Join(a.scope.Home, "Library", "Caches", "composer")
	} else {
		values["cache-dir"] = filepath.Join(a.scope.Home, ".cache", "composer")
	}
	if selected != "" && (a.exec.GOOS() == model.PlatformWindows || a.env["COMPOSER_HOME"] != "") {
		values["cache-dir"] = filepath.Join(selected, "cache")
	}
	for _, source := range []*model.ComposerConfigFile{global, f} {
		if source == nil {
			continue
		}
		if source.Status != "present" && source.Status != "absent" {
			result.Partial = true
		}
		for k, v := range a.paths[source.SourceID] {
			values[k] = v
		}
	}
	// An inactive home's old installation cannot be selected by today's process.
	process := a.process
	if globalHome != "" && a.key(globalHome) != a.key(a.Home) {
		process = nil
		result.Partial = true
	}
	if process != nil && a.scope.ProcessVerified {
		for key, setting := range map[string]string{"COMPOSER_VENDOR_DIR": "vendor-dir", "COMPOSER_BIN_DIR": "bin-dir", "COMPOSER_CACHE_DIR": "cache-dir", "COMPOSER_CAFILE": "cafile"} {
			if value := a.env[key]; value != "" {
				values[setting] = value
			}
		}
	}
	for _, field := range []struct {
		key  string
		dest *string
	}{{"vendor-dir", &result.Vendor}, {"cache-dir", &result.Cache}} {
		resolved, ok := composerResolvePath(values[field.key], p, a.scope.Home, values)
		if !ok {
			result.Partial = true
			a.degrade("path_unresolved")
		} else {
			*field.dest = resolved
		}
	}
	ids := []string{}
	for _, source := range []*model.ComposerConfigFile{process, f, global} {
		if source != nil {
			ids = append(ids, source.SourceID)
		}
	}
	if f != nil && global != nil && !a.limited {
		selection := "observed"
		if result.Partial {
			selection = "partial"
		}
		a.audit.Contexts = append(a.audit.Contexts, model.ComposerConfigContext{ProjectPath: p, ConfigSourceIDs: ids, SelectionStatus: selection})
		a.bytes += len(p) + len(ids)*70 + 128
	}
	a.credential(filepath.Join(p, "auth.json"))
	if selected != "" {
		a.credential(filepath.Join(selected, "auth.json"))
	}
	return result
}
func (a *ComposerConfigSnapshot) globalFor(home string) *model.ComposerConfigFile {
	if home != "" {
		return a.global(home)
	}
	return a.files[GoSourceID(a.scope.Username, "composer_config_user", "")]
}

// Only bounded substitutions between the allowlisted directory settings are
// supported. Cycles and unknown expressions remain unresolved.
func composerResolvePath(value, base, home string, values map[string]string) (string, bool) {
	seen := map[string]bool{}
	for range 8 {
		i := strings.Index(value, "{$")
		if i < 0 {
			break
		}
		j := strings.IndexByte(value[i:], '}')
		if j < 0 {
			return "", false
		}
		token := value[i : i+j+1]
		key := token[2 : len(token)-1]
		replacement, ok := values[key]
		if !ok || seen[key] || replacement == "" {
			return "", false
		}
		seen[key] = true
		value = strings.ReplaceAll(value, token, replacement)
	}
	if strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		value = filepath.Join(home, value[2:])
	}
	for _, prefix := range []string{"$HOME/", "${HOME}/", "%USERPROFILE%/", "%USERPROFILE%\\"} {
		if strings.HasPrefix(value, prefix) {
			value = filepath.Join(home, value[len(prefix):])
		}
	}
	if value == "" || !composerSafeText(value, 4096) || strings.ContainsAny(value, "${}%~") {
		return "", false
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(base, filepath.FromSlash(value))
	}
	return filepath.Clean(value), len(value) <= 4096
}

func (a *ComposerConfigSnapshot) credential(path string) {
	if a.limited || a.credentials[a.key(path)] {
		return
	}
	a.credentials[a.key(path)] = true
	c := model.CargoCredentialFile{Path: path, Status: "present", Presence: "present"}
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
			reason := a.reason(err, path)
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
}

func (a *ComposerConfigSnapshot) Finish() model.ComposerConfigAudit {
	if a.Home != "" {
		a.credential(filepath.Join(a.Home, "auth.json"))
	}
	for _, f := range a.files {
		// An incomplete config source has no current settings. The consumer
		// retains its last-known settings separately until a complete reread.
		if f.Status != "present" {
			f.Settings = []model.CargoConfigSetting{}
		}
		slices.Sort(f.Reasons)
		// Repository indices preserve declared order independently of key sorting.
		slices.SortFunc(f.Settings, func(x, y model.CargoConfigSetting) int { return strings.Compare(x.Key, y.Key) })
		a.audit.Files = append(a.audit.Files, *f)
		a.audit.Findings = append(a.audit.Findings, composerFindings(*f)...)
		for _, r := range f.Reasons {
			a.degrade(r)
		}
	}
	slices.SortFunc(a.audit.Files, func(x, y model.ComposerConfigFile) int {
		return strings.Compare(x.Scope+"\x00"+x.Path, y.Scope+"\x00"+y.Path)
	})
	slices.SortFunc(a.audit.Contexts, func(x, y model.ComposerConfigContext) int { return strings.Compare(x.ProjectPath, y.ProjectPath) })
	slices.SortFunc(a.audit.CredentialFiles, func(x, y model.CargoCredentialFile) int { return strings.Compare(x.Path, y.Path) })
	slices.SortFunc(a.audit.Findings, func(x, y model.CargoConfigFinding) int {
		return strings.Compare(x.Code+x.SourceID+x.Key, y.Code+y.SourceID+y.Key)
	})
	slices.Sort(a.audit.Reasons)
	data, _ := json.Marshal(a.audit)
	if len(data) > maxComposerAuditBytes {
		a.audit = emptyComposerAudit()
		a.degrade("output_size_limit")
	}
	return a.audit
}

func composerSafeText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

// SanitizeComposerURL parses the entire URL, never whitespace-split fragments.
// Local Windows paths are checked before URL parsing so drives are not schemes.
func SanitizeComposerURL(raw string) (string, bool) {
	if !composerSafeText(raw, 4096) {
		return goRedacted, true
	}
	if len(raw) > 2 && raw[1] == ':' && (raw[2] == '\\' || raw[2] == '/') || strings.HasPrefix(raw, `\\`) {
		if strings.ContainsAny(raw, "@?#") {
			return goRedacted, true
		}
		return raw, false
	}
	// SCP syntax is source metadata. Drop its user component, preserve host/path.
	if !strings.Contains(raw, "://") && strings.Contains(raw, "@") {
		user, rest, ok := strings.Cut(raw, "@")
		host, path, scp := strings.Cut(rest, ":")
		if ok && scp && user != "" && !strings.ContainsAny(user, ":/\\ \t") && host != "" && path != "" && !strings.ContainsAny(rest, "@?# \t\\") {
			return "ssh://" + host + "/" + strings.TrimPrefix(path, "/"), true
		}
		return goRedacted, true
	}
	safe, redacted := SanitizeCargoURL(raw)
	u, err := url.Parse(safe)
	if err != nil || u.Opaque != "" || u.Scheme != "" && u.Scheme != "file" && u.Host == "" {
		return goRedacted, true
	}
	// Escaped credentials cannot become a shared origin on a later decode.
	decoded, err := url.PathUnescape(safe)
	if err != nil || strings.ContainsAny(decoded, "@\r\n") {
		return goRedacted, true
	}
	return safe, redacted
}

var composerPattern = regexp.MustCompile(`^(?:\*|[a-z0-9*][a-z0-9_.*-]*/[a-z0-9*][a-z0-9_.*-]*)$`)

func composerValidPattern(s string) bool { return len(s) <= 256 && composerPattern.MatchString(s) }

// Proxy environment syntax permits an omitted scheme, unlike package URLs.
func sanitizeComposerProxy(raw string) (string, bool) {
	if !composerSafeText(raw, 4096) || raw == goRedacted {
		return goRedacted, true
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return goRedacted, true
	}
	if port := u.Port(); port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return goRedacted, true
		}
	}
	if strings.HasPrefix(u.Host, "[") {
		if ip, err := netip.ParseAddr(u.Hostname()); err != nil || !ip.Is6() {
			return goRedacted, true
		}
	}
	return SanitizeComposerURL(raw)
}

func composerNoProxy(s string) bool {
	if !composerSafeText(s, 4096) {
		return false
	}
	for entry := range strings.SplitSeq(s, ",") {
		entry = strings.TrimSpace(entry)
		if host, bits, cidr := strings.Cut(entry, "/"); cidr {
			// Brackets are also permitted around the IPv6 address in a CIDR.
			if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
				host = host[1 : len(host)-1]
			}
			if _, err := netip.ParsePrefix(host + "/" + bits); err != nil {
				return false
			}
			continue
		}
		for _, r := range entry {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(".*-:[]", r)) {
				return false
			}
		}
	}
	return true
}

// parse projects only known fields. Raw auth objects, options and scripts never
// leave this bounded decode or enter the path-resolution snapshot.
func (a *ComposerConfigSnapshot) parse(f *model.ComposerConfigFile, data []byte) {
	var doc map[string]json.RawMessage
	if !utf8.Valid(data) || int64(len(data)) > composerConfigBytes || json.Unmarshal(data, &doc) != nil || doc == nil {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	f.Status = "present"
	var config map[string]json.RawMessage
	if raw := doc["config"]; raw != nil && (json.Unmarshal(raw, &config) != nil || config == nil) {
		a.fileReason(f, "invalid", "parse_error")
	}
	a.paths[f.SourceID] = map[string]string{}
	boolKeys := []string{"secure-http", "disable-tls", "lock", "source-fallback"}
	for _, key := range boolKeys {
		a.scalar(f, key, config[key], "bool")
	}
	for _, key := range []string{"vendor-dir", "bin-dir", "cache-dir", "cafile", "capath"} {
		if raw := config[key]; raw != nil {
			var value string
			if json.Unmarshal(raw, &value) != nil || !composerSafeText(value, 4096) || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				a.fileReason(f, "invalid", "parse_error")
				continue
			}
			a.paths[f.SourceID][key] = value
			safe, redacted := SanitizeComposerURL(value)
			a.setting(f, key, safe, redacted)
		}
	}
	a.scalar(f, "store-auths", config["store-auths"], "bool|prompt")
	a.scalar(f, "platform-check", config["platform-check"], "bool|php-only")
	a.scalar(f, "minimum-stability", doc["minimum-stability"], "dev|alpha|beta|RC|rc|stable")
	a.scalar(f, "prefer-stable", doc["prefer-stable"], "bool")
	for _, key := range []string{"allow-plugins", "preferred-install"} {
		raw := config[key]
		if raw == nil {
			continue
		}
		typ := "bool"
		if key == "preferred-install" {
			typ = "dist|source|auto"
		}
		if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '{' {
			var entries map[string]json.RawMessage
			if json.Unmarshal(raw, &entries) != nil {
				a.fileReason(f, "invalid", "parse_error")
				continue
			}
			for i, k := range slices.Sorted(maps.Keys(entries)) {
				if i >= composerPatternLimit {
					a.fileReason(f, "unsupported", "record_limit")
					break
				}
				if !composerValidPattern(k) {
					a.fileReason(f, "invalid", "parse_error")
					continue
				}
				a.scalar(f, key+"."+k, entries[k], typ)
			}
		} else {
			a.scalar(f, key, raw, typ)
		}
	}
	for _, group := range []string{"audit", "policy"} {
		a.policy(f, group, config[group])
	}
	for _, obj := range []map[string]json.RawMessage{doc, config} {
		for _, key := range []string{"http-basic", "bearer", "github-oauth", "gitlab-oauth", "gitlab-token", "bitbucket-oauth", "forgejo-token", "client-certificate", "custom-headers"} {
			if _, ok := obj[key]; ok {
				if !slices.ContainsFunc(f.Settings, func(s model.CargoConfigSetting) bool { return s.Key == "auth_configured" }) {
					a.setting(f, "auth_configured", "true", true)
				}
			}
		}
	}
	a.repositories(f, doc["repositories"])
}

func (a *ComposerConfigSnapshot) scalar(f *model.ComposerConfigFile, key string, raw json.RawMessage, allowed string) {
	if raw == nil {
		return
	}
	raw = bytes.TrimSpace(raw)
	if string(raw) == "true" || string(raw) == "false" {
		if slices.Contains(strings.Split(allowed, "|"), "bool") {
			a.setting(f, key, string(raw), false)
			return
		}
	}
	var value string
	if json.Unmarshal(raw, &value) == nil && slices.Contains(strings.Split(allowed, "|"), value) && value != "bool" {
		a.setting(f, key, value, false)
		return
	}
	a.fileReason(f, "invalid", "parse_error")
}
func (a *ComposerConfigSnapshot) policy(f *model.ComposerConfigFile, key string, raw json.RawMessage) {
	if raw == nil {
		return
	}
	if key == "policy" && (string(raw) == "true" || string(raw) == "false") {
		a.scalar(f, key, raw, "bool")
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	if key == "audit" {
		a.scalar(f, "audit.abandoned", fields["abandoned"], "ignore|report|fail")
		for _, k := range []string{"block-insecure", "block-abandoned", "ignore-unreachable"} {
			a.scalar(f, "audit."+k, fields[k], "bool")
		}
		return
	}
	for _, k := range []string{"advisories", "malware", "abandoned"} {
		r := fields[k]
		if r == nil {
			continue
		}
		if string(r) == "true" || string(r) == "false" {
			a.scalar(f, "policy."+k, r, "bool")
			continue
		}
		var child map[string]json.RawMessage
		if json.Unmarshal(r, &child) != nil || child == nil {
			a.fileReason(f, "invalid", "parse_error")
			continue
		}
		a.scalar(f, "policy."+k+".block", child["block"], "bool")
		a.scalar(f, "policy."+k+".audit", child["audit"], "ignore|report|fail")
		if k == "malware" {
			a.scalar(f, "policy.malware.block-scope", child["block-scope"], "all|update|install")
		}
	}
	if raw := fields["ignore-unreachable"]; raw != nil {
		if string(raw) == "true" || string(raw) == "false" {
			a.scalar(f, "policy.ignore-unreachable", raw, "bool")
		} else {
			a.list(f, "policy.ignore-unreachable", raw, func(v string) bool { return v == "audit" || v == "install" || v == "update" })
		}
	}
}
func (a *ComposerConfigSnapshot) list(f *model.ComposerConfigFile, key string, raw json.RawMessage, valid func(string) bool) {
	var items []string
	if json.Unmarshal(raw, &items) != nil || items == nil || len(items) > composerPatternLimit {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	for _, s := range items {
		if !valid(s) {
			a.fileReason(f, "invalid", "parse_error")
			return
		}
	}
	encoded, _ := json.Marshal(items)
	a.setting(f, key, string(encoded), false)
}

// Decode repository objects in declared order. Object names may hold secrets;
// only numeric indices and the fixed Packagist-disabled key are serialized.
func (a *ComposerConfigSnapshot) repositories(f *model.ComposerConfigFile, raw json.RawMessage) {
	if raw == nil {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || (token != json.Delim('[') && token != json.Delim('{')) {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	for i := 0; dec.More(); i++ {
		if i >= composerPatternLimit {
			a.fileReason(f, "unsupported", "record_limit")
			return
		}
		name := ""
		if token == json.Delim('{') {
			key, err := dec.Token()
			if err != nil {
				a.fileReason(f, "invalid", "parse_error")
				return
			}
			name, _ = key.(string)
		}
		var entry json.RawMessage
		if dec.Decode(&entry) != nil {
			a.fileReason(f, "invalid", "parse_error")
			return
		}
		if name != "" && string(entry) == "false" {
			if name == "packagist.org" || name == "packagist" {
				a.setting(f, "repositories.packagist.org", "false", false)
			}
			continue
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(entry, &obj) != nil || obj == nil {
			a.fileReason(f, "invalid", "parse_error")
			continue
		}
		if string(obj["packagist.org"]) == "false" || string(obj["packagist"]) == "false" {
			a.setting(f, "repositories.packagist.org", "false", false)
			continue
		}
		prefix := "repositories." + strconv.Itoa(i) + "."
		for _, key := range []string{"type", "url"} {
			if valueRaw := obj[key]; valueRaw != nil {
				var value string
				if json.Unmarshal(valueRaw, &value) != nil || value == "" || !composerSafeText(value, 4096) {
					a.fileReason(f, "invalid", "parse_error")
					continue
				}
				redacted := false
				if key == "url" {
					value, redacted = SanitizeComposerURL(value)
				} else if len(value) > 64 || strings.ContainsFunc(value, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') }) {
					a.fileReason(f, "invalid", "parse_error")
					continue
				}
				a.setting(f, prefix+key, value, redacted)
			}
		}
		a.scalar(f, prefix+"canonical", obj["canonical"], "bool")
		for _, key := range []string{"only", "exclude"} {
			if obj[key] != nil {
				a.list(f, prefix+key, obj[key], composerValidPattern)
			}
		}
	}
}
func composerFindings(f model.ComposerConfigFile) []model.CargoConfigFinding {
	var out []model.CargoConfigFinding
	for _, s := range f.Settings {
		code, severity, detail := "", "MEDIUM", ""
		switch {
		case s.Key == "disable-tls" && s.Display == "true":
			code, detail = "composer-001", "TLS is disabled by Composer configuration."
		case s.Key == "secure-http" && s.Display == "false":
			code, detail = "composer-002", "Composer permits insecure HTTP connections."
		case strings.HasPrefix(s.Key, "repositories.") && strings.HasSuffix(s.Key, ".url") && strings.HasPrefix(strings.ToLower(s.Display), "http://"):
			code, detail = "composer-003", "Composer repository uses plaintext HTTP."
		case s.Key == "allow-plugins" && s.Display == "true":
			code, severity, detail = "composer-004", "LOW", "Composer allows all plugins."
		}
		if code != "" {
			out = append(out, model.CargoConfigFinding{SourceID: f.SourceID, Code: code, Severity: severity, Key: s.Key, Detail: detail})
		}
	}
	return out
}

// KeepProjects drops candidates later recognized as installed vendor packages.
// Discovery order must not turn a dependency's config into a root audit.
func (a *ComposerConfigSnapshot) KeepProjects(paths map[string]bool) {
	removed := map[string]bool{}
	for id, f := range a.files {
		if f.Scope == "project" && !paths[a.key(f.Path)] {
			removed[id] = true
			delete(a.files, id)
		}
	}
	a.audit.Contexts = slices.DeleteFunc(a.audit.Contexts, func(c model.ComposerConfigContext) bool {
		return slices.ContainsFunc(c.ConfigSourceIDs, func(id string) bool { return removed[id] })
	})
	keepCred := map[string]bool{}
	if a.Home != "" {
		keepCred[a.key(filepath.Join(a.Home, "auth.json"))] = true
	}
	for _, f := range a.files {
		if f.Path != "" {
			keepCred[a.key(filepath.Join(filepath.Dir(f.Path), "auth.json"))] = true
		}
	}
	a.audit.CredentialFiles = slices.DeleteFunc(a.audit.CredentialFiles, func(c model.CargoCredentialFile) bool { return !keepCred[a.key(c.Path)] })
}
