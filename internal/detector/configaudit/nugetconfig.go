package configaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

var maxNuGetAuditBytes = 256 << 10

const nugetConfigBytes int64 = 2 << 20
const nugetSettingLimit = 256

// NuGetConfigScope comes from the resolved developer, never a login shell.
type NuGetConfigScope struct {
	Username, Home  string
	Roots           []string // approved scope for ancestor NuGet.Config probes
	Protected       func(string) string
	Volume          func(string) bool
	ProcessVerified bool
}

// NuGetPaths are the locations an ambient context selects for inventory.
type NuGetPaths struct {
	Repository string // legacy repositoryPath, resolved
	Partial    bool
}

// NuGetConfigSnapshot accumulates observed NuGet configuration as the
// inventory discovers projects and restore graphs.
type NuGetConfigSnapshot struct {
	GlobalPackages   string   // effective expanded-package root for the user context
	CLIHome          string   // profile root for tools and templates
	PackageRoots     []string // every configured fallback, custom and legacy root
	exec             executor.Executor
	ctx              context.Context
	scope            NuGetConfigScope
	audit            model.NuGetConfigAudit
	files            map[string]*model.NuGetConfigFile
	paths            map[string]map[string]string // source ID → resolved path settings
	byPath           map[string]string            // path key → source ID
	env              map[string]string
	process          *model.NuGetConfigFile
	userChain        []*model.NuGetConfigFile // highest precedence first
	dirs             map[string][]*model.NuGetConfigFile
	contexts         map[string]bool
	bytes            int
	limited          bool
	selectionReasons []string        // why every selected chain is uncertain
	cleartext        map[string]bool // source IDs holding a literal ClearTextPassword
}

type NuGetConfigDetector struct{ exec executor.Executor }

func NewNuGetConfigDetector(exec executor.Executor) *NuGetConfigDetector {
	return &NuGetConfigDetector{exec: exec}
}

func emptyNuGetAudit() model.NuGetConfigAudit {
	return model.NuGetConfigAudit{
		SchemaVersion: model.NuGetInventorySchemaVersion, Status: "complete", Reasons: []string{},
		Files: []model.NuGetConfigFile{}, Contexts: []model.NuGetConfigContext{}, Findings: []model.CargoConfigFinding{},
		ObservedRegistries: []string{}, ObservedProxies: []string{}, FindingCodeCounts: map[string]int{}, FindingCounts: map[string]int{},
	}
}

func (d *NuGetConfigDetector) Detect(ctx context.Context, scope NuGetConfigScope) *NuGetConfigSnapshot {
	a := &NuGetConfigSnapshot{exec: d.exec, ctx: ctx, scope: scope, audit: emptyNuGetAudit(), files: map[string]*model.NuGetConfigFile{}, paths: map[string]map[string]string{}, byPath: map[string]string{}, env: map[string]string{}, dirs: map[string][]*model.NuGetConfigFile{}, contexts: map[string]bool{}, cleartext: map[string]bool{}}
	if scope.Username == "" || scope.Home == "" {
		a.degrade("user_unresolved")
		return a
	}
	if ctx.Err() != nil {
		a.degrade("deadline_exceeded")
		return a
	}
	a.CLIHome = scope.Home
	a.process = a.record("process", "")
	if a.process == nil {
		a.selectionReason("output_size_limit")
		return a
	}
	if scope.ProcessVerified {
		a.processEnv()
	} else {
		a.fileReason(a.process, "unsupported", "process_context_unverified")
		a.selectionReason("process_context_unverified")
	}
	a.userConfigs()
	a.GlobalPackages = filepath.Join(a.CLIHome, ".nuget", "packages")
	for _, f := range a.userChain {
		if p := a.paths[f.SourceID]["globalPackagesFolder"]; p != "" {
			a.GlobalPackages = p
			break
		}
	}
	if p := a.env["NUGET_PACKAGES"]; p != "" {
		a.GlobalPackages = p
	}
	return a
}

// processEnv observes the allowlisted variables of the verified developer process.
func (a *NuGetConfigSnapshot) processEnv() {
	for _, key := range []string{"NUGET_PACKAGES", "NUGET_HTTP_CACHE_PATH", "NUGET_FALLBACK_PACKAGES", "DOTNET_CLI_HOME", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		value := a.exec.Getenv(key)
		if value == "" {
			continue
		}
		display, redacted := value, false
		switch {
		case strings.EqualFold(key, "NO_PROXY"):
			if !composerNoProxy(value) {
				display, redacted = goRedacted, true
			}
		case strings.HasSuffix(strings.ToLower(key), "proxy"):
			display, redacted = sanitizeComposerProxy(value)
		case key == "NUGET_FALLBACK_PACKAGES":
			list := a.pathList(value, "", "")
			if list == nil {
				a.fileReason(a.process, a.process.Status, "path_unresolved")
				continue
			}
			a.PackageRoots = append(a.PackageRoots, list...)
			display = strings.Join(list, ";")
		default:
			if !composerSafeText(value, 4096) || !filepath.IsAbs(value) {
				a.fileReason(a.process, a.process.Status, "path_unresolved")
				a.selectionReason("path_unresolved")
				continue
			}
			a.env[key] = filepath.Clean(value)
			display = a.env[key]
		}
		a.setting(a.process, "environment."+key, display, redacted)
	}
	if a.env["DOTNET_CLI_HOME"] != "" {
		a.CLIHome = a.env["DOTNET_CLI_HOME"]
	}
	if a.exec.HasEnvPrefix("NuGetPackageSourceCredentials_") || a.exec.Getenv("VSS_NUGET_ACCESSTOKEN") != "" || a.exec.Getenv("VSS_NUGET_EXTERNAL_FEED_ENDPOINTS") != "" {
		a.setting(a.process, "auth_configured", "true", true)
	}
	if a.exec.Getenv("NUGET_PLUGIN_PATHS") != "" || a.exec.Getenv("NUGET_CREDENTIALPROVIDERS_PATH") != "" {
		a.setting(a.process, "credential_provider_configured", "true", true)
	}
	if len(a.process.Settings) > 0 {
		a.process.Status = "read"
	}
}

// userConfigs reads the user, additional and machine files in precedence order.
// Windows keeps the APPDATA profile; elsewhere the user directory follows the
// CLI home NuGet selected, as its tools and cache already do.
func (a *NuGetConfigSnapshot) userConfigs() {
	home := a.CLIHome
	var userDir, machineDir string
	switch a.exec.GOOS() {
	case model.PlatformWindows:
		appdata := filepath.Join(a.scope.Home, "AppData", "Roaming")
		if a.scope.ProcessVerified {
			if v := a.exec.Getenv("APPDATA"); v != "" {
				if filepath.IsAbs(v) && composerSafeText(v, 4096) {
					appdata = v
				} else {
					a.selectionReason("path_unresolved")
				}
			}
		}
		userDir = filepath.Join(appdata, "NuGet")
		programs := `C:\Program Files (x86)`
		if a.scope.ProcessVerified {
			if v := a.exec.Getenv("ProgramFiles(x86)"); v != "" && filepath.IsAbs(v) && composerSafeText(v, 4096) {
				programs = v
			}
		}
		machineDir = filepath.Join(programs, "NuGet", "Config")
	case model.PlatformDarwin:
		userDir = filepath.Join(home, ".nuget", "NuGet")
		machineDir = "/Library/Application Support/NuGet/Config"
	default:
		userDir = filepath.Join(home, ".nuget", "NuGet")
		machineDir = "/etc/opt/NuGet/Config"
	}
	if f := a.file("user", filepath.Join(userDir, "NuGet.Config")); f != nil {
		a.userChain = append(a.userChain, f)
	}
	if a.exec.GOOS() != model.PlatformWindows {
		// The Mono-era location is an independent candidate, not a merged home.
		alt := filepath.Join(a.scope.Home, ".config", "NuGet", "NuGet.Config")
		if info, err := a.guarded(alt, 0).Stat(alt); err == nil && info.Mode().IsRegular() {
			if f := a.file("user", alt); f != nil && len(a.userChain) > 0 && a.userChain[0].Status == "not_found" {
				a.userChain = append(a.userChain, f)
			}
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			a.degrade(a.reason(err, alt))
		}
	}
	for _, dir := range []struct{ path, scope string }{{filepath.Join(userDir, "config"), "user"}, {machineDir, "machine"}} {
		for _, p := range a.configFiles(dir.path) {
			if f := a.file(dir.scope, p); f != nil {
				a.userChain = append(a.userChain, f)
			}
		}
	}
}

// configFiles lists *.config files directly inside dir, in name order.
func (a *NuGetConfigSnapshot) configFiles(dir string) []string {
	if a.ctx.Err() != nil {
		a.selectionReason("deadline_exceeded")
		return nil
	}
	entries, more, err := a.guarded(dir, 0).ReadDirLimit(dir, nugetSettingLimit)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		a.selectionReason(a.reason(err, dir))
		return nil
	}
	if more {
		a.selectionReason("entry_limit")
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.EqualFold(filepath.Ext(e.Name()), ".config") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	slices.Sort(out)
	return out
}

func (a *NuGetConfigSnapshot) guarded(p string, limit int64) executor.Executor {
	return a.exec.GuardedFiles([]string{p}, a.scope.Protected, limit)
}
func (a *NuGetConfigSnapshot) key(p string) string { return GoPathKey(a.exec.GOOS(), p) }
func (a *NuGetConfigSnapshot) degrade(reason string) {
	a.audit.Status = "partial"
	if !slices.Contains(a.audit.Reasons, reason) {
		a.audit.Reasons = append(a.audit.Reasons, reason)
	}
}

// selectionReason marks every context partial: the selected chain itself is
// uncertain, not just one file in it.
func (a *NuGetConfigSnapshot) selectionReason(reason string) {
	a.degrade(reason)
	if !slices.Contains(a.selectionReasons, reason) {
		a.selectionReasons = append(a.selectionReasons, reason)
	}
}
func (a *NuGetConfigSnapshot) fileReason(f *model.NuGetConfigFile, status, reason string) {
	if f != nil {
		f.Status = status
		if !slices.Contains(f.Reasons, reason) {
			f.Reasons = append(f.Reasons, reason)
		}
	}
	a.degrade(reason)
}
func (a *NuGetConfigSnapshot) reason(err error, p string) string {
	return CargoReadReason(err, p, a.scope.Volume)
}

func (a *NuGetConfigSnapshot) record(scope, path string) *model.NuGetConfigFile {
	id := GoSourceID(a.scope.Username, "nuget_config_"+scope, path)
	if f := a.files[id]; f != nil {
		return f
	}
	if a.limited || a.bytes+len(path)+256 > maxNuGetAuditBytes {
		a.limited = true
		a.degrade("output_size_limit")
		return nil
	}
	f := &model.NuGetConfigFile{SourceID: id, Scope: scope, Path: path, Status: "not_found", Reasons: []string{}, Settings: []model.CargoConfigSetting{}}
	a.files[id] = f
	if path != "" {
		a.byPath[a.key(path)] = id
	}
	a.bytes += len(path) + 256
	return f
}
func (a *NuGetConfigSnapshot) setting(f *model.NuGetConfigFile, key, value string, redacted bool) {
	if f == nil {
		return
	}
	if !composerSafeText(value, 4096) {
		a.fileReason(f, "unreadable", "parse_error")
		return
	}
	if len(f.Settings) >= nugetSettingLimit {
		a.fileReason(f, "unsupported", "record_limit")
		return
	}
	if a.bytes+len(key)+len(value)+128 > maxNuGetAuditBytes {
		a.limited = true
		a.fileReason(f, "unsupported", "output_size_limit")
		return
	}
	a.bytes += len(key) + len(value) + 128
	f.Settings = append(f.Settings, model.CargoConfigSetting{Key: key, Display: value, SourceID: f.SourceID, Redacted: redacted})
}

// file records and reads one NuGet.Config once; later callers get the record.
func (a *NuGetConfigSnapshot) file(scope, p string) *model.NuGetConfigFile {
	if id := a.byPath[a.key(p)]; id != "" {
		return a.files[id]
	}
	f := a.record(scope, p)
	if f == nil {
		return nil
	}
	if a.ctx.Err() != nil {
		a.fileReason(f, "unreadable", "deadline_exceeded")
		return f
	}
	files := a.guarded(p, nugetConfigBytes)
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
	if info.Size() > nugetConfigBytes {
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
func (a *NuGetConfigSnapshot) readFailure(f *model.NuGetConfigFile, err error, p string) {
	reason := a.reason(err, p)
	status := "unreadable"
	if reason == "skipped_protected" || reason == "refused_network_volume" {
		status = "unsupported"
	}
	a.fileReason(f, status, reason)
}

// dir returns the NuGet.Config files directly in dir, probing every spelling
// the released reader accepts on a case-sensitive filesystem.
func (a *NuGetConfigSnapshot) dir(dir string) []*model.NuGetConfigFile {
	key := a.key(dir)
	if files, ok := a.dirs[key]; ok {
		return files
	}
	names := []string{"nuget.config", "NuGet.config", "NuGet.Config"}
	if a.exec.GOOS() != model.PlatformLinux {
		names = names[2:]
	}
	var out []*model.NuGetConfigFile
	for _, name := range names {
		p := filepath.Join(dir, name)
		info, err := a.guarded(p, 0).Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			a.selectionReason(a.reason(err, p))
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if f := a.file("project", p); f != nil {
			out = append(out, f)
		}
	}
	a.dirs[key] = out
	return out
}

// ProjectFile records the allowlisted literal properties of an MSBuild file
// already read by inventory. Property values that need evaluation are skipped.
// projectDir is the consuming project; a shared Directory.*.props/targets
// passes "" and leaves project-relative paths to each consumer's record.
func (a *NuGetConfigSnapshot) ProjectFile(path, status string, reasons []string, props map[string]string, projectDir string) *model.NuGetConfigFile {
	f := a.record("project", path)
	if f == nil {
		return nil
	}
	f.Status = status
	f.Reasons = slices.Clone(reasons)
	if f.Reasons == nil {
		f.Reasons = []string{}
	}
	if status != "read" {
		return f
	}
	a.paths[f.SourceID] = map[string]string{}
	dir := filepath.Dir(path)
	for _, key := range []string{"NuGetAudit", "RestoreLockedMode"} {
		a.boolean(f, "project."+key, props[key])
	}
	a.enum(f, "project.NuGetAuditMode", props["NuGetAuditMode"], "direct", "all")
	a.enum(f, "project.NuGetAuditLevel", props["NuGetAuditLevel"], "low", "moderate", "high", "critical")
	for _, key := range []string{"RestorePackagesPath", "NuGetLockFilePath"} {
		if props[key] == "" || projectDir == "" && nugetConsumerRelative(props[key]) {
			continue
		}
		p, ok := a.resolvePath(props[key], dir, projectDir)
		if !ok {
			a.degrade("path_unresolved")
			continue
		}
		a.paths[f.SourceID][key] = p
		a.setting(f, "project."+key, p, false)
	}
	for _, key := range []string{"RestoreFallbackFolders", "RestoreAdditionalProjectFallbackFolders"} {
		if props[key] == "" || projectDir == "" && nugetConsumerRelative(props[key]) {
			continue
		}
		list := a.pathList(props[key], dir, projectDir)
		if list == nil {
			a.degrade("path_unresolved")
			continue
		}
		a.PackageRoots = append(a.PackageRoots, list...)
		a.setting(f, "project."+key, strings.Join(list, ";"), false)
	}
	if p := a.paths[f.SourceID]["RestorePackagesPath"]; p != "" {
		a.PackageRoots = append(a.PackageRoots, p)
	}
	return f
}

// Ambient records the config sources NuGet would load for a project in dir:
// the leading records (process, project files), the directory chain inside
// approved roots, then user and machine configuration.
func (a *NuGetConfigSnapshot) Ambient(dir string, leading ...*model.NuGetConfigFile) NuGetPaths {
	result := NuGetPaths{}
	chain := []*model.NuGetConfigFile{}
	for _, f := range leading {
		if f != nil {
			chain = append(chain, f)
		}
	}
	for p := filepath.Clean(dir); GoWithinRoots(a.exec.GOOS(), p, a.scope.Roots); p = filepath.Dir(p) {
		chain = append(chain, a.dir(p)...)
		if filepath.Dir(p) == p {
			break
		}
	}
	chain = append(chain, a.userChain...)
	reasons := slices.Clone(a.selectionReasons)
	ids := []string{}
	for _, f := range chain {
		ids = append(ids, f.SourceID)
		if f.Status != "not_found" {
			reasons = append(reasons, f.Reasons...) // a read file can still be partial
		}
		if result.Repository == "" {
			result.Repository = a.paths[f.SourceID]["repositoryPath"]
		}
	}
	if a.process != nil && !slices.Contains(ids, a.process.SourceID) {
		ids = append([]string{a.process.SourceID}, ids...)
	}
	result.Partial = len(reasons) > 0
	a.context(model.NuGetConfigContext{ProjectPath: filepath.Clean(dir), ContextKind: "ambient", ConfigSourceIDs: ids}, reasons)
	return result
}

// Restore records the ordered config input one assets file recorded. Paths
// outside approved roots get a targeted read only.
func (a *NuGetConfigSnapshot) Restore(assets, project string, paths []string) {
	ids := []string{}
	reasons := slices.Clone(a.selectionReasons)
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			reasons = append(reasons, "path_unresolved")
			a.degrade("path_unresolved")
			continue
		}
		f := a.file("project", filepath.Clean(p))
		if f == nil {
			reasons = append(reasons, "output_size_limit")
			continue
		}
		ids = append(ids, f.SourceID)
		if f.Status != "not_found" {
			reasons = append(reasons, f.Reasons...)
		}
	}
	a.context(model.NuGetConfigContext{ProjectPath: project, ContextKind: "restore", RestoreMetadataPath: assets, ConfigSourceIDs: ids}, reasons)
}

func (a *NuGetConfigSnapshot) context(c model.NuGetConfigContext, reasons []string) {
	key := c.ContextKind + "\x00" + a.key(c.ProjectPath) + "\x00" + c.RestoreMetadataPath
	if a.limited || a.contexts[key] {
		return
	}
	a.contexts[key] = true
	slices.Sort(reasons)
	c.Reasons = slices.Compact(reasons)
	if c.Reasons == nil {
		c.Reasons = []string{}
	}
	c.Status = "complete"
	if len(c.Reasons) > 0 {
		c.Status = "partial"
	}
	a.audit.Contexts = append(a.audit.Contexts, c)
	a.bytes += len(c.ProjectPath) + len(c.RestoreMetadataPath) + len(c.ConfigSourceIDs)*70 + 128
}

// nugetConsumerRelative reports whether an MSBuild path only has meaning in
// the consuming project's directory, which a shared file does not have.
func nugetConsumerRelative(value string) bool {
	for entry := range strings.SplitSeq(value, ";") {
		entry = strings.TrimSpace(entry)
		if entry != "" && !strings.HasPrefix(entry, "$(MSBuildThisFileDirectory)") && !filepath.IsAbs(entry) {
			return true
		}
	}
	return false
}

// resolvePath anchors a literal path: $(MSBuildThisFileDirectory) to the
// defining file, everything else to the project directory (the config file's
// own directory for NuGet.Config). MSBuild property functions and %VAR%
// references stay unresolved, as does a project-relative path without a project.
func (a *NuGetConfigSnapshot) resolvePath(value, fileDir, projectDir string) (string, bool) {
	if rest, ok := strings.CutPrefix(value, "$(MSBuildThisFileDirectory)"); ok {
		value = fileDir + string(filepath.Separator) + strings.TrimLeft(rest, `/\`)
	} else if rest, ok := strings.CutPrefix(value, "$(MSBuildProjectDirectory)"); ok {
		value = filepath.Join(projectDir, strings.TrimLeft(rest, `/\`))
	}
	if value == "" || !composerSafeText(value, 4096) || strings.ContainsAny(value, "$%@*?") {
		return "", false
	}
	if !filepath.IsAbs(value) {
		if projectDir == "" {
			return "", false
		}
		value = filepath.Join(projectDir, filepath.FromSlash(value))
	}
	return filepath.Clean(value), true
}

// pathList resolves a ';'-separated path list; one bad entry rejects the list.
func (a *NuGetConfigSnapshot) pathList(value, fileDir, projectDir string) []string {
	var out []string
	for entry := range strings.SplitSeq(value, ";") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		p, ok := a.resolvePath(entry, fileDir, projectDir)
		if !ok {
			return nil
		}
		out = append(out, p)
	}
	return out
}

func (a *NuGetConfigSnapshot) boolean(f *model.NuGetConfigFile, key, value string) {
	switch strings.ToLower(value) {
	case "":
	case "true", "false":
		a.setting(f, key, strings.ToLower(value), false)
	default:
		a.fileReason(f, "unreadable", "parse_error")
	}
}
func (a *NuGetConfigSnapshot) enum(f *model.NuGetConfigFile, key, value string, allowed ...string) {
	if value == "" {
		return
	}
	if slices.Contains(allowed, strings.ToLower(value)) {
		a.setting(f, key, strings.ToLower(value), false)
		return
	}
	a.fileReason(f, "unreadable", "parse_error")
}

// nugetLiteralSecret reports whether a ClearTextPassword value stores the
// password itself. NuGet resolves a whole-value %VARIABLE% reference from the
// environment at use time, so that spelling leaves nothing in the file.
func nugetLiteralSecret(value string) bool {
	if value == "" {
		return false
	}
	inner, ok := strings.CutPrefix(value, "%")
	inner, ok2 := strings.CutSuffix(inner, "%")
	return !(ok && ok2 && inner != "" && !strings.Contains(inner, "%"))
}

// nugetAlias bounds a user-chosen source name; names may carry secrets.
func nugetAlias(name string) (string, bool) {
	if name == "" || !composerSafeText(name, 128) || strings.ContainsAny(name, "@:/\\?#") {
		return goRedacted, true
	}
	return name, false
}

// nugetSourceValue is a sanitized URL or an anchored local path.
func (a *NuGetConfigSnapshot) nugetSourceValue(value, base string) (string, bool) {
	if !composerSafeText(value, 4096) {
		return goRedacted, true
	}
	// URLs, file URIs, UNC and drive paths are already whole; only a
	// relative path needs the config directory as its anchor.
	if strings.Contains(value, "://") || strings.Contains(value, "@") || strings.HasPrefix(value, `\\`) || len(value) > 2 && value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
		return SanitizeComposerURL(value)
	}
	if p, ok := a.resolvePath(value, base, base); ok {
		return p, false
	}
	return goRedacted, true
}

type nugetSourceEntry struct {
	name, value, insecure, disableTLS string
}

// parse walks the configuration XML, reading only allowlisted scalar and
// list settings. Credential values become presence flags.
func (a *NuGetConfigSnapshot) parse(f *model.NuGetConfigFile, data []byte) {
	if !utf8.Valid(data) || bytes.Contains(bytes.ToUpper(data), []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
		a.fileReason(f, "unreadable", "parse_error")
		return
	}
	dec := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	dec.Strict = true
	dec.Entity = map[string]string{}
	base := filepath.Dir(f.Path)
	a.paths[f.SourceID] = map[string]string{}
	f.Status = "read"
	rootSeen := false
	var stack []xml.StartElement
	var sources []nugetSourceEntry
	disabled := map[string]bool{}
	mapping, fallback, signers := 0, 0, 0
	auth, cleartext := false, false
	attr := func(e xml.StartElement, name string) string {
		for _, x := range e.Attr {
			if strings.EqualFold(x.Name.Local, name) {
				return strings.TrimSpace(x.Value)
			}
		}
		return ""
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			a.fileReason(f, "unreadable", "parse_error")
			return
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) == 0 {
				if rootSeen || t.Name.Local != "configuration" {
					a.fileReason(f, "unreadable", "parse_error")
					return
				}
				rootSeen = true
			}
			stack = append(stack, t)
			if len(stack) < 3 || !strings.EqualFold(stack[0].Name.Local, "configuration") {
				continue
			}
			section, name := stack[1].Name.Local, t.Name.Local
			// <clear/> only matters for the effective-feed question the audit
			// does not answer, so it is not a setting.
			switch {
			case section == "packageSources" && len(stack) == 3 && name == "add":
				sources = append(sources, nugetSourceEntry{name: attr(t, "key"), value: attr(t, "value"), insecure: attr(t, "allowInsecureConnections"), disableTLS: attr(t, "disableTLSCertificateValidation")})
			case section == "disabledPackageSources" && len(stack) == 3 && name == "add":
				if strings.EqualFold(attr(t, "value"), "true") {
					disabled[strings.ToLower(attr(t, "key"))] = true
				}
			case section == "packageSourceMapping" && len(stack) == 4 && name == "package":
				alias, redacted := nugetAlias(attr(stack[2], "key"))
				pattern := attr(t, "pattern")
				if pattern == "" || !composerSafeText(pattern, 256) {
					a.fileReason(f, "unreadable", "parse_error")
					continue
				}
				prefix := "packageSourceMapping." + strconv.Itoa(mapping) + "."
				mapping++
				a.setting(f, prefix+"source", alias, redacted)
				a.setting(f, prefix+"pattern", pattern, false)
			case section == "fallbackPackageFolders" && len(stack) == 3 && name == "add":
				p, ok := a.resolvePath(attr(t, "value"), base, base)
				if !ok {
					a.degrade("path_unresolved")
					continue
				}
				a.PackageRoots = append(a.PackageRoots, p)
				a.setting(f, "fallbackPackageFolders."+strconv.Itoa(fallback)+".path", p, false)
				fallback++
			case section == "config" && len(stack) == 3 && name == "add":
				a.configSetting(f, attr(t, "key"), attr(t, "value"), base, &auth)
			case section == "trustedSigners" && len(stack) == 3 && (name == "author" || name == "repository"):
				a.setting(f, "trustedSigners."+strconv.Itoa(signers)+".type", name, false)
			case section == "trustedSigners" && len(stack) == 4 && name == "certificate":
				if v := strings.ToLower(attr(t, "allowUntrustedRoot")); v == "true" || v == "false" {
					a.setting(f, "trustedSigners."+strconv.Itoa(signers)+".allowUntrustedRoot", v, false)
				}
			case section == "packageSourceCredentials" && len(stack) == 4 && name == "add":
				auth = true
				if strings.EqualFold(attr(t, "key"), "ClearTextPassword") && nugetLiteralSecret(attr(t, "value")) {
					cleartext = true
				}
			case section == "apikeys" && len(stack) == 3 && name == "add":
				auth = true
			}
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(t)) != 0 {
				a.fileReason(f, "unreadable", "parse_error")
				return
			}
		case xml.EndElement:
			if len(stack) == 0 {
				a.fileReason(f, "unreadable", "parse_error")
				return
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(stack) == 2 && strings.EqualFold(stack[0].Name.Local, "configuration") && stack[1].Name.Local == "trustedSigners" && (top.Name.Local == "author" || top.Name.Local == "repository") {
				signers++
			}
		}
	}
	if !rootSeen {
		a.fileReason(f, "unreadable", "parse_error")
		return
	}
	for i, s := range sources {
		prefix := "packageSources." + strconv.Itoa(i) + "."
		alias, redacted := nugetAlias(s.name)
		a.setting(f, prefix+"name", alias, redacted)
		value, redactedValue := a.nugetSourceValue(s.value, base)
		a.setting(f, prefix+"url", value, redactedValue)
		enabled := "true"
		if disabled[strings.ToLower(s.name)] {
			enabled = "false"
			delete(disabled, strings.ToLower(s.name))
		}
		a.setting(f, prefix+"enabled", enabled, false)
		for _, b := range []struct{ key, value string }{{"allowInsecureConnections", s.insecure}, {"disableTLSCertificateValidation", s.disableTLS}} {
			if v := strings.ToLower(b.value); v == "true" || v == "false" {
				a.setting(f, prefix+b.key, v, false)
			}
		}
	}
	for i, name := range slices.Sorted(func(yield func(string) bool) {
		for n := range disabled {
			if !yield(n) {
				return
			}
		}
	}) {
		// A source disabled here but added elsewhere is still an observed fact.
		alias, redacted := nugetAlias(name)
		prefix := "packageSources." + strconv.Itoa(len(sources)+i) + "."
		a.setting(f, prefix+"name", alias, redacted)
		a.setting(f, prefix+"enabled", "false", false)
	}
	if auth {
		a.setting(f, "auth_configured", "true", true)
	}
	// Decided here, before redaction; only the finding leaves the device.
	a.cleartext[f.SourceID] = cleartext
}

func (a *NuGetConfigSnapshot) configSetting(f *model.NuGetConfigFile, key, value, base string, auth *bool) {
	switch key {
	case "globalPackagesFolder", "repositoryPath":
		p, ok := a.resolvePath(value, base, base)
		if !ok {
			a.degrade("path_unresolved")
			return
		}
		a.paths[f.SourceID][key] = p
		a.PackageRoots = append(a.PackageRoots, p)
		a.setting(f, "config."+key, p, false)
	case "http_proxy":
		display, redacted := sanitizeComposerProxy(value)
		a.setting(f, "config.http_proxy", display, redacted)
	case "no_proxy":
		display, redacted := value, false
		if !composerNoProxy(value) {
			display, redacted = goRedacted, true
		}
		a.setting(f, "config.no_proxy", display, redacted)
	case "http_proxy.user", "http_proxy.password":
		*auth = true
	case "signatureValidationMode":
		a.enum(f, "config.signatureValidationMode", value, "accept", "require")
	case "maxHttpRequestsPerSource":
		if n, err := strconv.Atoi(value); err == nil && n > 0 && strconv.Itoa(n) == value {
			a.setting(f, "config.maxHttpRequestsPerSource", value, false)
		} else {
			a.fileReason(f, "unreadable", "parse_error")
		}
	}
}

func nugetFindings(f model.NuGetConfigFile, cleartext bool) []model.CargoConfigFinding {
	values := map[string]string{}
	for _, s := range f.Settings {
		values[s.Key] = s.Display
	}
	var out []model.CargoConfigFinding
	add := func(code, severity, key, detail string) {
		out = append(out, model.CargoConfigFinding{SourceID: f.SourceID, Code: code, Severity: severity, Key: key, Detail: detail})
	}
	for _, s := range f.Settings {
		prefix, field, _ := strings.Cut(s.Key, ".url")
		switch {
		case strings.HasPrefix(s.Key, "packageSources.") && field == "" && strings.HasSuffix(s.Key, ".url") && values[prefix+".enabled"] != "false":
			if strings.HasPrefix(strings.ToLower(s.Display), "http://") {
				add("nuget-001", "MEDIUM", s.Key, "NuGet package source uses plaintext HTTP.")
			}
			if values[prefix+".disableTLSCertificateValidation"] == "true" {
				add("nuget-002", "HIGH", prefix+".disableTLSCertificateValidation", "NuGet package source disables TLS certificate validation.")
			}
		case s.Key == "auth_configured" && cleartext:
			add("nuget-003", "MEDIUM", s.Key, "NuGet configuration stores a literal cleartext password.")
		case s.Key == "project.NuGetAudit" && s.Display == "false":
			add("nuget-004", "MEDIUM", s.Key, "NuGet audit is disabled for the project.")
		}
	}
	return out
}

func (a *NuGetConfigSnapshot) Finish() model.NuGetConfigAudit {
	for _, f := range a.files {
		// An incomplete config source has no current settings. The consumer
		// retains its last-known settings separately until a complete reread.
		if f.Status != "read" {
			f.Settings = []model.CargoConfigSetting{}
		}
		slices.Sort(f.Reasons)
		slices.SortFunc(f.Settings, func(x, y model.CargoConfigSetting) int { return strings.Compare(x.Key, y.Key) })
		a.audit.Files = append(a.audit.Files, *f)
		a.audit.Findings = append(a.audit.Findings, nugetFindings(*f, a.cleartext[f.SourceID])...)
		for _, r := range f.Reasons {
			a.degrade(r)
		}
	}
	nugetSummarize(&a.audit)
	slices.SortFunc(a.audit.Files, func(x, y model.NuGetConfigFile) int {
		return strings.Compare(x.Scope+"\x00"+x.Path, y.Scope+"\x00"+y.Path)
	})
	slices.SortFunc(a.audit.Contexts, func(x, y model.NuGetConfigContext) int {
		return strings.Compare(x.ProjectPath+"\x00"+x.ContextKind+"\x00"+x.RestoreMetadataPath, y.ProjectPath+"\x00"+y.ContextKind+"\x00"+y.RestoreMetadataPath)
	})
	slices.SortFunc(a.audit.Findings, func(x, y model.CargoConfigFinding) int {
		return strings.Compare(x.Code+x.SourceID+x.Key, y.Code+y.SourceID+y.Key)
	})
	slices.Sort(a.audit.Reasons)
	data, _ := json.Marshal(a.audit)
	if len(data) > maxNuGetAuditBytes {
		a.audit = emptyNuGetAudit()
		a.degrade("output_size_limit")
	}
	return a.audit
}

// nugetSummarize derives the endpoint lists and counts from the read files.
func nugetSummarize(audit *model.NuGetConfigAudit) {
	registries, proxies := map[string]bool{}, map[string]bool{}
	for _, f := range audit.Files {
		if f.Status != "read" {
			continue
		}
		audit.SourceCount++
		for _, s := range f.Settings {
			switch {
			case s.Display == "" || s.Display == goRedacted:
			case strings.HasPrefix(s.Key, "packageSources.") && strings.HasSuffix(s.Key, ".url"):
				registries[s.Display] = true
			case slices.Contains([]string{"config.http_proxy", "environment.HTTP_PROXY", "environment.HTTPS_PROXY", "environment.http_proxy", "environment.https_proxy"}, s.Key):
				proxies[s.Display] = true
			}
		}
	}
	audit.ObservedRegistries = append(audit.ObservedRegistries[:0], slices.Sorted(maps.Keys(registries))...)
	audit.ObservedProxies = append(audit.ObservedProxies[:0], slices.Sorted(maps.Keys(proxies))...)
	audit.ObservedRegistryCount, audit.ObservedProxyCount, audit.FindingCount = len(audit.ObservedRegistries), len(audit.ObservedProxies), len(audit.Findings)
	for _, f := range audit.Findings {
		audit.FindingCodeCounts[f.Code]++
		audit.FindingCounts[f.Severity]++
	}
}
