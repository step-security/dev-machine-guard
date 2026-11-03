package configaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"net/netip"
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

var maxMavenAuditBytes = 256 << 10

const (
	mavenConfigBytes             int64 = 2 << 20
	mavenSettingLimit                  = 256
	mavenPropertyLimit                 = 4096
	mavenIndexLimit                    = 10_000 // N stays 1-4 digits
	mavenManager                       = "maven"
	gradleManager                      = "gradle"
	mavenUserHomeReference             = "${user.home}"
	mavenSplitLegacyKey                = "aether.enhancedLocalRepository.split"
	mavenSplitKey                      = "aether.lrm.enhanced.split"
	mavenRepoLocalProperty             = "maven.repo.local"
	mavenSettingsSecurityName          = "settings-security.xml"
	mavenSettingsSecurity4Name         = "settings-security4.xml"
	mavenTransportSecurityMode         = "aether.transport.https.securityMode"
	mavenResolverTransport             = "maven.resolver.transport"
	gradleDependencyVerification       = "org.gradle.dependency.verification"
)

var (
	mavenLabelPattern    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,256}$`)
	mavenSelectorPattern = regexp.MustCompile(`^[A-Za-z0-9_.:,*!-]+$`)
	mavenHostPattern     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*$`)
	mavenSHA256Pattern   = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	mavenIntervalPattern = regexp.MustCompile(`^interval:[1-9][0-9]{0,8}$`)
	mavenWagonTLSFlags   = []string{"maven.wagon.http.ssl.insecure", "maven.wagon.http.ssl.allowall", "maven.wagon.http.ssl.ignore.validity.dates"}
)

// MavenLabel reports whether s is a safe Maven ID or profile label.
func MavenLabel(s string) bool { return mavenLabelPattern.MatchString(s) }

// MavenConfigKind is the source-ID kind for a Maven or Gradle configuration scope.
func MavenConfigKind(manager, scope string) string { return manager + "_config_" + scope }

// MavenXML returns a strict decoder for bounded Maven and Gradle XML. A
// DOCTYPE is rejected outright, so no entity or external resolution ever
// happens. Older POMs and settings declare ISO-8859-1, which is decoded.
func MavenXML(data []byte) (*xml.Decoder, error) {
	if int64(len(data)) > mavenConfigBytes {
		return nil, errors.New("invalid metadata")
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if bytes.Contains(bytes.ToUpper(data), []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
		return nil, errors.New("document type declarations are not supported")
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	dec.Entity = map[string]string{}
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		switch strings.ToLower(charset) {
		case "iso-8859-1", "iso8859-1", "latin1", "latin-1", "us-ascii", "ascii":
			raw, err := io.ReadAll(input)
			if err != nil {
				return nil, err
			}
			return strings.NewReader(latin1(raw)), nil
		}
		return nil, errors.New("unsupported encoding")
	}
	return dec, nil
}

func latin1(raw []byte) string {
	runes := make([]rune, len(raw))
	for i, b := range raw {
		runes[i] = rune(b)
	}
	return string(runes)
}

// JavaProperty is one key/value pair from a Java Properties file.
type JavaProperty struct{ Key, Value string }

// ParseJavaProperties follows java.util.Properties#load: `#`/`!` comments,
// `=`, `:` or whitespace separators, backslash escapes and continuation
// lines. Text that is not UTF-8 is read as ISO-8859-1, the byte-stream
// encoding. complete is false for a malformed escape or the entry cap.
func ParseJavaProperties(data []byte) (props []JavaProperty, complete bool) {
	text := string(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}))
	if !utf8.ValidString(text) {
		text = latin1(data)
	}
	complete = true
	var logical []string
	var cur strings.Builder
	cont := false
	for line := range strings.SplitSeq(strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(text), "\n") {
		line = strings.TrimLeft(line, " \t\f")
		if !cont && (line == "" || line[0] == '#' || line[0] == '!') {
			continue
		}
		slashes := len(line) - len(strings.TrimRight(line, `\`))
		if slashes%2 == 1 {
			cur.WriteString(line[:len(line)-1])
			cont = true
			continue
		}
		cur.WriteString(line)
		logical = append(logical, cur.String())
		cur.Reset()
		cont = false
	}
	if cont {
		logical = append(logical, cur.String())
	}
	for _, l := range logical {
		if len(props) >= mavenPropertyLimit {
			return props, false
		}
		i := 0
		for i < len(l) && !strings.ContainsRune("=: \t\f", rune(l[i])) {
			if l[i] == '\\' {
				i++
			}
			i++
		}
		i = min(i, len(l))
		rest := strings.TrimLeft(l[i:], " \t\f")
		if rest != "" && (rest[0] == '=' || rest[0] == ':') {
			rest = strings.TrimLeft(rest[1:], " \t\f")
		}
		key, ok1 := javaUnescape(l[:i])
		value, ok2 := javaUnescape(rest)
		complete = complete && ok1 && ok2
		props = append(props, JavaProperty{key, value})
	}
	return props, complete
}

func javaUnescape(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i >= len(s) {
			break
		}
		switch s[i] {
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 'f':
			b.WriteByte('\f')
		case 'u':
			r, err := strconv.ParseUint(s[i+1:min(i+5, len(s))], 16, 16)
			if err != nil || i+5 > len(s) {
				return b.String(), false
			}
			b.WriteRune(rune(r))
			i += 4
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), true
}

// MavenRepositoryPolicy is a repository's releases or snapshots element.
type MavenRepositoryPolicy struct {
	Enabled        *string `xml:"enabled"`
	ChecksumPolicy *string `xml:"checksumPolicy"`
	UpdatePolicy   *string `xml:"updatePolicy"`
}

// MavenRepository is one declared repository or pluginRepository, from
// settings or a POM. Kind and ProfileID are set by the reader.
type MavenRepository struct {
	ID        *string                `xml:"id"`
	URL       *string                `xml:"url"`
	Releases  *MavenRepositoryPolicy `xml:"releases"`
	Snapshots *MavenRepositoryPolicy `xml:"snapshots"`
	Kind      string                 `xml:"-"` // dependency | plugin
	ProfileID *string                `xml:"-"`
}

// GradleVerification is the policy part of gradle/verification-metadata.xml.
type GradleVerification struct {
	VerifyMetadata, VerifySignatures *bool
	TrustedArtifacts, TrustedKeys    bool
	Invalid                          bool // a policy value could not be read
}

// MavenConfigScope comes from the resolved developer, never a login shell.
type MavenConfigScope struct {
	Username, Home  string
	Protected       func(string) string
	Volume          func(string) bool
	ProcessVerified bool
}

// MavenProjectLeads are a project's .mvn discovery leads: absolute local
// repositories and whether repository splitting was requested.
type MavenProjectLeads struct {
	Repositories []string
	Split        bool
}

// mavenAudit is one manager's section with its own output allowance.
type mavenAudit struct {
	audit   model.RubyConfigAudit
	files   map[string]*model.RubyConfigFile
	process *model.RubyConfigFile
	user    []*model.RubyConfigFile // highest precedence first
	system  []*model.RubyConfigFile
	bytes   int
	limited bool
}

type mavenProjectConfig struct {
	dir           string
	maven, gradle []*model.RubyConfigFile
	// user and system are settings files named by the project's options.
	user, system []*model.RubyConfigFile
	tool         string
	partial      map[string]bool // by manager
}

// MavenConfigSnapshot accumulates Maven and Gradle configuration
// observations as inventory discovers projects. Leads are absolute paths from
// verified process variables and present files, not effective selection.
type MavenConfigSnapshot struct {
	RepositoryLeads, GradleHomes []string
	// Split reports a verified process option requesting a split repository.
	Split       bool
	exec        executor.Executor
	ctx         context.Context
	scope       MavenConfigScope
	maven       *mavenAudit
	gradle      *mavenAudit
	env         map[string]string
	leads       map[string]bool
	credentials map[string]bool
	protected   map[string]bool
	projects    map[string]*mavenProjectConfig
	partial     bool
	// project and current are set while a Project call reads .mvn options.
	project *MavenProjectLeads
	current *mavenProjectConfig
}

type MavenConfigDetector struct{ exec executor.Executor }

func NewMavenConfigDetector(exec executor.Executor) *MavenConfigDetector {
	return &MavenConfigDetector{exec: exec}
}

func emptyMavenAudit() model.RubyConfigAudit {
	return model.RubyConfigAudit{SchemaVersion: model.MavenInventorySchemaVersion, Status: "complete", Reasons: []string{}, Files: []model.RubyConfigFile{},
		Contexts: []model.RubyConfigContext{}, CredentialFiles: []model.MavenCredentialFile{}, Findings: []model.CargoConfigFinding{}}
}

func (d *MavenConfigDetector) Detect(ctx context.Context, scope MavenConfigScope) *MavenConfigSnapshot {
	a := &MavenConfigSnapshot{exec: d.exec, ctx: ctx, scope: scope, env: map[string]string{}, leads: map[string]bool{}, credentials: map[string]bool{}, protected: map[string]bool{}, projects: map[string]*mavenProjectConfig{},
		maven:  &mavenAudit{audit: emptyMavenAudit(), files: map[string]*model.RubyConfigFile{}, bytes: mavenAuditSize(emptyMavenAudit()) + 128},
		gradle: &mavenAudit{audit: emptyMavenAudit(), files: map[string]*model.RubyConfigFile{}, bytes: mavenAuditSize(emptyMavenAudit()) + 128}}
	if scope.Username == "" || scope.Home == "" {
		a.Partial("user_unresolved")
		return a
	}
	if ctx.Err() != nil {
		a.Partial("deadline_exceeded")
		return a
	}
	home := scope.Home
	m2 := filepath.Join(home, ".m2")
	credentialFiles := []string{filepath.Join(m2, mavenSettingsSecurityName), filepath.Join(m2, mavenSettingsSecurity4Name)}
	for _, p := range credentialFiles {
		a.protected[a.key(p)] = true
		if ctx.Err() != nil {
			// Every later read checks the context before touching a file.
			continue
		}
		if resolved, err := a.exec.GuardedFiles([]string{p}, scope.Protected, 0).EvalSymlinks(p); err == nil {
			a.protected[a.key(resolved)] = true
		}
	}
	a.maven.process = a.record(mavenManager, "process", "")
	a.gradle.process = a.record(gradleManager, "process", "")
	if scope.ProcessVerified {
		a.processEnv()
	} else {
		a.fileReason(a.maven.process, "unsupported", "user_unresolved")
		a.fileReason(a.gradle.process, "unsupported", "user_unresolved")
		a.partial = true
	}
	a.maven.user = append(a.maven.user, a.readFile(mavenManager, "user", filepath.Join(m2, "settings.xml"), a.parseSettings))
	for _, key := range []string{"MAVEN_HOME", "M2_HOME"} {
		if dir := a.env[key]; dir != "" {
			a.maven.system = append(a.maven.system, a.readFile(mavenManager, "system", filepath.Join(dir, "conf", "settings.xml"), a.parseSettings))
		}
	}
	if dir := a.env["GRADLE_USER_HOME"]; dir != "" {
		a.gradle.user = append(a.gradle.user, a.readFile(gradleManager, "user", filepath.Join(dir, "gradle.properties"), a.parseGradleProperties))
	}
	a.gradle.user = append(a.gradle.user, a.readFile(gradleManager, "user", filepath.Join(home, ".gradle", "gradle.properties"), a.parseGradleProperties))
	if dir := a.env["GRADLE_HOME"]; dir != "" {
		a.gradle.system = append(a.gradle.system, a.readFile(gradleManager, "system", filepath.Join(dir, "gradle.properties"), a.parseGradleProperties))
	}
	for _, p := range credentialFiles {
		a.credential(p)
	}
	return a
}

// ContentGuard keeps Maven security settings existence-only, including
// redirected reads.
func (a *MavenConfigSnapshot) ContentGuard(path string) string {
	if a.scope.Protected != nil {
		if reason := a.scope.Protected(path); reason != "" {
			return reason
		}
	}
	key := a.key(path)
	for p := range a.protected {
		if key == p || isLexicalAncestor(p, key) {
			return "skipped_protected"
		}
	}
	return ""
}

func (a *MavenConfigSnapshot) key(p string) string { return GoPathKey(a.exec.GOOS(), p) }
func (a *MavenConfigSnapshot) state(manager string) *mavenAudit {
	if manager == gradleManager {
		return a.gradle
	}
	return a.maven
}
func (s *mavenAudit) degrade(reason string) {
	s.audit.Status = "partial"
	if !slices.Contains(s.audit.Reasons, reason) {
		s.audit.Reasons = append(s.audit.Reasons, reason)
	}
}

// Partial marks both audits incomplete, as when project discovery was cut short.
func (a *MavenConfigSnapshot) Partial(reason string) {
	a.partial = true
	a.maven.degrade(reason)
	a.gradle.degrade(reason)
}

func (a *MavenConfigSnapshot) fileReason(f *model.RubyConfigFile, status, reason string) {
	if f == nil {
		return
	}
	f.Status = status
	if !slices.Contains(f.Reasons, reason) {
		f.Reasons = append(f.Reasons, reason)
	}
	a.state(f.Manager).degrade(reason)
}

// limitation keeps a parseable file present with its supported settings
// while recording why its coverage is incomplete. Only contexts that include
// the file become partial.
func (a *MavenConfigSnapshot) limitation(f *model.RubyConfigFile, reason string) {
	if f == nil {
		return
	}
	if !slices.Contains(f.Reasons, reason) {
		f.Reasons = append(f.Reasons, reason)
	}
	a.state(f.Manager).degrade(reason)
}

func (a *MavenConfigSnapshot) record(manager, scope, path string) *model.RubyConfigFile {
	s := a.state(manager)
	id := GoSourceID(a.scope.Username, MavenConfigKind(manager, scope), path)
	if f := s.files[id]; f != nil {
		return f
	}
	f := &model.RubyConfigFile{SourceID: id, Manager: manager, Scope: scope, Path: path, Status: "absent", Reasons: []string{}, Settings: []model.CargoConfigSetting{}}
	size := mavenAuditSize(f) + 128 // room for later coverage reasons
	if s.limited || s.bytes+size > maxMavenAuditBytes {
		s.limited = true
		s.degrade("output_size_limit")
		return nil
	}
	s.files[id] = f
	s.bytes += size
	return f
}

func (a *MavenConfigSnapshot) setting(f *model.RubyConfigFile, key, value string, redacted bool) {
	if f == nil {
		return
	}
	s := a.state(f.Manager)
	if !composerSafeText(value, 4096) || len(key) > 512 {
		a.limitation(f, "unsupported_format")
		return
	}
	if slices.ContainsFunc(f.Settings, func(x model.CargoConfigSetting) bool { return x.Key == key && x.Display == value }) {
		return
	}
	if len(f.Settings) >= mavenSettingLimit {
		a.limitation(f, "record_limit")
		return
	}
	setting := model.CargoConfigSetting{Key: key, Display: value, SourceID: f.SourceID, Redacted: redacted}
	size := mavenAuditSize(setting)
	// Reserve the possible finding before admitting its setting. A blocked
	// mirror may suppress that finding, never increase this charge.
	for _, finding := range mavenFindings(model.RubyConfigFile{Manager: f.Manager, SourceID: f.SourceID, Settings: []model.CargoConfigSetting{setting}}) {
		size += mavenAuditSize(finding)
	}
	if s.limited || s.bytes+size > maxMavenAuditBytes {
		s.limited = true
		a.limitation(f, "output_size_limit")
		return
	}
	s.bytes += size
	f.Settings = append(f.Settings, setting)
}

func (a *MavenConfigSnapshot) readFile(manager, scope, p string, parse func(*model.RubyConfigFile, []byte)) *model.RubyConfigFile {
	if f := a.state(manager).files[GoSourceID(a.scope.Username, MavenConfigKind(manager, scope), p)]; f != nil {
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
	files := a.exec.GuardedFiles([]string{filepath.Dir(p), p}, a.ContentGuard, mavenConfigBytes)
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
	if info.Size() > mavenConfigBytes {
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

func (a *MavenConfigSnapshot) readFailure(f *model.RubyConfigFile, err error, p string) {
	reason := CargoReadReason(err, p, a.scope.Volume)
	status := "unreadable"
	if reason == "skipped_protected" || reason == "refused_network_volume" {
		status = "skipped_protected"
	}
	a.fileReason(f, status, reason)
}

// processEnv reads only allowlisted names from the verified process. Every
// name is upper case, which is also the only spelling read on Windows.
func (a *MavenConfigSnapshot) processEnv() {
	for _, key := range []string{"MAVEN_HOME", "M2_HOME", "GRADLE_USER_HOME", "GRADLE_HOME"} {
		v := a.exec.Getenv(key)
		if v == "" {
			continue
		}
		manager := mavenManager
		if strings.HasPrefix(key, "GRADLE") {
			manager = gradleManager
		}
		if !filepath.IsAbs(v) || !composerSafeText(v, 4096) {
			a.limitation(a.state(manager).process, "path_unresolved")
			continue
		}
		a.env[key] = filepath.Clean(v)
	}
	if dir := a.env["GRADLE_USER_HOME"]; dir != "" {
		a.GradleHomes = append(a.GradleHomes, dir)
		display, redacted := mavenPathDisplay(dir)
		a.setting(a.gradle.process, "gradle_user_home", display, redacted)
	}
	// MAVEN_ARGS holds Maven CLI options; MAVEN_OPTS holds JVM options, so
	// only the former can name settings files.
	if v := a.exec.Getenv("MAVEN_ARGS"); v != "" {
		a.options(a.maven.process, strings.Fields(v), true)
	}
	if v := a.exec.Getenv("MAVEN_OPTS"); v != "" {
		a.options(a.maven.process, strings.Fields(v), false)
	}
	for _, f := range []*model.RubyConfigFile{a.maven.process, a.gradle.process} {
		if f != nil && f.Status == "absent" && len(f.Settings) > 0 {
			f.Status = "present"
		}
	}
}

// options applies the supported literal options from one argument list.
// Quoted tokens and relative or variable paths are not resolved.
func (a *MavenConfigSnapshot) options(f *model.RubyConfigFile, args []string, cli bool) {
	if f == nil {
		return
	}
	value := func(i *int, arg, long string) (string, bool) {
		if v, ok := strings.CutPrefix(arg, long+"="); ok && long != "" {
			return v, true
		}
		if *i+1 < len(args) {
			*i++
			return args[*i], true
		}
		return "", false
	}
	defs, keys := map[string]string{}, []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "-D"):
			def := strings.TrimPrefix(arg, "-D")
			if def == "" {
				var ok bool
				if def, ok = value(&i, arg, ""); !ok {
					continue
				}
			}
			// Maven sets a bare -Dkey to true; the JVM sets it to "".
			k, v, set := strings.Cut(def, "=")
			if !set && cli {
				v = "true"
			}
			if _, seen := defs[k]; !seen {
				keys = append(keys, k)
			}
			defs[k] = v
		case cli && (arg == "-s" || arg == "--settings" || strings.HasPrefix(arg, "--settings=")):
			if p, ok := value(&i, arg, "--settings"); ok {
				a.settingsLead(f, "user", p)
			}
		case cli && (arg == "-gs" || arg == "--global-settings" || strings.HasPrefix(arg, "--global-settings=")):
			if p, ok := value(&i, arg, "--global-settings"); ok {
				a.settingsLead(f, "system", p)
			}
		}
	}
	// A later definition of a property replaces an earlier one, as in Maven
	// and the JVM.
	for _, k := range keys {
		a.define(f, k, defs[k])
	}
}

// settingsLead reads a settings file named by an option in f. A file named
// by project options belongs to that project's chain only.
func (a *MavenConfigSnapshot) settingsLead(f *model.RubyConfigFile, scope, p string) {
	if !mavenLiteralPath(p) {
		a.limitation(f, "path_unresolved")
		return
	}
	settings := a.readFile(mavenManager, scope, filepath.Clean(p), a.parseSettings)
	chain := &a.maven.system
	switch {
	case a.current != nil && scope == "user":
		chain = &a.current.user
	case a.current != nil:
		chain = &a.current.system
	case scope == "user":
		chain = &a.maven.user
	}
	if !slices.Contains(*chain, settings) {
		*chain = append(*chain, settings)
	}
}

// mavenLiteralPath admits an absolute path with no quoting or expressions.
func mavenLiteralPath(p string) bool {
	return filepath.IsAbs(p) && composerSafeText(p, 4096) && !strings.ContainsAny(p, `"'$`)
}

func (a *MavenConfigSnapshot) define(f *model.RubyConfigFile, k, v string) {
	switch {
	case k == mavenRepoLocalProperty:
		// A discovery lead, not an allowlisted setting.
		if !mavenLiteralPath(v) {
			a.limitation(f, "path_unresolved")
			return
		}
		a.repositoryLead(filepath.Clean(v))
	case k == mavenSplitKey || k == mavenSplitLegacyKey:
		// The splitLocal/splitRemote refinements apply only once split is true.
		if !strings.EqualFold(strings.TrimSpace(v), "true") {
			return
		}
		if a.project != nil {
			a.project.Split = true
		} else {
			a.Split = true
		}
	case k == mavenResolverTransport:
		a.enum(f, k, strings.ToLower(v), "auto", "native", "wagon")
	case k == mavenTransportSecurityMode:
		a.enum(f, k, strings.ToLower(v), "default", "insecure")
	case slices.Contains(mavenWagonTLSFlags, k):
		a.boolean(f, k, v)
	}
}

func (a *MavenConfigSnapshot) repositoryLead(p string) {
	if a.project != nil && !slices.Contains(a.project.Repositories, p) {
		a.project.Repositories = append(a.project.Repositories, p)
	}
	if a.leads[a.key(p)] {
		return
	}
	a.leads[a.key(p)] = true
	if a.project == nil {
		a.RepositoryLeads = append(a.RepositoryLeads, p)
	}
}

func (a *MavenConfigSnapshot) enum(f *model.RubyConfigFile, key, v string, allowed ...string) {
	if slices.Contains(allowed, v) {
		a.setting(f, key, v, false)
		return
	}
	a.limitation(f, "unsupported_format")
}

func (a *MavenConfigSnapshot) boolean(f *model.RubyConfigFile, key, v string) {
	if b, ok := mavenBool(v); ok {
		a.setting(f, key, b, false)
		return
	}
	a.limitation(f, "unsupported_format")
}

func mavenBool(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true":
		return "true", true
	case "false":
		return "false", true
	}
	return "", false
}

// mavenPathDisplay keeps a safe absolute path; anything else is redacted.
func mavenPathDisplay(p string) (string, bool) {
	if !mavenLiteralPath(p) || strings.ContainsAny(p, "@?#") {
		return goRedacted, true
	}
	return filepath.Clean(p), false
}

func mavenText(p *string) (string, bool) {
	if p == nil {
		return "", false
	}
	return strings.TrimSpace(*p), true
}

// mavenSettingsXML holds settings.xml's allowlisted elements.
type mavenSettingsXML struct {
	XMLName         xml.Name `xml:"settings"`
	LocalRepository *string  `xml:"localRepository"`
	Mirrors         []struct {
		ID              *string `xml:"id"`
		URL             *string `xml:"url"`
		MirrorOf        *string `xml:"mirrorOf"`
		MirrorOfLayouts *string `xml:"mirrorOfLayouts"`
		Blocked         *string `xml:"blocked"`
	} `xml:"mirrors>mirror"`
	Proxies []struct {
		Active   *string `xml:"active"`
		Protocol *string `xml:"protocol"`
		Host     *string `xml:"host"`
		Port     *string `xml:"port"`
		Password *string `xml:"password"`
	} `xml:"proxies>proxy"`
	Servers []struct {
		ID         *string `xml:"id"`
		Password   *string `xml:"password"`
		PrivateKey *string `xml:"privateKey"`
		Passphrase *string `xml:"passphrase"`
	} `xml:"servers>server"`
	Repositories       []MavenRepository `xml:"repositories>repository"`
	PluginRepositories []MavenRepository `xml:"pluginRepositories>pluginRepository"`
	Profiles           []struct {
		ID                 *string           `xml:"id"`
		Repositories       []MavenRepository `xml:"repositories>repository"`
		PluginRepositories []MavenRepository `xml:"pluginRepositories>pluginRepository"`
	} `xml:"profiles>profile"`
}

// parseSettings reads settings.xml allowlisted elements by local name, so
// the 1.0/1.1/1.2 schemas and Maven 4 top-level repositories all apply.
func (a *MavenConfigSnapshot) parseSettings(f *model.RubyConfigFile, data []byte) {
	var doc mavenSettingsXML
	dec, err := MavenXML(data)
	if err == nil {
		err = dec.Decode(&doc)
	}
	if err != nil {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	if v, ok := mavenText(doc.LocalRepository); ok && v != "" {
		p := strings.Replace(v, mavenUserHomeReference, a.scope.Home, 1)
		if mavenLiteralPath(p) {
			display, redacted := mavenPathDisplay(p)
			a.setting(f, "local_repository", display, redacted)
			a.repositoryLead(filepath.Clean(p))
		} else {
			a.setting(f, "local_repository", goRedacted, true)
			a.limitation(f, "path_unresolved")
		}
	}
	repos := MavenKinds(doc.Repositories, doc.PluginRepositories, nil)
	for _, p := range doc.Profiles {
		repos = append(repos, MavenKinds(p.Repositories, p.PluginRepositories, mavenProfile(p.ID))...)
	}
	a.repositories(f, repos)
	for i, m := range doc.Mirrors {
		if i >= mavenIndexLimit {
			a.limitation(f, "record_limit")
			break
		}
		prefix := "mirrors." + strconv.Itoa(i) + "."
		a.label(f, prefix+"id", m.ID)
		a.selector(f, prefix+"mirror_of", m.MirrorOf)
		a.selector(f, prefix+"mirror_of_layouts", m.MirrorOfLayouts)
		// A present mirror is unblocked unless it says otherwise.
		if v, ok := mavenText(m.Blocked); ok {
			a.boolean(f, prefix+"blocked", v)
		} else {
			a.setting(f, prefix+"blocked", "false", false)
		}
		// Keep the blocking policy before a URL that can raise a finding.
		a.url(f, prefix+"url", m.URL)
	}
	for i, p := range doc.Proxies {
		if i >= mavenIndexLimit {
			a.limitation(f, "record_limit")
			break
		}
		prefix := "proxies." + strconv.Itoa(i) + "."
		if v, ok := mavenText(p.Active); ok {
			a.boolean(f, prefix+"active", v)
		}
		if v, ok := mavenText(p.Protocol); ok {
			a.enum(f, prefix+"protocol", strings.ToLower(v), "http", "https", "socks")
		}
		a.host(f, prefix+"host", p.Host)
		a.port(f, prefix+"port", p.Port)
		a.credentialForm(f, prefix, mavenCredential(p.Password))
	}
	for i, s := range doc.Servers {
		if i >= mavenIndexLimit {
			a.limitation(f, "record_limit")
			break
		}
		prefix := "servers." + strconv.Itoa(i) + "."
		a.label(f, prefix+"id", s.ID)
		form := mavenCredential(s.Password)
		if form == "" {
			form = mavenCredential(s.Passphrase)
		}
		if v, _ := mavenText(s.PrivateKey); form == "" && v != "" {
			form = "unknown"
		}
		a.credentialForm(f, prefix, form)
	}
}

func mavenProfile(id *string) *string {
	v, _ := mavenText(id)
	return &v
}

// MavenKinds labels declared repositories and pluginRepositories, in that
// order, with their kind and the profile that declares them.
func MavenKinds(deps, plugins []MavenRepository, profile *string) []MavenRepository {
	out := []MavenRepository{}
	for _, r := range deps {
		r.Kind, r.ProfileID = "dependency", profile
		out = append(out, r)
	}
	for _, r := range plugins {
		r.Kind, r.ProfileID = "plugin", profile
		out = append(out, r)
	}
	return out
}

// mavenCredential classifies a credential value by syntax only; the value
// itself is never kept.
func mavenCredential(p *string) string {
	v, _ := mavenText(p)
	switch {
	case v == "":
		return ""
	case strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") && strings.Count(v, "${") == 1:
		return "reference"
	case strings.Contains(v, "${"):
		return "unknown"
	case strings.Contains(v, "{") && strings.Contains(v, "}"):
		return "encrypted"
	}
	return "literal"
}

func (a *MavenConfigSnapshot) credentialForm(f *model.RubyConfigFile, prefix, form string) {
	if form == "" {
		return
	}
	a.setting(f, prefix+"auth_configured", "true", true)
	a.setting(f, prefix+"credential_form", form, false)
}

func (a *MavenConfigSnapshot) label(f *model.RubyConfigFile, key string, p *string) {
	if v, ok := mavenText(p); ok {
		if mavenLabelPattern.MatchString(v) {
			a.setting(f, key, v, false)
		} else {
			a.limitation(f, "unsupported_format")
		}
	}
}

func (a *MavenConfigSnapshot) selector(f *model.RubyConfigFile, key string, p *string) {
	if v, ok := mavenText(p); ok {
		if len(v) <= 1024 && mavenSelectorPattern.MatchString(v) {
			a.setting(f, key, v, false)
		} else {
			a.limitation(f, "unsupported_format")
		}
	}
}

func (a *MavenConfigSnapshot) url(f *model.RubyConfigFile, key string, p *string) {
	if v, ok := mavenText(p); ok {
		display, redacted := SanitizeComposerURL(v)
		a.setting(f, key, display, redacted)
	}
}

func (a *MavenConfigSnapshot) host(f *model.RubyConfigFile, key string, p *string) {
	v, ok := mavenText(p)
	if !ok {
		return
	}
	if _, err := netip.ParseAddr(v); err == nil || len(v) <= 253 && mavenHostPattern.MatchString(v) {
		a.setting(f, key, v, false)
		return
	}
	a.limitation(f, "unsupported_format")
}

func (a *MavenConfigSnapshot) port(f *model.RubyConfigFile, key string, p *string) {
	v, ok := mavenText(p)
	if !ok {
		return
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 65535 {
		a.setting(f, key, strconv.Itoa(n), false)
		return
	}
	a.limitation(f, "unsupported_format")
}

// repositories records settings or POM repositories with their
// releases/snapshots policy. N follows MavenKinds order: top-level
// repositories before each profile's. Profile activation is never evaluated.
func (a *MavenConfigSnapshot) repositories(f *model.RubyConfigFile, repos []MavenRepository) {
	for i, r := range repos {
		if i >= mavenIndexLimit {
			a.limitation(f, "record_limit")
			break
		}
		prefix := "repositories." + strconv.Itoa(i) + "."
		a.label(f, prefix+"id", r.ID)
		a.url(f, prefix+"url", r.URL)
		a.setting(f, prefix+"kind", r.Kind, false)
		if r.ProfileID != nil {
			a.label(f, prefix+"profile_id", r.ProfileID)
			a.setting(f, prefix+"profile_activation", "unknown", false)
		}
		for _, p := range []struct {
			name   string
			policy *MavenRepositoryPolicy
		}{{"releases", r.Releases}, {"snapshots", r.Snapshots}} {
			if p.policy == nil {
				continue
			}
			if v, ok := mavenText(p.policy.Enabled); ok {
				a.boolean(f, prefix+p.name+"_enabled", v)
			}
			if v, ok := mavenText(p.policy.ChecksumPolicy); ok {
				a.enum(f, prefix+p.name+"_checksum_policy", strings.ToLower(v), "fail", "warn", "ignore")
			}
			if v, ok := mavenText(p.policy.UpdatePolicy); ok {
				v = strings.ToLower(v)
				if mavenIntervalPattern.MatchString(v) {
					a.setting(f, prefix+p.name+"_update_policy", v, false)
				} else {
					a.enum(f, prefix+p.name+"_update_policy", v, "always", "daily", "never")
				}
			}
		}
	}
}

// parseMavenConfig reads .mvn/maven.config. Maven before 3.9 splits the file
// on whitespace and 3.9+ reads one argument per line; a line holding
// whitespace means different things to each, so it is not followed.
func (a *MavenConfigSnapshot) parseMavenConfig(f *model.RubyConfigFile, data []byte) {
	args := []string{}
	for _, line := range mavenLines(data) {
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.ContainsFunc(line, unicode.IsSpace):
			a.limitation(f, "unsupported_format")
		default:
			args = append(args, line)
		}
	}
	a.options(f, args, true)
}

// parseJVMConfig reads .mvn/jvm.config: JVM options, so only -D properties apply.
func (a *MavenConfigSnapshot) parseJVMConfig(f *model.RubyConfigFile, data []byte) {
	args := []string{}
	for _, line := range mavenLines(data) {
		if !strings.HasPrefix(line, "#") {
			args = append(args, strings.Fields(line)...)
		}
	}
	a.options(f, args, false)
}

func mavenLines(data []byte) []string {
	text := string(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}))
	out := []string{}
	for line := range strings.SplitSeq(strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(text), "\n") {
		out = append(out, strings.TrimSpace(line))
	}
	return out
}

func mavenProperties(data []byte) (map[string]string, bool) {
	props, complete := ParseJavaProperties(data)
	out := map[string]string{}
	for _, p := range props {
		out[p.Key] = strings.TrimSpace(p.Value) // later entries win, as in Properties
	}
	return out, complete
}

// parseWrapper reads Maven or Gradle wrapper properties. A checksum marker
// is explicitly false only after the whole file parsed.
func (a *MavenConfigSnapshot) parseWrapper(f *model.RubyConfigFile, data []byte) {
	props, complete := mavenProperties(data)
	if !complete {
		a.limitation(f, "parse_error")
	}
	if v, ok := props["distributionUrl"]; ok {
		display, redacted := SanitizeComposerURL(v)
		a.setting(f, "wrapper.distribution_url", display, redacted)
	}
	checksums := [][2]string{{"distributionSha256Sum", "wrapper.distribution_checksum_configured"}}
	if f.Manager == mavenManager {
		if v, ok := props["wrapperUrl"]; ok {
			display, redacted := SanitizeComposerURL(v)
			a.setting(f, "wrapper.wrapper_url", display, redacted)
		}
		// A file without distributionType does not say which wrapper reads it.
		kind := strings.ToLower(props["distributionType"])
		if !slices.Contains([]string{"only-script", "bin", "source", "script"}, kind) {
			kind = "unknown"
		}
		a.setting(f, "wrapper.type", kind, false)
		checksums = append(checksums, [2]string{"wrapperSha256Sum", "wrapper.wrapper_checksum_configured"})
	}
	for _, c := range checksums {
		v, ok := props[c[0]]
		switch {
		case ok && mavenSHA256Pattern.MatchString(v):
			a.setting(f, c[1], "true", false)
		case ok:
			// An invalid checksum is incomplete coverage, never a missing one.
			a.limitation(f, "checksum_invalid")
		case complete:
			a.setting(f, c[1], "false", false)
		}
	}
}

// parseGradleProperties reads allowlisted gradle.properties keys only.
func (a *MavenConfigSnapshot) parseGradleProperties(f *model.RubyConfigFile, data []byte) {
	props, complete := mavenProperties(data)
	if !complete {
		a.limitation(f, "parse_error")
	}
	if v, ok := props[gradleDependencyVerification]; ok {
		a.enum(f, gradleDependencyVerification, strings.ToLower(v), "strict", "lenient", "off")
	}
	if v, ok := props["org.gradle.mirror.maven.settings"]; ok {
		a.boolean(f, "org.gradle.mirror.maven.settings", v)
	}
	if v, ok := props["org.gradle.java.home"]; ok {
		display, redacted := mavenPathDisplay(v)
		a.setting(f, "org.gradle.java.home", display, redacted)
	}
	for _, scheme := range []string{"http", "https"} {
		prefix := "proxy." + scheme + "."
		sys := "systemProp." + scheme + ".proxy"
		if v, ok := props[sys+"Host"]; ok {
			a.host(f, prefix+"host", &v)
		}
		if v, ok := props[sys+"Port"]; ok {
			a.port(f, prefix+"port", &v)
		}
		// Gradle never expands properties, so any password text is literal.
		if props[sys+"Password"] != "" {
			a.credentialForm(f, prefix, "literal")
		}
	}
}

// MavenProjectFiles are the project-relative configuration files Project reads.
var MavenProjectFiles = []string{".mvn/maven.config", ".mvn/jvm.config", ".mvn/wrapper/maven-wrapper.properties", "gradle.properties", "gradle/wrapper/gradle-wrapper.properties"}

// Project observes one project's configuration files, given as the absolute
// paths its directory listings found, and returns its .mvn discovery leads.
func (a *MavenConfigSnapshot) Project(dir, tool string, files []string) MavenProjectLeads {
	out := MavenProjectLeads{}
	if a.scope.Username == "" {
		return out
	}
	p := a.projectConfig(dir, tool)
	a.project, a.current = &out, p
	defer func() { a.project, a.current = nil, nil }()
	for _, path := range files {
		switch rel := filepath.ToSlash(strings.TrimPrefix(path, dir+string(filepath.Separator))); rel {
		case ".mvn/maven.config":
			p.maven = append(p.maven, a.readFile(mavenManager, "project", path, a.parseMavenConfig))
		case ".mvn/jvm.config":
			p.maven = append(p.maven, a.readFile(mavenManager, "project", path, a.parseJVMConfig))
		case ".mvn/wrapper/maven-wrapper.properties":
			p.maven = append(p.maven, a.readFile(mavenManager, "project", path, a.parseWrapper))
		case "gradle.properties":
			p.gradle = append(p.gradle, a.readFile(gradleManager, "project", path, a.parseGradleProperties))
		case "gradle/wrapper/gradle-wrapper.properties":
			p.gradle = append(p.gradle, a.readFile(gradleManager, "project", path, a.parseWrapper))
		}
	}
	return out
}

// Unlisted marks one manager's project context partial when a project
// configuration folder could not be fully listed.
func (a *MavenConfigSnapshot) Unlisted(dir, manager, reason string) {
	if a.scope.Username == "" {
		return
	}
	a.projectConfig(dir, manager).partial[manager] = true
	a.state(manager).degrade(reason)
}

func (a *MavenConfigSnapshot) projectConfig(dir, tool string) *mavenProjectConfig {
	p := a.projects[a.key(dir)]
	if p == nil {
		p = &mavenProjectConfig{dir: dir, tool: tool, partial: map[string]bool{}}
		a.projects[a.key(dir)] = p
	}
	return p
}

// Manifest records a POM's declared repositories as a project-scope source.
// Status and reasons describe the read, never inventory coverage.
func (a *MavenConfigSnapshot) Manifest(dir, path string, repos []MavenRepository, status string, reasons []string) {
	if a.scope.Username == "" {
		return
	}
	p := a.projectConfig(dir, mavenManager)
	f := a.record(mavenManager, "project", path)
	if f == nil {
		p.partial[mavenManager] = true
		return
	}
	f.Status, f.Reasons = status, append([]string{}, reasons...)
	if status == "present" {
		a.repositories(f, repos)
	}
	p.maven = append(p.maven, f)
}

// Verification records gradle/verification-metadata.xml policy booleans and
// trust-container presence; keys, selectors and reasons are never kept.
func (a *MavenConfigSnapshot) Verification(dir, path string, v GradleVerification, status string, reasons []string) {
	if a.scope.Username == "" {
		return
	}
	p := a.projectConfig(dir, gradleManager)
	f := a.record(gradleManager, "project", path)
	if f == nil {
		p.partial[gradleManager] = true
		return
	}
	f.Status, f.Reasons = status, append([]string{}, reasons...)
	if v.Invalid {
		a.limitation(f, "parse_error")
	}
	if status == "present" {
		for key, b := range map[string]*bool{"verification.verify_metadata": v.VerifyMetadata, "verification.verify_signatures": v.VerifySignatures} {
			if b != nil {
				a.setting(f, key, strconv.FormatBool(*b), false)
			}
		}
		if v.TrustedArtifacts {
			a.setting(f, "verification.trusted_artifacts_present", "true", false)
		}
		if v.TrustedKeys {
			a.setting(f, "verification.trusted_keys_present", "true", false)
		}
	}
	p.gradle = append(p.gradle, f)
}

func (a *MavenConfigSnapshot) credential(path string) {
	s := a.maven
	if s.limited || a.credentials[a.key(path)] {
		return
	}
	a.credentials[a.key(path)] = true
	c := model.MavenCredentialFile{Path: path, Status: "present", Presence: "present"}
	if a.ctx.Err() != nil {
		c.Status, c.Presence = "unreadable", "unknown"
		s.degrade("deadline_exceeded")
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
			s.degrade(reason)
		case !info.Mode().IsRegular():
			c.Status, c.Presence = "unsupported", "unknown"
			s.degrade("unsupported_entry")
		}
	}
	size := mavenAuditSize(c)
	if s.bytes+size > maxMavenAuditBytes {
		s.limited = true
		s.degrade("output_size_limit")
		return
	}
	s.audit.CredentialFiles = append(s.audit.CredentialFiles, c)
	s.bytes += size
}

func (s *mavenAudit) context(c model.RubyConfigContext) {
	if s.limited {
		return
	}
	size := mavenAuditSize(c)
	if s.bytes+size > maxMavenAuditBytes {
		s.limited = true
		s.degrade("output_size_limit")
		return
	}
	s.audit.Contexts = append(s.audit.Contexts, c)
	s.bytes += size
}

// chain lists observed sources highest precedence first. Maven: process
// options, project files, user then global settings. Gradle: process, user
// home, project, then installation properties.
func (a *MavenConfigSnapshot) chain(manager string, p *mavenProjectConfig) ([]string, bool) {
	s := a.state(manager)
	ids := []string{}
	project := &mavenProjectConfig{}
	if p != nil {
		project = p
	}
	partial := project.partial[manager] || a.partial
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
	add(s.process)
	if manager == mavenManager {
		add(project.maven...)
		add(project.user...)
		add(s.user...)
		add(project.system...)
	} else {
		add(s.user...)
		add(project.gradle...)
	}
	add(s.system...)
	return ids, partial
}

func mavenSelection(partial bool) string {
	if partial {
		return "partial"
	}
	return "observed"
}

func (a *MavenConfigSnapshot) Finish() (model.MavenConfigAudit, model.GradleConfigAudit) {
	for _, manager := range []string{mavenManager, gradleManager} {
		s := a.state(manager)
		if s.process != nil {
			ids, partial := a.chain(manager, nil)
			s.context(model.RubyConfigContext{Manager: manager, ConfigSourceIDs: ids, SelectionStatus: mavenSelection(partial)})
		}
		// A project has a context for each manager whose files it holds, whose
		// tool it uses, or whose configuration folder it could not list.
		for _, p := range a.projects {
			own := p.maven
			if manager == gradleManager {
				own = p.gradle
			}
			if len(own) == 0 && p.tool != manager && p.tool != "unknown" && !p.partial[manager] {
				continue
			}
			ids, partial := a.chain(manager, p)
			s.context(model.RubyConfigContext{Manager: manager, ProjectPath: p.dir, ConfigSourceIDs: ids, SelectionStatus: mavenSelection(partial)})
		}
	}
	return a.maven.finish(), a.gradle.finish()
}

func (s *mavenAudit) finish() model.RubyConfigAudit {
	for _, f := range s.files {
		// An incomplete source has no current settings or findings.
		if f.Status != "present" {
			f.Settings = []model.CargoConfigSetting{}
		}
		slices.Sort(f.Reasons)
		slices.SortFunc(f.Settings, func(x, y model.CargoConfigSetting) int {
			return strings.Compare(x.Key+"\x00"+x.Display, y.Key+"\x00"+y.Display)
		})
		s.audit.Files = append(s.audit.Files, *f)
		s.audit.Findings = append(s.audit.Findings, mavenFindings(*f)...)
		for _, r := range f.Reasons {
			s.degrade(r)
		}
	}
	slices.SortFunc(s.audit.Files, func(x, y model.RubyConfigFile) int {
		return strings.Compare(x.Scope+"\x00"+x.Path, y.Scope+"\x00"+y.Path)
	})
	slices.SortFunc(s.audit.Contexts, func(x, y model.RubyConfigContext) int {
		return strings.Compare(x.ProjectPath+"\x00"+strings.Join(x.ConfigSourceIDs, ","), y.ProjectPath+"\x00"+strings.Join(y.ConfigSourceIDs, ","))
	})
	slices.SortFunc(s.audit.CredentialFiles, func(x, y model.MavenCredentialFile) int { return strings.Compare(x.Path, y.Path) })
	slices.SortFunc(s.audit.Findings, func(x, y model.CargoConfigFinding) int {
		return strings.Compare(x.Code+x.SourceID+x.Key, y.Code+y.SourceID+y.Key)
	})
	slices.Sort(s.audit.Reasons)
	return s.audit
}

// mavenAuditSize includes JSON escaping and the array separator.
func mavenAuditSize(record any) int {
	data, _ := json.Marshal(record)
	return len(data) + 1
}

// mavenFindings derives the stable catalog from kept settings. Details are
// fixed text: they describe declarations, never observed network use.
func mavenFindings(f model.RubyConfigFile) []model.CargoConfigFinding {
	values := map[string]string{}
	for _, s := range f.Settings {
		values[s.Key] = s.Display
	}
	var out []model.CargoConfigFinding
	add := func(code, severity, key, detail string) {
		out = append(out, model.CargoConfigFinding{Code: code, Severity: severity, SourceID: f.SourceID, Key: key, Detail: detail})
	}
	http := func(v string) bool { return strings.HasPrefix(strings.ToLower(v), "http://") }
	for _, s := range f.Settings {
		index, field, indexed := mavenIndexed(s.Key)
		switch {
		case f.Manager == mavenManager && indexed && strings.HasPrefix(s.Key, "repositories.") && field == "url" && http(s.Display):
			add("maven-001", "MEDIUM", s.Key, "A declared Maven repository uses an unencrypted HTTP URL; whether it is contacted is not established.")
		case f.Manager == mavenManager && indexed && strings.HasPrefix(s.Key, "mirrors.") && field == "url" && http(s.Display) && values["mirrors."+index+".blocked"] != "true":
			add("maven-001", "MEDIUM", s.Key, "A declared unblocked Maven mirror uses an unencrypted HTTP URL; whether it is contacted is not established.")
		case f.Manager == mavenManager && indexed && strings.HasSuffix(field, "_checksum_policy") && (s.Display == "warn" || s.Display == "ignore"):
			add("maven-002", "LOW", s.Key, "A declared Maven repository does not fail on checksum mismatches.")
		case f.Manager == mavenManager && (s.Key == mavenTransportSecurityMode && s.Display == "insecure" || slices.Contains(mavenWagonTLSFlags, s.Key) && s.Display == "true"):
			add("maven-003", "MEDIUM", s.Key, "An option weakens Maven TLS verification; transport applicability is not established.")
		case s.Key == "wrapper.distribution_url" && http(s.Display):
			code := "maven-004"
			if f.Manager == gradleManager {
				code = "gradle-003"
			}
			add(code, "MEDIUM", s.Key, "The wrapper distribution URL uses an unencrypted HTTP connection.")
		case s.Key == "wrapper.distribution_checksum_configured" && s.Display == "false":
			code := "maven-005"
			if f.Manager == gradleManager {
				code = "gradle-004"
			}
			add(code, "LOW", s.Key, "The wrapper properties set no distribution checksum, a missing defense rather than proven execution.")
		case s.Key == gradleDependencyVerification && s.Display == "off":
			add("gradle-001", "MEDIUM", s.Key, "Gradle dependency verification is disabled by properties.")
		case s.Key == gradleDependencyVerification && s.Display == "lenient":
			add("gradle-002", "LOW", s.Key, "Gradle dependency verification only warns on failures.")
		case s.Key == "verification.verify_metadata" && s.Display == "false":
			add("gradle-005", "LOW", s.Key, "Gradle verification metadata disables metadata checking; artifact checksums are unaffected.")
		}
	}
	return out
}

// mavenIndexed splits an indexed family key "family.N.field".
func mavenIndexed(key string) (index, field string, ok bool) {
	parts := strings.SplitN(key, ".", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", "", false
	}
	return parts[1], parts[2], true
}
