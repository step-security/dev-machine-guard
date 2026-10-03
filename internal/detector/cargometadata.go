package detector

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	toml "github.com/pelletier/go-toml/v2"
	"golang.org/x/mod/semver"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Cargo metadata limits.
// ponytail: unmeasured starting values; tune after lab measurements.
var (
	maxCargoMetadataBytes  int64 = 2 << 20 // Cargo.toml, Cargo.lock, receipts, archive manifest member
	maxCargoChecksumBytes  int64 = 8 << 20 // .cargo-checksum.json
	maxCargoArchiveBytes   int64 = 32 << 20
	maxCargoUnpackedBytes  int64 = 64 << 20
	maxCargoArchiveHeaders       = 10_000
	maxCargoTextLen              = 256  // package names, versions, requirements, selectors
	maxCargoDisplayLen           = 4096 // receipt text
)

// cargoCratesIOIndex is the canonical crates.io index URL, which is also what
// Cargo records in lockfiles for crates.io packages.
const cargoCratesIOIndex = "https://github.com/rust-lang/crates.io-index"

// cargoDepTables are the dependency tables of one manifest level: the top
// level or one target.<cfg> table. Both hyphen and underscore spellings are
// accepted by Cargo.
type cargoDepTables struct {
	Dependencies       map[string]any `toml:"dependencies"`
	DevDependencies    map[string]any `toml:"dev-dependencies"`
	DevDependencies2   map[string]any `toml:"dev_dependencies"`
	BuildDependencies  map[string]any `toml:"build-dependencies"`
	BuildDependencies2 map[string]any `toml:"build_dependencies"`
}

type cargoTOMLManifest struct {
	Package *struct {
		Name      string `toml:"name"`
		Version   any    `toml:"version"` // string or {workspace = true}
		Workspace string `toml:"workspace"`
	} `toml:"package"`
	Workspace *struct {
		Members []string `toml:"members"`
		Exclude []string `toml:"exclude"`
		Package struct {
			Version string `toml:"version"`
		} `toml:"package"`
		Dependencies map[string]any `toml:"dependencies"`
	} `toml:"workspace"`
	Dependencies       map[string]any            `toml:"dependencies"`
	DevDependencies    map[string]any            `toml:"dev-dependencies"`
	DevDependencies2   map[string]any            `toml:"dev_dependencies"`
	BuildDependencies  map[string]any            `toml:"build-dependencies"`
	BuildDependencies2 map[string]any            `toml:"build_dependencies"`
	Target             map[string]cargoDepTables `toml:"target"`
	Patch              map[string]map[string]any `toml:"patch"`
	Replace            map[string]any            `toml:"replace"`
}

// cargoManifest is the subset of one Cargo.toml the inventory uses.
type cargoManifest struct {
	name, version    string // version is empty when missing or inherited
	versionInherited bool   // version.workspace = true
	workspaceRef     string // package.workspace, as written
	workspace        *cargoWorkspaceTable
	deps             []cargoDep
	overrides        []cargoDep // [patch.*] and [replace] entries; never declarations
	invalid          bool       // an entry was dropped as malformed
}

func (m *cargoManifest) isPackage() bool { return m.name != "" }

type cargoWorkspaceTable struct {
	members, exclude []string
	packageVersion   string
	deps             map[string]cargoDep // workspace.dependencies, used only when inherited
}

// cargoDep is one dependency entry before its origin is resolved.
type cargoDep struct {
	decl        model.CargoDeclaration
	packageName string // the package key, or the declared name
	requested   string
	sel         cargoSelectors
	inherit     bool // workspace = true
}

// cargoSelectors are the source keys of a dependency entry, as written.
type cargoSelectors struct {
	registry, registryIndex, git, branch, tag, rev, path string
}

// parseCargoManifest decodes the fields the inventory reads. A decode failure
// is returned; a malformed dependency entry is dropped and flagged.
func parseCargoManifest(data []byte) (*cargoManifest, error) {
	var t cargoTOMLManifest
	if err := toml.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	m := &cargoManifest{}
	if p := t.Package; p != nil {
		name, ok := cargoText(p.Name)
		if !ok || name == "" {
			return nil, errors.New("invalid package name")
		}
		m.name, m.workspaceRef = name, p.Workspace
		switch v := p.Version.(type) {
		case nil:
		case string:
			if m.version, ok = cargoText(v); !ok {
				return nil, errors.New("invalid package version")
			}
		case map[string]any:
			m.versionInherited = v["workspace"] == true
		default:
			return nil, errors.New("invalid package version")
		}
	}
	if w := t.Workspace; w != nil {
		m.workspace = &cargoWorkspaceTable{
			members: w.Members, exclude: w.Exclude, packageVersion: w.Package.Version, deps: map[string]cargoDep{},
		}
		for name, raw := range w.Dependencies {
			if d, ok := cargoDependency(name, raw, model.CargoDependencyNormal, ""); ok {
				m.workspace.deps[name] = d
			} else {
				m.invalid = true
			}
		}
	}
	top := cargoDepTables{t.Dependencies, t.DevDependencies, t.DevDependencies2, t.BuildDependencies, t.BuildDependencies2}
	m.addDeps(top, "")
	for target, tables := range t.Target {
		m.addDeps(tables, target)
	}
	for _, entries := range t.Patch {
		m.addOverrides(entries)
	}
	m.addOverrides(t.Replace)
	return m, nil
}

func (m *cargoManifest) addDeps(t cargoDepTables, target string) {
	for _, table := range []struct {
		kind    string
		entries map[string]any
	}{
		{model.CargoDependencyNormal, t.Dependencies},
		{model.CargoDependencyDev, t.DevDependencies},
		{model.CargoDependencyDev, t.DevDependencies2},
		{model.CargoDependencyBuild, t.BuildDependencies},
		{model.CargoDependencyBuild, t.BuildDependencies2},
	} {
		for name, raw := range table.entries {
			if d, ok := cargoDependency(name, raw, table.kind, target); ok {
				m.deps = append(m.deps, d)
			} else {
				m.invalid = true
			}
		}
	}
}

// addOverrides keeps [patch] and [replace] entries, which name override
// locations rather than dependencies. A [replace] key is a package ID spec,
// "name:version" or "name@version"; only its name is kept.
func (m *cargoManifest) addOverrides(entries map[string]any) {
	for key, raw := range entries {
		name, _, _ := strings.Cut(key, "@")
		name, _, _ = strings.Cut(name, ":")
		if d, ok := cargoDependency(name, raw, model.CargoDependencyNormal, ""); ok {
			m.overrides = append(m.overrides, d)
		} else {
			m.invalid = true
		}
	}
}

// cargoDependency reads one dependency entry in string or table form. Omitted
// booleans stay unset so they are never reported as false.
func cargoDependency(declared string, raw any, kind, target string) (cargoDep, bool) {
	declared, ok := cargoText(declared)
	if !ok || declared == "" || len(target) > maxCargoDisplayLen {
		return cargoDep{}, false
	}
	d := cargoDep{
		decl: model.CargoDeclaration{
			DeclaredName: declared, DependencyKind: kind, Target: target, Features: []string{},
		},
		packageName: declared,
	}
	switch v := raw.(type) {
	case string:
		d.requested, ok = cargoText(v)
		return d, ok
	case map[string]any:
		t := cargoTable(v)
		if pkg := t.str("package"); pkg != "" {
			d.packageName = pkg
		}
		d.requested = t.str("version")
		if optional := t.flag("optional"); optional != nil {
			d.decl.Optional = *optional
		}
		d.decl.DefaultFeatures = t.flag("default-features")
		if d.decl.DefaultFeatures == nil {
			d.decl.DefaultFeatures = t.flag("default_features")
		}
		d.decl.Features = t.strs("features")
		d.inherit = v["workspace"] == true
		d.sel = cargoSelectors{
			registry: t.str("registry"), registryIndex: t.str("registry-index"),
			git: t.str("git"), branch: t.str("branch"), tag: t.str("tag"), rev: t.str("rev"), path: t.str("path"),
		}
		return d, !t.bad
	}
	return cargoDep{}, false
}

// cargoTableReader reads typed values from a decoded TOML table; a present
// value of the wrong type or length sets bad.
type cargoTableReader struct {
	m   map[string]any
	bad bool
}

func cargoTable(m map[string]any) *cargoTableReader { return &cargoTableReader{m: m} }

func (t *cargoTableReader) str(key string) string {
	raw, ok := t.m[key]
	if !ok {
		return ""
	}
	s, isStr := raw.(string)
	v, fits := cargoText(s)
	if !isStr || !fits {
		t.bad = true
		return ""
	}
	return v
}

func (t *cargoTableReader) flag(key string) *bool {
	raw, ok := t.m[key]
	if !ok {
		return nil
	}
	b, isBool := raw.(bool)
	if !isBool {
		t.bad = true
		return nil
	}
	return &b
}

func (t *cargoTableReader) strs(key string) []string {
	out := []string{}
	raw, ok := t.m[key]
	if !ok {
		return out
	}
	list, isList := raw.([]any)
	if !isList {
		t.bad = true
		return out
	}
	for _, item := range list {
		s, isStr := item.(string)
		v, fits := cargoText(s)
		if !isStr || !fits {
			t.bad = true
			continue
		}
		out = append(out, v)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// cargoText accepts a bounded string without control characters.
func cargoText(s string) (string, bool) {
	if len(s) > maxCargoTextLen || strings.ContainsFunc(s, unicode.IsControl) {
		return "", false
	}
	return s, true
}

// cargoInherit applies a workspace.dependencies entry to a member's
// `workspace = true` entry. The source and requirement come from the
// workspace; features add together; optional stays the member's own.
func cargoInherit(member, ws cargoDep) cargoDep {
	out := member
	out.packageName, out.requested, out.sel = ws.packageName, ws.requested, ws.sel
	out.decl.WorkspaceInherited = true
	if ws.decl.DefaultFeatures != nil {
		out.decl.DefaultFeatures = ws.decl.DefaultFeatures
	}
	features := append(slices.Clone(ws.decl.Features), member.decl.Features...)
	slices.Sort(features)
	out.decl.Features = slices.Compact(features)
	return out
}

// cargoLockEntry is one [[package]] of a lockfile. Exact duplicates are
// collapsed; checksums lists every distinct valid value recorded for it.
type cargoLockEntry struct {
	name, version, source string
	checksums             []string
	reasons               []string // checksum_invalid, checksum_mismatch
}

// parseCargoLock reads lockfile formats 3 and 4. Any other or missing version
// is unsupported_format; unused patches are not selected packages and are not
// read.
func parseCargoLock(data []byte) ([]cargoLockEntry, string) {
	var t struct {
		Version *int64 `toml:"version"`
		Package []struct {
			Name     string `toml:"name"`
			Version  string `toml:"version"`
			Source   string `toml:"source"`
			Checksum string `toml:"checksum"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &t); err != nil {
		return nil, model.CargoReasonParseError
	}
	if t.Version == nil || (*t.Version != 3 && *t.Version != 4) {
		return nil, model.CargoReasonUnsupportedFormat
	}
	type key struct{ name, version, source string }
	index := map[key]int{}
	var out []cargoLockEntry
	malformed := false
	for _, p := range t.Package {
		name, okName := cargoText(p.Name)
		version, okVersion := cargoText(p.Version)
		if !okName || !okVersion || name == "" || version == "" || len(p.Source) > maxCargoDisplayLen {
			malformed = true
			continue
		}
		k := key{name, version, p.Source}
		i, seen := index[k]
		if !seen {
			i = len(out)
			index[k] = i
			out = append(out, cargoLockEntry{name: name, version: version, source: p.Source})
		}
		e := &out[i]
		switch sum, ok := cargoSHA256(p.Checksum); {
		case p.Checksum == "":
		case !ok:
			e.addReason(model.CargoReasonChecksumInvalid)
		case !slices.Contains(e.checksums, sum):
			e.checksums = append(e.checksums, sum)
			if len(e.checksums) > 1 {
				e.addReason(model.CargoReasonChecksumMismatch)
			}
		}
	}
	if malformed {
		return out, model.CargoReasonParseError
	}
	return out, ""
}

func (e *cargoLockEntry) addReason(r string) {
	if !slices.Contains(e.reasons, r) {
		e.reasons = append(e.reasons, r)
	}
}

// cargoSHA256 normalizes a recorded SHA-256 hex value.
func cargoSHA256(s string) (string, bool) {
	s = strings.ToLower(s)
	return s, cargoIsHex(s, 64)
}

func cargoIsHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// cargoOrigin reads a lockfile or package-ID source string. Git selectors and
// the full revision are taken before the URL is sanitized; ok is false for an
// unrecognized form.
func cargoOrigin(source string) (model.CargoOrigin, bool) {
	kind, rest, _ := strings.Cut(source, "+")
	switch kind {
	case "registry":
		u, _ := configaudit.SanitizeCargoURL(rest)
		return model.CargoOrigin{Kind: model.CargoOriginRegistry, URL: u}, rest != ""
	case "sparse":
		u, _ := configaudit.SanitizeCargoURL(rest)
		return model.CargoOrigin{Kind: model.CargoOriginRegistry, URL: "sparse+" + u}, rest != ""
	case "git":
		o := model.CargoOrigin{Kind: model.CargoOriginGit}
		base, fragment, _ := strings.Cut(rest, "#")
		if sha := strings.ToLower(fragment); cargoIsHex(sha, 40) || cargoIsHex(sha, 64) {
			o.ResolvedRevision = sha
		}
		base, query, _ := strings.Cut(base, "?")
		if q, err := url.ParseQuery(query); err == nil {
			o.Branch, _ = cargoText(q.Get("branch"))
			o.Tag, _ = cargoText(q.Get("tag"))
			o.Rev, _ = cargoText(q.Get("rev"))
		}
		o.URL, _ = configaudit.SanitizeCargoURL(base)
		return o, base != ""
	case "path":
		p, ok := cargoFileURLPath(rest)
		return model.CargoOrigin{Kind: model.CargoOriginLocal, Path: p, IsLocal: true}, ok
	}
	return model.CargoOrigin{}, false
}

// cargoFileURLPath turns a file:// URL into a native absolute path.
func cargoFileURLPath(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "file" || u.Path == "" {
		return "", false
	}
	p := u.Path
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' { // /C:/x on Windows
		p = p[1:]
	}
	return filepath.Clean(filepath.FromSlash(p)), true
}

// parseCargoPackageID splits "name version (source)", the key format of both
// install receipts.
func parseCargoPackageID(id string) (name, version, source string, ok bool) {
	name, rest, ok1 := strings.Cut(id, " ")
	version, rest, ok2 := strings.Cut(rest, " ")
	source, ok3 := strings.CutPrefix(rest, "(")
	source, ok4 := strings.CutSuffix(source, ")")
	name, okName := cargoText(name)
	version, okVersion := cargoText(version)
	ok = ok1 && ok2 && ok3 && ok4 && okName && okVersion && name != "" && version != "" && len(source) <= maxCargoDisplayLen
	return name, version, source, ok
}

// parseCratesToml reads .crates.toml v1: package ID to recorded bin names.
func parseCratesToml(data []byte) (map[string][]string, error) {
	var t struct {
		V1 map[string][]string `toml:"v1"`
	}
	if err := toml.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	if t.V1 == nil {
		t.V1 = map[string][]string{}
	}
	return t.V1, nil
}

// cargoInstallInfo is one .crates2.json install entry.
type cargoInstallInfo struct {
	VersionReq        *string  `json:"version_req"`
	Features          []string `json:"features"`
	AllFeatures       bool     `json:"all_features"`
	NoDefaultFeatures bool     `json:"no_default_features"`
	Profile           string   `json:"profile"`
	Target            *string  `json:"target"`
	Rustc             *string  `json:"rustc"`
}

func parseCrates2JSON(data []byte) (map[string]cargoInstallInfo, error) {
	var t struct {
		Installs map[string]cargoInstallInfo `json:"installs"`
	}
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return t.Installs, nil
}

// apply copies the receipt details onto an installation. Only the first line
// of the recorded rustc text is kept.
func (info cargoInstallInfo) apply(inst *model.CargoInstallation) {
	if info.VersionReq != nil {
		inst.VersionReq, _ = cargoText(*info.VersionReq)
	}
	for _, f := range info.Features {
		if v, ok := cargoText(f); ok {
			inst.Features = append(inst.Features, v)
		}
	}
	slices.Sort(inst.Features)
	inst.Features = slices.Compact(inst.Features)
	inst.AllFeatures, inst.NoDefaultFeatures = &info.AllFeatures, &info.NoDefaultFeatures
	inst.Profile, _ = cargoText(info.Profile)
	if info.Target != nil {
		inst.Target, _ = cargoText(*info.Target)
	}
	if info.Rustc != nil {
		line, _, _ := strings.Cut(*info.Rustc, "\n")
		if line = strings.TrimSpace(line); len(line) <= maxCargoDisplayLen && !strings.ContainsFunc(line, unicode.IsControl) {
			inst.Rustc = line
		}
	}
}

// cargoBinName accepts a recorded bin name only as a plain file name.
func cargoBinName(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 &&
		!strings.ContainsAny(name, `/\:`) && !strings.ContainsFunc(name, unicode.IsControl)
}

// splitCargoFilename splits "name-version" at the first hyphen that leaves a
// valid package name and a full three-part semantic version, so hyphenated
// names and prerelease versions both split correctly.
func splitCargoFilename(base string) (name, version string, ok bool) {
	for i := 0; i < len(base); i++ {
		if base[i] != '-' {
			continue
		}
		name, version = base[:i], base[i+1:]
		if cargoASCIIName(name) && cargoSemver(version) {
			return name, version, true
		}
	}
	return "", "", false
}

func cargoASCIIName(s string) bool {
	if s == "" || len(s) > maxCargoTextLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func cargoSemver(v string) bool {
	core, _, _ := strings.Cut(v, "+")
	core, _, _ = strings.Cut(core, "-")
	return len(v) <= maxCargoTextLen && strings.Count(core, ".") == 2 && semver.IsValid("v"+v)
}

var errCargoArchiveLimit = errors.New("archive limit")

// cargoArchiveManifest confirms a .crate archive's identity from its
// name-version/Cargo.toml member, reading headers only until that member. It
// returns "" when the member names name and version, else a reason code.
func cargoArchiveManifest(ctx context.Context, data []byte, name, version string) string {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return model.CargoReasonParseError
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(&cargoLimitReader{r: gz, left: maxCargoUnpackedBytes})
	prefix := name + "-" + version
	for range maxCargoArchiveHeaders {
		if ctx.Err() != nil {
			return model.CargoReasonDeadlineExceeded
		}
		hdr, err := tr.Next()
		switch {
		case errors.Is(err, io.EOF):
			return model.CargoReasonParseError // no manifest member
		case errors.Is(err, errCargoArchiveLimit):
			return model.CargoReasonSizeLimit
		case err != nil:
			return model.CargoReasonParseError
		}
		member := hdr.Name
		if path.IsAbs(member) || strings.Contains(member, `\`) || slices.Contains(strings.Split(member, "/"), "..") {
			return model.CargoReasonParseError
		}
		dir, file := path.Split(path.Clean(member))
		if file != "Cargo.toml" || strings.Contains(strings.TrimSuffix(dir, "/"), "/") {
			continue
		}
		if dir != prefix+"/" || hdr.Typeflag != tar.TypeReg {
			return model.CargoReasonParseError
		}
		if hdr.Size > maxCargoMetadataBytes {
			return model.CargoReasonSizeLimit
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxCargoMetadataBytes))
		if errors.Is(err, errCargoArchiveLimit) {
			return model.CargoReasonSizeLimit
		} else if err != nil {
			return model.CargoReasonParseError
		}
		m, err := parseCargoManifest(body)
		if err != nil || m.name != name || m.version != version {
			return model.CargoReasonParseError
		}
		return ""
	}
	return model.CargoReasonEntryLimit
}

// cargoLimitReader fails once more than left bytes have been decompressed.
type cargoLimitReader struct {
	r    io.Reader
	left int64
}

func (l *cargoLimitReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errCargoArchiveLimit
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

// parseCargoOK accepts every .cargo-ok marker generation: empty, "ok", and
// the current {"v":1} JSON. A marker records completed extraction, not
// integrity.
func parseCargoOK(data []byte) bool {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "ok" {
		return true
	}
	var v struct {
		V int `json:"v"`
	}
	return json.Unmarshal(data, &v) == nil && v.V == 1
}

// parseCargoChecksumJSON returns the package checksum recorded in a
// .cargo-checksum.json. The per-file map and any other field are ignored.
func parseCargoChecksumJSON(data []byte) (sum string, invalid bool, err error) {
	var v struct {
		Package *string `json:"package"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return "", false, err
	}
	if v.Package == nil || *v.Package == "" {
		return "", false, nil
	}
	sum, ok := cargoSHA256(*v.Package)
	if !ok {
		return "", true, nil
	}
	return sum, false, nil
}

// cargoMemberMatch matches a workspace members pattern against a slash path
// relative to the workspace root, one path component at a time. ok is false
// for a pattern this matcher cannot evaluate, such as a recursive "**".
func cargoMemberMatch(pattern, rel string) (match, ok bool) {
	pattern = path.Clean(strings.ReplaceAll(pattern, `\`, "/"))
	pat, got := strings.Split(pattern, "/"), strings.Split(rel, "/")
	if slices.Contains(pat, "**") || strings.HasPrefix(pattern, "../") || pattern == ".." {
		return false, false
	}
	if len(pat) != len(got) {
		return false, true
	}
	for i := range pat {
		m, err := path.Match(pat[i], got[i])
		if err != nil {
			return false, false
		}
		if !m {
			return false, true
		}
	}
	return true, true
}

// cargoIsGlob reports whether a members entry needs matching rather than
// naming one directory.
func cargoIsGlob(pattern string) bool { return strings.ContainsAny(pattern, "*?[") }

// parseGitHead reads a .git/HEAD: a detached full commit, or a symbolic ref.
func parseGitHead(data []byte) (sha, ref string) {
	s := strings.TrimSpace(string(data))
	if r, ok := strings.CutPrefix(s, "ref: "); ok {
		return "", strings.TrimSpace(r)
	}
	if s = strings.ToLower(s); cargoIsHex(s, 40) || cargoIsHex(s, 64) {
		return s, ""
	}
	return "", ""
}

// parsePackedRef finds ref in a packed-refs file.
func parsePackedRef(data []byte, ref string) string {
	for line := range strings.SplitSeq(string(data), "\n") {
		sha, name, ok := strings.Cut(strings.TrimSpace(line), " ")
		if sha = strings.ToLower(sha); ok && name == ref && (cargoIsHex(sha, 40) || cargoIsHex(sha, 64)) {
			return sha
		}
	}
	return ""
}

// parseGitDirFile reads a .git file's "gitdir: <path>" indirection.
func parseGitDirFile(data []byte) (string, bool) {
	s, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir: ")
	return strings.TrimSpace(s), ok && s != ""
}
