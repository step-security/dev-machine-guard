package detector

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// maxCondaMetadataBytes bounds receipts, cache records, manifests and locks.
// Receipts stay small because file lists are never decoded.
var maxCondaMetadataBytes int64 = 2 << 20

const maxCondaRequestedSpecs = 32

var errCondaUnsupportedFormat = errors.New("unsupported conda metadata format")

const condaRedacted = "[redacted]"

var (
	condaNamePattern     = regexp.MustCompile(`^[a-z0-9_][a-z0-9._-]*$`)
	condaLabelPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	condaSelectorPattern = regexp.MustCompile(`(?m)#\s*\[[^\]\n]+\]\s*$`)
)

// condaName lowercases like Conda's MatchSpec and admits the native grammar
// without folding separators. Reserved `__` capability names never pass.
func condaName(s string) (string, bool) {
	s = strings.ToLower(s)
	return s, len(s) <= 256 && condaNamePattern.MatchString(s) && !strings.HasPrefix(s, "__")
}

func condaVirtual(s string) bool { return strings.HasPrefix(s, "__") }

// condaOpaque bounds a version or build string without interpreting it.
func condaOpaque(s string) bool {
	return s != "" && composerText(s, 256) && !strings.ContainsFunc(s, unicode.IsSpace)
}

// condaLabel bounds a subdir or target platform without a platform catalog.
func condaLabel(s string) bool { return len(s) <= 64 && condaLabelPattern.MatchString(s) }

func condaChecksum(algorithm, value string) bool {
	switch algorithm {
	case "md5":
		return cargoIsHex(value, 32)
	case "sha256":
		return cargoIsHex(value, 64)
	}
	return false
}

// condaDist splits an artifact or receipt stem like Conda's dist rsplit:
// name-version-build, where only the last two dashes separate.
func condaDist(fn string) (name, version, build string, ok bool) {
	stem := strings.TrimSuffix(strings.TrimSuffix(fn, ".conda"), ".tar.bz2")
	i := strings.LastIndex(stem, "-")
	if i <= 0 {
		return "", "", "", false
	}
	build = stem[i+1:]
	j := strings.LastIndex(stem[:i], "-")
	if j <= 0 {
		return "", "", "", false
	}
	name, version = stem[:j], stem[j+1:i]
	if name, ok = condaName(name); !ok || !condaOpaque(version) || !condaOpaque(build) {
		return "", "", "", false
	}
	return name, version, build, true
}

// condaRecord is one prefix receipt or cache record. Channel and URL stay raw
// until condaOrigin sanitizes them; requested specs are already sanitized.
type condaRecord struct {
	name, version, build, subdir string
	buildNumber                  *int64
	channel, url                 string
	md5, sha256                  string
	checksumInvalid              bool
	requested                    []string
	reasons                      []string
}

func condaJSONString(obj map[string]json.RawMessage, keys ...string) (string, bool) {
	for _, key := range keys {
		if raw := obj[key]; raw != nil {
			s, ok := composerString(raw, 4096)
			return s, ok
		}
	}
	return "", true
}

// parseCondaRecord reads only identity, origin, checksum and request fields.
// File lists, dependency graphs, licenses and link data are never decoded.
// Virtual package types are solver overlays Conda never writes to disk.
func parseCondaRecord(data []byte) (*condaRecord, error) {
	if int64(len(data)) > maxCondaMetadataBytes {
		return nil, errors.New("record too large")
	}
	obj, err := composerObject(data)
	if err != nil {
		return nil, err
	}
	if t, ok := condaJSONString(obj, "package_type"); !ok {
		return nil, errors.New("invalid package type")
	} else if strings.HasPrefix(t, "virtual_") {
		return nil, errCondaUnsupportedFormat
	}
	r := &condaRecord{reasons: []string{}, requested: []string{}}
	name, ok := condaJSONString(obj, "name")
	if !ok {
		return nil, errors.New("invalid record name")
	}
	if r.name, ok = condaName(name); !ok {
		return nil, errors.New("invalid record name")
	}
	if r.version, ok = condaJSONString(obj, "version"); !ok || !condaOpaque(r.version) {
		return nil, errors.New("invalid record version")
	}
	if r.build, ok = condaJSONString(obj, "build", "build_string"); !ok || !condaOpaque(r.build) {
		return nil, errors.New("invalid record build")
	}
	if subdir, ok := condaJSONString(obj, "subdir"); !ok || subdir != "" && !condaLabel(subdir) {
		r.reasons = append(r.reasons, "parse_error")
	} else {
		r.subdir = subdir
	}
	if raw := obj["build_number"]; raw != nil {
		var n int64
		if err := json.Unmarshal(raw, &n); err != nil || n < 0 {
			r.reasons = append(r.reasons, "parse_error")
		} else {
			r.buildNumber = &n
		}
	}
	if r.channel, ok = condaJSONString(obj, "channel"); !ok {
		r.channel = condaRedacted
	}
	if r.url, ok = condaJSONString(obj, "url"); !ok {
		r.url = condaRedacted
	}
	for _, algorithm := range []string{"md5", "sha256"} {
		v, ok := condaJSONString(obj, algorithm)
		if v == "" && ok {
			continue
		}
		v = strings.ToLower(v)
		if !ok || !condaChecksum(algorithm, v) {
			r.checksumInvalid = true
			continue
		}
		if algorithm == "md5" {
			r.md5 = v
		} else {
			r.sha256 = v
		}
	}
	// Conda's own reader prefers a nonempty list, then the legacy scalar.
	var specs []string
	if raw := obj["requested_specs"]; raw != nil && !strings.EqualFold(strings.TrimSpace(string(raw)), "null") {
		if json.Unmarshal(raw, &specs) != nil {
			r.reasons = append(r.reasons, "parse_error")
			specs = nil
		}
	}
	if len(specs) == 0 {
		// Early Conda wrote the Python None literal for packages nobody asked for.
		if s, ok := condaJSONString(obj, "requested_spec"); !ok {
			r.reasons = append(r.reasons, "parse_error")
		} else if s != "" && s != "None" {
			specs = []string{s}
		}
	}
	for _, s := range specs {
		if len(r.requested) >= maxCondaRequestedSpecs {
			r.reasons = append(r.reasons, "entry_limit")
			break
		}
		if display := condaSanitizeSpec(s); !slices.Contains(r.requested, display) {
			r.requested = append(r.requested, display)
		}
	}
	return r, nil
}

// condaSanitizeSpec keeps a request readable while any URL or credential
// bearing text is cleaned or redacted whole.
func condaSanitizeSpec(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" || !composerText(spec, 4096) {
		return condaRedacted
	}
	if channel, rest, ok := strings.Cut(spec, "::"); ok {
		display, _ := configaudit.CondaChannelDisplay(channel)
		if strings.ContainsAny(rest, "@:?#") || strings.Contains(rest, "/t/") {
			return condaRedacted
		}
		return display + "::" + rest
	}
	switch {
	case strings.Contains(spec, "://"):
		if strings.ContainsAny(spec, " \t[]()") {
			return condaRedacted
		}
		display, _ := configaudit.CondaSanitizeURL(spec)
		return display
	case strings.ContainsAny(spec, "@?#") || strings.Contains(spec, "/t/"):
		// A query or fragment marks a URL-like request, not a match spec.
		return condaRedacted
	}
	return spec
}

// condaArtifact is a recorded download location: a sanitized URL or local
// path, its checksum fragment and the identity its filename carries.
type condaArtifact struct {
	display                       string
	redacted, local, wheel, ok    bool
	name, version, build          string
	subdir, channel               string
	md5, sha256                   string
	checksumInvalid, unresolvable bool
}

// condaLocalChannel recognizes a file URL or an absolute path in either OS
// syntax; a bare label like conda-forge or pkgs/main is never a path.
func condaLocalChannel(raw string) (string, bool) {
	if strings.HasPrefix(strings.ToLower(raw), "file://") {
		return composerLocalURL(raw, "")
	}
	return raw, isCondaAbs(raw)
}

// isCondaAbs accepts either OS syntax: explicit files are written on one
// platform and read on another.
func isCondaAbs(p string) bool {
	return strings.HasPrefix(p, "/") || len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') || strings.HasPrefix(p, `\\`)
}

// parseCondaArtifactURL extracts a valid checksum fragment before the URL is
// sanitized, then reads identity only from the standard artifact filename
// and the channel only from an unambiguous `<channel>/<subdir>/<file>` tail.
func parseCondaArtifactURL(raw string) condaArtifact {
	var a condaArtifact
	if !composerText(raw, 4096) {
		a.display, a.redacted = condaRedacted, true
		return a
	}
	base, fragment, _ := strings.Cut(raw, "#")
	if fragment != "" {
		fragment = strings.ToLower(fragment)
		switch digest, ok := strings.CutPrefix(fragment, "sha256:"); {
		case ok && cargoIsHex(digest, 64), cargoIsHex(fragment, 64):
			a.sha256 = strings.TrimPrefix(fragment, "sha256:")
		case cargoIsHex(fragment, 32):
			a.md5 = fragment
		default:
			a.checksumInvalid = true
		}
	}
	var dir, fn, prefix string
	seps := "/"
	if p, local := condaLocalChannel(base); local || !strings.Contains(base, "://") {
		// A scheme-less row is a path relative to an unknown invocation directory.
		a.local, a.unresolvable = true, !local
		a.display, a.redacted = configaudit.SanitizeComposerURL(p)
		if a.display == condaRedacted {
			return a
		}
		seps = `/\`
		i := strings.LastIndexAny(a.display, seps)
		dir, fn = a.display[:max(i, 0)], a.display[i+1:]
	} else {
		a.display, a.redacted = configaudit.CondaSanitizeURL(base)
		u, err := url.Parse(a.display)
		if a.display == condaRedacted || err != nil {
			a.display, a.redacted = condaRedacted, true
			return a
		}
		i := strings.LastIndex(u.Path, "/")
		dir, fn = u.Path[:max(i, 0)], u.Path[i+1:]
		prefix = u.Scheme + "://" + u.Host
	}
	if strings.HasSuffix(fn, ".whl") {
		a.wheel = true
		return a
	}
	if a.name, a.version, a.build, a.ok = condaDist(fn); !a.ok {
		return a
	}
	if j := strings.LastIndexAny(dir, seps); j >= 0 && condaLabel(dir[j+1:]) && (!a.local || j > 0) {
		a.subdir, a.channel = dir[j+1:], prefix+dir[:j]
	}
	return a
}

// condaOrigin establishes a channel only when credentials are gone and the
// identity is unambiguous. A bare label maps through a recorded standard
// artifact URL whose subdir matches; a wheel host never names a channel.
func condaOrigin(channel, rawURL, subdir string) (model.CondaOrigin, string) {
	unknown := model.CondaOrigin{Kind: "unknown"}
	strip := func(u string) string {
		if subdir != "" {
			u = strings.TrimSuffix(u, "/"+subdir)
		}
		return u
	}
	switch p, local := condaLocalChannel(channel); {
	case local:
		display, _ := configaudit.SanitizeComposerURL(p)
		if display == condaRedacted {
			return unknown, "origin_unresolved"
		}
		return model.CondaOrigin{Kind: "local", Path: strip(strings.TrimSuffix(display, "/"))}, ""
	case strings.Contains(channel, "://"):
		display, _ := configaudit.CondaSanitizeURL(channel)
		if display == condaRedacted {
			return unknown, "origin_unresolved"
		}
		return model.CondaOrigin{Kind: "channel", URL: strip(display)}, ""
	case channel != "" && channel != "<unknown>":
		if _, bad := configaudit.CondaChannelDisplay(channel); bad {
			return unknown, "origin_unresolved"
		}
	}
	if rawURL == "" {
		return unknown, ""
	}
	a := parseCondaArtifactURL(rawURL)
	switch {
	case a.display == condaRedacted:
		return unknown, "origin_unresolved"
	case !a.ok || a.wheel || a.channel == "" || a.unresolvable || subdir != "" && a.subdir != subdir:
		return unknown, ""
	case a.local:
		return model.CondaOrigin{Kind: "local", Path: a.channel}, ""
	}
	return model.CondaOrigin{Kind: "channel", URL: a.channel}, ""
}

// condaFact builds identity evidence from a record; installed and cached
// rows differ only in what the scanner attaches afterwards.
func condaFact(r *condaRecord) model.CondaPackage {
	p := model.CondaPackage{PackageName: r.name, Reasons: slices.Clone(r.reasons), VersionStatus: "known", Version: r.version, Build: r.build, Subdir: r.subdir, BuildNumber: r.buildNumber,
		RequestedSpecs: slices.Clone(r.requested), DependencyRelation: "unknown", Origin: model.CondaOrigin{Kind: "unknown"}, ChecksumStatus: "absent", RecordedChecksums: []model.CondaRecordedChecksum{}}
	if len(p.RequestedSpecs) > 0 {
		p.DependencyRelation = "direct"
	}
	var reason string
	p.Origin, reason = condaOrigin(r.channel, r.url, r.subdir)
	if reason != "" {
		p.Reasons = append(p.Reasons, reason)
	}
	if r.url != "" {
		a := parseCondaArtifactURL(r.url)
		if a.display != condaRedacted && !a.unresolvable {
			p.ArtifactURL = a.display
		}
	}
	condaChecksums(&p, r.md5, r.sha256, r.checksumInvalid)
	return p
}

func condaChecksums(p *model.CondaPackage, md5, sha256 string, invalid bool) {
	for _, h := range [][2]string{{"sha256", sha256}, {"md5", md5}} {
		if h[1] != "" {
			p.RecordedChecksums = append(p.RecordedChecksums, model.CondaRecordedChecksum{Algorithm: h[0], Value: h[1], Verification: "not_verified"})
		}
	}
	switch {
	case invalid:
		p.ChecksumStatus = "partial"
		p.Reasons = append(p.Reasons, "checksum_invalid")
	case len(p.RecordedChecksums) > 0:
		p.ChecksumStatus = "recorded"
	}
}

// condaDeclaration is one literal manifest requirement. The channel display
// is already sanitized; the spec keeps its constraint text.
type condaDeclaration struct {
	name, spec, channel string
	channelRedacted     bool
}

// parseCondaMatchSpec reads concrete-name forms only: an optional channel
// qualifier, then a name followed by version/build text that is kept, not
// solved. Bracket, namespace and wildcard forms are unsupported.
func parseCondaMatchSpec(raw string) (condaDeclaration, string) {
	var d condaDeclaration
	raw = strings.TrimSpace(raw)
	if raw == "" || !composerText(raw, 4096) {
		return d, "invalid"
	}
	if strings.ContainsAny(raw, "[]()") {
		return d, "unsupported"
	}
	rest := raw
	if channel, after, ok := strings.Cut(raw, "::"); ok {
		if !strings.Contains(channel, "://") && strings.Contains(channel, ":") || strings.Contains(after, "::") {
			return d, "unsupported"
		}
		d.channel, _ = configaudit.CondaChannelDisplay(channel)
		d.channelRedacted = d.channel == condaRedacted
		rest = after
	} else if strings.Contains(raw, ":") {
		return d, "unsupported"
	}
	end := strings.IndexAny(rest, " =<>!~,|")
	if end < 0 {
		end = len(rest)
	}
	name := rest[:end]
	switch {
	case strings.Contains(name, "*"):
		return d, "unsupported"
	case condaVirtual(name):
		return d, "virtual"
	}
	var ok bool
	if d.name, ok = condaName(name); !ok {
		return d, "invalid"
	}
	d.spec = condaSanitizeSpec(raw)
	return d, "ok"
}

// condaManifest is a whole environment file. Unsupported constructs leave
// the declaration set partial without rejecting the readable rows.
type condaManifest struct {
	channels             []string
	declarations         []condaDeclaration
	unsupported, invalid bool
}

func condaYAMLPlain(n *yaml.Node) bool {
	return n != nil && n.Kind != yaml.AliasNode && n.Anchor == "" && n.Style&yaml.TaggedStyle == 0
}

// condaYAMLData rejects anchors, aliases and tags anywhere below n; lock
// writers never emit them and an alias could inject another row's fields.
func condaYAMLData(n *yaml.Node, depth int) bool {
	if depth > 8 || !condaYAMLPlain(n) {
		return false
	}
	for i, c := range n.Content {
		if n.Kind == yaml.MappingNode && i%2 == 0 && (c.Kind != yaml.ScalarNode || c.Value == "<<") {
			return false
		}
		if !condaYAMLData(c, depth+1) {
			return false
		}
	}
	return true
}

// condaScalar reads a plain scalar; null reads as empty text.
func condaScalar(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	if n.ShortTag() == "!!null" {
		return "", true
	}
	return n.Value, true
}

// condaYAMLField returns a mapping value, or nil with found when the key
// repeats or uses unsupported YAML key syntax.
func condaYAMLField(m *yaml.Node, field string) (*yaml.Node, bool) {
	var out *yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind != yaml.ScalarNode || !condaYAMLPlain(k) || k.Value == "<<" {
			return nil, true
		}
		if k.Value == field {
			if out != nil {
				return nil, true
			}
			out = m.Content[i+1]
		}
	}
	return out, out != nil
}

// parseCondaEnvironment reads environment.yml and the exported JSON form
// through one YAML reader, since JSON is a YAML flow document. Selector
// comments are found on the raw bytes before the parser discards them.
func parseCondaEnvironment(data []byte) (*condaManifest, error) {
	if int64(len(data)) > maxCondaMetadataBytes || !utf8.Valid(data) {
		return nil, errors.New("invalid environment file")
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil {
		return nil, errors.New("invalid environment file")
	}
	m := &condaManifest{channels: []string{}}
	if len(doc.Content) == 0 {
		return m, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || !condaYAMLPlain(root) {
		return nil, errCondaUnsupportedFormat
	}
	selected := map[int]bool{}
	for _, loc := range condaSelectorPattern.FindAllIndex(data, -1) {
		m.unsupported = true
		selected[bytes.Count(data[:loc[0]], []byte("\n"))+1] = true
	}
	if n, found := condaYAMLField(root, "channels"); found {
		switch {
		case n == nil || !condaYAMLData(n, 0):
			m.unsupported = true
		case n.Kind != yaml.SequenceNode:
			m.invalid = true
		default:
			for _, item := range n.Content {
				if v, ok := condaScalar(item); ok && v != "" && composerText(v, 4096) && !selected[item.Line] {
					m.channels = append(m.channels, v)
				} else {
					m.invalid = true
				}
			}
		}
	}
	n, found := condaYAMLField(root, "dependencies")
	switch {
	case !found:
	case n == nil || !condaYAMLData(n, 0):
		m.unsupported = true
	case n.Kind != yaml.SequenceNode:
		m.invalid = true
	default:
		for _, item := range n.Content {
			if selected[item.Line] {
				continue
			}
			if item.Kind == yaml.MappingNode {
				// `pip:` lists Python requirements; anything else is a selector
				// or plugin form this reader does not evaluate.
				if len(item.Content) == 2 && item.Content[0].Value == "pip" {
					continue
				}
				m.unsupported = true
				continue
			}
			v, ok := condaScalar(item)
			if !ok {
				m.invalid = true
				continue
			}
			d, status := parseCondaMatchSpec(v)
			switch status {
			case "ok":
				m.declarations = append(m.declarations, d)
			case "unsupported":
				m.unsupported = true
			case "invalid":
				m.invalid = true
			}
		}
	}
	return m, nil
}

// condaLockEntry is one locked row; reasons on the row are also reported on
// the lock source by the scanner.
type condaLockEntry struct{ pkg model.CondaPackage }

func condaLocked(name, version string) model.CondaPackage {
	return model.CondaPackage{PackageName: name, Reasons: []string{}, VersionStatus: "known", Version: version, RequestedSpecs: []string{}, DependencyRelation: "unknown",
		Origin: model.CondaOrigin{Kind: "unknown"}, ChecksumStatus: "absent", RecordedChecksums: []model.CondaRecordedChecksum{}}
}

func condaLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	}
	return lines
}

// condaIsExplicit reports the @EXPLICIT header as the first content line,
// so a probe of the first bytes decides whether a `conda-*.lock` is read.
func condaIsExplicit(data []byte) bool {
	for _, line := range condaLines(data) {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line == "@EXPLICIT"
	}
	return false
}

// parseCondaExplicit reads an @EXPLICIT artifact list. Rows are locked
// artifacts, not solver requirements; a relative path is anchored to an
// unknown invocation directory, never to the file.
func parseCondaExplicit(data []byte) ([]condaLockEntry, []string, error) {
	if int64(len(data)) > maxCondaMetadataBytes || !utf8.Valid(data) {
		return nil, nil, errors.New("invalid explicit file")
	}
	var entries []condaLockEntry
	var reasons []string
	note := func(r string) {
		if !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
	}
	platform, started := "", false
	for _, line := range condaLines(data) {
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#"):
			if v, ok := strings.CutPrefix(line, "# platform:"); ok && !started {
				if v = strings.TrimSpace(v); condaLabel(v) {
					platform = v
				}
			}
			continue
		case !started:
			if line != "@EXPLICIT" {
				return nil, nil, errCondaUnsupportedFormat
			}
			started = true
			continue
		}
		a := parseCondaArtifactURL(line)
		switch {
		case a.wheel:
			note("unsupported_format")
			continue
		case !a.ok:
			note("parse_error")
			continue
		}
		p := condaLocked(a.name, a.version)
		p.Build, p.Subdir, p.TargetPlatform = a.build, a.subdir, platform
		switch {
		case a.unresolvable:
			p.Reasons = append(p.Reasons, "path_unresolved")
			note("path_unresolved")
		case a.local && a.channel != "":
			p.Origin, p.ArtifactURL = model.CondaOrigin{Kind: "local", Path: a.channel}, a.display
		case a.local:
			p.ArtifactURL = a.display
		case a.channel != "":
			p.Origin, p.ArtifactURL = model.CondaOrigin{Kind: "channel", URL: a.channel}, a.display
		default:
			p.ArtifactURL = a.display
		}
		condaChecksums(&p, a.md5, a.sha256, a.checksumInvalid)
		if a.checksumInvalid {
			note("checksum_invalid")
		}
		entries = append(entries, condaLockEntry{p})
	}
	if !started {
		return nil, nil, errCondaUnsupportedFormat
	}
	return entries, reasons, nil
}

func condaYAMLString(m *yaml.Node, field string) (string, bool) {
	n, found := condaYAMLField(m, field)
	if !found {
		return "", true
	}
	if n == nil || !condaYAMLPlain(n) {
		return "", false
	}
	v, ok := condaScalar(n)
	return v, ok && composerText(v, 4096)
}

// parseCondaLockYAML dispatches on the file's own version: conda-lock
// version 1 package rows, or rattler/pixi version 6 and 7 environments,
// which share one package table shape. Rows no environment references are
// not emitted.
func parseCondaLockYAML(data []byte) ([]condaLockEntry, []string, error) {
	if int64(len(data)) > maxCondaMetadataBytes || !utf8.Valid(data) {
		return nil, nil, errors.New("invalid lock file")
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil || len(doc.Content) == 0 {
		return nil, nil, errors.New("invalid lock file")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || !condaYAMLPlain(root) {
		return nil, nil, errors.New("invalid lock file")
	}
	version, ok := condaYAMLString(root, "version")
	if !ok {
		return nil, nil, errors.New("invalid lock version")
	}
	switch version {
	case "1":
		return parseCondaLockV1(root)
	case "6", "7":
		return parseCondaLockV6(root)
	}
	return nil, nil, errCondaUnsupportedFormat
}

func condaSequence(m *yaml.Node, field string) ([]*yaml.Node, bool) {
	n, found := condaYAMLField(m, field)
	if !found {
		return nil, true
	}
	if n == nil || !condaYAMLPlain(n) || n.Kind != yaml.SequenceNode {
		return nil, false
	}
	return n.Content, true
}

// condaLockArtifact applies a lock row's recorded URL: filename identity
// must agree with the declared one, and a wheel is never a Conda artifact.
func condaLockArtifact(p *model.CondaPackage, rawURL string, note func(string)) (condaArtifact, bool) {
	a := parseCondaArtifactURL(rawURL)
	switch {
	case a.wheel:
		if a.display != condaRedacted {
			p.ArtifactURL = a.display
		}
		note("unsupported_format")
		return a, false
	case a.display == condaRedacted:
		p.Reasons = append(p.Reasons, "origin_unresolved")
		note("origin_unresolved")
		return a, false
	case !a.ok:
		p.Reasons = append(p.Reasons, "parse_error")
		note("parse_error")
		return a, false
	case a.name != p.PackageName || a.version != p.Version:
		p.Reasons = append(p.Reasons, "identity_mismatch")
		note("identity_mismatch")
		return a, false
	case a.unresolvable:
		p.Reasons = append(p.Reasons, "path_unresolved")
		note("path_unresolved")
		return a, false
	}
	p.ArtifactURL = a.display
	switch {
	case a.local && a.channel != "":
		p.Origin = model.CondaOrigin{Kind: "local", Path: a.channel}
	case !a.local && a.channel != "":
		p.Origin = model.CondaOrigin{Kind: "channel", URL: a.channel}
	}
	return a, true
}

func parseCondaLockV1(root *yaml.Node) ([]condaLockEntry, []string, error) {
	var entries []condaLockEntry
	var reasons []string
	note := func(r string) {
		if !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
	}
	rows, ok := condaSequence(root, "package")
	if !ok {
		return nil, nil, errors.New("invalid lock packages")
	}
	for _, row := range rows {
		if row.Kind != yaml.MappingNode || !condaYAMLData(row, 0) {
			note("parse_error")
			continue
		}
		manager, ok := condaYAMLString(row, "manager")
		if !ok {
			note("parse_error")
			continue
		}
		if manager != "conda" {
			continue
		}
		name, ok1 := condaYAMLString(row, "name")
		version, ok2 := condaYAMLString(row, "version")
		name, valid := condaName(name)
		if !ok1 || !ok2 || !valid || !condaOpaque(version) {
			note("parse_error")
			continue
		}
		p := condaLocked(name, version)
		if platform, ok := condaYAMLString(row, "platform"); !ok || platform != "" && !condaLabel(platform) {
			note("parse_error")
			continue
		} else {
			p.TargetPlatform = platform
		}
		rawURL, ok := condaYAMLString(row, "url")
		if !ok {
			note("parse_error")
			continue
		}
		if rawURL != "" {
			if a, ok := condaLockArtifact(&p, rawURL, note); ok {
				p.Build, p.Subdir = a.build, a.subdir
			}
		}
		md5, sha := "", ""
		invalid := false
		if h, found := condaYAMLField(row, "hash"); found {
			if h == nil || h.Kind != yaml.MappingNode {
				invalid = true
			} else {
				for _, algorithm := range []string{"md5", "sha256"} {
					v, ok := condaYAMLString(h, algorithm)
					v = strings.ToLower(v)
					switch {
					case v == "" && ok:
					case !ok || !condaChecksum(algorithm, v):
						invalid = true
					case algorithm == "md5":
						md5 = v
					default:
						sha = v
					}
				}
			}
		}
		condaChecksums(&p, md5, sha, invalid)
		if invalid {
			note("checksum_invalid")
		}
		entries = append(entries, condaLockEntry{p})
	}
	return entries, reasons, nil
}

// parseCondaLockV6 tables the rows at each Conda location, then emits one
// row per environment and platform reference. A source location can hold
// several variants that a reference picks by name, build or subdir. A wheel
// under `conda:` is tabled as unsupported so its references are not
// mistaken for missing ones.
func parseCondaLockV6(root *yaml.Node) ([]condaLockEntry, []string, error) {
	var entries []condaLockEntry
	var reasons []string
	note := func(r string) {
		if !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
	}
	rows, ok := condaSequence(root, "packages")
	if !ok {
		return nil, nil, errors.New("invalid lock packages")
	}
	table := map[string][]*model.CondaPackage{}
	for _, row := range rows {
		if row.Kind != yaml.MappingNode || !condaYAMLData(row, 0) {
			note("parse_error")
			continue
		}
		location, ok := condaYAMLString(row, "conda")
		if !ok {
			note("parse_error")
			continue
		}
		if location == "" {
			continue // pypi rows are Python requirements
		}
		a := parseCondaArtifactURL(location)
		if a.wheel {
			note("unsupported_format")
			table[location] = append(table[location], nil)
			continue
		}
		name, ok1 := condaYAMLString(row, "name")
		version, ok2 := condaYAMLString(row, "version")
		build, ok3 := condaYAMLString(row, "build")
		subdir, ok4 := condaYAMLString(row, "subdir")
		if !ok1 || !ok2 || !ok3 || !ok4 || subdir != "" && !condaLabel(subdir) {
			note("parse_error")
			continue
		}
		// Explicit fields win; the filename supplies whatever they omit.
		name, valid := condaName(cmpOr(name, a.name))
		version, build, subdir = cmpOr(version, a.version), cmpOr(build, a.build), cmpOr(subdir, a.subdir)
		if !valid || !condaOpaque(version) || !condaOpaque(build) {
			note("parse_error")
			continue
		}
		p := condaLocked(name, version)
		p.Build, p.Subdir = build, subdir
		if a.display == condaRedacted {
			p.Reasons = append(p.Reasons, "origin_unresolved")
			note("origin_unresolved")
		} else if a.ok && (a.name != name || a.version != version || a.build != build) {
			p.Reasons = append(p.Reasons, "identity_mismatch")
			note("identity_mismatch")
		} else if a.unresolvable {
			p.Reasons = append(p.Reasons, "path_unresolved")
			note("path_unresolved")
		} else {
			p.ArtifactURL = a.display
			switch {
			case a.local && a.channel != "":
				p.Origin = model.CondaOrigin{Kind: "local", Path: a.channel}
			case !a.local && a.channel != "":
				p.Origin = model.CondaOrigin{Kind: "channel", URL: a.channel}
			}
		}
		if n, found := condaYAMLField(row, "build_number"); found {
			v, ok := condaScalar(n)
			if i, err := strconv.ParseInt(v, 10, 64); !ok || err != nil || i < 0 {
				p.Reasons = append(p.Reasons, "parse_error")
				note("parse_error")
			} else {
				p.BuildNumber = &i
			}
		}
		var md5, sha string
		invalid := false
		for _, algorithm := range []string{"md5", "sha256"} {
			v, ok := condaYAMLString(row, algorithm)
			v = strings.ToLower(v)
			switch {
			case v == "" && ok:
			case !ok || !condaChecksum(algorithm, v):
				invalid = true
			case algorithm == "md5":
				md5 = v
			default:
				sha = v
			}
		}
		condaChecksums(&p, md5, sha, invalid)
		if invalid {
			note("checksum_invalid")
		}
		table[location] = append(table[location], &p)
	}
	envs, found := condaYAMLField(root, "environments")
	if !found {
		return nil, nil, errors.New("invalid lock environments")
	}
	if envs == nil || !condaYAMLPlain(envs) || envs.Kind != yaml.MappingNode {
		return nil, nil, errors.New("invalid lock environments")
	}
	for i := 0; i+1 < len(envs.Content); i += 2 {
		envName, env := envs.Content[i].Value, envs.Content[i+1]
		if envName == "" || !composerText(envName, 256) || env.Kind != yaml.MappingNode || !condaYAMLPlain(env) {
			note("parse_error")
			continue
		}
		platforms, found := condaYAMLField(env, "packages")
		if !found || platforms == nil || !condaYAMLPlain(platforms) || platforms.Kind != yaml.MappingNode {
			note("parse_error")
			continue
		}
		for j := 0; j+1 < len(platforms.Content); j += 2 {
			platform, refs := platforms.Content[j].Value, platforms.Content[j+1]
			if !condaLabel(platform) || refs.Kind != yaml.SequenceNode || !condaYAMLPlain(refs) {
				note("parse_error")
				continue
			}
			for _, ref := range refs.Content {
				if ref.Kind != yaml.MappingNode || !condaYAMLData(ref, 0) {
					note("parse_error")
					continue
				}
				location, ok := condaYAMLString(ref, "conda")
				if !ok {
					note("parse_error")
					continue
				}
				if location == "" {
					continue
				}
				base, ok := condaLockVariant(table[location], ref)
				switch {
				case !ok:
					note("parse_error")
					continue
				case base == nil:
					continue
				}
				p := *base
				p.Reasons, p.RecordedChecksums = slices.Clone(base.Reasons), slices.Clone(base.RecordedChecksums)
				p.LockEnvironment, p.TargetPlatform = envName, platform
				entries = append(entries, condaLockEntry{p})
			}
		}
	}
	return entries, reasons, nil
}

// condaLockVariant selects the one tabled row a reference names; the
// reference's own name, build and subdir narrow a multi-variant location.
func condaLockVariant(rows []*model.CondaPackage, ref *yaml.Node) (*model.CondaPackage, bool) {
	var match *model.CondaPackage
	count := 0
	for _, row := range rows {
		if row != nil {
			ok := true
			for _, field := range [][2]string{{"name", row.PackageName}, {"build", row.Build}, {"subdir", row.Subdir}} {
				v, valid := condaYAMLString(ref, field[0])
				if !valid {
					return nil, false
				}
				if field[0] == "name" {
					v = strings.ToLower(v)
				}
				ok = ok && (v == "" || v == field[1])
			}
			if !ok {
				continue
			}
		}
		match, count = row, count+1
	}
	return match, count == 1
}

func cmpOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func condaParseReason(err error) string {
	if errors.Is(err, errCondaUnsupportedFormat) {
		return "unsupported_format"
	}
	return "parse_error"
}
