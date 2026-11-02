package detector

import (
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
)

const (
	maxMavenMetadataBytes  int64 = 2 << 20
	maxMavenRequestedSpecs       = 32
	maxMavenChecksums            = 32
	// mavenPluginGroup is Maven's syntax default for a declared build plugin.
	mavenPluginGroup = "org.apache.maven.plugins"
)

var (
	mavenSnapshotStamp = regexp.MustCompile(`^([0-9]{8}\.[0-9]{6}-[0-9]+)(?:-(.+))?$`)
	// Gradle names a cache file's folder by its SHA-1 in hex without leading
	// zeros, so a key is 1-40 digits.
	mavenContentKey = regexp.MustCompile(`^[0-9a-f]{1,40}$`)
	mavenHexLengths = map[string]int{"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
	// mavenExtensions are the supported payload and metadata suffixes, so
	// sidecars, markers and temporaries never match.
	mavenExtensions = []string{"jar", "aar", "pom", "module"}
)

// mavenCoordinate classifies one group or artifact segment: "" when it is
// a literal identity, unresolved_coordinate for a missing or expression
// value, and parse_error for anything else unusable.
func mavenCoordinate(s string) string {
	switch {
	case s == "" || strings.Contains(s, "${"):
		return "unresolved_coordinate"
	case len(s) > 256 || !utf8.ValidString(s) || s == "." || s == ".." ||
		strings.ContainsAny(s, `:/\`) || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }):
		return "parse_error"
	}
	return ""
}

// mavenVersion admits an exact version as an opaque coordinate segment.
func mavenVersion(s string) bool {
	return s != "" && len(s) <= 256 && utf8.ValidString(s) && s != "." && s != ".." &&
		!strings.ContainsAny(s, `/\:@?#`) && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

// mavenRequirement keeps raw requested text, including ranges and property
// expressions, unless it could carry a URL, path or token.
func mavenRequirement(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 1024 || !utf8.ValidString(s) || strings.Contains(s, "://") || strings.ContainsAny(s, `@?#/\`) ||
		strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) && r != ' ' }) {
		return condaRedacted, true
	}
	return s, false
}

// mavenLabelText keeps declared scope/type/classifier text that is safe to
// emit; property expressions stay literal.
func mavenLabelText(s string) bool {
	return len(s) <= 256 && utf8.ValidString(s) && !strings.Contains(s, "://") && !strings.ContainsAny(s, `@?#/\`) &&
		!strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

// mavenDeclaration is one POM or catalog declaration before identity checks.
type mavenDeclaration struct {
	group, artifact, role, context, profile string
	scope, declaredType                     string
	classifier                              *string
	optional                                *bool
	specs                                   []string
}

// mavenPOMText trims an optional element's text; nil stays absent.
func mavenPOMText(p *string) *string {
	if p == nil {
		return nil
	}
	v := strings.TrimSpace(*p)
	return &v
}

func mavenDeref(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

type mavenPOMDependency struct {
	GroupID    *string `xml:"groupId"`
	ArtifactID *string `xml:"artifactId"`
	Version    *string `xml:"version"`
	Scope      *string `xml:"scope"`
	Type       *string `xml:"type"`
	Classifier *string `xml:"classifier"`
	Optional   *string `xml:"optional"`
}

type mavenPOMPlugin struct {
	GroupID      *string              `xml:"groupId"`
	ArtifactID   *string              `xml:"artifactId"`
	Version      *string              `xml:"version"`
	Dependencies []mavenPOMDependency `xml:"dependencies>dependency"`
}

// mavenPOMModel holds the declaration parts shared by a project and its profiles.
type mavenPOMModel struct {
	Dependencies       []mavenPOMDependency          `xml:"dependencies>dependency"`
	Managed            []mavenPOMDependency          `xml:"dependencyManagement>dependencies>dependency"`
	Plugins            []mavenPOMPlugin              `xml:"build>plugins>plugin"`
	ManagedPlugins     []mavenPOMPlugin              `xml:"build>pluginManagement>plugins>plugin"`
	Extensions         []mavenPOMDependency          `xml:"build>extensions>extension"`
	Repositories       []configaudit.MavenRepository `xml:"repositories>repository"`
	PluginRepositories []configaudit.MavenRepository `xml:"pluginRepositories>pluginRepository"`
}

type mavenPOMXML struct {
	XMLName    xml.Name `xml:"project"`
	GroupID    *string  `xml:"groupId"`
	ArtifactID *string  `xml:"artifactId"`
	Version    *string  `xml:"version"`
	Parent     *struct {
		GroupID    *string `xml:"groupId"`
		ArtifactID *string `xml:"artifactId"`
		Version    *string `xml:"version"`
	} `xml:"parent"`
	mavenPOMModel
	Profiles []struct {
		ID *string `xml:"id"`
		mavenPOMModel
	} `xml:"profiles>profile"`
}

// mavenPOM is a project file's literal declarations; no effective model,
// inheritance, interpolation or profile activation is applied.
type mavenPOM struct {
	declarations []mavenDeclaration
	repositories []configaudit.MavenRepository
	reasons      []string
}

func decodeMavenPOM(data []byte) (mavenPOMXML, error) {
	var doc mavenPOMXML
	dec, err := configaudit.MavenXML(data)
	if err == nil {
		err = dec.Decode(&doc)
	}
	return doc, err
}

func parseMavenPOM(data []byte) (*mavenPOM, error) {
	doc, err := decodeMavenPOM(data)
	if err != nil {
		return nil, err
	}
	m := &mavenPOM{}
	note := func(reason string) {
		if !slices.Contains(m.reasons, reason) {
			m.reasons = append(m.reasons, reason)
		}
	}
	if p := doc.Parent; p != nil {
		m.declaration(note, mavenDeclaration{role: "parent"}, p.GroupID, p.ArtifactID, p.Version, nil)
	}
	m.model(note, doc.mavenPOMModel, "")
	m.repositories = configaudit.MavenKinds(doc.Repositories, doc.PluginRepositories, nil)
	for _, p := range doc.Profiles {
		id := mavenDeref(p.ID)
		if !configaudit.MavenLabel(id) {
			note("parse_error")
			continue
		}
		m.model(note, p.mavenPOMModel, id)
		m.repositories = append(m.repositories, configaudit.MavenKinds(p.Repositories, p.PluginRepositories, &id)...)
	}
	return m, nil
}

func (m *mavenPOM) model(note func(string), model mavenPOMModel, profile string) {
	for _, d := range model.Dependencies {
		m.dependency(note, mavenDeclaration{role: "direct", profile: profile}, d)
	}
	for _, d := range model.Managed {
		role := "managed"
		if mavenDeref(d.Scope) == "import" && mavenDeref(d.Type) == "pom" {
			role = "bom_import"
		}
		m.dependency(note, mavenDeclaration{role: role, profile: profile}, d)
	}
	for _, d := range model.Extensions {
		m.dependency(note, mavenDeclaration{role: "extension", profile: profile}, d)
	}
	for _, set := range []struct {
		role    string
		plugins []mavenPOMPlugin
	}{{"plugin", model.Plugins}, {"managed_plugin", model.ManagedPlugins}} {
		for _, p := range set.plugins {
			group := p.GroupID
			if mavenDeref(group) == "" {
				def := mavenPluginGroup
				group = &def
			}
			ok := m.declaration(note, mavenDeclaration{role: set.role, profile: profile}, group, p.ArtifactID, p.Version, nil)
			if !ok {
				if len(p.Dependencies) > 0 {
					// Without its owner's identity a plugin dependency could
					// collide with another plugin's.
					note("unresolved_coordinate")
				}
				continue
			}
			context := set.role + ":" + mavenDeref(group) + ":" + mavenDeref(p.ArtifactID)
			for _, d := range p.Dependencies {
				m.dependency(note, mavenDeclaration{role: "plugin_dependency", context: context, profile: profile}, d)
			}
		}
	}
}

func (m *mavenPOM) dependency(note func(string), d mavenDeclaration, dep mavenPOMDependency) {
	m.declaration(note, d, dep.GroupID, dep.ArtifactID, dep.Version, &dep)
}

// declaration validates and keeps one declaration, reporting whether its
// identity was literal.
func (m *mavenPOM) declaration(note func(string), d mavenDeclaration, group, artifact, version *string, dep *mavenPOMDependency) bool {
	d.group, d.artifact = mavenDeref(group), mavenDeref(artifact)
	for _, s := range []string{d.group, d.artifact} {
		if reason := mavenCoordinate(s); reason != "" {
			note(reason)
			return false
		}
	}
	if v := mavenDeref(version); v != "" {
		d.specs = []string{v}
	}
	if dep != nil {
		for _, f := range []struct {
			dst *string
			src *string
		}{{&d.scope, dep.Scope}, {&d.declaredType, dep.Type}} {
			if v := mavenDeref(f.src); v != "" && mavenLabelText(v) {
				*f.dst = v
			} else if v != "" {
				note("unsupported_format")
			}
		}
		if c := mavenPOMText(dep.Classifier); c != nil {
			if mavenLabelText(*c) {
				d.classifier = c
			} else {
				note("unsupported_format")
			}
		}
		if v := mavenDeref(dep.Optional); v == "true" || v == "false" {
			d.optional = boolPtr(v == "true")
		}
	}
	m.declarations = append(m.declarations, d)
	return true
}

// mavenPOMIdentity returns a POM's literal own coordinates, inheriting the
// group and version from its parent element as Maven's syntax allows.
func mavenPOMIdentity(data []byte) (group, artifact, version string, err error) {
	doc, err := decodeMavenPOM(data)
	if err != nil {
		return "", "", "", err
	}
	group, artifact, version = mavenDeref(doc.GroupID), mavenDeref(doc.ArtifactID), mavenDeref(doc.Version)
	if p := doc.Parent; p != nil {
		group, version = cmpOr(group, mavenDeref(p.GroupID)), cmpOr(version, mavenDeref(p.Version))
	}
	return group, artifact, version, nil
}

// mavenIvyMatches reports whether data is an Ivy 2.0 descriptor for exactly
// this module revision.
func mavenIvyMatches(data []byte, group, module, version string) bool {
	var doc struct {
		XMLName xml.Name `xml:"ivy-module"`
		Version string   `xml:"version,attr"`
		Info    struct {
			Organisation string `xml:"organisation,attr"`
			Module       string `xml:"module,attr"`
			Revision     string `xml:"revision,attr"`
		} `xml:"info"`
	}
	dec, err := configaudit.MavenXML(data)
	if err != nil || dec.Decode(&doc) != nil {
		return false
	}
	return doc.Version == "2.0" && doc.Info.Organisation == group && doc.Info.Module == module && doc.Info.Revision == version
}

// mavenFile is a classified artifact filename. classifier is nil when the
// name does not follow the conventional shape.
type mavenFile struct {
	extension, fileVersion string
	classifier             *string
}

// mavenFilename matches artifact-version[-classifier].ext, including a
// timestamped snapshot file under its base version directory. A name is
// never split on its last hyphen.
func mavenFilename(name, artifact, version string) (mavenFile, bool) {
	for _, ext := range mavenExtensions {
		stem, ok := strings.CutSuffix(name, "."+ext)
		if !ok {
			continue
		}
		rest, ok := strings.CutPrefix(stem, artifact+"-")
		if !ok {
			return mavenFile{}, false
		}
		f := mavenFile{extension: ext}
		if rest == version {
			f.classifier = new(string)
			return f, true
		}
		if cls, ok := strings.CutPrefix(rest, version+"-"); ok && mavenCoordinate(cls) == "" {
			f.classifier = &cls
			return f, true
		}
		if base, ok := strings.CutSuffix(version, "SNAPSHOT"); ok && strings.HasPrefix(rest, base) {
			if m := mavenSnapshotStamp.FindStringSubmatch(rest[len(base):]); m != nil && (m[2] == "" || mavenCoordinate(m[2]) == "") {
				f.fileVersion, f.classifier = base+m[1], &m[2]
				return f, true
			}
		}
		return mavenFile{}, false
	}
	return mavenFile{}, false
}

// mavenLockEntry is one locked component and the configurations naming it.
type mavenLockEntry struct {
	group, artifact, version string
	configurations           []string
}

// mavenLock is one parsed Gradle lock state. named lists every configuration
// the file speaks for, including explicitly empty ones.
type mavenLock struct {
	entries []mavenLockEntry
	named   []string
	invalid bool
}

// parseGradleLock reads a modern lockfile, or, when legacyConfiguration is
// set, a legacy per-configuration file of bare coordinates.
func parseGradleLock(data []byte, legacyConfiguration string) (*mavenLock, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid lockfile")
	}
	l := &mavenLock{}
	if legacyConfiguration != "" {
		l.named = []string{legacyConfiguration}
	}
	index := map[string]int{}
	name := func(c string) {
		if !slices.Contains(l.named, c) {
			l.named = append(l.named, c)
		}
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		coords, confText := line, legacyConfiguration
		if legacyConfiguration == "" {
			var ok bool
			if coords, confText, ok = strings.Cut(line, "="); !ok {
				l.invalid = true
				continue
			}
		}
		confs := []string{}
		for c := range strings.SplitSeq(confText, ",") {
			if c = strings.TrimSpace(c); c == "" {
				continue
			}
			if !configaudit.MavenLabel(c) {
				l.invalid = true
				continue
			}
			confs = append(confs, c)
			name(c)
		}
		if legacyConfiguration == "" && coords == "empty" {
			continue
		}
		parts := strings.Split(coords, ":")
		if len(parts) != 3 || mavenCoordinate(parts[0]) != "" || mavenCoordinate(parts[1]) != "" || !mavenVersion(parts[2]) {
			l.invalid = true
			continue
		}
		if i, ok := index[coords]; ok {
			for _, c := range confs {
				if !slices.Contains(l.entries[i].configurations, c) {
					l.entries[i].configurations = append(l.entries[i].configurations, c)
				}
			}
			continue
		}
		index[coords] = len(l.entries)
		l.entries = append(l.entries, mavenLockEntry{group: parts[0], artifact: parts[1], version: parts[2], configurations: confs})
	}
	return l, nil
}

// mavenLockPair names the modern lockfile that supersedes a legacy
// gradle/dependency-locks file, and the configuration that file holds.
func mavenLockPair(legacyName string) (modern, configuration string) {
	conf := strings.TrimSuffix(legacyName, ".lockfile")
	for _, prefix := range []string{"buildscript-", "settings-"} {
		if c, ok := strings.CutPrefix(conf, prefix); ok {
			return prefix + "gradle.lockfile", c
		}
	}
	return "gradle.lockfile", conf
}

// mavenCatalog holds a version catalog's library declarations.
type mavenCatalog struct {
	declarations []mavenDeclaration
	reasons      []string
}

// parseGradleCatalog reads [libraries] from libs.versions.toml with
// same-file [versions] references. Rich constraints become ordered
// key=value requirements; bundles and plugins are not packages.
func parseGradleCatalog(data []byte) (*mavenCatalog, error) {
	var doc struct {
		Versions  map[string]any `toml:"versions"`
		Libraries map[string]any `toml:"libraries"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	c := &mavenCatalog{}
	note := func(reason string) {
		if !slices.Contains(c.reasons, reason) {
			c.reasons = append(c.reasons, reason)
		}
	}
	aliases := make([]string, 0, len(doc.Libraries))
	for alias := range doc.Libraries {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)
	for _, alias := range aliases {
		if !configaudit.MavenLabel(alias) {
			note("parse_error")
			continue
		}
		d := mavenDeclaration{role: "catalog_entry", context: "catalog:" + alias}
		var version any
		switch v := doc.Libraries[alias].(type) {
		case string:
			parts := strings.Split(v, ":")
			if len(parts) < 2 || len(parts) > 3 {
				note("parse_error")
				continue
			}
			d.group, d.artifact = parts[0], parts[1]
			if len(parts) == 3 {
				version = parts[2]
			}
		case map[string]any:
			if module, ok := v["module"].(string); ok {
				group, artifact, ok := strings.Cut(module, ":")
				if !ok {
					note("parse_error")
					continue
				}
				d.group, d.artifact = group, artifact
			} else {
				d.group, _ = v["group"].(string)
				d.artifact, _ = v["name"].(string)
			}
			version = v["version"]
		default:
			note("parse_error")
			continue
		}
		if reason := cmpOr(mavenCoordinate(d.group), mavenCoordinate(d.artifact)); reason != "" {
			note(reason)
			continue
		}
		if t, ok := version.(map[string]any); ok {
			if ref, ok := t["ref"].(string); ok {
				if version, ok = doc.Versions[ref]; !ok {
					// The entry stays, with no requirement it could claim.
					note("parse_error")
				}
			}
		}
		specs, ok := mavenCatalogSpecs(version)
		if !ok {
			note("parse_error")
		}
		d.specs = specs
		c.declarations = append(c.declarations, d)
	}
	return c, nil
}

// mavenCatalogSpecs renders a catalog version as requested text: a plain
// string as-is, a rich table in require/strictly/prefer/reject order.
func mavenCatalogSpecs(v any) ([]string, bool) {
	switch t := v.(type) {
	case nil:
		return nil, true
	case string:
		if t == "" {
			return nil, true
		}
		return []string{t}, true
	case map[string]any:
		specs := []string{}
		for _, k := range []string{"require", "strictly", "prefer"} {
			if s, ok := t[k].(string); ok {
				specs = append(specs, k+"="+s)
			}
		}
		rejects, _ := t["reject"].([]any)
		for _, r := range rejects {
			if s, ok := r.(string); ok {
				specs = append(specs, "reject="+s)
			}
		}
		if all, _ := t["rejectAll"].(bool); all {
			specs = append(specs, "reject_all=true")
		}
		return specs, len(specs) > 0
	}
	return nil, false
}

// mavenChecksum is one expected hash from verification metadata.
type mavenChecksum struct{ algorithm, value string }

// mavenReference is one verification metadata component artifact.
type mavenReference struct {
	group, artifact, version, filename string
	checksums                          []mavenChecksum
	invalid, limited                   bool
}

type gradleChecksumXML struct {
	Value     string `xml:"value,attr"`
	AlsoTrust []struct {
		Value string `xml:"value,attr"`
	} `xml:"also-trust"`
}

// parseGradleVerification reads components and policy booleans. Key
// material, trust selectors, origins and reasons are never kept.
func parseGradleVerification(data []byte) ([]mavenReference, configaudit.GradleVerification, []string, error) {
	var doc struct {
		XMLName          xml.Name   `xml:"verification-metadata"`
		VerifyMetadata   *string    `xml:"configuration>verify-metadata"`
		VerifySignatures *string    `xml:"configuration>verify-signatures"`
		Trust            []struct{} `xml:"configuration>trusted-artifacts>trust"`
		Keys             []struct{} `xml:"configuration>trusted-keys>trusted-key"`
		Components       []struct {
			Group     string `xml:"group,attr"`
			Name      string `xml:"name,attr"`
			Version   string `xml:"version,attr"`
			Artifacts []struct {
				Name   string              `xml:"name,attr"`
				MD5    []gradleChecksumXML `xml:"md5"`
				SHA1   []gradleChecksumXML `xml:"sha1"`
				SHA256 []gradleChecksumXML `xml:"sha256"`
				SHA512 []gradleChecksumXML `xml:"sha512"`
			} `xml:"artifact"`
		} `xml:"components>component"`
	}
	dec, err := configaudit.MavenXML(data)
	if err == nil {
		err = dec.Decode(&doc)
	}
	if err == nil {
		// Gradle rejects the whole file when anything after the root is malformed.
		err = mavenXMLEnd(dec)
	}
	if err != nil {
		return nil, configaudit.GradleVerification{}, nil, err
	}
	policy := configaudit.GradleVerification{TrustedArtifacts: len(doc.Trust) > 0, TrustedKeys: len(doc.Keys) > 0}
	reasons := []string{}
	note := func(reason string) {
		if !slices.Contains(reasons, reason) {
			reasons = append(reasons, reason)
		}
	}
	for _, f := range []struct {
		dst **bool
		src *string
	}{{&policy.VerifyMetadata, doc.VerifyMetadata}, {&policy.VerifySignatures, doc.VerifySignatures}} {
		switch v := mavenDeref(f.src); v {
		case "true", "false":
			*f.dst = boolPtr(v == "true")
		case "":
		default:
			note("parse_error")
		}
	}
	// Repeated entries for one artifact file add acceptable checksums, as in
	// Gradle, so they merge into one reference.
	refs, index := []mavenReference{}, map[string]int{}
	for _, c := range doc.Components {
		if reason := cmpOr(mavenCoordinate(c.Group), mavenCoordinate(c.Name)); reason != "" || !mavenVersion(c.Version) {
			note(cmpOr(reason, "parse_error"))
			continue
		}
		for _, a := range c.Artifacts {
			if a.Name == "" || !mavenLabelText(a.Name) {
				note("parse_error")
				continue
			}
			key := strings.Join([]string{c.Group, c.Name, c.Version, a.Name}, ":")
			i, ok := index[key]
			if !ok {
				i, index[key] = len(refs), len(refs)
				refs = append(refs, mavenReference{group: c.Group, artifact: c.Name, version: c.Version, filename: a.Name})
			}
			r := &refs[i]
			for _, set := range []struct {
				algorithm string
				values    []gradleChecksumXML
			}{{"sha256", a.SHA256}, {"sha512", a.SHA512}, {"sha1", a.SHA1}, {"md5", a.MD5}} {
				for _, h := range set.values {
					r.checksum(set.algorithm, h.Value)
					for _, also := range h.AlsoTrust {
						r.checksum(set.algorithm, also.Value)
					}
				}
			}
		}
	}
	return refs, policy, reasons, nil
}

// mavenXMLEnd reads the rest of a document after its root element, which
// may hold only comments, processing instructions and whitespace.
func mavenXMLEnd(dec *xml.Decoder) error {
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return errors.New("second root element")
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return errors.New("text after the root element")
			}
		}
	}
}

// checksum keeps one expected lowercase hex value; anything else is invalid.
func (r *mavenReference) checksum(algorithm, value string) {
	if len(value) != mavenHexLengths[algorithm] || strings.ContainsFunc(value, func(c rune) bool { return !strings.ContainsRune("0123456789abcdef", c) }) {
		r.invalid = true
		return
	}
	h := mavenChecksum{algorithm, value}
	if slices.Contains(r.checksums, h) {
		return
	}
	if len(r.checksums) >= maxMavenChecksums {
		r.limited = true
		return
	}
	r.checksums = append(r.checksums, h)
}
