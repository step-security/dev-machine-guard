package detector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"howett.net/plist"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/model"
)

const (
	maxSwiftMetadataBytes  int64 = 2 << 20
	maxSwiftGitConfigBytes       = 64 << 10
	maxSwiftPlistBytes           = 1 << 20
	maxSwiftSubpathParts         = 16
)

// errSwiftUnsupported marks a well-formed file whose schema version has no
// supported reader.
var errSwiftUnsupported = errors.New("unsupported format")

var swiftSemVer = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// swiftText is a nonempty bounded field value.
func swiftText(s string, limit int) bool { return s != "" && composerText(s, limit) }

// swiftIdentityFromLocation follows SwiftPM's location rule: the last path
// component without a trailing separator or ".git", lowercased. A location
// that cannot be displayed safely, such as one with a query, names nothing,
// and neither does one whose name would come from its credentials, such as a
// URL with userinfo and no path.
func swiftIdentityFromLocation(location string) (string, bool) {
	display, _, ok := configaudit.SwiftURL(location)
	if !ok {
		return "", false
	}
	id := swiftLastComponent(location)
	if id != swiftLastComponent(display) {
		return "", false
	}
	return id, swiftText(id, 512)
}

func swiftLastComponent(location string) string {
	s := strings.TrimRight(location, `/\`)
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	} else if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[i+1:] // SCP-like host:repo
	}
	return strings.ToLower(strings.TrimSuffix(s, ".git"))
}

// swiftOrigin maps a recorded package location. A local file URL or path is
// a path origin whatever its reference kind says; a registry location is the
// package identity, never an endpoint.
func swiftOrigin(kind, location string) (model.SwiftOrigin, string) {
	unknown := model.SwiftOrigin{Kind: "unknown"}
	switch kind {
	case "registry", "root":
		return unknown, ""
	}
	if location == "" {
		return unknown, "origin_unresolved"
	}
	if p, local := composerLocalURL(location, ""); local {
		if configaudit.SwiftAbsPath(p) && composerText(p, 4096) {
			return model.SwiftOrigin{Kind: "path", Path: p}, ""
		}
		return unknown, "origin_unresolved"
	}
	display, _, ok := configaudit.SwiftURL(location)
	if !ok || kind == "fileSystem" || kind == "localSourceControl" {
		return unknown, "origin_unresolved"
	}
	return model.SwiftOrigin{Kind: "git", URL: display}, ""
}

// swiftSubpath validates a recorded relative subpath before it is joined
// under scratch: bounded components, no root, drive, "." or "..".
func swiftSubpath(s string) ([]string, bool) {
	if !swiftText(s, 4096) || configaudit.SwiftAbsPath(s) || strings.Contains(s, ":") {
		return nil, false
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) == 0 || len(parts) > maxSwiftSubpathParts || strings.Count(s, "/")+strings.Count(s, `\`)+1 != len(parts) {
		return nil, false
	}
	for _, p := range parts {
		if p == "." || p == ".." {
			return nil, false
		}
	}
	return parts, true
}

// swiftPin is one resolved-file pin. kind is localSourceControl,
// remoteSourceControl or registry.
type swiftPin struct {
	identity, kind, location, originalLocation string
	version, revision, branch                  string
}

type swiftResolvedState struct {
	Version  *string `json:"version"`
	Branch   *string `json:"branch"`
	Revision *string `json:"revision"`
}

// parseSwiftResolved reads Package.resolved versions 1–3. An invalid or
// duplicate pin is skipped with parse_error; its neighbors are kept.
func parseSwiftResolved(data []byte) ([]swiftPin, []string, error) {
	var doc struct {
		Version *int `json:"version"`
		Object  *struct {
			Pins *[]json.RawMessage `json:"pins"`
		} `json:"object"`
		Pins *[]json.RawMessage `json:"pins"`
	}
	if err := configaudit.SwiftJSON(data, &doc); err != nil || doc.Version == nil {
		return nil, nil, errors.New("invalid resolved file")
	}
	var raw *[]json.RawMessage
	switch *doc.Version {
	case 1:
		if doc.Object != nil {
			raw = doc.Object.Pins
		}
	case 2, 3:
		raw = doc.Pins
	default:
		return nil, nil, errSwiftUnsupported
	}
	if raw == nil {
		return nil, nil, errors.New("missing pins")
	}
	pins, reasons := []swiftPin{}, []string{}
	seen := map[string]bool{}
	for _, r := range *raw {
		pin, ok := swiftResolvedPin(*doc.Version, r)
		if ok && seen[pin.identity] {
			ok = false // SwiftPM rejects a duplicate identity; the first stands.
		}
		if !ok {
			reasons = swiftReason(reasons, "parse_error")
			continue
		}
		seen[pin.identity] = true
		pins = append(pins, pin)
	}
	return pins, reasons, nil
}

func swiftResolvedPin(version int, raw json.RawMessage) (swiftPin, bool) {
	text := func(p *string, limit int) (string, bool) {
		if p == nil {
			return "", true
		}
		return *p, swiftText(*p, limit)
	}
	if version == 1 {
		var p struct {
			RepositoryURL *string             `json:"repositoryURL"`
			State         *swiftResolvedState `json:"state"`
		}
		if configaudit.SwiftJSON(raw, &p) != nil || p.RepositoryURL == nil || p.State == nil || p.State.Revision == nil || !swiftText(*p.RepositoryURL, 4096) {
			return swiftPin{}, false
		}
		id, ok := swiftIdentityFromLocation(*p.RepositoryURL)
		pin := swiftPin{identity: id, kind: "remoteSourceControl", location: *p.RepositoryURL}
		if configaudit.SwiftAbsPath(pin.location) {
			pin.kind = "localSourceControl"
		}
		var okR, okV, okB bool
		pin.revision, okR = text(p.State.Revision, 256)
		pin.version, okV = text(p.State.Version, 256)
		pin.branch, okB = text(p.State.Branch, 256)
		if pin.version != "" {
			pin.branch = "" // a version pin wins over its branch
		}
		return pin, ok && okR && okV && okB
	}
	var p struct {
		Identity         *string             `json:"identity"`
		Kind             *string             `json:"kind"`
		Location         *string             `json:"location"`
		OriginalLocation *string             `json:"originalLocation"`
		State            *swiftResolvedState `json:"state"`
	}
	if configaudit.SwiftJSON(raw, &p) != nil || p.Identity == nil || p.Kind == nil || p.Location == nil || p.State == nil {
		return swiftPin{}, false
	}
	pin := swiftPin{identity: strings.ToLower(*p.Identity), kind: *p.Kind, location: *p.Location}
	switch pin.kind {
	case "localSourceControl":
		if !configaudit.SwiftAbsPath(pin.location) {
			return swiftPin{}, false
		}
	case "remoteSourceControl":
		if pin.location == "" {
			return swiftPin{}, false
		}
	case "registry":
	default:
		return swiftPin{}, false
	}
	var okO, okR, okV, okB bool
	pin.originalLocation, okO = text(p.OriginalLocation, 4096)
	pin.revision, okR = text(p.State.Revision, 256)
	pin.version, okV = text(p.State.Version, 256)
	pin.branch, okB = text(p.State.Branch, 256)
	switch {
	case pin.version != "":
		pin.branch = ""
	case pin.revision != "":
	default:
		return swiftPin{}, false // a branch needs its revision; no state is invalid
	}
	ok := swiftText(pin.identity, 512) && composerText(pin.location, 4096)
	return pin, ok && okO && okR && okV && okB
}

// swiftDependency is one managed dependency. state is checkout | registry |
// filesystem | edited | custom; path is the explicit state path.
type swiftDependency struct {
	identity, refKind, location string
	state, path, subpath        string
	version, revision, branch   string
	scmURL                      string
	basedOn                     *model.SwiftBasedOn
}

// swiftManagedArtifact is one binary artifact record. kind is xcframework |
// artifact_archive | unknown.
type swiftManagedArtifact struct {
	identity, refKind, location string
	target, kind, url, checksum string
	path                        string
}

type swiftWorkspaceRef struct {
	Identity *string `json:"identity"`
	Kind     *string `json:"kind"`
	Location *string `json:"location"`
	Path     *string `json:"path"` // legacy spelling of location
}

// parseSwiftWorkspace reads workspace-state.json versions 4–7. Versions 1–3
// and later versions have no authentic fixtures and stay unsupported. An
// invalid record is skipped with parse_error; prebuilts are not packages.
func parseSwiftWorkspace(data []byte) ([]swiftDependency, []swiftManagedArtifact, []string, error) {
	var doc struct {
		Version *int `json:"version"`
		Object  *struct {
			Dependencies *[]json.RawMessage `json:"dependencies"`
			Artifacts    *[]json.RawMessage `json:"artifacts"`
			Prebuilts    []json.RawMessage  `json:"prebuilts"`
		} `json:"object"`
	}
	if err := configaudit.SwiftJSON(data, &doc); err != nil || doc.Version == nil {
		return nil, nil, nil, errors.New("invalid workspace state")
	}
	v := *doc.Version
	if v < 4 || v > 7 {
		return nil, nil, nil, errSwiftUnsupported
	}
	if doc.Object == nil || doc.Object.Dependencies == nil || doc.Object.Artifacts == nil {
		return nil, nil, nil, errors.New("missing object")
	}
	deps, artifacts, reasons := []swiftDependency{}, []swiftManagedArtifact{}, []string{}
	if len(doc.Object.Prebuilts) > 0 {
		// Prebuilt binaries are not inventoried, so their state is not covered.
		reasons = swiftReason(reasons, "unsupported_format")
	}
	for _, raw := range *doc.Object.Dependencies {
		if d, ok := swiftWorkspaceDependency(v, raw, true); ok {
			deps = append(deps, d)
		} else {
			reasons = swiftReason(reasons, "parse_error")
		}
	}
	for _, raw := range *doc.Object.Artifacts {
		a, reason := swiftWorkspaceArtifact(v, raw)
		if reason != "" {
			reasons = swiftReason(reasons, reason)
		}
		if reason != "parse_error" {
			artifacts = append(artifacts, a)
		}
	}
	return deps, artifacts, reasons, nil
}

// swiftRef normalizes a package reference to the modern kinds. Version 4
// spelled them root | local | remote, where a remote at an absolute path is
// a local repository.
func swiftRef(version int, r *swiftWorkspaceRef) (identity, kind, location string, ok bool) {
	if r == nil || r.Identity == nil || r.Kind == nil {
		return "", "", "", false
	}
	switch {
	case r.Location != nil:
		location = *r.Location
	case version == 4 && r.Path != nil:
		location = *r.Path
	default:
		return "", "", "", false
	}
	identity, kind = strings.ToLower(*r.Identity), *r.Kind
	if version == 4 {
		switch kind {
		case "root":
		case "local":
			kind = "fileSystem"
		case "remote":
			kind = "remoteSourceControl"
			if configaudit.SwiftAbsPath(location) {
				kind = "localSourceControl"
			}
		default:
			return "", "", "", false
		}
	}
	switch kind {
	case "root", "fileSystem", "localSourceControl":
		ok = configaudit.SwiftAbsPath(location)
	case "remoteSourceControl":
		ok = location != ""
	case "registry":
		ok = true
	}
	return identity, kind, location, ok && swiftText(identity, 512) && composerText(location, 4096)
}

func swiftWorkspaceDependency(version int, raw json.RawMessage, top bool) (swiftDependency, bool) {
	var d struct {
		PackageRef *swiftWorkspaceRef `json:"packageRef"`
		State      *struct {
			Name     *string             `json:"name"`
			Path     *string             `json:"path"`
			Version  *string             `json:"version"`
			ScmURL   *string             `json:"scmUrl"`
			Checkout *swiftResolvedState `json:"checkoutState"`
		} `json:"state"`
		Subpath *string         `json:"subpath"`
		BasedOn json.RawMessage `json:"basedOn"`
	}
	if configaudit.SwiftJSON(raw, &d) != nil || d.State == nil || d.State.Name == nil || d.Subpath == nil || top && d.BasedOn == nil {
		return swiftDependency{}, false
	}
	identity, kind, location, ok := swiftRef(version, d.PackageRef)
	if !ok || kind == "root" {
		return swiftDependency{}, false
	}
	dep := swiftDependency{identity: identity, refKind: kind, location: location, subpath: *d.Subpath}
	str := func(p *string, limit int, required bool) (string, bool) {
		if p == nil {
			return "", !required
		}
		return *p, swiftText(*p, limit)
	}
	valid := true
	check := func(v string, ok bool) string {
		valid = valid && ok
		return v
	}
	switch name := *d.State.Name; {
	case name == "local" && version == 4:
		dep.state, dep.path = "filesystem", location
	case name == "local", name == "fileSystem" && version > 4:
		dep.state = "filesystem"
		dep.path = check(str(d.State.Path, 4096, true))
	case name == "checkout", name == "sourceControlCheckout" && version > 4:
		c := d.State.Checkout
		if c == nil || c.Revision == nil {
			return swiftDependency{}, false
		}
		dep.state = "checkout"
		dep.revision = check(str(c.Revision, 256, true))
		dep.branch = check(str(c.Branch, 256, false))
		dep.version = check(str(c.Version, 256, false))
		if dep.branch != "" {
			dep.version = "" // SwiftPM restores a branch checkout first
		}
	case name == "registryDownload" && version > 4:
		dep.state = "registry"
		dep.version = check(str(d.State.Version, 256, true))
		dep.scmURL = check(str(d.State.ScmURL, 4096, false))
	case name == "edited":
		dep.state = "edited"
		dep.path = check(str(d.State.Path, 4096, false))
		if top && !bytes.Equal(bytes.TrimSpace(d.BasedOn), []byte("null")) {
			// Only the historical release fields of the base are kept.
			if base, ok := swiftWorkspaceDependency(version, d.BasedOn, false); ok {
				dep.basedOn = &model.SwiftBasedOn{Version: base.version, Revision: base.revision, Branch: base.branch}
			} else {
				return swiftDependency{}, false
			}
		}
	case name == "custom" && version > 4:
		dep.state = "custom"
		dep.version = check(str(d.State.Version, 256, true))
		dep.path = check(str(d.State.Path, 4096, true))
	default:
		return swiftDependency{}, false
	}
	if dep.path != "" && !configaudit.SwiftAbsPath(dep.path) {
		return swiftDependency{}, false
	}
	return dep, valid
}

// swiftWorkspaceArtifact returns parse_error for a record it cannot keep,
// and unsupported_format for a kept record whose kind is not recognized.
func swiftWorkspaceArtifact(version int, raw json.RawMessage) (swiftManagedArtifact, string) {
	var a struct {
		PackageRef *swiftWorkspaceRef `json:"packageRef"`
		TargetName *string            `json:"targetName"`
		Source     *struct {
			Type     *string `json:"type"`
			URL      *string `json:"url"`
			Checksum *string `json:"checksum"`
		} `json:"source"`
		Path *string         `json:"path"`
		Kind json.RawMessage `json:"kind"`
	}
	if configaudit.SwiftJSON(raw, &a) != nil || a.TargetName == nil || a.Source == nil || a.Source.Type == nil || a.Path == nil {
		return swiftManagedArtifact{}, "parse_error"
	}
	identity, kind, location, ok := swiftRef(version, a.PackageRef)
	if !ok || !swiftText(*a.TargetName, 256) || !configaudit.SwiftAbsPath(*a.Path) || !composerText(*a.Path, 4096) {
		return swiftManagedArtifact{}, "parse_error"
	}
	out := swiftManagedArtifact{identity: identity, refKind: kind, location: location, target: *a.TargetName, path: *a.Path}
	switch *a.Source.Type {
	case "local":
	case "remote":
		if a.Source.URL == nil || a.Source.Checksum == nil || !swiftText(*a.Source.URL, 4096) {
			return swiftManagedArtifact{}, "parse_error"
		}
		out.url = *a.Source.URL
	default:
		return swiftManagedArtifact{}, "parse_error"
	}
	if a.Source.Checksum != nil {
		out.checksum = *a.Source.Checksum
	}
	reason := ""
	out.kind, reason = swiftArtifactKind(version, a.Kind, out.path)
	return out, reason
}

// swiftArtifactKind reads the recorded kind: absent before version 6, a
// string in 6 and 7, or a Swift enum object in later 7 writers.
func swiftArtifactKind(version int, raw json.RawMessage, path string) (string, string) {
	if version < 6 {
		switch strings.ToLower(filepath.Ext(strings.TrimRight(path, `/\`))) {
		case ".xcframework":
			return "xcframework", ""
		case ".artifactbundle":
			return "artifact_archive", ""
		}
		return "unknown", ""
	}
	var name string
	if json.Unmarshal(raw, &name) != nil {
		var object map[string]json.RawMessage
		if version < 7 || json.Unmarshal(raw, &object) != nil || len(object) != 1 {
			return "unknown", "unsupported_format"
		}
		for k := range object {
			name = k
		}
	}
	switch name {
	case "xcframework":
		return "xcframework", ""
	case "artifactsArchive", "typedArtifactsArchive":
		return "artifact_archive", ""
	case "unknown":
		return "unknown", ""
	}
	return "unknown", "unsupported_format"
}

// parseSwiftReceipt reads only the registry URL from a .registry-metadata
// receipt; author, signature and source-control links are ignored.
func parseSwiftReceipt(data []byte) (string, error) {
	var r struct {
		Registry *string `json:"registry"`
	}
	if err := configaudit.SwiftJSON(data, &r); err != nil || r.Registry == nil || *r.Registry == "" {
		return "", errors.New("invalid receipt")
	}
	return *r.Registry, nil
}

// parseSwiftInfoPlist reads DerivedData's WorkspacePath; other keys are ignored.
func parseSwiftInfoPlist(data []byte) (string, error) {
	var info struct {
		WorkspacePath string `plist:"WorkspacePath"`
	}
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return "", err
	}
	return info.WorkspacePath, nil
}

// parseSwiftGitConfig reads a bare cache repository's literal core.bare and
// remote "origin" url. Includes are not followed. ok is false for more than
// one origin url.
func parseSwiftGitConfig(data []byte) (bare bool, origin string, ok bool) {
	if len(data) > maxSwiftGitConfigBytes {
		return false, "", false
	}
	section, sub := "", ""
	origins := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxSwiftGitConfigBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				return false, "", false
			}
			header := strings.TrimSpace(line[1:end])
			section, sub = strings.ToLower(header), ""
			if name, quoted, found := strings.Cut(header, " "); found {
				section = strings.ToLower(name)
				q := strings.TrimSpace(quoted)
				if len(q) < 2 || q[0] != '"' || q[len(q)-1] != '"' {
					return false, "", false
				}
				sub = strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(q[1 : len(q)-1])
			}
			if line = strings.TrimSpace(line[end+1:]); line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
		}
		key, value, hasValue := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value, valid := swiftGitValue(value)
		if !valid {
			return false, "", false
		}
		switch {
		case section == "core" && sub == "" && key == "bare":
			v := strings.ToLower(value)
			bare = !hasValue || v == "true" || v == "yes" || v == "on" || v == "1"
		case section == "remote" && sub == "origin" && key == "url":
			origins++
			origin = value
		}
	}
	if sc.Err() != nil || origins > 1 {
		return false, "", false
	}
	return bare, origin, true
}

// swiftGitValue unquotes a git config value and drops a trailing comment.
func swiftGitValue(s string) (string, bool) {
	var b strings.Builder
	quoted := false
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			quoted = !quoted
		case c == '\\':
			i++
			if i >= len(s) {
				return "", false
			}
			switch s[i] {
			case '"', '\\':
				b.WriteByte(s[i])
			case 't':
				b.WriteByte('\t')
			case 'n':
				b.WriteByte('\n')
			default:
				return "", false
			}
		case !quoted && (c == '#' || c == ';'):
			return strings.TrimSpace(b.String()), true
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String()), !quoted
}

func swiftVersion(s string) bool { return len(s) <= 256 && swiftSemVer.MatchString(s) }

func swiftReason(reasons []string, reason string) []string {
	if slices.Contains(reasons, reason) {
		return reasons
	}
	return append(reasons, reason)
}
