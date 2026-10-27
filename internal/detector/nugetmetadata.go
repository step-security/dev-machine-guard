package detector

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/model"
)

var (
	maxNuGetMetadataBytes int64 = 2 << 20
	maxNuGetArchiveBytes  int64 = 32 << 20
)

var errNuGetUnsupportedFormat = errors.New("unsupported metadata format")

// nugetPackageID is NuGet's documented ID syntax; comparison is case-insensitive.
var nugetPackageID = regexp.MustCompile(`^\w+([.-]\w+)*$`)

func nugetID(raw string) (string, bool) {
	if len(raw) > 100 || !nugetPackageID.MatchString(raw) {
		return "", false
	}
	return strings.ToLower(raw), true
}

// nugetNormalizeVersion is the comparison identity of an exact NuGet version:
// 1-4 numeric parts without leading zeros, padded to three, a zero fourth
// part dropped, build metadata removed and the prerelease label lowercased.
// Ranges and floating requests are not exact versions.
func nugetNormalizeVersion(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 256 || strings.ContainsAny(raw, " \t[](),*") {
		return "", false
	}
	core, _, _ := strings.Cut(raw, "+")
	core, pre, hasPre := strings.Cut(core, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 4 {
		return "", false
	}
	for i, p := range parts {
		if p == "" || len(p) > 18 || strings.ContainsFunc(p, func(r rune) bool { return r < '0' || r > '9' }) {
			return "", false
		}
		if parts[i] = strings.TrimLeft(p, "0"); parts[i] == "" {
			parts[i] = "0"
		}
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	if len(parts) == 4 && parts[3] == "0" {
		parts = parts[:3]
	}
	out := strings.Join(parts, ".")
	if !hasPre {
		return out, true
	}
	if pre == "" {
		return "", false
	}
	for ident := range strings.SplitSeq(pre, ".") {
		if ident == "" || strings.ContainsFunc(ident, func(r rune) bool {
			return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-')
		}) {
			return "", false
		}
		// Numeric identifiers with leading zeros are invalid; alpha01 is fine.
		if len(ident) > 1 && ident[0] == '0' && !strings.ContainsFunc(ident, func(r rune) bool { return r < '0' || r > '9' }) {
			return "", false
		}
	}
	return out + "-" + strings.ToLower(pre), true
}

func nugetText(s string, limit int) bool { return composerText(s, limit) }

func newNuGetPackage(rawID string) model.NuGetPackage {
	id, _ := nugetID(rawID)
	return model.NuGetPackage{
		PackageName: id, DisplayName: rawID, DependencyRelation: "unknown", VersionStatus: "unknown",
		Reasons: []string{}, Origin: model.NuGetOrigin{Kind: "unknown"}, ChecksumStatus: "not_recorded",
		RecordedChecksums: []model.NuGetRecordedChecksum{},
	}
}

// nugetExact fills the exact version fields of a resolved or receipt record.
func nugetExact(p *model.NuGetPackage, version string) bool {
	normalized, ok := nugetNormalizeVersion(version)
	if !ok {
		return false
	}
	p.Version, p.VersionNormalized, p.VersionStatus = version, normalized, "known"
	return true
}

// nugetContentHash validates a recorded base64 SHA-512 and records its kind.
func nugetContentHash(p *model.NuGetPackage, kind, value string) {
	if value == "" {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 64 {
		p.ChecksumStatus = "partial"
		p.Reasons = append(p.Reasons, "checksum_invalid")
		return
	}
	if p.ChecksumStatus == "not_recorded" {
		p.ChecksumStatus = "recorded"
	}
	p.RecordedChecksums = append(p.RecordedChecksums, model.NuGetRecordedChecksum{Kind: kind, Algorithm: "sha512", Value: value, Verification: "recorded"})
}

// nugetXML returns a strict decoder for bounded UTF-8 XML. A DOCTYPE is
// rejected outright: no entity or external resolution ever happens.
func nugetXML(data []byte) (*xml.Decoder, error) {
	if !utf8.Valid(data) || int64(len(data)) > maxNuGetMetadataBytes {
		return nil, errors.New("invalid metadata")
	}
	if bytes.Contains(bytes.ToUpper(data), []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
		return nil, errors.New("document type declarations are not supported")
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	dec.Entity = map[string]string{}
	return dec, nil
}

// nugetXMLText returns the trimmed text of the first element reached through
// the given local-name path from the root, ignoring namespaces.
func nugetXMLText(data []byte, want ...string) (string, error) {
	dec, err := nugetXML(data)
	if err != nil {
		return "", err
	}
	depth, matched := 0, 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == matched && matched < len(want) && t.Name.Local == want[matched] {
				matched++
				if matched == len(want) {
					var text string
					if err := dec.DecodeElement(&text, &t); err != nil {
						return "", err
					}
					return strings.TrimSpace(text), nil
				}
			}
			depth++
		case xml.EndElement:
			depth--
			if depth < matched {
				matched = depth
			}
		}
	}
}

// nugetAttr reads one attribute by local name.
func nugetAttr(e xml.StartElement, name string) (string, bool) {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return strings.TrimSpace(a.Value), true
		}
	}
	return "", false
}

type nugetItem struct {
	kind                                        string // PackageReference | PackageVersion | GlobalPackageReference | PackageDownload
	id, version, versionOverride                string
	privateAssets, includeAssets, excludeAssets string
	conditional                                 bool
}

// nugetProjectFile is a literal read of MSBuild XML, never an evaluation.
// Properties keep the last unconditional value; conditional ones are noted.
type nugetProjectFile struct {
	properties  map[string]string
	conditional map[string]bool
	items       []nugetItem
	sdks        []nugetItem // msbuild_sdk declarations with explicit versions
	imports     bool        // an explicit Import leaves the context unresolved
}

var nugetProjectProperties = []string{
	"TargetFramework", "TargetFrameworks", "RuntimeIdentifier", "RuntimeIdentifiers", "RestorePackagesPath",
	"RestoreFallbackFolders", "RestoreAdditionalProjectFallbackFolders", "NuGetLockFilePath", "RestoreLockedMode",
	"NuGetAudit", "NuGetAuditMode", "NuGetAuditLevel", "ManagePackageVersionsCentrally",
	"MSBuildProjectExtensionsPath", "BaseIntermediateOutputPath", "UseArtifactsOutput", "ArtifactsPath",
	"ArtifactsProjectName", "IncludeProjectNameInArtifactsPaths", "UseArtifactsIntermediateOutput",
}

// parseNuGetProject reads project, Directory.Packages.props and similar
// MSBuild files. Conditions are observed as a flag; their text is not kept.
func parseNuGetProject(data []byte) (*nugetProjectFile, error) {
	dec, err := nugetXML(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if err != nil {
		return nil, err
	}
	f := &nugetProjectFile{properties: map[string]string{}, conditional: map[string]bool{}}
	type frame struct {
		name        string
		conditional bool
		item        *nugetItem
	}
	rootSeen := false
	var stack []frame
	addSDK := func(spec string, conditional bool) {
		for entry := range strings.SplitSeq(spec, ";") {
			name, version, ok := strings.Cut(strings.TrimSpace(entry), "/")
			if ok && name != "" && version != "" {
				f.sdks = append(f.sdks, nugetItem{kind: "msbuild_sdk", id: name, version: version, conditional: conditional})
			}
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) == 0 {
				if rootSeen || t.Name.Local != "Project" {
					return nil, errors.New("expected one Project root")
				}
				rootSeen = true
			}
			cond, hasCond := nugetAttr(t, "Condition")
			conditional := hasCond && cond != "" || len(stack) > 0 && stack[len(stack)-1].conditional
			fr := frame{name: t.Name.Local, conditional: conditional}
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1].name
			}
			switch {
			case len(stack) == 0 && t.Name.Local == "Project":
				if sdk, ok := nugetAttr(t, "Sdk"); ok {
					addSDK(sdk, false)
				}
			case t.Name.Local == "Sdk" && parent == "Project":
				name, _ := nugetAttr(t, "Name")
				if version, ok := nugetAttr(t, "Version"); ok && name != "" && version != "" {
					f.sdks = append(f.sdks, nugetItem{kind: "msbuild_sdk", id: name, version: version, conditional: conditional})
				}
			case t.Name.Local == "Import":
				if sdk, ok := nugetAttr(t, "Sdk"); ok {
					addSDK(sdk, conditional)
				} else {
					f.imports = true
				}
			case parent == "PropertyGroup" && slices.Contains(nugetProjectProperties, t.Name.Local):
				var text string
				if err := dec.DecodeElement(&text, &t); err != nil {
					return nil, err
				}
				if conditional {
					f.conditional[t.Name.Local] = true
				} else {
					f.properties[t.Name.Local] = strings.TrimSpace(text)
				}
				continue
			case parent == "ItemGroup" && (t.Name.Local == "PackageReference" || t.Name.Local == "PackageVersion" || t.Name.Local == "GlobalPackageReference" || t.Name.Local == "PackageDownload"):
				item := &nugetItem{kind: t.Name.Local, conditional: conditional}
				item.id, _ = nugetAttr(t, "Include")
				if item.id == "" {
					item.id, _ = nugetAttr(t, "Update")
				}
				item.version, _ = nugetAttr(t, "Version")
				item.versionOverride, _ = nugetAttr(t, "VersionOverride")
				item.privateAssets, _ = nugetAttr(t, "PrivateAssets")
				item.includeAssets, _ = nugetAttr(t, "IncludeAssets")
				item.excludeAssets, _ = nugetAttr(t, "ExcludeAssets")
				fr.item = item
			case len(stack) > 0 && stack[len(stack)-1].item != nil:
				item := stack[len(stack)-1].item
				item.conditional = item.conditional || conditional
				var text string
				if err := dec.DecodeElement(&text, &t); err != nil {
					return nil, err
				}
				text = strings.TrimSpace(text)
				switch t.Name.Local {
				case "Version":
					item.version = text
				case "VersionOverride":
					item.versionOverride = text
				case "PrivateAssets":
					item.privateAssets = text
				case "IncludeAssets":
					item.includeAssets = text
				case "ExcludeAssets":
					item.excludeAssets = text
				}
				continue
			}
			stack = append(stack, fr)
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(t)) != 0 {
				return nil, errors.New("text outside Project root")
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unbalanced element")
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if top.item != nil && top.item.id != "" {
				f.items = append(f.items, *top.item)
			}
		}
	}
	if !rootSeen {
		return nil, errors.New("missing Project root")
	}
	return f, nil
}

// nugetUnresolved reports an MSBuild value that needs evaluation.
func nugetUnresolved(value string) bool {
	return strings.Contains(value, "$(") || strings.Contains(value, "@(") || strings.Contains(value, "%(")
}

type nugetLegacyEntry struct {
	id, version, targetFramework, allowedVersions string
	developmentDependency                         *bool
}

func parseNuGetPackagesConfig(data []byte) ([]nugetLegacyEntry, bool, error) {
	dec, err := nugetXML(data)
	if err != nil {
		return nil, false, err
	}
	var doc struct {
		XMLName  xml.Name `xml:"packages"`
		Packages []struct {
			ID                    string `xml:"id,attr"`
			Version               string `xml:"version,attr"`
			TargetFramework       string `xml:"targetFramework,attr"`
			AllowedVersions       string `xml:"allowedVersions,attr"`
			DevelopmentDependency string `xml:"developmentDependency,attr"`
		} `xml:"package"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, false, err
	}
	var out []nugetLegacyEntry
	partial := false
	for _, p := range doc.Packages {
		if _, ok := nugetID(p.ID); !ok {
			partial = true
			continue
		}
		e := nugetLegacyEntry{id: p.ID, version: p.Version, targetFramework: p.TargetFramework, allowedVersions: p.AllowedVersions}
		switch strings.ToLower(p.DevelopmentDependency) {
		case "true":
			e.developmentDependency = new(bool)
			*e.developmentDependency = true
		case "false":
			e.developmentDependency = new(bool)
		}
		out = append(out, e)
	}
	return out, partial, nil
}

// parseNuGetNuspec reads the package identity; every other member is ignored.
func parseNuGetNuspec(data []byte) (id, version string, err error) {
	if id, err = nugetXMLText(data, "package", "metadata", "id"); err != nil {
		return "", "", err
	}
	if version, err = nugetXMLText(data, "package", "metadata", "version"); err != nil {
		return "", "", err
	}
	if _, ok := nugetID(id); !ok || version == "" {
		return "", "", errors.New("missing package identity")
	}
	return id, version, nil
}

// nugetArchiveNuspec returns the single root .nuspec member of a .nupkg, read
// without extracting anything else. Unsafe member names reject the archive.
func nugetArchiveNuspec(data []byte) ([]byte, string) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, "parse_error"
	}
	var nuspec *zip.File
	seen := map[string]bool{}
	for i, f := range zr.File {
		if i >= maxGoZipEntries {
			return nil, "entry_limit"
		}
		name := strings.TrimSuffix(f.Name, "/")
		if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") || seen[name] {
			return nil, "parse_error"
		}
		seen[name] = true
		if !strings.Contains(name, "/") && strings.HasSuffix(strings.ToLower(name), ".nuspec") {
			if nuspec != nil {
				return nil, "parse_error"
			}
			nuspec = f
		}
	}
	if nuspec == nil {
		return nil, "unsupported_format"
	}
	if nuspec.UncompressedSize64 > uint64(maxNuGetMetadataBytes) { // #nosec G115 -- the cap is a positive byte count
		return nil, "size_limit"
	}
	rc, err := nuspec.Open()
	if err != nil {
		return nil, "parse_error"
	}
	defer rc.Close()
	out, err := io.ReadAll(io.LimitReader(rc, maxNuGetMetadataBytes+1))
	if err != nil || int64(len(out)) > maxNuGetMetadataBytes {
		return nil, "size_limit"
	}
	return out, ""
}

// nugetObject decodes a bounded JSON object, isolating malformed members.
func nugetObject(data []byte) (map[string]json.RawMessage, error) {
	if int64(len(data)) > maxNuGetMetadataBytes {
		return nil, errors.New("invalid metadata")
	}
	return composerObject(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
}

func nugetString(raw json.RawMessage, limit int) (string, bool) { return composerString(raw, limit) }

// nugetLibrary splits a "Id/Version" graph key.
func nugetLibrary(key string) (id, version string, ok bool) {
	id, version, ok = strings.Cut(key, "/")
	if !ok || version == "" {
		return "", "", false
	}
	_, ok = nugetID(id)
	return id, version, ok
}

type nugetTargetPackage struct {
	id, version string
}

type nugetTarget struct {
	alias, framework, rid string
	packages              []nugetTargetPackage
}

type nugetAssets struct {
	version    int
	libraries  map[string]nugetAssetsLibrary // lowercase "id/version"
	targets    []nugetTarget
	direct     map[string]map[string]bool // alias → lowercase direct IDs
	hasProject bool
	folders    []string // packageFolders, primary first
	restore    nugetRestore
	partial    bool
}

type nugetAssetsLibrary struct {
	id, version, sha512, path string
}

type nugetRestore struct {
	projectPath, packagesPath string
	configFilePaths, fallback []string
}

// parseNuGetAssets reads schema 3 and 4 restore graphs, including the
// minimal tool-store receipt whose libraries map is empty.
func parseNuGetAssets(data []byte) (*nugetAssets, error) {
	obj, err := nugetObject(data)
	if err != nil {
		return nil, err
	}
	a := &nugetAssets{libraries: map[string]nugetAssetsLibrary{}, direct: map[string]map[string]bool{}}
	if json.Unmarshal(obj["version"], &a.version) != nil || a.version < 3 || a.version > 4 {
		return nil, errNuGetUnsupportedFormat
	}
	var libraries map[string]json.RawMessage
	if obj["libraries"] == nil || json.Unmarshal(obj["libraries"], &libraries) != nil {
		return nil, errNuGetUnsupportedFormat
	}
	for key, raw := range libraries {
		id, version, ok := nugetLibrary(key)
		entry, err := composerObject(raw)
		if !ok || err != nil {
			a.partial = true
			continue
		}
		typ, _ := nugetString(entry["type"], 64)
		if typ != "package" {
			continue
		}
		lib := nugetAssetsLibrary{id: id, version: version}
		var okHash, okPath bool
		lib.sha512, okHash = nugetString(entry["sha512"], 256)
		lib.path, okPath = nugetString(entry["path"], 4096)
		if !okHash || !okPath {
			a.partial = true
		}
		a.libraries[strings.ToLower(key)] = lib
	}
	frameworks := map[string]string{}
	if project := obj["project"]; project != nil {
		p, err := composerObject(project)
		if err != nil {
			a.partial = true
		} else {
			a.hasProject = true
			a.parseRestore(p)
			var fws map[string]json.RawMessage
			if p["frameworks"] != nil && json.Unmarshal(p["frameworks"], &fws) == nil {
				for alias, raw := range fws {
					fw, err := composerObject(raw)
					if err != nil {
						a.partial = true
						continue
					}
					if name, ok := nugetString(fw["framework"], 256); ok && name != "" {
						frameworks[alias] = name
					} else if ok {
						frameworks[alias] = alias
					}
					if name, ok := nugetString(fw["targetAlias"], 256); ok && name != "" && name != alias {
						a.partial = true
					}
					direct := map[string]bool{}
					var deps map[string]json.RawMessage
					if fw["dependencies"] != nil && json.Unmarshal(fw["dependencies"], &deps) == nil {
						for id := range deps {
							direct[strings.ToLower(id)] = true
						}
					}
					a.direct[alias] = direct
				}
			}
		}
	}
	var targets map[string]json.RawMessage
	if obj["targets"] == nil || json.Unmarshal(obj["targets"], &targets) != nil {
		return nil, errNuGetUnsupportedFormat
	}
	// Schema 3 keys targets by framework name rather than alias; map a unique
	// name back to the project framework it belongs to.
	byName := map[string]string{}
	for alias, name := range frameworks {
		if _, dup := byName[name]; dup {
			byName[name] = ""
		} else {
			byName[name] = alias
		}
	}
	for _, key := range slices.Sorted(maps.Keys(targets)) {
		alias, rid, _ := strings.Cut(key, "/")
		t := nugetTarget{alias: alias, framework: frameworks[alias], rid: rid}
		if t.framework == "" {
			t.framework = alias
		}
		if _, known := frameworks[alias]; !known && a.hasProject {
			t.alias, t.framework = byName[alias], alias
		}
		var entries map[string]json.RawMessage
		if json.Unmarshal(targets[key], &entries) != nil {
			a.partial = true
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(entries)) {
			id, version, ok := nugetLibrary(name)
			entry, err := composerObject(entries[name])
			if !ok || err != nil {
				a.partial = true
				continue
			}
			if typ, _ := nugetString(entry["type"], 64); typ == "package" {
				t.packages = append(t.packages, nugetTargetPackage{id: id, version: version})
			}
		}
		a.targets = append(a.targets, t)
	}
	if obj["packageFolders"] != nil {
		var folders map[string]json.RawMessage
		if json.Unmarshal(obj["packageFolders"], &folders) != nil {
			a.partial = true
		} else {
			// Object order is the restore's probe order; the decoder keeps it.
			dec := json.NewDecoder(bytes.NewReader(obj["packageFolders"]))
			if tok, err := dec.Token(); err == nil && tok == json.Delim('{') {
				for dec.More() {
					key, err := dec.Token()
					if err != nil {
						break
					}
					var skip json.RawMessage
					if dec.Decode(&skip) != nil {
						break
					}
					if folder, ok := key.(string); ok && nugetText(folder, 4096) {
						a.folders = append(a.folders, folder)
					}
				}
			}
		}
	}
	return a, nil
}

func (a *nugetAssets) parseRestore(project map[string]json.RawMessage) {
	if project["restore"] == nil {
		return
	}
	r, err := composerObject(project["restore"])
	if err != nil {
		a.partial = true
		return
	}
	var ok bool
	if a.restore.projectPath, ok = nugetString(r["projectPath"], 4096); !ok {
		a.partial = true
	}
	if a.restore.packagesPath, ok = nugetString(r["packagesPath"], 4096); !ok {
		a.partial = true
	}
	for _, field := range []struct {
		key  string
		dest *[]string
	}{{"configFilePaths", &a.restore.configFilePaths}, {"fallbackFolders", &a.restore.fallback}} {
		if r[field.key] == nil {
			continue
		}
		var list []string
		if json.Unmarshal(r[field.key], &list) != nil {
			a.partial = true
			continue
		}
		for _, p := range list {
			if nugetText(p, 4096) {
				*field.dest = append(*field.dest, p)
			} else {
				a.partial = true
			}
		}
	}
}

type nugetLockEntry struct {
	id, requested, resolved, typ, contentHash, alias, framework string
}

// parseNuGetLock reads packages.lock.json versions 1-3. Project entries are
// not packages and are skipped.
func parseNuGetLock(data []byte) ([]nugetLockEntry, bool, error) {
	obj, err := nugetObject(data)
	if err != nil {
		return nil, false, err
	}
	var version int
	if json.Unmarshal(obj["version"], &version) != nil || version < 1 || version > 3 {
		return nil, false, errNuGetUnsupportedFormat
	}
	type group struct {
		alias, framework string
		deps             json.RawMessage
	}
	var groups []group
	partial := false
	if version == 3 {
		for _, alias := range slices.Sorted(maps.Keys(obj)) {
			if alias == "version" {
				continue
			}
			g, err := composerObject(obj[alias])
			if err != nil {
				partial = true
				continue
			}
			framework, _ := nugetString(g["framework"], 256)
			groups = append(groups, group{alias: alias, framework: framework, deps: g["dependencies"]})
		}
	} else {
		var frameworks map[string]json.RawMessage
		if obj["dependencies"] == nil || json.Unmarshal(obj["dependencies"], &frameworks) != nil {
			return nil, false, errNuGetUnsupportedFormat
		}
		for _, framework := range slices.Sorted(maps.Keys(frameworks)) {
			groups = append(groups, group{framework: framework, deps: frameworks[framework]})
		}
	}
	var out []nugetLockEntry
	for _, g := range groups {
		var deps map[string]json.RawMessage
		if g.deps == nil || json.Unmarshal(g.deps, &deps) != nil {
			partial = true
			continue
		}
		for _, id := range slices.Sorted(maps.Keys(deps)) {
			entry, err := composerObject(deps[id])
			if _, ok := nugetID(id); !ok || err != nil {
				partial = true
				continue
			}
			typ, _ := nugetString(entry["type"], 64)
			if typ == "Project" {
				continue
			}
			e := nugetLockEntry{id: id, typ: typ, alias: g.alias, framework: g.framework}
			var okReq, okRes, okHash bool
			e.requested, okReq = nugetString(entry["requested"], 256)
			e.resolved, okRes = nugetString(entry["resolved"], 256)
			e.contentHash, okHash = nugetString(entry["contentHash"], 256)
			if !okReq || !okRes || !okHash || e.resolved == "" || (typ != "Direct" && typ != "Transitive" && typ != "CentralTransitive") {
				partial = true
				continue
			}
			out = append(out, e)
		}
	}
	return out, partial, nil
}

// parseNuGetMarker reads .nupkg.metadata versions 1 and 2; only v2 records
// the download source.
func parseNuGetMarker(data []byte) (contentHash, source string, err error) {
	obj, err := nugetObject(data)
	if err != nil {
		return "", "", err
	}
	var version int
	if json.Unmarshal(obj["version"], &version) != nil || version < 1 || version > 2 {
		return "", "", errNuGetUnsupportedFormat
	}
	var ok bool
	if contentHash, ok = nugetString(obj["contentHash"], 256); !ok || contentHash == "" {
		return "", "", errors.New("missing content hash")
	}
	if source, ok = nugetString(obj["source"], 4096); !ok {
		return "", "", errors.New("invalid source")
	}
	return contentHash, source, nil
}

type nugetToolEntry struct {
	id, version string
	commands    []string
}

func parseNuGetToolManifest(data []byte) ([]nugetToolEntry, bool, error) {
	obj, err := nugetObject(data)
	if err != nil {
		return nil, false, err
	}
	var version int
	if json.Unmarshal(obj["version"], &version) != nil || version != 1 {
		return nil, false, errNuGetUnsupportedFormat
	}
	var tools map[string]json.RawMessage
	if obj["tools"] == nil || json.Unmarshal(obj["tools"], &tools) != nil {
		return nil, false, errNuGetUnsupportedFormat
	}
	var out []nugetToolEntry
	partial := false
	for _, id := range slices.Sorted(maps.Keys(tools)) {
		entry, err := composerObject(tools[id])
		if _, ok := nugetID(id); !ok || err != nil {
			partial = true
			continue
		}
		e := nugetToolEntry{id: id}
		var ok bool
		if e.version, ok = nugetString(entry["version"], 256); !ok || e.version == "" {
			partial = true
			continue
		}
		if e.commands, ok = nugetCommands(entry["commands"]); !ok {
			partial = true
		}
		out = append(out, e)
	}
	return out, partial, nil
}

// nugetCommands bounds tool command names: they are names, never arguments.
func nugetCommands(raw json.RawMessage) ([]string, bool) {
	var names []string
	if raw == nil || json.Unmarshal(raw, &names) != nil || len(names) > 64 {
		return nil, false
	}
	for _, n := range names {
		if n == "" || !nugetText(n, 256) || strings.ContainsAny(n, "/\\ \t") {
			return nil, false
		}
	}
	return names, true
}

type nugetResolverEntry struct {
	version, framework, rid, name, executable string
}

func parseNuGetResolverCache(data []byte) ([]nugetResolverEntry, bool, error) {
	if int64(len(data)) > maxNuGetMetadataBytes || !utf8.Valid(data) {
		return nil, false, errors.New("invalid metadata")
	}
	var entries []json.RawMessage
	if json.Unmarshal(data, &entries) != nil {
		return nil, false, errNuGetUnsupportedFormat
	}
	var out []nugetResolverEntry
	partial := false
	for _, raw := range entries {
		obj, err := composerObject(raw)
		if err != nil {
			partial = true
			continue
		}
		e := nugetResolverEntry{}
		ok := true
		for _, field := range []struct {
			key   string
			dest  *string
			limit int
		}{{"Version", &e.version, 256}, {"TargetFramework", &e.framework, 256}, {"RuntimeIdentifier", &e.rid, 256}, {"Name", &e.name, 256}, {"PathToExecutable", &e.executable, 4096}} {
			var valid bool
			*field.dest, valid = nugetString(obj[field.key], field.limit)
			ok = ok && valid
		}
		if !ok || e.version == "" || e.name == "" {
			partial = true
			continue
		}
		out = append(out, e)
	}
	return out, partial, nil
}

// parseNuGetToolSettings reads command names from DotnetToolSettings.xml.
func parseNuGetToolSettings(data []byte) ([]string, error) {
	dec, err := nugetXML(data)
	if err != nil {
		return nil, err
	}
	var doc struct {
		XMLName  xml.Name `xml:"DotNetCliTool"`
		Commands []struct {
			Name string `xml:"Name,attr"`
		} `xml:"Commands>Command"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	var names []string
	for _, c := range doc.Commands {
		if c.Name != "" && nugetText(c.Name, 256) && !strings.ContainsAny(c.Name, "/\\ \t") {
			names = append(names, c.Name)
		}
	}
	return names, nil
}

type nugetTemplateEntry struct {
	id, version, mount, source string
}

func parseNuGetTemplates(data []byte) ([]nugetTemplateEntry, bool, error) {
	obj, err := nugetObject(data)
	if err != nil {
		return nil, false, err
	}
	var packages []json.RawMessage
	if obj["Packages"] == nil || json.Unmarshal(obj["Packages"], &packages) != nil {
		return nil, false, errNuGetUnsupportedFormat
	}
	var out []nugetTemplateEntry
	partial := false
	for _, raw := range packages {
		entry, err := composerObject(raw)
		if err != nil {
			partial = true
			continue
		}
		details, err := composerObject(entry["Details"])
		if err != nil {
			// Directory-mounted templates have no NuGet identity.
			continue
		}
		e := nugetTemplateEntry{}
		var okID, okVer, okMount, okSource bool
		e.id, okID = nugetString(details["PackageId"], 100)
		e.version, okVer = nugetString(details["Version"], 256)
		e.mount, okMount = nugetString(entry["MountPointUri"], 4096)
		e.source, okSource = nugetString(details["NuGetSource"], 4096)
		if _, valid := nugetID(e.id); e.id == "" || e.version == "" {
			continue
		} else if !valid || !okID || !okVer || !okMount || !okSource {
			partial = true
			continue
		}
		out = append(out, e)
	}
	return out, partial, nil
}

type nugetDepsEntry struct {
	id, version, sha512, framework, rid string
}

// parseNuGetDeps reads package libraries from a runtime *.deps.json.
func parseNuGetDeps(data []byte) ([]nugetDepsEntry, bool, error) {
	obj, err := nugetObject(data)
	if err != nil {
		return nil, false, err
	}
	var libraries map[string]json.RawMessage
	if obj["libraries"] == nil || obj["targets"] == nil || json.Unmarshal(obj["libraries"], &libraries) != nil {
		return nil, false, errNuGetUnsupportedFormat
	}
	framework, rid := "", ""
	if obj["runtimeTarget"] != nil {
		if rt, err := composerObject(obj["runtimeTarget"]); err == nil {
			name, _ := nugetString(rt["name"], 256)
			framework, rid, _ = strings.Cut(name, "/")
		}
	}
	var out []nugetDepsEntry
	partial := false
	for _, key := range slices.Sorted(maps.Keys(libraries)) {
		id, version, ok := nugetLibrary(key)
		entry, err := composerObject(libraries[key])
		if !ok || err != nil {
			partial = true
			continue
		}
		if typ, _ := nugetString(entry["type"], 64); typ != "package" {
			continue
		}
		e := nugetDepsEntry{id: id, version: version, framework: framework, rid: rid}
		hash, okHash := nugetString(entry["sha512"], 256)
		if !okHash {
			partial = true
		}
		e.sha512 = strings.TrimPrefix(hash, "sha512-")
		out = append(out, e)
	}
	return out, partial, nil
}

type nugetDirective struct {
	kind, id, version string // kind: package | sdk
}

// parseNuGetCSharpDirectives reads #:package and #:sdk directives from the
// leading trivia of a file-based app; directives after code are ignored.
func parseNuGetCSharpDirectives(data []byte) []nugetDirective {
	if !utf8.Valid(data) {
		return nil
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var out []nugetDirective
	inComment := false
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if inComment {
			if _, after, ok := strings.Cut(line, "*/"); ok {
				inComment, line = false, strings.TrimSpace(after)
			} else {
				continue
			}
		}
		switch {
		case line == "", strings.HasPrefix(line, "//"), strings.HasPrefix(line, "#!"):
			continue
		case strings.HasPrefix(line, "/*"):
			if !strings.Contains(line, "*/") {
				inComment = true
			}
			continue
		case strings.HasPrefix(line, "#:"):
			kind, rest, _ := strings.Cut(line[2:], " ")
			if kind != "package" && kind != "sdk" {
				continue
			}
			id, version, _ := strings.Cut(strings.TrimSpace(rest), "@")
			version = strings.TrimSpace(version)
			if kind == "sdk" && version == "" {
				continue // a built-in SDK name is not a package
			}
			if _, ok := nugetID(id); ok {
				out = append(out, nugetDirective{kind: kind, id: id, version: version})
			}
		default:
			return out
		}
	}
	return out
}

var nugetFSharpReference = regexp.MustCompile(`(?m)^\s*#r\s+"nuget:\s*([^",]+?)\s*(?:,\s*([^"]*?)\s*)?"`)

// parseNuGetFSharpDirectives reads literal #r "nuget: ID[, version]" lines.
// #i source directives and #if branches are not evaluated.
func parseNuGetFSharpDirectives(data []byte) []nugetDirective {
	if !utf8.Valid(data) {
		return nil
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var out []nugetDirective
	for _, m := range nugetFSharpReference.FindAllStringSubmatch(string(data), 1000) {
		if _, ok := nugetID(m[1]); ok {
			out = append(out, nugetDirective{kind: "package", id: m[1], version: m[2]})
		}
	}
	return out
}
