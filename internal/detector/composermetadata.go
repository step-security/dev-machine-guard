package detector

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/model"
)

var maxComposerMetadataBytes int64 = 2 << 20

var errComposerUnsupportedFormat = errors.New("unsupported metadata format")

var composerPackageName = regexp.MustCompile(`^[a-z0-9]+(?:(?:[_.]|-{1,2})[a-z0-9]+)*/[a-z0-9]+(?:(?:[_.]|-{1,2})[a-z0-9]+)*$`)

type composerManifest struct {
	name, version string
	packages      []model.ComposerPackage
	partial       bool
}

type composerEntry struct {
	pkg                    model.ComposerPackage
	installPath, targetDir string
	pathProvided           bool
}

// RawMessage isolates malformed entries without discarding readable neighbors.
func composerObject(data []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if !utf8.Valid(data) || int64(len(data)) > maxComposerMetadataBytes {
		return nil, errors.New("invalid metadata")
	}
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, errors.New("invalid metadata object")
	}
	return obj, nil
}

func composerText(s string, limit int) bool {
	return len(s) <= limit && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

func composerString(raw json.RawMessage, limit int) (string, bool) {
	if raw == nil {
		return "", true
	}
	var s string
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &s) != nil || !composerText(s, limit) {
		return "", false
	}
	return s, true
}

func composerName(raw string) (string, bool) {
	s := strings.ToLower(raw)
	return s, len(s) <= 256 && composerPackageName.MatchString(s)
}

func composerPlatformRequirement(name string) bool {
	if strings.Contains(name, "/") {
		return false
	}
	switch name {
	case "php", "php-64bit", "php-ipv6", "php-zts", "php-debug", "composer", "composer-plugin-api", "composer-runtime-api":
		return true
	}
	return strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-")
}

func newComposerPackage(name, kind string) model.ComposerPackage {
	return model.ComposerPackage{
		PackageName: name, DependencyKind: kind, DependencyRelation: "unknown", VersionStatus: "unknown",
		Reasons: []string{}, Origin: model.ComposerOrigin{Kind: "unknown"}, ChecksumStatus: "absent",
		RecordedChecksums: []model.ComposerRecordedChecksum{},
	}
}

func parseComposerManifest(data []byte) (*composerManifest, error) {
	obj, err := composerObject(data)
	if err != nil {
		return nil, err
	}
	m := &composerManifest{}
	if name, ok := composerString(obj["name"], 256); ok && name != "" {
		m.name, ok = composerName(name)
		m.partial = !ok
		if !ok {
			m.name = ""
		}
	} else if !ok {
		m.partial = true
	}
	var ok bool
	m.version, ok = composerString(obj["version"], 256)
	m.partial = m.partial || !ok
	for _, section := range []struct{ key, kind string }{{"require", "require"}, {"require-dev", "require_dev"}} {
		raw := obj[section.key]
		if raw == nil {
			continue
		}
		deps, err := composerObject(raw)
		if err != nil {
			m.partial = true
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(deps)) {
			// Platform requirements are not Composer package identities.
			if composerPlatformRequirement(name) {
				continue
			}
			canonical, valid := composerName(name)
			constraint, validText := composerString(deps[name], 1024)
			if !valid || !validText || constraint == "" {
				m.partial = true
				continue
			}
			p := newComposerPackage(canonical, section.kind)
			p.RequestedVersion, p.DependencyRelation = constraint, "direct"
			m.packages = append(m.packages, p)
		}
	}
	return m, nil
}

// parseComposerPackages accepts only the documented receipt/lock shapes. A
// missing packages member is not an empty installation.
func parseComposerPackages(data []byte, installed bool) ([]composerEntry, bool, error) {
	if !utf8.Valid(data) || int64(len(data)) > maxComposerMetadataBytes {
		return nil, false, errors.New("invalid metadata")
	}
	type group struct {
		raw  json.RawMessage
		kind string
	}
	var groups []group
	var devNames map[string]bool
	partial := false
	trimmed := bytes.TrimSpace(data)
	if installed && len(trimmed) > 0 && trimmed[0] == '[' {
		groups = append(groups, group{trimmed, "unknown"})
	} else {
		obj, err := composerObject(data)
		if err != nil {
			return nil, false, err
		}
		if obj["packages"] == nil {
			return nil, false, errComposerUnsupportedFormat
		}
		kind := "require"
		if installed {
			kind = "unknown"
			if raw, exists := obj["dev-package-names"]; exists {
				var names []json.RawMessage
				if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '[' || json.Unmarshal(raw, &names) != nil {
					partial = true
				} else {
					devNames = map[string]bool{}
					for _, rawName := range names {
						name, ok := composerString(rawName, 256)
						name, valid := composerName(name)
						if !ok || !valid {
							partial = true
							continue
						}
						devNames[name] = true
					}
					// A corrupt dev-name list cannot establish production membership.
					if partial {
						devNames = nil
					}
				}
			}
		}
		groups = append(groups, group{obj["packages"], kind})
		if !installed && obj["packages-dev"] != nil {
			groups = append(groups, group{obj["packages-dev"], "require_dev"})
		}
	}
	var out []composerEntry
	for _, group := range groups {
		var entries []json.RawMessage
		raw := bytes.TrimSpace(group.raw)
		if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &entries) != nil {
			return nil, false, errComposerUnsupportedFormat
		}
		for _, entry := range entries {
			e, valid, incomplete := parseComposerEntry(entry, group.kind)
			partial = partial || !valid || incomplete
			if !valid {
				continue
			}
			if installed && devNames != nil {
				e.pkg.DependencyKind = "require"
				if devNames[e.pkg.PackageName] {
					e.pkg.DependencyKind = "require_dev"
				}
			}
			out = append(out, e)
		}
	}
	return out, partial, nil
}

func parseComposerEntry(raw []byte, kind string) (composerEntry, bool, bool) {
	e := composerEntry{}
	obj, err := composerObject(raw)
	if err != nil {
		return e, false, false
	}
	name, ok := composerString(obj["name"], 256)
	name, valid := composerName(name)
	version, versionOK := composerString(obj["version"], 256)
	if !ok || !valid || !versionOK || version == "" {
		return e, false, false
	}
	e.pkg = newComposerPackage(name, kind)
	e.pkg.Version, e.pkg.VersionStatus = version, "known"
	partial := false
	for _, field := range []struct {
		key   string
		dest  *string
		limit int
	}{
		{"version_normalized", &e.pkg.VersionNormalized, 256}, {"type", &e.pkg.PackageType, 256},
		{"target-dir", &e.targetDir, 4096},
	} {
		*field.dest, ok = composerString(obj[field.key], field.limit)
		partial = partial || !ok
	}
	if p, exists := obj["install-path"]; exists && !bytes.Equal(bytes.TrimSpace(p), []byte("null")) {
		e.pathProvided = true
		e.installPath, ok = composerString(p, 4096)
		partial = partial || !ok
	}
	if e.pkg.PackageType == "metapackage" && e.installPath != "" {
		e.installPath = ""
		partial = true
	}
	for _, field := range []struct {
		key  string
		dest **model.ComposerDescriptor
	}{{"source", &e.pkg.Source}, {"dist", &e.pkg.Dist}} {
		if obj[field.key] == nil || bytes.Equal(bytes.TrimSpace(obj[field.key]), []byte("null")) {
			continue
		}
		descriptor, err := composerObject(obj[field.key])
		if err != nil {
			partial = true
			continue
		}
		typ, typeOK := composerString(descriptor["type"], 256)
		rawURL, urlOK := composerString(descriptor["url"], 4096)
		ref, refOK := composerString(descriptor["reference"], 1024)
		if bytes.Equal(bytes.TrimSpace(descriptor["reference"]), []byte("null")) {
			ref, refOK = "", true
		}
		if !typeOK || !urlOK || !refOK || typ == "" || rawURL == "" {
			partial = true
		} else {
			safe, _ := configaudit.SanitizeComposerURL(rawURL)
			*field.dest = &model.ComposerDescriptor{Type: typ, URL: safe, Reference: ref}
		}
		if field.key == "dist" {
			value, valid := composerString(descriptor["shasum"], 40)
			if descriptor["shasum"] == nil || bytes.Equal(bytes.TrimSpace(descriptor["shasum"]), []byte("null")) {
				value, valid = "", true
			}
			if value == "" && valid {
				continue
			}
			decoded, err := hex.DecodeString(value)
			if !valid || err != nil || len(decoded) != 20 {
				e.pkg.ChecksumStatus = "partial"
				e.pkg.Reasons = append(e.pkg.Reasons, "checksum_invalid")
			} else {
				e.pkg.ChecksumStatus = "recorded"
				e.pkg.RecordedChecksums = append(e.pkg.RecordedChecksums, model.ComposerRecordedChecksum{Algorithm: "sha1", Value: strings.ToLower(value), Verification: "not_verified"})
			}
		}
	}
	if partial {
		e.pkg.Reasons = append(e.pkg.Reasons, "parse_error")
	}
	return e, true, partial
}

func composerLockPath(manifest string) string {
	if strings.HasSuffix(manifest, ".json") {
		return strings.TrimSuffix(manifest, ".json") + ".lock"
	}
	return manifest + ".lock"
}

// composerLocalURL distinguishes Windows drives and file URLs before URI schemes.
func composerLocalURL(raw, typ string) (string, bool) {
	if typ == "path" || filepath.IsAbs(raw) || strings.HasPrefix(raw, `\\`) || len(raw) >= 3 && raw[1] == ':' && (raw[2] == '\\' || raw[2] == '/') {
		return raw, true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if u.Scheme == "file" {
		p := u.Path
		if u.Host != "" && u.Host != "localhost" {
			p = "//" + u.Host + p
		}
		if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
			p = p[1:]
		}
		return p, true
	}
	if u.Scheme == "" && u.Host == "" && !strings.Contains(raw, ":") {
		return raw, true
	}
	return "", false
}
