package detector

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Nix manifest limits. Generated manifests hold a handful of elements; the
// bounds keep a hostile or corrupt file from costing more than a scan.
const (
	maxNixManifestBytes  int64 = 2 << 20
	maxNixDepth                = 32
	maxNixElements             = 10_000
	maxNixOutputs              = 64
	maxNixStorePathBytes       = 4096
)

const nixStorePrefix = "/nix/store/"

var errNixUnparsed = errors.New("unparsed manifest")

// nixElement is one profile registration before it becomes a record.
type nixElement struct {
	storePaths  []string // every output path the element installs
	outputNames []string // declared output names, when the manifest has them
	drvName     string   // legacy derivation name, when present
}

// parseNixManifestJSON reads a `nix profile` manifest.json. Version 3 keys
// elements by name; versions 1 and 2 have an array. incomplete reports
// elements that could not be identified or were cut by the element bound.
func parseNixManifestJSON(data []byte) (pkgs []model.SystemPackage, incomplete bool, err error) {
	if !jsonDepthWithin(data, maxNixDepth) {
		return nil, false, errNixUnparsed
	}
	var m struct {
		Version  int             `json:"version"`
		Elements json.RawMessage `json:"elements"`
	}
	if configaudit.SwiftJSON(data, &m) != nil {
		return nil, false, errNixUnparsed
	}

	// elements null decodes without error into a nil slice or map; only []
	// and {} are an empty profile.
	var raws []json.RawMessage
	switch m.Version {
	case 1, 2:
		if err := json.Unmarshal(m.Elements, &raws); err != nil || raws == nil {
			return nil, false, errNixUnparsed
		}
	case 3:
		var byKey map[string]json.RawMessage
		if err := json.Unmarshal(m.Elements, &byKey); err != nil || byKey == nil {
			return nil, false, errNixUnparsed
		}
		for _, k := range slices.Sorted(maps.Keys(byKey)) {
			raws = append(raws, byKey[k])
		}
	default:
		return nil, false, errNixUnparsed
	}
	if len(raws) > maxNixElements {
		raws, incomplete = raws[:maxNixElements], true
	}

	for _, raw := range raws {
		var e struct {
			Outputs    json.RawMessage `json:"outputs"`
			StorePaths []string        `json:"storePaths"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			incomplete = true
			continue
		}
		el := nixElement{storePaths: e.StorePaths}
		// null (all default outputs) and a missing field leave the names unknown.
		_ = json.Unmarshal(e.Outputs, &el.outputNames)
		pkg, ok := el.record()
		if !ok {
			incomplete = true
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, incomplete, nil
}

// jsonDepthWithin bounds nesting before decoding, so depth inside fields the
// decoder would skip is bounded too.
func jsonDepthWithin(data []byte, limit int) bool {
	depth, inString, escaped := 0, false, false
	for _, c := range data {
		switch {
		case escaped:
			escaped = false
		case inString:
			escaped = c == '\\'
			inString = c != '"'
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			if depth++; depth > limit {
				return false
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return true
}

// record turns an element into a system package. ok=false when the element
// has no valid store path to identify it. InstallPath is the "out" output
// when the manifest proves which path that is, else the first sorted path.
func (el nixElement) record() (model.SystemPackage, bool) {
	paths := el.storePaths
	slices.Sort(paths)
	paths = slices.Compact(paths)
	if len(paths) == 0 || len(paths) > maxNixOutputs || len(el.outputNames) > maxNixOutputs {
		return model.SystemPackage{}, false
	}
	for _, p := range paths {
		if nixStoreBase(p) == "" {
			return model.SystemPackage{}, false
		}
	}

	install := paths[0]
	base, out, named := nixOutputBase(paths, el.outputNames)
	if out != "" {
		install = out
	}
	switch {
	case el.drvName != "":
		base = el.drvName
	case !named:
		base = nixSharedBase(paths, len(el.outputNames) == 0)
	}
	if base == "" {
		base = nixStoreBase(install)
	}
	name, version := splitNixName(base)
	return model.SystemPackage{Name: name, Version: version, InstallPath: install}, true
}

// nixOutputBase maps each path to a declared output name: the "out" output's
// basename is the base and every other output's is base-<name>. It returns
// the base and the "out" path only when exactly one base explains every path.
func nixOutputBase(paths, names []string) (base, out string, ok bool) {
	if len(names) != len(paths) {
		return "", "", false
	}
	for _, candidate := range nixBaseCandidates(paths, names) {
		if o, mapped := nixMapOutputs(paths, names, candidate); mapped {
			if ok {
				return "", "", false // two bases explain the paths: ambiguous
			}
			base, out, ok = candidate, o, true
		}
	}
	return base, out, ok
}

// nixSharedBase returns the first path's name when every path has it, else
// "". When the manifest names no outputs (outputs: null installs the
// defaults, such as jq-1.7.1-bin and jq-1.7.1-man), a path may also be
// base-<output>, and the base may be the first name without its last
// -<output>. An output name here is lowercase letters only.
func nixSharedBase(paths []string, undeclared bool) string {
	first := nixStoreBase(paths[0])
	if nixPathsShare(paths, first, undeclared) {
		return first
	}
	if i := strings.LastIndexByte(first, '-'); undeclared && i > 0 && isNixOutputName(first[i+1:]) &&
		nixPathsShare(paths, first[:i], true) {
		return first[:i]
	}
	return ""
}

func nixPathsShare(paths []string, base string, outputs bool) bool {
	prefix := base + "-"
	for _, p := range paths {
		b := nixStoreBase(p)
		if rest, ok := strings.CutPrefix(b, prefix); b != base && !(outputs && ok && isNixOutputName(rest)) {
			return false
		}
	}
	return true
}

func isNixOutputName(s string) bool {
	return s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz") == ""
}

func nixBaseCandidates(paths, names []string) []string {
	var out []string
	for _, p := range paths {
		b := nixStoreBase(p)
		for _, n := range names {
			if n == "out" {
				out = append(out, b)
			} else if s, ok := strings.CutSuffix(b, "-"+n); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// nixMapOutputs reports whether base gives every path a distinct declared
// name, and returns the path named "out", if any.
func nixMapOutputs(paths, names []string, base string) (out string, ok bool) {
	used := map[string]bool{}
	for _, p := range paths {
		b := nixStoreBase(p)
		name := ""
		for _, n := range names {
			if (n == "out" && b == base) || (n != "out" && b == base+"-"+n) {
				name = n
				break
			}
		}
		if name == "" || used[name] {
			return "", false
		}
		used[name] = true
		if name == "out" {
			out = p
		}
	}
	return out, true
}

// nixStoreBase returns <name> of /nix/store/<32-char hash>-<name>, or "" when
// the path is not a top-level store path.
func nixStoreBase(p string) string {
	rest, ok := strings.CutPrefix(p, nixStorePrefix)
	if !ok || len(p) > maxNixStorePathBytes || len(rest) < 34 || rest[32] != '-' || strings.ContainsRune(rest, '/') {
		return ""
	}
	for _, c := range rest[:32] {
		if !strings.ContainsRune("0123456789abcdfghijklmnpqrsvwxyz", c) {
			return ""
		}
	}
	return rest[33:]
}

// splitNixName applies Nix's derivation-name rule: the version starts at the
// first dash followed by a character that is not a letter. A leading dash
// stays in the name, so the name is never empty.
func splitNixName(s string) (name, version string) {
	for i := 1; i+1 < len(s); i++ {
		if c := s[i+1] | 0x20; s[i] == '-' && (c < 'a' || c > 'z') {
			return s[:i], s[i+1:]
		}
	}
	return s, "unknown"
}

// parseNixManifestLegacy reads the manifest.nix that `nix-env` writes. It is a
// Nix expression; only its literal subset is accepted (lists, attribute sets,
// strings, integers, booleans, null) and nothing is ever evaluated. Any other
// construct rejects the whole file. An element marked inactive is still a
// registration and is listed.
func parseNixManifestLegacy(data []byte) (pkgs []model.SystemPackage, incomplete bool, err error) {
	p := &nixLiteralParser{src: data}
	v, err := p.value(0)
	if err != nil {
		return nil, false, errNixUnparsed
	}
	if p.skipSpace(); p.pos != len(p.src) {
		return nil, false, errNixUnparsed
	}
	list, ok := v.([]any)
	if !ok {
		return nil, false, errNixUnparsed
	}
	if len(list) > maxNixElements {
		list, incomplete = list[:maxNixElements], true
	}
	for _, item := range list {
		pkg, ok := legacyElement(item).record()
		if !ok {
			incomplete = true
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, incomplete, nil
}

// legacyElement selects the fields of one manifest.nix entry.
func legacyElement(item any) nixElement {
	set, _ := item.(map[string]any)
	el := nixElement{}
	el.drvName, _ = set["name"].(string)
	names := []string{"out"}
	if list, ok := set["outputs"].([]any); ok {
		names = names[:0]
		for _, n := range list {
			if s, ok := n.(string); ok {
				names = append(names, s)
			}
		}
	}
	el.outputNames = names
	for _, n := range names {
		out, _ := set[n].(map[string]any)
		path, _ := out["outPath"].(string)
		if path == "" && n == "out" {
			path, _ = set["outPath"].(string)
		}
		if path == "" {
			el.storePaths = nil
			return el
		}
		el.storePaths = append(el.storePaths, path)
	}
	return el
}

// nixLiteralParser is a recursive-descent parser for literal Nix values.
type nixLiteralParser struct {
	src []byte
	pos int
}

func (p *nixLiteralParser) skipSpace() {
	for p.pos < len(p.src) && strings.IndexByte(" \t\r\n", p.src[p.pos]) >= 0 {
		p.pos++
	}
}

func (p *nixLiteralParser) value(depth int) (any, error) {
	if depth > maxNixDepth {
		return nil, errNixUnparsed
	}
	p.skipSpace()
	if p.pos >= len(p.src) {
		return nil, errNixUnparsed
	}
	switch c := p.src[p.pos]; {
	case c == '[':
		p.pos++
		var list []any
		for {
			p.skipSpace()
			if p.pos < len(p.src) && p.src[p.pos] == ']' {
				p.pos++
				return list, nil
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
	case c == '{':
		p.pos++
		set := map[string]any{}
		for {
			p.skipSpace()
			if p.pos < len(p.src) && p.src[p.pos] == '}' {
				p.pos++
				return set, nil
			}
			key, err := p.key()
			if err != nil {
				return nil, err
			}
			if !p.expect('=') {
				return nil, errNixUnparsed
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if !p.expect(';') {
				return nil, errNixUnparsed
			}
			set[key] = v
		}
	case c == '"':
		return p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		start := p.pos
		p.pos++
		for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == start+1 && c == '-' {
			return nil, errNixUnparsed
		}
		return string(p.src[start:p.pos]), nil // integers are never selected
	default:
		switch p.ident() {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null":
			return nil, nil
		}
		return nil, errNixUnparsed // a variable, keyword or function call
	}
}

func (p *nixLiteralParser) expect(c byte) bool {
	p.skipSpace()
	if p.pos < len(p.src) && p.src[p.pos] == c {
		p.pos++
		return true
	}
	return false
}

// key reads a bare or quoted attribute name. A dotted path, inherit or a
// dynamic attribute is not literal and is rejected by the caller's expect.
func (p *nixLiteralParser) key() (string, error) {
	if p.pos < len(p.src) && p.src[p.pos] == '"' {
		return p.str()
	}
	k := p.ident()
	if k == "" {
		return "", errNixUnparsed
	}
	return k, nil
}

func (p *nixLiteralParser) ident() string {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '_' || c == '\'' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (p.pos > start && c >= '0' && c <= '9') {
			p.pos++
			continue
		}
		break
	}
	return string(p.src[start:p.pos])
}

// str reads a double-quoted string. Interpolation is evaluation and rejects
// the file.
func (p *nixLiteralParser) str() (string, error) {
	p.pos++ // opening quote
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == '"':
			p.pos++
			return b.String(), nil
		case c == '\\' && p.pos+1 < len(p.src):
			switch e := p.src[p.pos+1]; e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(e)
			}
			p.pos += 2
		case c == '$' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '{':
			return "", errNixUnparsed
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
	return "", errNixUnparsed
}
