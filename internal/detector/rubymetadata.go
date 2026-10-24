package detector

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"errors"
	"io"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/model"
)

var (
	maxRubyMetadataBytes int64 = 2 << 20
	maxRubyArchiveBytes  int64 = 32 << 20
)

const (
	maxRubyRequirements = 32
	maxRubyLabels       = 32
	maxRubyNesting      = 32
)

var errRubyUnsupportedFormat = errors.New("unsupported metadata format")

var (
	rubyVersionPattern  = regexp.MustCompile(`^[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	rubyRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	rubySHA256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func rubyVersion(s string) bool { return len(s) <= 256 && rubyVersionPattern.MatchString(s) }

// rubyDeclaration is one literal requirement before the scanner attaches its
// owner and project. Local paths and URLs stay raw until resolved/sanitized;
// an empty origin means the manifest tree's global sources decide.
type rubyDeclaration struct {
	name, kind        string
	requirements      []string
	groups, platforms []string
	origin, url, path string
}

type rubyGemspecRef struct{ path, name string }

// rubyManifest is a whole supported Gemfile or gemspec; any unsupported
// statement rejects the file rather than yielding a partial declaration set.
type rubyManifest struct {
	name, version string
	declarations  []rubyDeclaration
	sources       []configaudit.RubyManifestSource
	globals       []string
	evals         []string
	gemspecs      []rubyGemspecRef
	lockfile      string
	lockfileSet   bool
	noLockfile    bool
	partial       bool
	declared      map[string]int
	sourceSeen    map[string]bool
}

const (
	rubyTokIdent = iota + 1
	rubyTokString
	rubyTokSymbol
	rubyTokLabel
	rubyTokInt
	rubyTokPunct
	rubyTokNewline
)

type rubyToken struct {
	kind int
	text string
}

func rubyIdentStart(c byte) bool { return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
func rubyIdentByte(c byte) bool  { return rubyIdentStart(c) || c >= '0' && c <= '9' }

// rubyLex accepts only the literal subset. Heredocs, percent literals,
// backticks, interpolation, operators and globals all reject the file.
func rubyLex(data []byte) ([]rubyToken, error) {
	if int64(len(data)) > maxRubyMetadataBytes || !utf8.Valid(data) {
		return nil, errors.New("invalid ruby source")
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var toks []rubyToken
	for i := 0; i < len(data); {
		c := data[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '\n' || c == ';':
			toks = append(toks, rubyToken{kind: rubyTokNewline})
			i++
		case c == '#':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case (i == 0 || data[i-1] == '\n') && c == '=' && bytes.HasPrefix(data[i:], []byte("=begin")):
			return nil, errRubyUnsupportedFormat
		case c == '"' || c == '\'':
			s, n, err := rubyString(data[i:])
			if err != nil {
				return nil, err
			}
			toks = append(toks, rubyToken{rubyTokString, s})
			i += n
		case c == ':' && i+1 < len(data) && data[i+1] == ':':
			toks = append(toks, rubyToken{rubyTokPunct, "::"})
			i += 2
		case c == ':' && i+1 < len(data) && (data[i+1] == '"' || data[i+1] == '\''):
			s, n, err := rubyString(data[i+1:])
			if err != nil {
				return nil, err
			}
			toks = append(toks, rubyToken{rubyTokSymbol, s})
			i += 1 + n
		case c == ':' && i+1 < len(data) && rubyIdentStart(data[i+1]):
			j := i + 1
			for j < len(data) && rubyIdentByte(data[j]) {
				j++
			}
			toks = append(toks, rubyToken{rubyTokSymbol, string(data[i+1 : j])})
			i = j
		case rubyIdentStart(c):
			j := i
			for j < len(data) && rubyIdentByte(data[j]) {
				j++
			}
			word := string(data[i:j])
			if word == "__END__" || j < len(data) && (data[j] == '?' || data[j] == '!') {
				return nil, errRubyUnsupportedFormat
			}
			// `key:` is a keyword label; `Const::Name` is scope resolution.
			if j < len(data) && data[j] == ':' && (j+1 >= len(data) || data[j+1] != ':') {
				toks = append(toks, rubyToken{rubyTokLabel, word})
				i = j + 1
				continue
			}
			toks = append(toks, rubyToken{rubyTokIdent, word})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(data) && data[j] >= '0' && data[j] <= '9' {
				j++
			}
			if j < len(data) && (rubyIdentByte(data[j]) || data[j] == '.') {
				return nil, errRubyUnsupportedFormat
			}
			toks = append(toks, rubyToken{rubyTokInt, string(data[i:j])})
			i = j
		case c == '=' && i+1 < len(data) && data[i+1] == '>':
			toks = append(toks, rubyToken{rubyTokPunct, "=>"})
			i += 2
		case c == '=' && (i+1 >= len(data) || data[i+1] != '=' && data[i+1] != '~'):
			toks = append(toks, rubyToken{rubyTokPunct, "="})
			i++
		case strings.IndexByte("()[]{},.|", c) >= 0:
			toks = append(toks, rubyToken{rubyTokPunct, string(c)})
			i++
		default:
			return nil, errRubyUnsupportedFormat
		}
	}
	return toks, nil
}

// rubyString decodes one single-line quoted literal with Ruby's quote rules.
// Double quotes accept only \\ and \" escapes and never interpolation.
func rubyString(data []byte) (string, int, error) {
	quote := data[0]
	var b strings.Builder
	for j := 1; j < len(data) && b.Len() <= 1<<16; j++ {
		c := data[j]
		switch {
		case c == '\n':
			return "", 0, errRubyUnsupportedFormat
		case c == quote:
			return b.String(), j + 1, nil
		case c == '\\':
			if j+1 >= len(data) {
				return "", 0, errRubyUnsupportedFormat
			}
			switch next := data[j+1]; {
			case next == '\\' || next == quote:
				b.WriteByte(next)
				j++
			case quote == '\'':
				// Single quotes keep every other backslash literally.
				b.WriteByte(c)
			default:
				return "", 0, errRubyUnsupportedFormat
			}
		case quote == '"' && c == '#' && j+1 < len(data) && strings.IndexByte("{@$", data[j+1]) >= 0:
			return "", 0, errRubyUnsupportedFormat
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, errRubyUnsupportedFormat
}

// rubyValue is a literal; hash contents are validated but never retained.
type rubyValue struct {
	kind  byte // s string, y symbol, i integer, b boolean, n nil, a array, h hash
	text  string
	items []rubyValue
}

type rubyCall struct {
	recv, name string
	assign     bool
	args       []rubyValue
	opts       map[string]rubyValue
	block      bool
	param      string
	body       []rubyCall
}

type rubyParser struct {
	toks  []rubyToken
	pos   int
	depth int
}

func (p *rubyParser) peek() rubyToken {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return rubyToken{}
}
func (p *rubyParser) take() rubyToken {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}
func (p *rubyParser) is(kind int, text string) bool {
	t := p.peek()
	return t.kind == kind && t.text == text
}
func (p *rubyParser) accept(kind int, text string) bool {
	if p.is(kind, text) {
		p.pos++
		return true
	}
	return false
}
func (p *rubyParser) newlines() {
	for p.peek().kind == rubyTokNewline {
		p.pos++
	}
}

func (p *rubyParser) value() (rubyValue, error) {
	if p.depth >= maxRubyNesting {
		return rubyValue{}, errRubyUnsupportedFormat
	}
	p.depth++
	defer func() { p.depth-- }()
	t := p.take()
	switch {
	case t.kind == rubyTokString:
		return rubyValue{kind: 's', text: t.text}, nil
	case t.kind == rubyTokSymbol:
		return rubyValue{kind: 'y', text: t.text}, nil
	case t.kind == rubyTokInt:
		return rubyValue{kind: 'i', text: t.text}, nil
	case t.kind == rubyTokIdent && (t.text == "true" || t.text == "false"):
		return rubyValue{kind: 'b', text: t.text}, nil
	case t.kind == rubyTokIdent && t.text == "nil":
		return rubyValue{kind: 'n'}, nil
	case t.kind == rubyTokPunct && (t.text == "[" || t.text == "{"):
		closer, v := "]", rubyValue{kind: 'a'}
		if t.text == "{" {
			closer, v.kind = "}", 'h'
		}
		for {
			p.newlines()
			if p.accept(rubyTokPunct, closer) {
				return v, nil
			}
			if v.kind == 'a' {
				item, err := p.value()
				if err != nil {
					return v, err
				}
				v.items = append(v.items, item)
			} else if _, _, err := p.pair(); err != nil {
				return v, err
			}
			p.newlines()
			if !p.accept(rubyTokPunct, ",") {
				if p.accept(rubyTokPunct, closer) {
					return v, nil
				}
				return v, errRubyUnsupportedFormat
			}
		}
	}
	return rubyValue{}, errRubyUnsupportedFormat
}

// pair reads `key: value` or a literal string/symbol `key => value`.
func (p *rubyParser) pair() (string, rubyValue, error) {
	if t := p.peek(); t.kind == rubyTokLabel {
		p.pos++
		p.newlines()
		v, err := p.value()
		return t.text, v, err
	}
	key, err := p.value()
	if err != nil || key.kind != 's' && key.kind != 'y' || !p.accept(rubyTokPunct, "=>") {
		return "", rubyValue{}, errRubyUnsupportedFormat
	}
	p.newlines()
	v, err := p.value()
	return key.text, v, err
}

func (p *rubyParser) arguments(c *rubyCall) error {
	paren := p.accept(rubyTokPunct, "(")
	if t := p.peek(); !paren && (t.kind == 0 || t.kind == rubyTokNewline || t.kind == rubyTokIdent && (t.text == "do" || t.text == "end")) {
		return nil
	}
	// A brace after a bare call is a block, never a hash argument.
	if !paren && p.is(rubyTokPunct, "{") {
		return errRubyUnsupportedFormat
	}
	for {
		if paren {
			p.newlines()
			if p.accept(rubyTokPunct, ")") {
				return nil
			}
		}
		keyed := p.peek().kind == rubyTokLabel
		var key string
		var v rubyValue
		var err error
		if keyed {
			key, v, err = p.pair()
		} else if v, err = p.value(); err == nil && p.accept(rubyTokPunct, "=>") {
			if v.kind != 's' && v.kind != 'y' {
				return errRubyUnsupportedFormat
			}
			keyed, key = true, v.text
			p.newlines()
			v, err = p.value()
		}
		if err != nil {
			return err
		}
		if keyed {
			if _, dup := c.opts[key]; dup {
				return errRubyUnsupportedFormat
			}
			if c.opts == nil {
				c.opts = map[string]rubyValue{}
			}
			c.opts[key] = v
		} else {
			if len(c.opts) > 0 {
				return errRubyUnsupportedFormat
			}
			c.args = append(c.args, v)
		}
		if p.accept(rubyTokPunct, ",") {
			p.newlines()
			continue
		}
		if paren {
			p.newlines()
			if !p.accept(rubyTokPunct, ")") {
				return errRubyUnsupportedFormat
			}
		}
		return nil
	}
}

func (p *rubyParser) statement() (rubyCall, error) {
	t := p.take()
	if t.kind != rubyTokIdent {
		return rubyCall{}, errRubyUnsupportedFormat
	}
	c := rubyCall{name: t.text}
	if p.accept(rubyTokPunct, ".") {
		m := p.take()
		if m.kind != rubyTokIdent {
			return c, errRubyUnsupportedFormat
		}
		c.recv, c.name = t.text, m.text
		if p.accept(rubyTokPunct, "=") {
			p.newlines()
			v, err := p.value()
			c.assign, c.args = true, []rubyValue{v}
			return c, err
		}
	}
	if err := p.arguments(&c); err != nil {
		return c, err
	}
	if p.accept(rubyTokIdent, "do") {
		c.block = true
		if p.accept(rubyTokPunct, "|") {
			param := p.take()
			if param.kind != rubyTokIdent || !p.accept(rubyTokPunct, "|") {
				return c, errRubyUnsupportedFormat
			}
			c.param = param.text
		}
		if p.depth >= maxRubyNesting {
			return c, errRubyUnsupportedFormat
		}
		p.depth++
		body, err := p.statements(true)
		p.depth--
		if err != nil {
			return c, err
		}
		c.body = body
	}
	return c, nil
}

// statements reads one call per line up to `end` (block) or end of input.
func (p *rubyParser) statements(block bool) ([]rubyCall, error) {
	var out []rubyCall
	for {
		p.newlines()
		t := p.peek()
		if t.kind == 0 {
			if block {
				return nil, errRubyUnsupportedFormat
			}
			return out, nil
		}
		if t.kind == rubyTokIdent && t.text == "end" {
			if !block {
				return nil, errRubyUnsupportedFormat
			}
			p.pos++
			return out, nil
		}
		c, err := p.statement()
		if err != nil {
			return nil, err
		}
		// Trailing tokens are modifiers or expressions outside the subset.
		if next := p.peek(); next.kind != 0 && next.kind != rubyTokNewline && !(next.kind == rubyTokIdent && next.text == "end") {
			return nil, errRubyUnsupportedFormat
		}
		out = append(out, c)
	}
}

// rubyLabels flattens literal symbol/string selectors, sorted and deduplicated.
func rubyLabels(values ...rubyValue) ([]string, bool) {
	out := []string{}
	for _, v := range values {
		items := []rubyValue{v}
		if v.kind == 'a' {
			items = v.items
		}
		for _, item := range items {
			if item.kind != 's' && item.kind != 'y' || !configaudit.RubyToken(item.text) {
				return nil, false
			}
			out = append(out, item.text)
		}
	}
	return rubyLabelSet(out)
}

func rubyLabelSet(labels []string) ([]string, bool) {
	out := slices.Clone(labels)
	slices.Sort(out)
	out = slices.Compact(out)
	return out, len(out) <= maxRubyLabels
}

// rubyRequirements keeps requirement text exactly; it is never solved.
func rubyRequirements(values []rubyValue) ([]string, bool) {
	out := []string{}
	for _, v := range values {
		items := []rubyValue{v}
		if v.kind == 'a' {
			items = v.items
		}
		for _, item := range items {
			if item.kind != 's' || strings.TrimSpace(item.text) == "" || !composerText(item.text, 1024) {
				return nil, false
			}
			out = append(out, item.text)
		}
	}
	return out, len(out) <= maxRubyRequirements
}

// declare collapses exact repeats of one identity. Repeats that differ in
// requirements or labels could describe different contexts, so the whole
// file becomes unsupported instead of a guessed union.
func (m *rubyManifest) declare(d rubyDeclaration) error {
	if !configaudit.RubyGemName(d.name) {
		m.partial = true
		return nil
	}
	if m.declared == nil {
		m.declared = map[string]int{}
	}
	key := strings.Join([]string{d.name, d.kind, d.origin, d.url, d.path}, "\x00")
	if i, ok := m.declared[key]; ok {
		prev := m.declarations[i]
		if slices.Equal(prev.requirements, d.requirements) && slices.Equal(prev.groups, d.groups) && slices.Equal(prev.platforms, d.platforms) {
			return nil
		}
		return errRubyUnsupportedFormat
	}
	m.declared[key] = len(m.declarations)
	m.declarations = append(m.declarations, d)
	return nil
}

func (m *rubyManifest) source(typ, url, cooldown string) {
	key := typ + "\x00" + url + "\x00" + cooldown
	if m.sourceSeen == nil {
		m.sourceSeen = map[string]bool{}
	}
	if !m.sourceSeen[key] {
		m.sourceSeen[key] = true
		m.sources = append(m.sources, configaudit.RubyManifestSource{Type: typ, URL: url, Cooldown: cooldown})
	}
}

type rubyScope struct {
	groups, platforms []string
	origin, url, path string
}

func parseRubyGemfile(data []byte) (*rubyManifest, error) {
	toks, err := rubyLex(data)
	if err != nil {
		return nil, err
	}
	p := &rubyParser{toks: toks}
	body, err := p.statements(false)
	if err != nil {
		return nil, err
	}
	m := &rubyManifest{}
	if err := m.gemfile(body, rubyScope{}, true); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *rubyManifest) gemfile(calls []rubyCall, scope rubyScope, top bool) error {
	for _, c := range calls {
		if c.recv != "" || c.assign || c.param != "" {
			return errRubyUnsupportedFormat
		}
		var err error
		switch c.name {
		case "source":
			err = m.gemfileSource(c, scope, top)
		case "gem":
			err = m.gemfileGem(c, scope)
		case "group", "platforms", "platform":
			labels, ok := rubyLabels(c.args...)
			if !ok || len(c.args) == 0 || !c.block {
				return errRubyUnsupportedFormat
			}
			inner := scope
			if c.name == "group" {
				// `optional:` is an annotation; it never proves installation.
				for k, v := range c.opts {
					if k != "optional" || v.kind != 'b' {
						return errRubyUnsupportedFormat
					}
				}
				inner.groups = append(slices.Clone(scope.groups), labels...)
			} else {
				if len(c.opts) > 0 {
					return errRubyUnsupportedFormat
				}
				inner.platforms = append(slices.Clone(scope.platforms), labels...)
			}
			err = m.gemfile(c.body, inner, false)
		case "git", "path":
			if len(c.args) != 1 || c.args[0].kind != 's' || c.args[0].text == "" || !c.block || scope.origin != "" {
				return errRubyUnsupportedFormat
			}
			allowed := []string{"glob"}
			if c.name == "git" {
				allowed = []string{"branch", "tag", "ref", "glob"}
			}
			for k, v := range c.opts {
				if !slices.Contains(allowed, k) || v.kind != 's' {
					return errRubyUnsupportedFormat
				}
			}
			inner := scope
			if c.name == "git" {
				inner.origin, inner.url = "git", c.args[0].text
				m.source("git", c.args[0].text, "")
			} else {
				inner.origin, inner.path = "path", c.args[0].text
			}
			err = m.gemfile(c.body, inner, false)
		case "gemspec":
			if !top || c.block || len(c.args) > 0 {
				return errRubyUnsupportedFormat
			}
			ref := rubyGemspecRef{path: "."}
			for k, v := range c.opts {
				switch {
				case k == "path" && v.kind == 's' && v.text != "":
					ref.path = v.text
				case k == "name" && v.kind == 's':
					ref.name = v.text
				case k == "glob" && v.kind == 's', k == "development_group" && (v.kind == 's' || v.kind == 'y'):
				default:
					return errRubyUnsupportedFormat
				}
			}
			m.gemspecs = append(m.gemspecs, ref)
		case "eval_gemfile":
			if !top || c.block || len(c.opts) > 0 || len(c.args) != 1 || c.args[0].kind != 's' || c.args[0].text == "" {
				return errRubyUnsupportedFormat
			}
			m.evals = append(m.evals, c.args[0].text)
		case "lockfile":
			if !top || c.block || len(c.opts) > 0 || len(c.args) != 1 {
				return errRubyUnsupportedFormat
			}
			switch v := c.args[0]; {
			case v.kind == 's' && v.text != "":
				m.lockfile = v.text
			case v.kind == 'b' && v.text == "false":
				m.noLockfile = true
			default:
				return errRubyUnsupportedFormat
			}
			m.lockfileSet = true
		case "ruby":
			// The interpreter requirement is context only, never a gem.
			if !top || c.block {
				return errRubyUnsupportedFormat
			}
		default:
			return errRubyUnsupportedFormat
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *rubyManifest) gemfileSource(c rubyCall, scope rubyScope, top bool) error {
	if len(c.args) != 1 || c.args[0].kind != 's' || c.args[0].text == "" {
		return errRubyUnsupportedFormat
	}
	cooldown := ""
	for k, v := range c.opts {
		// Plugin `type:` and other options are not silently registry origins.
		if k != "cooldown" || v.kind != 'i' || len(v.text) > 9 {
			return errRubyUnsupportedFormat
		}
		n, _ := strconv.Atoi(v.text)
		cooldown = strconv.Itoa(n)
	}
	url := c.args[0].text
	m.source("registry", url, cooldown)
	if !c.block {
		if !top {
			return errRubyUnsupportedFormat
		}
		if !slices.Contains(m.globals, url) {
			m.globals = append(m.globals, url)
		}
		return nil
	}
	if scope.origin != "" {
		return errRubyUnsupportedFormat
	}
	inner := scope
	inner.origin, inner.url = "registry", url
	return m.gemfile(c.body, inner, false)
}

var rubyGemOptions = []string{"group", "groups", "platform", "platforms", "require", "source", "git", "path", "branch", "tag", "ref", "glob", "force_ruby_platform"}

func (m *rubyManifest) gemfileGem(c rubyCall, scope rubyScope) error {
	if c.block || len(c.args) == 0 || c.args[0].kind != 's' {
		return errRubyUnsupportedFormat
	}
	reqs, ok := rubyRequirements(c.args[1:])
	if !ok {
		return errRubyUnsupportedFormat
	}
	d := rubyDeclaration{name: c.args[0].text, kind: "unknown", requirements: reqs, origin: scope.origin, url: scope.url, path: scope.path}
	groups, platforms := slices.Clone(scope.groups), slices.Clone(scope.platforms)
	explicit := 0
	for _, k := range slices.Sorted(maps.Keys(c.opts)) {
		v := c.opts[k]
		if !slices.Contains(rubyGemOptions, k) {
			return errRubyUnsupportedFormat
		}
		switch k {
		case "group", "groups", "platform", "platforms":
			labels, ok := rubyLabels(v)
			if !ok {
				return errRubyUnsupportedFormat
			}
			if strings.HasPrefix(k, "group") {
				groups = append(groups, labels...)
			} else {
				platforms = append(platforms, labels...)
			}
		case "force_ruby_platform":
			if v.kind != 'b' {
				return errRubyUnsupportedFormat
			}
		case "require":
			// Load behavior is never executed or modeled.
		case "source", "git", "path":
			if v.kind != 's' || v.text == "" {
				return errRubyUnsupportedFormat
			}
			explicit++
			switch k {
			case "source":
				d.origin, d.url, d.path = "registry", v.text, ""
			case "git":
				d.origin, d.url, d.path = "git", v.text, ""
			default:
				d.origin, d.url, d.path = "path", "", v.text
			}
			if k != "path" {
				m.source(d.origin, v.text, "")
			}
		default:
			// branch, tag, ref and glob select within a Git/path source.
			if v.kind != 's' {
				return errRubyUnsupportedFormat
			}
		}
	}
	if explicit > 1 {
		return errRubyUnsupportedFormat
	}
	if d.groups, ok = rubyLabelSet(groups); !ok {
		return errRubyUnsupportedFormat
	}
	if d.platforms, ok = rubyLabelSet(platforms); !ok {
		return errRubyUnsupportedFormat
	}
	return m.declare(d)
}

// Non-identity gemspec fields: literal values are skipped and never
// serialized, so personal text, file lists and key paths stay on device.
var rubyGemspecIgnored = []string{"summary", "description", "authors", "author", "email", "homepage", "license", "licenses", "files", "executables", "extensions", "bindir", "require_paths", "metadata", "required_ruby_version", "required_rubygems_version", "extra_rdoc_files", "rdoc_options", "post_install_message", "cert_chain", "signing_key"}

// parseRubyGemspec accepts only the literal `Gem::Specification.new` block.
// Generated library gemspecs that compute versions or file lists stay
// unsupported until they are built or locked.
func parseRubyGemspec(data []byte) (*rubyManifest, error) {
	toks, err := rubyLex(data)
	if err != nil {
		return nil, err
	}
	p := &rubyParser{toks: toks}
	p.newlines()
	for _, want := range []rubyToken{{rubyTokIdent, "Gem"}, {rubyTokPunct, "::"}, {rubyTokIdent, "Specification"}, {rubyTokPunct, "."}, {rubyTokIdent, "new"}, {rubyTokIdent, "do"}, {rubyTokPunct, "|"}} {
		if !p.accept(want.kind, want.text) {
			return nil, errRubyUnsupportedFormat
		}
	}
	param := p.take()
	if param.kind != rubyTokIdent || !p.accept(rubyTokPunct, "|") {
		return nil, errRubyUnsupportedFormat
	}
	body, err := p.statements(true)
	if err != nil {
		return nil, err
	}
	if p.newlines(); p.peek().kind != 0 {
		return nil, errRubyUnsupportedFormat
	}
	m := &rubyManifest{}
	for _, c := range body {
		if c.recv != param.text || c.block {
			return nil, errRubyUnsupportedFormat
		}
		switch {
		case c.assign && (c.name == "name" || c.name == "version" || c.name == "platform"):
			v := c.args[0]
			if v.kind != 's' {
				return nil, errRubyUnsupportedFormat
			}
			if c.name == "name" && configaudit.RubyGemName(v.text) {
				m.name = v.text
			}
			if c.name == "version" && rubyVersion(strings.TrimSpace(v.text)) {
				m.version = strings.TrimSpace(v.text)
			}
		case c.assign && slices.Contains(rubyGemspecIgnored, c.name):
		case !c.assign && (c.name == "add_dependency" || c.name == "add_runtime_dependency" || c.name == "add_development_dependency"):
			if len(c.opts) > 0 || len(c.args) == 0 || c.args[0].kind != 's' {
				return nil, errRubyUnsupportedFormat
			}
			reqs, ok := rubyRequirements(c.args[1:])
			if !ok {
				return nil, errRubyUnsupportedFormat
			}
			kind := "runtime"
			if c.name == "add_development_dependency" {
				kind = "development"
			}
			if err := m.declare(rubyDeclaration{name: c.args[0].text, kind: kind, requirements: reqs}); err != nil {
				return nil, err
			}
		default:
			return nil, errRubyUnsupportedFormat
		}
	}
	return m, nil
}

// rubyLockEntry is one resolved lock spec. A local Git/PATH remote stays raw
// until the scanner resolves it against the project directory.
type rubyLockEntry struct {
	pkg   model.RubyPackage
	local string
}

type rubyLockSource struct {
	section  string
	remotes  []string
	revision string
	specs    []model.RubyPackage
}

var (
	rubyLockSpec     = regexp.MustCompile(`^    ([^ ()!]+) \(([^-)]*)(?:-([^)]+))?\)$`)
	rubyLockDep      = regexp.MustCompile(`^  ([^ ()!]+)(?: \([^()]*\))?(!)?$`)
	rubyLockChecksum = regexp.MustCompile(`^  ([^ ()!]+) \(([^-)]*)(?:-([^)]+))?\)(?: (\S+))?$`)
	rubyLockAttr     = regexp.MustCompile(`^  ([a-z_]+):(?: (.*))?$`)
)

// parseRubyLock follows Bundler's lock text format. The version/platform
// split at the first hyphen is lock-only grammar (LockfileParser NAME_VERSION);
// it is never applied to filenames. Reasons are source-level coverage gaps.
func parseRubyLock(data []byte) ([]rubyLockEntry, []string, error) {
	if int64(len(data)) > maxRubyMetadataBytes || !utf8.Valid(data) {
		return nil, nil, errors.New("invalid lockfile")
	}
	reasons := []string{}
	note := func(r string) {
		if !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
	}
	type checksum struct {
		values  []string
		invalid bool
	}
	var sources []*rubyLockSource
	var cur *rubyLockSource
	section, inSpecs, known := "", false, false
	direct := map[string]bool{}
	depsSeen, depsBad := false, false
	sums := map[string]*checksum{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			section, cur, inSpecs = "", nil, false
			continue
		}
		if line[0] != ' ' {
			section, cur, inSpecs = line, nil, false
			switch line {
			case "GEM", "GIT", "PATH", "PLUGIN SOURCE":
				cur = &rubyLockSource{section: line}
				sources = append(sources, cur)
				if line == "PLUGIN SOURCE" {
					// Plugin sources are never loaded; identities stay, origin is unknown.
					note("unsupported_format")
				}
			case "DEPENDENCIES":
				depsSeen = true
			case "PLATFORMS", "RUBY VERSION", "BUNDLED WITH", "CHECKSUMS":
			default:
				// An unknown section never becomes complete empty inventory.
				note("unsupported_format")
				section = "\x00"
			}
			known = known || section != "\x00"
			continue
		}
		switch {
		case section == "\x00":
		case cur != nil:
			if m := rubyLockSpec.FindStringSubmatch(line); inSpecs && m != nil {
				platform := cmp.Or(m[3], "ruby")
				if !configaudit.RubyGemName(m[1]) || !rubyVersion(m[2]) || !configaudit.RubyToken(platform) {
					note("parse_error")
					continue
				}
				cur.specs = append(cur.specs, model.RubyPackage{PackageName: m[1], Version: m[2], Platform: platform})
				continue
			}
			// Six-space lines are a spec's own requirements, never packages.
			if inSpecs && strings.HasPrefix(line, "      ") && len(line) > 6 && line[6] != ' ' {
				continue
			}
			if m := rubyLockAttr.FindStringSubmatch(line); m != nil {
				inSpecs = m[1] == "specs"
				switch m[1] {
				case "remote":
					cur.remotes = append(cur.remotes, m[2])
				case "revision":
					cur.revision = m[2]
				}
				continue
			}
			note("parse_error")
		case section == "DEPENDENCIES":
			// The `!` suffix marks a pinned source, not part of the name.
			if m := rubyLockDep.FindStringSubmatch(line); m != nil && configaudit.RubyGemName(m[1]) {
				direct[m[1]] = true
				continue
			}
			depsBad = true
			note("parse_error")
		case section == "CHECKSUMS":
			m := rubyLockChecksum.FindStringSubmatch(line)
			if m == nil || !configaudit.RubyGemName(m[1]) || !rubyVersion(m[2]) || !configaudit.RubyToken(cmp.Or(m[3], "ruby")) {
				note("parse_error")
				continue
			}
			c := &checksum{}
			if m[4] != "" {
				for _, item := range strings.Split(m[4], ",") {
					algo, value, ok := strings.Cut(item, "=")
					switch {
					case !ok:
						c.invalid = true
					case algo != "sha256":
						// Only SHA-256 is a supported recorded checksum.
					case rubySHA256Pattern.MatchString(value):
						c.values = append(c.values, value)
					default:
						c.invalid = true
					}
				}
			}
			sums[m[1]+"\x00"+m[2]+"\x00"+cmp.Or(m[3], "ruby")] = c
		case section == "PLATFORMS" || section == "RUBY VERSION" || section == "BUNDLED WITH":
			// Runtime sections are context, never package lists.
		default:
			note("parse_error")
		}
	}
	if !known {
		return nil, nil, errors.New("no lockfile sections")
	}
	if !depsSeen {
		depsBad = true
		note("parse_error")
	}
	var out []rubyLockEntry
	for _, src := range sources {
		origin, local, reason := rubyLockOrigin(src)
		revision := ""
		if src.section == "GIT" && src.revision != "" {
			if rubyRevisionPattern.MatchString(src.revision) {
				revision = src.revision
			} else {
				note("parse_error")
			}
		}
		for _, p := range src.specs {
			p.Reasons, p.VersionStatus, p.DependencyKind, p.Origin, p.Revision = []string{}, "known", "unknown", origin, revision
			if reason != "" {
				p.Reasons = append(p.Reasons, reason)
			}
			p.DependencyRelation = "transitive"
			if direct[p.PackageName] {
				p.DependencyRelation = "direct"
			}
			if depsBad {
				p.DependencyRelation = "unknown"
			}
			p.ChecksumStatus, p.RecordedChecksums = "absent", []model.RubyRecordedChecksum{}
			if c := sums[p.PackageName+"\x00"+p.Version+"\x00"+p.Platform]; c != nil {
				for _, v := range c.values {
					p.RecordedChecksums = append(p.RecordedChecksums, model.RubyRecordedChecksum{Algorithm: "sha256", Value: v, SourceKind: "lockfile", Verification: "not_verified"})
				}
				switch {
				case c.invalid:
					p.ChecksumStatus = "partial"
					note("checksum_invalid")
				case len(c.values) > 0:
					p.ChecksumStatus = "recorded"
				}
			}
			out = append(out, rubyLockEntry{pkg: p, local: local})
		}
	}
	return out, reasons, nil
}

// rubyLockOrigin maps one lock source block. Several GEM remotes are an older
// ambiguous format; local Git remotes are device-scoped paths, not endpoints.
func rubyLockOrigin(src *rubyLockSource) (model.RubyOrigin, string, string) {
	unknown := model.RubyOrigin{Kind: "unknown"}
	single := len(src.remotes) == 1 && src.remotes[0] != ""
	switch src.section {
	case "PLUGIN SOURCE":
		return unknown, "", ""
	case "PATH":
		if !single {
			return unknown, "", "path_unresolved"
		}
		return model.RubyOrigin{Kind: "path"}, src.remotes[0], ""
	}
	if !single {
		return unknown, "", "origin_unresolved"
	}
	kind := "registry"
	if src.section == "GIT" {
		kind = "git"
		if p, local := composerLocalURL(src.remotes[0], ""); local {
			return model.RubyOrigin{Kind: "path"}, p, ""
		}
	}
	url, _ := configaudit.SanitizeRubyURL(src.remotes[0])
	if url == "[redacted]" {
		return model.RubyOrigin{Kind: kind, URL: url}, "", "origin_unresolved"
	}
	return model.RubyOrigin{Kind: kind, URL: url}, "", ""
}

// parseRubyStub reads RubyGems' generated `# stub:` header, never the Ruby
// below it. Without the header RubyGems would evaluate the file, so it is
// unsupported; identity is never inferred from a filename.
func parseRubyStub(data []byte) (name, version, platform string, err error) {
	lines := strings.SplitN(string(data), "\n", 3)
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "#") {
		return "", "", "", errRubyUnsupportedFormat
	}
	line, ok := strings.CutPrefix(strings.TrimSuffix(lines[1], "\r"), "# stub: ")
	if !ok {
		return "", "", "", errRubyUnsupportedFormat
	}
	fields := strings.SplitN(line, " ", 4)
	if !utf8.ValidString(line) || len(fields) < 3 || !configaudit.RubyGemName(fields[0]) || !rubyVersion(fields[1]) || !configaudit.RubyToken(fields[2]) {
		return "", "", "", errors.New("invalid stub identity")
	}
	return fields[0], fields[1], fields[2], nil
}

// parseRubyArchive reads identity from a .gem's single metadata member. It
// never extracts files or decompresses data.tar.gz; header iteration
// continues so a later duplicate identity member is still rejected.
func parseRubyArchive(data []byte) (name, version, platform, reason string) {
	tr := tar.NewReader(bytes.NewReader(data))
	var metadata []byte
	found := false
	for i := 0; ; i++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", "", "", "parse_error"
		}
		if i >= maxGoZipEntries {
			return "", "", "", "entry_limit"
		}
		if h.Name != "metadata.gz" && h.Name != "metadata" {
			continue
		}
		if found || h.Typeflag != tar.TypeReg {
			return "", "", "", "parse_error"
		}
		found = true
		if h.Size > maxRubyMetadataBytes {
			return "", "", "", "size_limit"
		}
		raw, err := io.ReadAll(io.LimitReader(tr, maxRubyMetadataBytes+1))
		if err != nil {
			return "", "", "", "parse_error"
		}
		if h.Name == "metadata.gz" {
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				return "", "", "", "parse_error"
			}
			raw, err = io.ReadAll(io.LimitReader(zr, maxRubyMetadataBytes+1))
			if err != nil {
				return "", "", "", "parse_error"
			}
		}
		// The identity bound applies after decompression.
		if int64(len(raw)) > maxRubyMetadataBytes {
			return "", "", "", "size_limit"
		}
		metadata = raw
	}
	if !found {
		return "", "", "", "unsupported_format"
	}
	name, version, platform, ok := rubyMetadataIdentity(metadata)
	if !ok {
		return "", "", "", "parse_error"
	}
	return name, version, platform, ""
}

// rubyMetadataIdentity reads name, version and platform from YAML nodes.
// Ruby object tags are never instantiated and aliases never expanded; an
// alias or duplicate on an identity field rejects it, unrelated nodes do not.
func rubyMetadataIdentity(data []byte) (name, version, platform string, ok bool) {
	var doc yaml.Node
	if !utf8.Valid(data) || yaml.Unmarshal(data, &doc) != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return "", "", "", false
	}
	root := doc.Content[0]
	seen := map[string]bool{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Value != "name" && key.Value != "version" && key.Value != "platform" {
			continue
		}
		if seen[key.Value] {
			return "", "", "", false
		}
		seen[key.Value] = true
		if key.Value == "version" && value.Kind == yaml.MappingNode {
			value = rubyYAMLField(value, "version")
		}
		text, valid := rubyYAMLScalar(value)
		if !valid {
			return "", "", "", false
		}
		switch key.Value {
		case "name":
			name = text
		case "version":
			version = text
		default:
			platform = text
		}
	}
	return name, version, platform, configaudit.RubyGemName(name) && rubyVersion(version) && configaudit.RubyToken(platform)
}

// Aliases are their own node kind, so they never pass as identity scalars.
func rubyYAMLScalar(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	switch n.ShortTag() {
	case "!!str", "!!int", "!!float":
		return strings.TrimSpace(n.Value), true
	}
	return "", false
}

func rubyYAMLField(m *yaml.Node, field string) *yaml.Node {
	var out *yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := m.Content[i]; k.Kind == yaml.ScalarNode && k.Value == field {
			if out != nil {
				return nil
			}
			out = m.Content[i+1]
		}
	}
	return out
}
