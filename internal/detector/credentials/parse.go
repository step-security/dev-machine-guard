package credentials

import (
	"bytes"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// Written as an escape because a literal mark in Go source is a syntax error.
const utf8Mark = "\uFEFF"

// UTF-16 byte-order marks, little- and big-endian.
var (
	utf16LEMark = []byte{0xFF, 0xFE}
	utf16BEMark = []byte{0xFE, 0xFF}
)

// stripBOM returns b without a leading UTF-8 byte-order mark. The mark is
// invisible but binds to the first token after it, so an unstripped file yields
// fewer entries — silently, which reads as a safer machine — and it is what a
// Windows developer's own tooling writes. Only a leading mark is a mark.
func stripBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte(utf8Mark))
}

// hasUTF16BOM reports whether b begins with a UTF-16 byte-order mark. Those
// bytes cannot be stripped and parsed on from: every character after them is two
// bytes wide, so a byte-oriented parser matches almost nothing and returns a
// small result rather than an error. The encoding is reported instead.
func hasUTF16BOM(b []byte) bool {
	return bytes.HasPrefix(b, utf16LEMark) || bytes.HasPrefix(b, utf16BEMark)
}

// scanLines walks a text file line by line, tolerating either line ending and
// stopping early when the visitor returns false. No line length is special: a
// certificate pinned into a setting is one very long line.
func scanLines(data []byte, visit func(line string) bool) {
	body := string(data)
	for len(body) > 0 {
		line := body
		if i := strings.IndexByte(body, '\n'); i >= 0 {
			line, body = body[:i], body[i+1:]
		} else {
			body = ""
		}
		if !visit(strings.TrimSuffix(line, "\r")) {
			return
		}
	}
}

// iniPair is one key and value. Keys repeat within a section in some formats,
// so pairs are a list rather than a map.
type iniPair struct {
	Key   string
	Value string
}

type iniSection struct {
	// Raw text between the brackets, so a caller that needs the
	// `section "subsection"` form can read it.
	Name  string
	Pairs []iniPair
}

// parseINI reads the INI dialect the credential files in this catalog use, and
// reports separately whether any line had no interpretation. A malformed line no
// longer disappears: skipping it silently would let a file this build cannot read
// resolve to "holds no credential", which is the one wrong answer an inventory
// must not give. Keys are lowercased, values keep their spelling less surrounding
// quotes, and pairs before any header land in a leading section with an empty name.
//
// bareKeys admits a valueless word as a setting. Only one of these formats spells
// a boolean that way, and admitting it everywhere would let a stray word in a file
// with no such spelling pass as a line that was understood.
func parseINI(data []byte, bareKeys bool) (sections []iniSection, malformed bool) {
	sections = []iniSection{{}}
	scanLines(data, func(line string) bool {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';' {
			return true
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			sections = append(sections, iniSection{Name: name})
			return true
		}
		// A line opening a header that never closes one. It is caught ahead of the
		// pair split because the torn remainder can itself hold an equals sign,
		// which would file the header text away as a setting and every pair after
		// it under whichever section came before. No key in these formats opens
		// with a bracket, so a whole header is the only thing this can be.
		if strings.HasPrefix(trimmed, "[") {
			malformed = true
			return true
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			switch {
			case continuesPreviousValue(line, sections):
				// An indented line under an open key carries that key's value on
				// rather than stating one of its own. It is appended rather than
				// skipped: a key written with its value on the next line is a
				// layout every one of these readers accepts, and dropping the
				// continuation would describe a filled-in field as empty.
				appendContinuation(sections, trimmed)
			case strings.HasSuffix(trimmed, "]"):
				// A header closed but never opened. The same boundary is lost as
				// when it opens without closing, and a value ending in a bracket
				// is a value, so this is only read as a header where the line
				// states no setting at all.
				malformed = true
			case bareKeys && len(strings.Fields(trimmed)) == 1:
				// A boolean setting spelled as a bare word: a recognised line
				// that holds no value and can therefore never be material.
				addPair(sections, iniPair{Key: strings.ToLower(trimmed)})
			default:
				malformed = true
			}
			return true
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			malformed = true
			return true
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		addPair(sections, iniPair{Key: key, Value: value})
		return true
	})
	return sections, malformed
}

// continuesPreviousValue reports an indented line that states no key, which is
// how a value written across several lines carries on. It is only a continuation
// where there is an open key to continue: the same line under a fresh header
// states nothing this build has a reading for.
func continuesPreviousValue(line string, sections []iniSection) bool {
	if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
		return false
	}
	return len(sections[len(sections)-1].Pairs) > 0
}

// appendContinuation carries a value on to the line below it. The lines are
// joined the way the readers of these formats join them, so a value spelled
// across several lines is one value rather than a fragment.
func appendContinuation(sections []iniSection, text string) {
	pairs := sections[len(sections)-1].Pairs
	last := &pairs[len(pairs)-1]
	if last.Value == "" {
		last.Value = text
		return
	}
	last.Value += "\n" + text
}

// addPair appends to the section being filled.
func addPair(sections []iniSection, p iniPair) {
	last := len(sections) - 1
	sections[last].Pairs = append(sections[last].Pairs, p)
}

// holds reports whether a section fills in a key with material. Every pair for
// the key is checked rather than the first: a key stated twice is a key whose
// first statement can be the empty one, and reading only that would describe a
// filled-in field as blank — which is the file's credential going unreported.
func (s iniSection) holds(key string) bool {
	return slices.ContainsFunc(s.Pairs, func(p iniPair) bool {
		return p.Key == key && concrete(p.Value)
	})
}

// blank reports a file of nothing but whitespace — neither a credential nor a
// parse failure: a tool wrote a placeholder, or the developer emptied it.
func blank(data []byte) bool {
	return len(bytes.TrimSpace(data)) == 0
}

// concrete reports whether a value is credential material sitting in the file
// rather than a name for one kept somewhere else. This is the whole test applied
// to a value: nothing here looks at the characters of a secret, only at whether
// the field was filled in at all and whether what filled it defers elsewhere.
func concrete(value string) bool {
	return value != "" && !isEnvRef(value)
}

// isEnvRef reports whether a value is entirely a shell-style variable reference,
// which the surrounding tool expands at read time — so the material is in the
// developer's environment, not in this file. The match is on the whole value: a
// string that merely embeds a reference still carries characters of its own, and
// calling that a reference would drop a configured credential from the inventory.
func isEnvRef(value string) bool {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		return validEnvName(value[2 : len(value)-1])
	}
	if strings.HasPrefix(value, "$") {
		return validEnvName(value[1:])
	}
	return false
}

// validEnvName reports whether a name is spelled the way a shell variable is: a
// leading letter or underscore, then letters, digits and underscores.
func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// protectionRank orders the two states a finding may carry. Nothing else has a
// rank, which is what makes an unmapped state fail closed rather than fold into
// its neighbours.
var protectionRank = map[string]int{
	model.CredentialProtectionProtected: 1,
	model.CredentialProtectionPlaintext: 2,
}

// fold accumulates the worst protection state across one source's entries and
// counts them. Folding the other way would describe a file by its safest part
// and hide the exposure sitting beside it.
type fold struct {
	count int
	state string
	// Set where something in the file could not be interpreted. Independent of
	// the count: a file can hold one confirmed credential and one entry this
	// build cannot read, and reporting only the first would call the rest clean.
	unrecognized bool
	// Set where the parser stopped counting at a bound of its own, so the count
	// is a lower bound the same way a byte-capped read's is.
	capped bool
	// Whether the tenant opted in to key fragments, and the fragments of the
	// recognized keys counted so far, grouped. Dropped is set where a fragment
	// was left out by the per-finding bound.
	fragments bool
	hints     map[model.CredentialKeyFragment]int
	dropped   bool
}

// add records one credential. A state outside the two-value vocabulary is not a
// credential this build understands, so it adds nothing and marks the source
// uninterpreted — a parser that grows a case and forgets to map it cannot
// silently improve a file's reported protection.
func (f *fold) add(state string) {
	rank, known := protectionRank[state]
	if !known {
		f.unrecognized = true
		return
	}
	f.count++
	if rank > protectionRank[f.state] {
		f.state = state
	}
}

// observation is the result of reading one credential location: how much
// material was confirmed, how the worst of it is held, and whether any part of
// the file resisted interpretation.
type observation struct {
	Count      int
	Protection string
	// The file existed and was read, and something in it has no interpretation.
	// Never a finding on its own — a parse failure is not evidence a credential
	// is there — so it travels as an error and costs the scan its completeness.
	Unrecognized bool
	// The parser reached a bound of its own before the end of the file, so the
	// count is a lower bound.
	Capped bool
}

// result closes the fold.
func (f *fold) result() observation {
	return observation{Count: f.count, Protection: f.state, Unrecognized: f.unrecognized, Capped: f.capped}
}

// unparseable is the observation for a file that exists, was read, and has no
// recognisable shape at all.
func unparseable() observation {
	return observation{Unrecognized: true}
}

// observed runs one format's fold over a file and applies the outcomes every
// source shares. fill reports whether the document had a shape it recognised.
// Whitespace holds nothing and is not a failure; bytes with no recognisable shape
// are a failure, since reporting those as holding nothing would describe an
// unreadable credential file as a clean machine. Each is a silent under-report if
// a format decides it alone, and the byte-order mark comes off here for the same
// reason.
func observed(data []byte, fill func(data []byte, f *fold) bool) observation {
	body := stripBOM(data)
	if blank(body) {
		return observation{}
	}
	var f fold
	if !fill(body, &f) {
		return unparseable()
	}
	return f.result()
}

// parser turns one source's bytes into an observation.
type parser func(data []byte) observation

// parsers is the whole dispatch: one entry per catalog source that gets read.
// Keeping it as data makes its invariant checkable — every source the agent opens
// has a reader, and every reader is reachable from a source — so a source added
// without one fails the suite rather than reporting an unreadable file.
var parsers = map[string]parser{
	sourceAWSCredentials:       parseAWSProfiles,
	sourceAWSConfig:            parseAWSProfiles,
	sourceGCPADC:               parseGCPADC,
	sourceGitCredentials:       parseGitCredentials,
	sourceNetrc:                parseNetrc,
	sourceGitHubCLIHosts:       parseGitHubCLIHosts,
	sourceNPMRC:                parseNPMRC,
	sourcePypirc:               parsePypirc,
	sourceDockerConfig:         parseDockerConfig,
	sourceKubeconfig:           parseKubeconfig,
	sourceTerraformCredentials: parseTerraformCredentials,
	sourceVaultToken:           parseVaultToken,
	sourceInsomnia:             parseInsomnia,
}

// parseSource reads one location with the parser its source declares. A source
// with no parser is reported uninterpreted rather than empty: describing the file
// as holding nothing would turn this agent's own gap into a claim about the machine.
func parseSource(s source, data []byte) observation {
	parse, ok := parsers[s.ID]
	if !ok {
		return unparseable()
	}
	return parse(data)
}

// awsInlineSecretKeys hold usable material in the file itself. Only presence is
// inspected: the identifier prefix that says whether a key is long or short lived
// is derived from the credential's own characters, so it is never read. The access
// key identifier is absent deliberately — it names a credential, it is not one.
//
// Every other AWS credential mechanism — a helper process, a single-sign-on
// session, an assumed role, a web identity token file — puts material somewhere
// this file does not reach, so none of them appears here or anywhere below.
var awsInlineSecretKeys = []string{"aws_secret_access_key", "aws_session_token"}

// parseAWSProfiles counts the profiles carrying credential material. It serves
// both AWS sources: separate catalog entries because independent variables
// relocate them, but either can legally hold the other's content.
func parseAWSProfiles(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		sections, malformed := parseINI(data, false)
		f.unrecognized = malformed
		for _, s := range sections {
			for _, p := range s.Pairs {
				if !slices.Contains(awsInlineSecretKeys, p.Key) || !concrete(p.Value) {
					continue
				}
				// One profile is one credential however many of its fields
				// carry material: the secret and its session token are halves
				// of the same grant.
				f.add(model.CredentialProtectionPlaintext)
				break
			}
		}
		return true
	})
}

// npmAuthKeys are the documented fields that carry a registry credential. Keys
// naming TLS files are absent: a path is not a secret.
var npmAuthKeys = []string{"_auth", "_authtoken", "_password"}

// parseNPMRC counts the registry credentials written into the file.
func parseNPMRC(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		// This format spells a boolean setting as a bare word.
		sections, malformed := parseINI(data, true)
		f.unrecognized = malformed
		for _, s := range sections {
			for _, p := range s.Pairs {
				// A list suffix is part of the setting's spelling, not its name.
				if isNPMAuthKey(strings.TrimSuffix(p.Key, "[]")) && concrete(p.Value) {
					f.add(model.CredentialProtectionPlaintext)
				}
			}
		}
		return true
	})
}

// isNPMAuthKey reports whether a setting names a credential. The name is
// compared whole rather than by its ending: these keys are scoped by a registry
// URI prefix and nothing else about their spelling is free, so a setting that
// merely ends in one of these words is a different setting and counting it would
// report a credential the file does not hold.
func isNPMAuthKey(key string) bool {
	// A scoped key carries its registry before the final colon.
	if i := strings.LastIndexByte(key, ':'); i >= 0 {
		key = key[i+1:]
	}
	return slices.Contains(npmAuthKeys, key)
}

// pypircIndexList is the section that names the servers rather than describing
// one. Its fields configure the list, so a password written there is a login to
// nothing the tool would ever present it to.
const pypircIndexList = "distutils"

// parsePypirc counts the index servers that carry a password. Server and user
// names are read to find the sections and then discarded: a private index host is
// internal infrastructure detail. A server configured without a password is a
// login the tool completes from a keyring or a prompt, so it is not counted.
func parsePypirc(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		sections, malformed := parseINI(data, false)
		f.unrecognized = malformed
		for _, s := range sections {
			// A password belongs to the server whose section holds it. The
			// leading section names no server at all, and the index list names
			// the set rather than a login to any member of it.
			if s.Name == "" || strings.EqualFold(s.Name, pypircIndexList) {
				continue
			}
			if s.holds("password") {
				f.add(model.CredentialProtectionPlaintext)
			}
		}
		return true
	})
}

// parseGitCredentials counts the stored logins in the credential store file. Each
// line is a URL whose userinfo carries the credential; the host is parsed only to
// establish the line is real, and the userinfo only for the password.
func parseGitCredentials(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		scanLines(data, func(line string) bool {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				return true
			}
			if u, err := url.Parse(trimmed); err == nil && u.Host != "" {
				if u.User != nil {
					if password, set := u.User.Password(); set && concrete(password) {
						f.add(model.CredentialProtectionPlaintext)
					}
				}
				return true
			}
			// An unescaped character in the password is enough to fail a strict
			// parse, so a structural reading is what keeps a plaintext credential
			// from being dropped. A line neither reading recognises is not called
			// clean: this file has one shape, and something else in it is a shape
			// this build cannot account for.
			password, recognized := structuralURLPassword(trimmed)
			switch {
			case !recognized:
				f.unrecognized = true
			case concrete(password):
				f.add(model.CredentialProtectionPlaintext)
			}
			return true
		})
		return true
	})
}

// structuralURLPassword extracts the password from a line the strict parser
// rejected, and reports whether the line is a credential URL at all. The host is
// validated separately so a line that merely contains an at-sign cannot pass as
// one. Nothing but the password is returned, and nothing at all is retained.
func structuralURLPassword(line string) (string, bool) {
	scheme, rest, ok := strings.Cut(line, "://")
	if !ok || scheme == "" {
		return "", false
	}
	// The last at-sign separates userinfo from host: an at-sign inside the
	// password is legal and unescaped in files these helpers write.
	at := strings.LastIndexByte(rest, '@')
	if at <= 0 || at == len(rest)-1 {
		return "", false
	}
	host, err := url.Parse("//" + rest[at+1:])
	if err != nil || host.Host == "" || host.User != nil {
		return "", false
	}
	userinfo := rest[:at]
	colon := strings.IndexByte(userinfo, ':')
	if colon < 0 {
		// A username with no password: a real entry holding no material.
		return "", true
	}
	return userinfo[colon+1:], true
}

// netrcDirectives is the whole grammar of the network login file. A token that is
// neither one of these nor the value of one is text this build cannot account for.
var netrcDirectives = []string{"machine", "default", "login", "password", "account", "macdef"}

func isNetrcDirective(token string) bool {
	return slices.Contains(netrcDirectives, strings.ToLower(token))
}

// parseNetrc counts the machine entries that carry a concrete password. Names,
// logins and account fields are consumed by the tokeniser and discarded: this
// inventory does not report who you log in to.
func parseNetrc(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		// Entries are whitespace-separated token pairs that may wrap across
		// lines, so the state machine carries across the line loop.
		inEntry := false
		hasPassword := false
		inMacro := false
		pendingKey := ""
		// Set where a directive appeared in the place its predecessor's value
		// belonged, which leaves this entry's fields ambiguous: whatever follows
		// cannot be attributed to the field it looks like it belongs to.
		spoiled := false

		closeEntry := func() {
			if inEntry && hasPassword && !spoiled {
				f.add(model.CredentialProtectionPlaintext)
			}
			inEntry, hasPassword, spoiled = false, false, false
		}

		scanLines(data, func(line string) bool {
			// A macro definition runs to the next blank line and its body is
			// arbitrary commands. Tokenising it would invent entries out of
			// text that is not configuration.
			if inMacro {
				if strings.TrimSpace(line) == "" {
					inMacro = false
				}
				return true
			}
			// Stripped before tokenising, so commented-out text cannot supply a
			// value to the directive above it.
			content, _, _ := strings.Cut(line, "#")
			for _, token := range strings.Fields(content) {
				if pendingKey != "" {
					if !isNetrcDirective(token) {
						if pendingKey == "password" && concrete(token) {
							hasPassword = true
						}
						pendingKey = ""
						continue
					}
					// A directive where a value belongs leaves the previous
					// directive unterminated, and the entry incomplete.
					f.unrecognized = true
					spoiled = true
					pendingKey = ""
				}
				switch strings.ToLower(token) {
				case "machine":
					closeEntry()
					inEntry = true
					// The host name follows and is consumed without being read.
					pendingKey = "machine"
				case "default":
					// The catch-all entry names no host, so nothing follows it.
					closeEntry()
					inEntry = true
				case "login", "password", "account":
					pendingKey = strings.ToLower(token)
				case "macdef":
					// The macro name is the rest of this line and the body
					// follows; neither is configuration.
					inMacro = true
					return true
				default:
					f.unrecognized = true
				}
			}
			return true
		})
		if pendingKey != "" {
			// The file ended where a value was owed, so the entry being built was
			// never completed. Its password is dropped with the rest of it: an
			// entry that stops mid-directive is one this build cannot say it read.
			f.unrecognized = true
			spoiled = true
		}
		closeEntry()
		return true
	})
}

// parseVaultToken reads the one source whose whole contents are the credential.
// The bytes are compared against nothing and retained nowhere: the value is
// trimmed, tested for being a reference rather than material, and dropped with
// the buffer when this returns.
func parseVaultToken(data []byte) observation {
	value := strings.TrimSpace(string(data))
	if !concrete(value) {
		return observation{}
	}
	return observation{Count: 1, Protection: model.CredentialProtectionPlaintext}
}

// fileInput is what an AI-tool or MCP parser is given for one file. The path
// selects the document shape, since one source spans several files, and anchors
// any file the document refers to.
type fileInput struct {
	Path string
	// Nil for a database, whose rows arrive in Rows instead.
	Data   []byte
	Rows   []dbRow
	SQLite bool
	// The file was named as a configuration, so its name does not select its
	// shape.
	Config bool
	Home   string
	// The source's other files that are not databases, for a document whose
	// meaning depends on a declaration kept beside it.
	Companions []candidate
	// Reads an associated file through the same guard. It records its own
	// refusals and bounds, so nil means only "nothing usable".
	Read func(path string, limit int64) []byte
	// Whether the tenant opted in to key fragments.
	Fragments bool
}

// parsed is one file's observation plus what only these sources can report: an
// encrypted store whose contents cannot be counted, a reference this build
// could not resolve, and the files a reference names.
type parsed struct {
	observation
	Opaque     bool
	Unresolved bool
	Refs       []fileRef
	// The fragments of the recognized keys counted, when the tenant opted in,
	// and whether the per-finding bound left any out.
	Hints        []model.CredentialKeyFragment
	HintsDropped bool
}

// fileRef is a file another file names as the holder of its secret. Raw means
// the whole file is the secret; otherwise it is a dotenv file. Key carries
// whether the naming slot holds an API key, which a raw file's secret takes on.
type fileRef struct {
	Path string
	Raw  bool
	Key  bool
}

// fileParser reads one file of an AI-tool or MCP source.
type fileParser func(in fileInput) parsed

// fileParsers is the dispatch for the AI-tool and MCP sources, kept apart from
// parsers because these read several shapes per source and report more than an
// observation.
var fileParsers = map[string]fileParser{
	sourceClaudeCode:      parseClaudeCode,
	sourceCodex:           parseCodex,
	sourceOpenCode:        parseOpenCode,
	sourcePi:              parsePi,
	sourceHermes:          parseHermes,
	sourceCopilotCLI:      parseCopilotCLI,
	sourceCursor:          parseCursor,
	sourceVSCode:          parseVSCode,
	sourceClaudeMCP:       parseClaudeMCP,
	sourceCodexMCP:        parseCodexMCP,
	sourceOpenCodeMCP:     parseOpenCodeMCP,
	sourcePiMCP:           parsePiMCP,
	sourceHermesMCP:       parseHermesMCP,
	sourceCopilotCLIMCP:   parseCopilotCLIMCP,
	sourceCursorMCP:       parseCursorMCP,
	sourceVSCodeMCP:       parseVSCodeMCP,
	sourceSharedMCPConfig: parseSharedMCPConfig,
}

// entry records one retained credential and reports whether it was counted.
// These files hold their material as text, so every entry is plaintext; an
// encrypted store is reported opaque rather than counted.
func (f *fold) entry() bool {
	if f.count >= maxAICount {
		f.capped = true
		return false
	}
	f.add(model.CredentialProtectionPlaintext)
	return true
}

// key records one API-key slot. With fragments on, a value that is wholly a
// recognized provider key also leaves its fragment. A fragment is only ever
// kept for a counted entry, so a location's occurrences never exceed its count.
func (f *fold) key(value string) {
	if !f.entry() || !f.fragments {
		return
	}
	hint, ok := keyHint(value)
	if !ok {
		return
	}
	if _, seen := f.hints[hint]; !seen && len(f.hints) >= maxHintsPerFinding {
		f.dropped = true
		return
	}
	if f.hints == nil {
		f.hints = map[model.CredentialKeyFragment]int{}
	}
	f.hints[hint]++
}

// absorb adds another fold's entries and fragments to this one.
func (f *fold) absorb(o *fold) {
	for range o.count {
		f.entry()
	}
	f.unrecognized = f.unrecognized || o.unrecognized
	f.dropped = f.dropped || o.dropped
	if f.capped {
		// Past the bound the entries were not all counted, so their fragments
		// could outnumber the count.
		f.dropped = f.dropped || len(o.hints) > 0
		return
	}
	for hint, n := range o.hints {
		if _, seen := f.hints[hint]; !seen && len(f.hints) >= maxHintsPerFinding {
			f.dropped = true
			continue
		}
		if f.hints == nil {
			f.hints = map[model.CredentialKeyFragment]int{}
		}
		f.hints[hint] += n
	}
}

// into closes the fold into a file's result.
func (f *fold) into(p *parsed) {
	p.observation = f.result()
	f.hintsInto(p)
}

// hintsInto hands the fold's fragments to a file's result, in a fixed order.
func (f *fold) hintsInto(p *parsed) {
	p.HintsDropped = f.dropped
	for hint, n := range f.hints {
		hint.Occurrences = n
		p.Hints = append(p.Hints, hint)
	}
	slices.SortFunc(p.Hints, func(a, b model.CredentialKeyFragment) int {
		return strings.Compare(a.CredentialType+"\x00"+a.Prefix+"\x00"+a.Suffix, b.CredentialType+"\x00"+b.Prefix+"\x00"+b.Suffix)
	})
}

// maxHintsPerFinding bounds the distinct fragments one location reports.
const maxHintsPerFinding = 100

// keyFamily is one provider key format: its type, its public prefix, and the
// whole-value form a key of that family takes.
type keyFamily struct {
	typ    string
	prefix string
	form   *regexp.Regexp
}

// keyFamilies are ordered longest prefix first, so a key is judged by the most
// specific family its prefix names and never falls back to a shorter one. Each
// form is anchored and ASCII-only; every body is at least 36 characters, so the
// three leading and four trailing characters kept never meet.
var keyFamilies = []keyFamily{
	{"anthropic_admin_api_key", "sk-ant-admin01-", regexp.MustCompile(`^sk-ant-admin01-[A-Za-z0-9_-]{93}AA$`)},
	{"anthropic_api_key", "sk-ant-api03-", regexp.MustCompile(`^sk-ant-api03-[A-Za-z0-9_-]{93}AA$`)},
	{"openai_service_account_api_key", "sk-svcacct-", regexp.MustCompile(`^sk-svcacct-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})$`)},
	{"github_fine_grained_pat", "github_pat_", regexp.MustCompile(`^github_pat_[A-Za-z0-9_]{82}$`)},
	{"openai_admin_api_key", "sk-admin-", regexp.MustCompile(`^sk-admin-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})$`)},
	{"openrouter_api_key", "sk-or-v1-", regexp.MustCompile(`^sk-or-v1-[0-9a-f]{64}$`)},
	{"openai_project_api_key", "sk-proj-", regexp.MustCompile(`^sk-proj-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})$`)},
	{"github_classic_pat", "ghp_", regexp.MustCompile(`^ghp_[A-Za-z0-9]{36}$`)},
	{"openai_legacy_api_key", "sk-", regexp.MustCompile(`^sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}$`)},
}

// keyFamilyOf returns the family a value wholly belongs to, if any.
func keyFamilyOf(value string) (keyFamily, bool) {
	for _, family := range keyFamilies {
		if strings.HasPrefix(value, family.prefix) {
			return family, family.form.MatchString(value)
		}
	}
	return keyFamily{}, false
}

// keyHint derives a recognized key's fragment: the family prefix and the next
// three characters, and the last four. Both are copied so the fragment does
// not keep the whole key reachable.
func keyHint(value string) (model.CredentialKeyFragment, bool) {
	family, ok := keyFamilyOf(value)
	if !ok {
		return model.CredentialKeyFragment{}, false
	}
	return model.CredentialKeyFragment{
		CredentialType: family.typ,
		Prefix:         strings.Clone(value[:len(family.prefix)+3]),
		Suffix:         strings.Clone(value[len(value)-4:]),
	}, true
}

// grammar is one client's rule for telling a value written into its file from a
// reference to material kept elsewhere. Clients disagree: one tool's "$NAME" is
// another's literal key, so no single test serves them all.
type grammar struct {
	// Tokens the client substitutes when it reads the value. Nil means the
	// client substitutes nothing and every value is literal.
	refs *regexp.Regexp
	// "${NAME:-fallback}" keeps the fallback in the field, so it is literal.
	fallback bool
	// A value starting with this runs a command or names a vault instead of
	// holding material.
	helper string
	// "{file:path}" names the file the client reads the value from.
	files bool
}

var (
	literalGrammar = grammar{}
	// Claude Code and the portable project file expand "${NAME}" and keep a
	// fallback written after ":-".
	claudeGrammar = grammar{refs: regexp.MustCompile(`\$\{[^}]*\}`), fallback: true}
	// Copilot CLI MCP fields also expand a bare "$NAME" and "${secret:...}".
	copilotMCPGrammar = grammar{refs: regexp.MustCompile(`\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*`), fallback: true}
	// Pi interpolates anywhere in a string, runs "!command", and writes "$$"
	// and "$!" for the literal characters.
	piGrammar = grammar{refs: regexp.MustCompile(`\$\$|\$!|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*`), helper: "!"}
	// OpenCode substitutes "{env:NAME}" and "{file:path}".
	openCodeGrammar = grammar{refs: regexp.MustCompile(`\{(?:env|file):[^}]*\}`), files: true}
	// Hermes expands "${NAME}" and resolves "op://" from a password manager.
	hermesGrammar = grammar{refs: regexp.MustCompile(`\$\{[^}]*\}`), helper: "op://"}
	// Cursor and VS Code substitute "${env:NAME}", "${input:id}" and their
	// public path variables.
	editorGrammar = grammar{refs: regexp.MustCompile(`\$\{[^}]*\}`)}
)

// literal reports whether a value holds characters of its own once the
// client's references are taken out. A value that is nothing but references
// defers to material held elsewhere.
func (g grammar) literal(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || (g.helper != "" && strings.HasPrefix(value, g.helper)) {
		return false
	}
	if g.refs == nil {
		return true
	}
	rest := g.refs.ReplaceAllStringFunc(value, func(tok string) string {
		if tok == "$$" || tok == "$!" {
			return tok[1:]
		}
		if g.fallback {
			if _, def, ok := strings.Cut(tok, ":-"); ok {
				return strings.TrimSuffix(def, "}")
			}
		}
		return ""
	})
	return strings.TrimSpace(rest) != ""
}

// literalAny is literal for a decoded field, which only counts as a string.
func (g grammar) literalAny(v any) bool {
	s, ok := v.(string)
	return ok && g.literal(s)
}

// headerCredential takes the scheme word off an authentication header, so a
// scheme name alone, such as "Bearer " before a reference, is not counted as a
// credential and a key after it is judged whole.
func headerCredential(value string) string {
	if scheme, rest, ok := strings.Cut(strings.TrimSpace(value), " "); ok && authSchemes[strings.ToLower(scheme)] {
		return rest
	}
	return value
}

// authSchemes are the scheme words that precede a credential in a header.
var authSchemes = map[string]bool{"bearer": true, "basic": true, "token": true, "digest": true}

// providerEnvNames are the provider key variables a tool keeps in its own
// environment settings, matched exactly.
var providerEnvNames = map[string]bool{
	"OPENAI_API_KEY":          true,
	"ANTHROPIC_API_KEY":       true,
	"ANTHROPIC_AUTH_TOKEN":    true,
	"CLAUDE_CODE_OAUTH_TOKEN": true,
	"OPENROUTER_API_KEY":      true,
	"GEMINI_API_KEY":          true,
	"GOOGLE_API_KEY":          true,
	"AZURE_OPENAI_API_KEY":    true,
	"GROQ_API_KEY":            true,
	"MISTRAL_API_KEY":         true,
	"DEEPSEEK_API_KEY":        true,
	"TOGETHER_API_KEY":        true,
}

// mcpEnvNames are the variables commonly passed to MCP servers, counted only
// inside a server's environment map.
var mcpEnvNames = map[string]bool{
	"GITHUB_TOKEN":                 true,
	"GITHUB_PERSONAL_ACCESS_TOKEN": true,
	"BRAVE_API_KEY":                true,
	"SLACK_BOT_TOKEN":              true,
}

// urlQueryNames are the query parameters, folded like environment names, whose
// value is a credential.
var urlQueryNames = map[string]bool{
	"token":         true,
	"api_token":     true,
	"api_key":       true,
	"apikey":        true,
	"access_token":  true,
	"refresh_token": true,
	"client_secret": true,
	"password":      true,
	"passwd":        true,
}

// keyFlags are the secret flags whose value is an API key or access token.
var keyFlags = map[string]bool{"--token": true, "--api-key": true, "--api_key": true}

// secretFlags are the command-line flags whose value is a credential. Flags
// that take a key identifier, a file or an ambiguous value are absent.
var secretFlags = map[string]bool{
	"--password":      true,
	"--passwd":        true,
	"--pass":          true,
	"--pwd":           true,
	"--secret":        true,
	"--token":         true,
	"--api-key":       true,
	"--api_key":       true,
	"--client-secret": true,
	"--client_secret": true,
}

// secretEnvName reports whether a variable's value is a credential: the generic
// names, the provider key names, and inside an MCP server's environment the
// common server token names.
func secretEnvName(name string, mcp bool) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	return insomniaEnvKeys[insomniaEnvName(name)] || providerEnvNames[upper] || (mcp && mcpEnvNames[upper])
}

// keyNames are the generic variable and query names, folded like environment
// names, whose value is an API key or access token rather than a password, a
// client secret or an OAuth grant.
var keyNames = map[string]bool{"token": true, "api_token": true, "api_key": true, "apikey": true}

// keyEnvName reports whether a credential variable holds an API key, so a
// recognized value may leave a fragment. Subscription sign-in tokens do not.
func keyEnvName(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if upper == "CLAUDE_CODE_OAUTH_TOKEN" {
		return false
	}
	return keyNames[insomniaEnvName(name)] || providerEnvNames[upper] || mcpEnvNames[upper]
}

// counter counts the credential slots of one document under one client's
// grammar. A slot whose value defers elsewhere is not counted; where the client
// resolves it from a file, that file is named instead, and where it is a VS Code
// input, the input is noted so the cached value can be matched to it.
type counter struct {
	f *fold
	p *parsed
	g grammar
	// The directory a relative file reference resolves against, and the
	// project a "${workspaceFolder}" names, when the file belongs to one.
	dir       string
	home      string
	workspace string
	// Input identifiers that feed a credential slot, collected only when set,
	// each true while every slot it feeds holds an API key.
	inputs map[string]bool
}

// openCodeFileRef matches OpenCode's file substitution and captures its path.
var openCodeFileRef = regexp.MustCompile(`\{file:([^}]*)\}`)

// editorInputRef matches a VS Code input substitution and captures its id.
var editorInputRef = regexp.MustCompile(`\$\{input:([^}]*)\}`)

// value counts one credential field that is not an API key: a password, a
// client secret, a private key or a sign-in token.
func (c counter) value(v any) {
	if s, ok := v.(string); ok {
		c.slot(s, false)
	}
}

// key counts one API-key or access-token field.
func (c counter) key(v any) {
	if s, ok := v.(string); ok {
		c.slot(s, true)
	}
}

// header counts one authentication header value.
func (c counter) header(v any) {
	if s, ok := v.(string); ok {
		c.slot(headerCredential(s), true)
	}
}

// slot counts a literal, or follows what a reference names.
func (c counter) slot(s string, key bool) {
	if c.g.literal(s) {
		if key {
			c.f.key(s)
		} else {
			c.f.entry()
		}
		return
	}
	if c.inputs != nil {
		for _, m := range editorInputRef.FindAllStringSubmatch(s, -1) {
			allKeys, fed := c.inputs[m[1]]
			c.inputs[m[1]] = key && (allKeys || !fed)
		}
	}
	if c.p == nil || !c.g.files {
		return
	}
	for _, m := range openCodeFileRef.FindAllStringSubmatch(s, -1) {
		c.ref(m[1], true, key)
	}
}

// ref names a file holding a secret, anchored the way the client anchors it:
// "~" is the home and anything else relative is the configuration's directory.
func (c counter) ref(path string, raw, key bool) {
	path = strings.TrimSpace(path)
	switch {
	case path == "":
		return
	case path == "~" || strings.HasPrefix(path, "~/"):
		path = filepath.Join(c.home, path[1:])
	case !filepath.IsAbs(path):
		path = filepath.Join(c.dir, filepath.FromSlash(path))
	}
	c.p.Refs = append(c.p.Refs, fileRef{Path: path, Raw: raw, Key: key})
}

// object reads a field that must be an object when present. Another type is a
// document this build cannot account for.
func (c counter) object(v any) map[string]any {
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		c.f.unrecognized = true
	}
	return m
}

// list reads a field that must be a list when present.
func (c counter) list(v any) []any {
	if v == nil {
		return nil
	}
	l, ok := v.([]any)
	if !ok {
		c.f.unrecognized = true
	}
	return l
}

// env counts the credential variables of one environment map. A server's
// variable of any name also counts when its value is wholly a recognized
// provider key: servers name their key variables freely.
func (c counter) env(v any, mcp bool) {
	for name, value := range c.object(v) {
		switch {
		case secretEnvName(name, mcp) && keyEnvName(name):
			c.key(value)
		case secretEnvName(name, mcp):
			c.value(value)
		case mcp:
			if s, ok := value.(string); ok {
				if _, known := keyFamilyOf(s); known {
					c.key(s)
				}
			}
		}
	}
}

// headers counts the authentication headers of one header map.
func (c counter) headers(v any) {
	for name, value := range c.object(v) {
		if insomniaHeaderNames[strings.ToLower(strings.TrimSpace(name))] {
			c.header(value)
		}
	}
}

// url counts the credentials a URL carries: a password in its user info and
// each credential query parameter. A user name alone is an identifier.
func (c counter) url(v any) {
	raw, ok := v.(string)
	if !ok {
		return
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return
	}
	if pw, ok := u.User.Password(); ok {
		c.slot(pw, false)
	}
	for name, values := range u.Query() {
		folded := insomniaEnvName(name)
		if !urlQueryNames[folded] {
			continue
		}
		// One literal is the parameter's credential; without one, each value
		// may still name where the client reads it from.
		if i := slices.IndexFunc(values, c.g.literal); i >= 0 {
			c.slot(values[i], keyNames[folded])
			continue
		}
		for _, v := range values {
			c.slot(v, keyNames[folded])
		}
	}
}

// args counts the credentials passed on a server's command line: the value of
// a secret flag, in either the split or the "=" form, and an authentication
// header given to "--header" or "-H".
func (c counter) args(v any) {
	args := c.list(v)
	for i := 0; i < len(args); i++ {
		arg, ok := args[i].(string)
		if !ok {
			continue
		}
		flag, value, joined := strings.Cut(arg, "=")
		isHeader := flag == "--header" || flag == "-H"
		if !secretFlags[flag] && !isHeader {
			continue
		}
		if !joined {
			if i+1 >= len(args) {
				continue
			}
			i++
			if value, ok = args[i].(string); !ok {
				continue
			}
		}
		if !isHeader {
			c.slot(value, keyFlags[flag])
			continue
		}
		if name, hv, ok := strings.Cut(value, ":"); ok && insomniaHeaderNames[strings.ToLower(strings.TrimSpace(name))] {
			c.header(hv)
		}
	}
}

// field counts the non-key value at a path of nested objects.
func (c counter) field(v any, path ...string) {
	c.value(c.at(v, path...))
}

// at reads the value at a path of nested objects. A false in place of an
// object is how a client switches the feature off, so nothing is below it.
func (c counter) at(v any, path ...string) any {
	for _, key := range path {
		if v == false {
			return nil
		}
		m := c.object(v)
		if m == nil {
			return nil
		}
		v = m[key]
	}
	return v
}

// grant counts one OAuth grant or account record: one credential however many
// of its fields hold a literal. A field holding a structure instead is
// material this build cannot read, so the record is reported rather than
// passed over as empty.
func (c counter) grant(v any, keys ...string) {
	m := c.object(v)
	switch {
	case slices.ContainsFunc(keys, func(k string) bool { return c.g.literalAny(m[k]) }):
		c.f.entry()
	case slices.ContainsFunc(keys, func(k string) bool { return holdsValues(m[k]) }):
		c.f.unrecognized = true
	}
}

// holdsValues reports whether a decoded field is a non-empty object or list.
func holdsValues(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		return len(v) > 0
	case []any:
		return len(v) > 0
	}
	return false
}

// observedKeys is observed for an AI-tool or MCP file, carrying the fragments
// of the keys it counted.
func observedKeys(data []byte, fragments bool, fill func(data []byte, f *fold) bool) parsed {
	var p parsed
	p.observation = observed(data, func(data []byte, f *fold) bool {
		f.fragments = fragments
		if !fill(data, f) {
			return false
		}
		f.hintsInto(&p)
		return true
	})
	return p
}

// parseDotenv counts the credential variables of a dotenv file named by a
// server's configuration, which is the server's environment.
func parseDotenv(data []byte, fragments bool) parsed {
	return observedKeys(data, fragments, func(data []byte, f *fold) bool {
		for name, value := range dotenvPairs(data) {
			if !literalGrammar.literal(value) || isEnvRef(value) {
				continue
			}
			_, known := keyFamilyOf(value)
			switch secret := secretEnvName(name, true); {
			case secret && !keyEnvName(name):
				f.entry()
			case secret || known:
				f.key(value)
			}
		}
		return true
	})
}

// dotenvPairs reads "NAME=value" lines, with an optional "export" and quotes.
// A later assignment replaces an earlier one, as the loaders apply them.
func dotenvPairs(data []byte) map[string]string {
	out := map[string]string{}
	scanLines(stripBOM(data), func(line string) bool {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			return true
		}
		line = strings.TrimPrefix(line, "export ")
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !ok || !validEnvName(name) {
			return true
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		out[name] = value
		return true
	})
	return out
}

// rawSecret counts a file whose whole contents are one secret, judged as a key
// without the line ending a file conventionally closes with.
func rawSecret(data []byte, fragments bool) parsed {
	var p parsed
	body := stripBOM(data)
	if blank(body) {
		return p
	}
	f := fold{fragments: fragments}
	f.key(strings.TrimRight(string(body), "\r\n"))
	f.into(&p)
	return p
}
