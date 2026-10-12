package credentials

import (
	"bytes"
	"net/url"
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
