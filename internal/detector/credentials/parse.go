package credentials

import (
	"bytes"
	"net/url"
	"path"
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

// parseINI reads the INI dialect the credential files in this catalog use.
// Deliberately tolerant: a malformed line is skipped rather than failing the
// file, because one bad line must not hide the entries around it. Keys are
// lowercased, values keep their spelling less surrounding quotes, and pairs
// before any header land in a leading section with an empty name.
func parseINI(data []byte) []iniSection {
	sections := []iniSection{{}}
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
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			return true
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:eq]))
		if key == "" {
			return true
		}
		value := strings.TrimSpace(trimmed[eq+1:])
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		last := len(sections) - 1
		sections[last].Pairs = append(sections[last].Pairs, iniPair{Key: key, Value: value})
		return true
	})
	return sections
}

// get returns the first value for a key, and whether it was present.
func (s iniSection) get(key string) (string, bool) {
	for _, p := range s.Pairs {
		if p.Key == key {
			return p.Value, true
		}
	}
	return "", false
}

// has reports whether any named key carries a non-empty value. A key present
// but empty is not a credential: tools write an empty value to mean "unset",
// and counting it would report a credential where the developer removed one.
func (s iniSection) has(keys ...string) bool {
	for _, key := range keys {
		if v, ok := s.get(key); ok && v != "" {
			return true
		}
	}
	return false
}

// structured reports whether an INI parse found any shape at all. A file with
// bytes but no shape is a parse failure, which is a different outcome from a
// file with shape and nothing credential-bearing in it.
func structured(sections []iniSection) bool {
	return len(sections) > 1 || len(sections[0].Pairs) > 0
}

// blank reports a file of nothing but whitespace — neither a credential nor a
// parse failure: a tool wrote a placeholder, or the developer emptied it.
func blank(data []byte) bool {
	return len(bytes.TrimSpace(data)) == 0
}

// isEnvRef reports whether a value defers to an environment variable rather
// than carrying a secret. These are the forms the surrounding tools expand at
// read time, so a value in this shape means the material is not in the file.
func isEnvRef(value string) bool {
	return strings.Contains(value, "${") || strings.HasPrefix(value, "$")
}

// protectionRank orders the states from safest to worst. `unknown` outranks
// `protected` deliberately: ranking it lower would let one unrecognised entry
// inherit the protection of the entries beside it.
var protectionRank = map[string]int{
	model.CredentialProtectionExternal:  1,
	model.CredentialProtectionProtected: 2,
	model.CredentialProtectionUnknown:   3,
	model.CredentialProtectionPlaintext: 4,
}

// fold accumulates the worst protection state across one source's entries and
// counts them. Folding the other way would describe a file by its safest part
// and hide the exposure sitting beside it.
type fold struct {
	count int
	state string
}

// add records one entry. An unrecognised state becomes `unknown` rather than
// being dropped, so a parser that grows a case and forgets to map it cannot
// silently improve a file's reported protection.
func (f *fold) add(state string) {
	f.count++
	if _, known := protectionRank[state]; !known {
		state = model.CredentialProtectionUnknown
	}
	if protectionRank[state] > protectionRank[f.state] {
		f.state = state
	}
}

// empty reports that nothing was found to fold. That source produces no
// finding: the file existed but held no credential and no reference to one.
func (f *fold) empty() bool { return f.count == 0 }

// observation is the result of reading one credential location.
type observation struct {
	// Credentials for the plaintext, protected and unknown states;
	// configuration references for external.
	Count int
	// The worst state among those entries.
	Protection string
}

// result closes the fold. Only meaningful when empty() is false.
func (f *fold) result() observation {
	return observation{Count: f.count, Protection: f.state}
}

// unparseable is the observation for a file that exists, was read, and could not
// be interpreted. One entry rather than none, because zero would describe the
// machine as not having the file; `unknown` because a parse failure says nothing
// about what guards the contents.
func unparseable() observation {
	return observation{Count: 1, Protection: model.CredentialProtectionUnknown}
}

// observed runs one format's fold over a file and applies the outcomes every
// source shares. fill reports whether the document had a shape it recognised.
// Whitespace holds nothing and is not a failure; bytes with no recognisable shape
// are a failure, since reporting those as holding nothing would describe an
// unreadable credential file as a clean machine; shape with nothing
// credential-bearing in it holds nothing. Each is a silent under-report if a
// format decides it alone, and the byte-order mark comes off here for the same
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
	if f.empty() {
		return observation{}
	}
	return f.result()
}

// parser turns one source's bytes into an observation. The path is a parameter
// because one family shares a parser across three serialisations distinguished by
// extension. Only one source populates the host list.
type parser func(path string, data []byte) (observation, []githubHostConfig)

// fromBytes adapts a parser that needs neither the path nor a host list.
func fromBytes(parse func(data []byte) observation) parser {
	return func(_ string, data []byte) (observation, []githubHostConfig) {
		return parse(data), nil
	}
}

// parsers is the whole dispatch: one entry per catalog source that gets read.
// Keeping it as data makes its invariant checkable — every source the agent opens
// has a reader, and every reader is reachable from a source — so a source added
// without one fails the suite rather than reporting an unreadable file.
var parsers = map[string]parser{
	sourceAWSCredentials:       fromBytes(parseAWSProfiles),
	sourceAWSConfig:            fromBytes(parseAWSProfiles),
	sourceGCPADC:               fromBytes(parseGCPADC),
	sourceGitCredentials:       fromBytes(parseGitCredentials),
	sourceNetrc:                fromBytes(parseNetrc),
	sourceGitconfigHelper:      fromBytes(parseGitconfigHelper),
	sourceNPMRC:                fromBytes(parseNPMRC),
	sourcePypirc:               fromBytes(parsePypirc),
	sourceDockerConfig:         fromBytes(parseDockerConfig),
	sourceKubeconfig:           fromBytes(parseKubeconfig),
	sourceTerraformCredentials: fromBytes(parseTerraformCredentials),
	sourceMCPConfig: func(path string, data []byte) (observation, []githubHostConfig) {
		return parseMCPConfig(path, data), nil
	},
	sourceGitHubCLIHosts: func(_ string, data []byte) (observation, []githubHostConfig) {
		return parseGitHubCLIHosts(data)
	},
}

// parseSource reads one location with the parser its source declares. A source
// with no parser is reported unreadable rather than empty: describing the file as
// holding nothing would turn this agent's own gap into a claim about the machine.
func parseSource(s source, resolved string, data []byte) (observation, []githubHostConfig) {
	parse, ok := parsers[s.ID]
	if !ok {
		return unparseable(), nil
	}
	return parse(resolved, data)
}

// awsInlineSecretKeys hold usable material in the file itself. Only presence is
// inspected: the identifier prefix that says whether a key is long or short lived
// is derived from the credential's own characters, so it is never read.
var awsInlineSecretKeys = []string{"aws_secret_access_key", "aws_session_token"}

// awsExternalKeys name a credential the tool obtains elsewhere at run time: a
// helper process, a single-sign-on session, or a role it assumes through another
// profile. None puts material in this file.
var awsExternalKeys = []string{
	"credential_process",
	"credential_source",
	"sso_start_url",
	"sso_session",
	"sso_account_id",
	"sso_role_name",
	"role_arn",
	"source_profile",
	"web_identity_token_file",
}

// parseAWSProfiles counts the profiles that carry credential material or point at
// it. It serves both AWS sources: separate catalog entries because independent
// variables relocate them, but either can legally hold the other's content.
func parseAWSProfiles(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		sections := parseINI(data)
		if !structured(sections) {
			return false
		}
		for _, s := range sections {
			// A profile whose keys are all unrecognised holds no material and
			// points at nothing, so counting it would report a credential on
			// the strength of a section header.
			switch {
			case s.has(awsInlineSecretKeys...):
				f.add(model.CredentialProtectionPlaintext)
			case s.has(awsExternalKeys...):
				f.add(model.CredentialProtectionExternal)
			}
		}
		return true
	})
}

// npmAuthKeySuffixes are the trailing key segments that carry registry
// credentials, matched on the suffix because these keys are scoped by a registry
// URI prefix. Keys naming TLS files are absent: a path is not a secret.
var npmAuthKeySuffixes = []string{"_auth", "_authtoken", "_password", "-authtoken"}

// parseNPMRC counts registry credentials and folds whether each is written in the
// clear or deferred to the environment. Shallow on purpose: the same file is
// inventoried in depth elsewhere, and one entry here keeps a reader from wondering
// whether the category was checked at all.
func parseNPMRC(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		sections := parseINI(data)
		keyed := false
		for _, s := range sections {
			for _, p := range s.Pairs {
				keyed = true
				// A list suffix is part of the setting's spelling, not its name.
				if !isNPMAuthKey(strings.TrimSuffix(p.Key, "[]")) || p.Value == "" {
					continue
				}
				if isEnvRef(p.Value) {
					// Expanded when the package manager runs, so the material
					// lives in the developer's environment, not here.
					f.add(model.CredentialProtectionExternal)
					continue
				}
				f.add(model.CredentialProtectionPlaintext)
			}
		}
		// This format puts every value in a key, so a file of section headers
		// and no settings has not been read.
		return keyed
	})
}

func isNPMAuthKey(key string) bool {
	// A scoped key carries its registry before the final colon.
	if i := strings.LastIndexByte(key, ':'); i >= 0 {
		key = key[i+1:]
	}
	return slices.ContainsFunc(npmAuthKeySuffixes, func(suffix string) bool {
		return strings.HasSuffix(key, suffix)
	})
}

// parsePypirc counts the configured index servers and folds whether each carries
// a password. Server and user names are read to find the sections and then
// discarded: a private index host is internal infrastructure detail.
func parsePypirc(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		sections := parseINI(data)
		if !structured(sections) {
			return false
		}
		for _, s := range sections {
			// The index list itself is not a server entry.
			if strings.EqualFold(s.Name, "distutils") || s.Name == "" {
				continue
			}
			switch {
			case s.has("password"):
				value, _ := s.get("password")
				if isEnvRef(value) {
					f.add(model.CredentialProtectionExternal)
				} else {
					f.add(model.CredentialProtectionPlaintext)
				}
			case s.has("username", "repository"):
				// A server configured without a password is a login the tool
				// completes from a keyring or a prompt when it runs.
				f.add(model.CredentialProtectionExternal)
			}
		}
		return true
	})
}

// parseGitCredentials counts the stored logins in the credential store file. Each
// line is a URL whose userinfo carries the credential; the host is parsed only to
// establish the line is real, and the userinfo only for whether a password is set.
func parseGitCredentials(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		scanLines(data, func(line string) bool {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				return true
			}
			u, err := url.Parse(trimmed)
			if err != nil || u.Host == "" {
				// An unescaped character in the password is enough to fail the
				// parse, so the structural test keeps a strict parser from
				// turning a plaintext credential into an inconclusive one.
				if hasInlineURLPassword(trimmed) {
					f.add(model.CredentialProtectionPlaintext)
				} else {
					f.add(model.CredentialProtectionUnknown)
				}
				return true
			}
			if _, hasPassword := u.User.Password(); hasPassword {
				f.add(model.CredentialProtectionPlaintext)
				return true
			}
			// A user with no password is the store recording that this host is
			// authenticated without holding the secret for it.
			f.add(model.CredentialProtectionExternal)
			return true
		})
		// Every line in this format is an entry, so a file of comments has a
		// shape and simply holds nothing — the empty fold reports that.
		return true
	})
}

// hasInlineURLPassword reports whether a line has userinfo with both halves
// present. It looks at the separator positions only and reads neither half.
func hasInlineURLPassword(line string) bool {
	_, rest, ok := strings.Cut(line, "://")
	if !ok {
		return false
	}
	userinfo, _, ok := strings.Cut(rest, "@")
	if !ok {
		return false
	}
	_, secret, ok := strings.Cut(userinfo, ":")
	return ok && secret != ""
}

// parseNetrc counts the machine entries in the network login file and folds
// whether each carries a password. Names, logins and account fields are consumed
// by the tokeniser and discarded: this inventory does not report who you log in to.
func parseNetrc(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		// Entries are whitespace-separated token pairs that may wrap across
		// lines, so the state machine carries across the line loop.
		inEntry := false
		hasPassword := false
		inMacro := false
		pendingKey := ""

		closeEntry := func() {
			if !inEntry {
				return
			}
			if hasPassword {
				f.add(model.CredentialProtectionPlaintext)
			} else {
				// A login with no password beside it means the secret is
				// supplied from somewhere else when the tool runs.
				f.add(model.CredentialProtectionExternal)
			}
			inEntry, hasPassword = false, false
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
			for _, token := range strings.Fields(line) {
				if pendingKey != "" {
					if pendingKey == "password" {
						hasPassword = true
					}
					pendingKey = ""
					continue
				}
				switch strings.ToLower(token) {
				case "machine", "default":
					closeEntry()
					inEntry = true
				case "login", "password", "account", "port", "protocol":
					pendingKey = strings.ToLower(token)
				case "macdef":
					// The macro name is the rest of this line and the body
					// follows; neither is configuration.
					inMacro = true
					return true
				}
			}
			return true
		})
		closeEntry()
		return true
	})
}

// parseGitconfigHelper counts the configured credential helpers and classifies
// where each keeps the secret. The helper is the whole signal: the file holds no
// credential but says what the machine does with one. Nothing else is inspected.
func parseGitconfigHelper(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		sections := parseINI(data)
		if !structured(sections) {
			return false
		}
		for _, s := range sections {
			// Both the bare section and the per-URL form configure a helper,
			// and the name may repeat because the setting is a list.
			if !isCredentialSection(s.Name) {
				continue
			}
			for _, p := range s.Pairs {
				if p.Key != "helper" || p.Value == "" {
					continue
				}
				f.add(classifyGitHelper(p.Value))
			}
		}
		return true
	})
}

// isCredentialSection matches the credential section and its per-URL form,
// comparing the first word only so the URL in the quoted subsection is never
// interpreted.
func isCredentialSection(name string) bool {
	first, _, _ := strings.Cut(name, " ")
	return strings.EqualFold(strings.TrimSpace(first), "credential")
}

// classifyGitHelper decides where a helper keeps the secret. The plaintext-storing
// helper is the one case identified positively. Every other helper — a keystore, a
// cache, a custom program — leaves nothing readable here, so an unrecognised one is
// external rather than unknown: whatever it does, it is a redirection.
func classifyGitHelper(value string) string {
	name, _, _ := strings.Cut(strings.TrimSpace(value), " ")
	// A helper may be a shell fragment or an absolute path to a program.
	name = strings.TrimPrefix(name, "!")
	name = path.Base(strings.ReplaceAll(name, `\`, "/"))
	// An executable extension belongs to the file's name, not the helper's
	// identity: the same helper spelled as a path on Windows would otherwise
	// fail to match and a store in the clear would read as a redirection.
	switch ext := strings.ToLower(path.Ext(name)); ext {
	case ".exe", ".cmd", ".bat":
		name = name[:len(name)-len(ext)]
	}
	name = strings.TrimPrefix(name, "git-credential-")
	if strings.EqualFold(name, "store") {
		return model.CredentialProtectionPlaintext
	}
	return model.CredentialProtectionExternal
}
