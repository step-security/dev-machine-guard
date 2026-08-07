package credentials

import (
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// bomMark is what a Windows editor writes at the head of a text file.
const bomMark = "\xef\xbb\xbf"

// parseCase is one file's bytes and the observation its format owes for them.
type parseCase struct {
	name string
	body string
	want observation
}

// Shorthands so a table row can state its expectation inline. obsNone is a
// location that holds no credential and no reference to one.
func obsPlain(n int) observation {
	return observation{Count: n, Protection: model.CredentialProtectionPlaintext}
}
func obsExt(n int) observation {
	return observation{Count: n, Protection: model.CredentialProtectionExternal}
}
func obsUnk(n int) observation {
	return observation{Count: n, Protection: model.CredentialProtectionUnknown}
}

var obsNone observation

// runParseCases drives one format over its table. Every format answers the same two
// questions — how many credential-bearing entries, and guarded how — so they share
// one harness and each table carries only what differs.
func runParseCases(t *testing.T, parse func([]byte) observation, cases []parseCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := parse([]byte(tt.body)); got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestStripBOM(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no mark", "[default]\n", "[default]\n"},
		{"leading mark", bomMark + "[default]\n", "[default]\n"},
		{"mark only", bomMark, ""},
		{"empty", "", ""},
		// Only a leading mark is a byte-order mark. Mid-file the same bytes are a
		// zero-width no-break space and part of the content.
		{"interior mark retained", "a" + bomMark + "b", "a" + bomMark + "b"},
		// Doubled marks are malformed input rather than two marks, so the second
		// belongs to the content.
		{"double mark strips one", bomMark + bomMark + "x", bomMark + "x"},
		// A UTF-16 mark is a different encoding and must pass through untouched, so
		// the caller can reject the file rather than mangle it.
		{"utf16 mark untouched", "\xFF\xFEx\x00", "\xFF\xFEx\x00"},
		{"truncated mark untouched", "\xEF\xBB", "\xEF\xBB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(stripBOM([]byte(tt.in))); got != tt.want {
				t.Errorf("stripBOM(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestHasUTF16BOM(t *testing.T) {
	tests := map[string]bool{
		"\xFF\xFE[\x00d\x00": true,
		"\xFE\xFF\x00[\x00d": true,
		"\xFF\xFE":           true,
		bomMark + "[d]":      false,
		"[default]":          false,
		"\xFF":               false,
		"":                   false,
		// Only a leading mark says what the file is encoded in.
		"x\xFF\xFE": false,
	}
	for in, want := range tests {
		if got := hasUTF16BOM([]byte(in)); got != want {
			t.Errorf("hasUTF16BOM(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseINI_SectionsKeysAndComments(t *testing.T) {
	data := []byte(`; a comment
# another
leading = before any header

[first]
Key = value
quoted = "  spaced  "
repeated = one
repeated = two

[  second  ]
bare
= novalue
`)

	sections := parseINI(data)
	if len(sections) != 3 {
		t.Fatalf("sections = %d, want 3 (leading + two headers)", len(sections))
	}
	if v, ok := sections[0].get("leading"); !ok || v != "before any header" {
		t.Errorf("leading pair = %q/%v, want %q/true", v, ok, "before any header")
	}
	if sections[1].Name != "first" {
		t.Errorf("section name = %q, want %q", sections[1].Name, "first")
	}
	// Keys are matched case-insensitively by the formats this serves, so the
	// parser lowercases them and a caller only ever asks in lower case.
	if v, _ := sections[1].get("key"); v != "value" {
		t.Errorf("key = %q, want %q", v, "value")
	}
	if v, _ := sections[1].get("quoted"); v != "  spaced  " {
		t.Errorf("quoted value = %q, want the inner spacing preserved", v)
	}
	// The first value wins for a repeated key, and both are retained.
	if v, _ := sections[1].get("repeated"); v != "one" {
		t.Errorf("repeated = %q, want %q", v, "one")
	}
	if len(sections[1].Pairs) != 4 {
		t.Errorf("pairs = %d, want 4 — a repeated key is a second pair", len(sections[1].Pairs))
	}
	if sections[2].Name != "second" {
		t.Errorf("section name = %q, want %q", sections[2].Name, "second")
	}
	// A line with no separator and a line with no key are both skipped rather
	// than failing the file.
	if len(sections[2].Pairs) != 0 {
		t.Errorf("pairs = %v, want none", sections[2].Pairs)
	}
}

// TestIniSection_HasRejectsAnEmptyValue holds because tools write an empty value
// to mean "unset"; counting one would report a credential the developer removed.
func TestIniSection_HasRejectsAnEmptyValue(t *testing.T) {
	sections := parseINI([]byte("[default]\naws_secret_access_key =\n"))
	if len(sections) < 2 {
		t.Fatalf("sections = %d, want the header to parse", len(sections))
	}
	if sections[1].has("aws_secret_access_key") {
		t.Error("an empty value must not count as present")
	}
}

func TestStructured_DistinguishesShapeFromBytes(t *testing.T) {
	if structured(parseINI([]byte("this file is prose, not configuration\n"))) {
		t.Error("prose has no INI shape")
	}
	if !structured(parseINI([]byte("[section]\n"))) {
		t.Error("a bracketed header is shape")
	}
	if !structured(parseINI([]byte("key = value\n"))) {
		t.Error("a bare pair is shape")
	}
}

func TestBlank(t *testing.T) {
	if !blank([]byte("\n \t\n")) {
		t.Error("a file holding only whitespace is blank")
	}
	if blank([]byte("key = value")) {
		t.Error("a file with content is not blank")
	}
}

// TestObserved_AppliesTheSharedOutcomes covers the three decisions no format may
// make for itself, each a silent under-report when one gets it wrong: whitespace
// holds nothing, unrecognised bytes are a failure rather than an absence, and a
// recognised document with nothing credential-bearing holds nothing.
func TestObserved_AppliesTheSharedOutcomes(t *testing.T) {
	foundNothing := func([]byte, *fold) bool { return true }
	tests := []struct {
		name string
		data string
		fill func([]byte, *fold) bool
		want observation
	}{
		{"empty file", "", foundNothing, obsNone},
		{"whitespace only", "\n \t\n", foundNothing, obsNone},
		{"mark and whitespace only", bomMark + "\n \t\n", foundNothing, obsNone},
		{"no recognised shape", "prose", func([]byte, *fold) bool { return false }, unparseable()},
		{"shape but nothing in it", "[section]\n", foundNothing, obsNone},
		{
			name: "one entry",
			data: "key = value\n",
			fill: func(_ []byte, f *fold) bool {
				f.add(model.CredentialProtectionPlaintext)
				return true
			},
			want: obsPlain(1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := observed([]byte(tt.data), tt.fill); got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestObserved_StripsTheMarkBeforeTheFormatSeesIt is why no individual format
// strips it: the mark binds to the first token after it, so a format that forgot
// would lose its first key and report fewer entries than the file holds.
func TestObserved_StripsTheMarkBeforeTheFormatSeesIt(t *testing.T) {
	var got string
	observed([]byte(bomMark+"[default]"), func(data []byte, _ *fold) bool {
		got = string(data)
		return true
	})
	if got != "[default]" {
		t.Errorf("format saw %q, want the mark already off", got)
	}
}

func TestIsEnvRef(t *testing.T) {
	tests := map[string]bool{
		"${NPM_TOKEN}":      true,
		"prefix-${TOKEN}":   true,
		"$NPM_TOKEN":        true,
		"npm_literalvalue":  false,
		"":                  false,
		"pypi-AgEIcHlwaS5v": false,
	}
	for value, want := range tests {
		if got := isEnvRef(value); got != want {
			t.Errorf("isEnvRef(%q) = %v, want %v", value, got, want)
		}
	}
}

// TestScanLines_SurvivesALongLine holds because a configuration value can
// legitimately be one very long line — a certificate pinned into a setting.
func TestScanLines_SurvivesALongLine(t *testing.T) {
	long := strings.Repeat("a", 200<<10)
	data := []byte("first = 1\nlong = " + long + "\nlast = 2\n")

	var keys []string
	scanLines(data, func(line string) bool {
		key, _, ok := strings.Cut(line, " = ")
		if ok {
			keys = append(keys, key)
		}
		return true
	})
	if len(keys) != 3 {
		t.Errorf("keys = %v, want all three lines visited", keys)
	}
}

func TestScanLines_StopsWhenTheVisitorSaysSo(t *testing.T) {
	seen := 0
	scanLines([]byte("a\nb\nc\n"), func(string) bool {
		seen++
		return seen < 2
	})
	if seen != 2 {
		t.Errorf("visited %d lines, want 2", seen)
	}
}

// TestParsers_ByteOrderMarkChangesNothing is the parity that keeps a Windows
// developer's own files from reading as a safer machine. The mark is invisible and
// binds to the first token after it, so an unstripped file loses its first header or
// key — silently, by yielding fewer entries, which is exactly the failure this phase
// cannot afford. Every format is covered, not just the one written last.
func TestParsers_ByteOrderMarkChangesNothing(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		parse func([]byte) observation
		want  observation
	}{
		{name: "ini", body: "[default]\naws_secret_access_key = value\n", parse: parseAWSProfiles, want: obsPlain(1)},
		{name: "json", body: `{"auths":{"registry.example.com":{"auth":"encoded"}}}`, parse: parseDockerConfig, want: obsPlain(1)},
		{name: "yaml", body: "users:\n  - user:\n      token: value\n", parse: parseKubeconfig, want: obsPlain(1)},
		{name: "line-oriented", body: "https://user:secret@example.com\n", parse: parseGitCredentials, want: obsPlain(1)},
		{name: "netrc", body: "machine example.com login user password secret\n", parse: parseNetrc, want: obsPlain(1)},
		{name: "npmrc", body: "//registry.example.com/:_authToken=value\n", parse: parseNPMRC, want: obsPlain(1)},
		{name: "toml", body: "[mcp_servers.demo]\ncommand = \"run\"\n\n[mcp_servers.demo.env]\nAPI_KEY = \"value\"\n", parse: func(data []byte) observation { return parseMCPConfig("config.toml", data) }, want: obsPlain(1)},
		{
			name: "yaml host map",
			body: "github.com:\n    oauth_token: value\n    user: octocat\n",
			parse: func(data []byte) observation {
				obs, _ := parseGitHubCLIHosts(data)
				return obs
			},
			want: obsPlain(1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plain := tt.parse([]byte(tt.body))
			if plain != tt.want {
				t.Fatalf("without a mark: %+v, want %+v", plain, tt.want)
			}
			marked := tt.parse([]byte(bomMark + tt.body))
			if marked != plain {
				t.Errorf("with a mark: %+v, want %+v", marked, plain)
			}
		})
	}
}

// TestFold pins the ordering. The case that matters most is unknown beside
// protected: preferring protected there would let one unclassifiable entry inherit
// the protection of the entry beside it and report the file as guarded.
func TestFold(t *testing.T) {
	tests := []struct {
		name   string
		states []string
		want   string
	}{
		{"external alone", []string{model.CredentialProtectionExternal}, model.CredentialProtectionExternal},
		{"protected outranks external", []string{model.CredentialProtectionExternal, model.CredentialProtectionProtected}, model.CredentialProtectionProtected},
		{"unknown outranks protected", []string{model.CredentialProtectionProtected, model.CredentialProtectionUnknown}, model.CredentialProtectionUnknown},
		{"unknown outranks protected either order", []string{model.CredentialProtectionUnknown, model.CredentialProtectionProtected}, model.CredentialProtectionUnknown},
		{"plaintext outranks unknown", []string{model.CredentialProtectionUnknown, model.CredentialProtectionPlaintext}, model.CredentialProtectionPlaintext},
		{"plaintext outranks external", []string{model.CredentialProtectionPlaintext, model.CredentialProtectionExternal}, model.CredentialProtectionPlaintext},
		{"plaintext survives every sibling", []string{
			model.CredentialProtectionExternal,
			model.CredentialProtectionPlaintext,
			model.CredentialProtectionProtected,
		}, model.CredentialProtectionPlaintext},
		// An unparseable entry beside a redirection does not inherit it.
		{"an unparseable entry stays unknown", []string{model.CredentialProtectionExternal, model.CredentialProtectionUnknown}, model.CredentialProtectionUnknown},
		// A state the fold does not know is counted as unclassified rather than
		// ignored, so a new parser case cannot improve a file's reading by accident.
		{"an unrecognised state becomes unknown", []string{model.CredentialProtectionProtected, "something-a-later-parser-invented"}, model.CredentialProtectionUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f fold
			for _, state := range tt.states {
				f.add(state)
			}
			got := f.result()
			if got.Protection != tt.want {
				t.Errorf("protection = %q, want %q", got.Protection, tt.want)
			}
			// Every entry is counted, including one nothing could classify.
			if got.Count != len(tt.states) {
				t.Errorf("count = %d, want %d", got.Count, len(tt.states))
			}
		})
	}

	t.Run("empty until something is added", func(t *testing.T) {
		var f fold
		if !f.empty() {
			t.Fatal("a fresh fold must be empty")
		}
		f.add(model.CredentialProtectionExternal)
		if f.empty() {
			t.Error("fold must not be empty after an entry")
		}
	})

	// A file that exists and could not be read as anything has to stay in the
	// inventory without resolving to a state a reader could act on as safe.
	t.Run("unparseable counts one unknown", func(t *testing.T) {
		got := unparseable()
		if got.Count != 1 {
			t.Errorf("count = %d, want 1 — a file that exists must not report as absent", got.Count)
		}
		if got.Protection != model.CredentialProtectionUnknown {
			t.Errorf("protection = %q, want %q", got.Protection, model.CredentialProtectionUnknown)
		}
	})
}

func TestParseAWSProfiles(t *testing.T) {
	runParseCases(t, parseAWSProfiles, []parseCase{
		{name: "inline secret is plaintext", body: "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = value\n", want: obsPlain(1)},
		{name: "session token alone is material", body: "[default]\naws_session_token = value\n", want: obsPlain(1)},
		{name: "single sign-on is a reference", body: "[profile work]\nsso_start_url = https://example.awsapps.com/start\nsso_account_id = 123456789012\nregion = us-east-1\n", want: obsExt(1)},
		{name: "helper process is a reference", body: "[profile ci]\ncredential_process = /usr/local/bin/issue-credentials\n", want: obsExt(1)},
		{name: "assumed role is a reference", body: "[profile admin]\nrole_arn = arn:aws:iam::123456789012:role/Admin\nsource_profile = default\n", want: obsExt(1)},
		// The inline test runs first, so a profile that holds material and also
		// names a source is not described by the safer half.
		{name: "material beside a reference is plaintext", body: "[default]\naws_secret_access_key = value\ncredential_process = /usr/local/bin/issue\n", want: obsPlain(1)},
		{name: "profiles fold to the worst state and count separately", body: "[default]\naws_secret_access_key = value\n\n[profile work]\nsso_session = corp\n", want: obsPlain(2)},
		// A settings file is usually all references, and a machine can hold one
		// without the credentials file existing at all.
		{name: "references only", body: "[profile a]\nsso_session = corp\n\n[profile b]\nrole_arn = arn:aws:iam::1:role/R\n", want: obsExt(2)},
		// A section header is not evidence of a credential.
		{name: "profile with settings and no credential", body: "[profile scratch]\nregion = eu-west-1\noutput = json\n", want: obsNone},
		{name: "empty value is not a credential", body: "[default]\naws_secret_access_key =\n", want: obsNone},
		{name: "blank file", body: "\n\n   \n", want: obsNone},
		{name: "bytes with no shape are unclassified", body: "this is not a configuration file at all\n", want: obsUnk(1)},
	})
}

func TestParseNPMRC(t *testing.T) {
	runParseCases(t, parseNPMRC, []parseCase{
		{name: "scoped registry token", body: "//registry.example.com/:_authToken=value\n", want: obsPlain(1)},
		{name: "environment reference defers the secret", body: "//registry.example.com/:_authToken=${NPM_TOKEN}\n", want: obsExt(1)},
		{name: "unscoped basic credential", body: "_auth=dXNlcjpwYXNz\n", want: obsPlain(1)},
		{name: "password key counts", body: "//registry.example.com/:_password=dmFsdWU=\n", want: obsPlain(1)},
		{name: "entries fold to the worst state", body: "//a.example.com/:_authToken=${A_TOKEN}\n//b.example.com/:_authToken=value\n", want: obsPlain(2)},
		// A path to TLS material is not a secret, so counting one would report a
		// credential that is not in this file.
		{name: "certificate paths are not credentials", body: "cafile=/etc/ssl/corp.pem\nkeyfile=/home/octocat/.certs/client.key\n", want: obsNone},
		{name: "settings with no credential", body: "registry=https://registry.example.com/\nsave-exact=true\n", want: obsNone},
		{name: "empty value is not a credential", body: "//registry.example.com/:_authToken=\n", want: obsNone},
		{name: "comments are not settings", body: "; written by the package manager\n# and another form\nregistry=https://registry.example.com/\n", want: obsNone},
		{name: "blank file", body: "\n \n", want: obsNone},
		{name: "bytes with no setting at all are unclassified", body: "prose in place of configuration\n", want: obsUnk(1)},
	})
}

// TestIsNPMAuthKey matches on the trailing segment because these keys are scoped by
// a registry URI prefix: the part saying "credential" is after the final colon.
func TestIsNPMAuthKey(t *testing.T) {
	tests := map[string]bool{
		"//registry.example.com/:_authtoken": true,
		"//registry.example.com/:_password":  true,
		"//registry.example.com/:_auth":      true,
		"@scope:registry:_authtoken":         true,
		"_authtoken":                         true,
		"-authtoken":                         true,
		"_auth":                              true,
		"//registry.example.com/:email":      false,
		"registry":                           false,
		"cafile":                             false,
		"strict-ssl":                         false,
	}
	for key, want := range tests {
		if got := isNPMAuthKey(key); got != want {
			t.Errorf("isNPMAuthKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestParsePypirc(t *testing.T) {
	runParseCases(t, parsePypirc, []parseCase{
		{name: "server with a password", body: "[distutils]\nindex-servers =\n    pypi\n\n[pypi]\nusername = __token__\npassword = value\n", want: obsPlain(1)},
		{name: "environment reference defers the secret", body: "[pypi]\nusername = __token__\npassword = ${PYPI_TOKEN}\n", want: obsExt(1)},
		{name: "server without a password is a reference", body: "[private]\nrepository = https://pypi.example.com/simple/\nusername = octocat\n", want: obsExt(1)},
		{name: "servers fold to the worst state", body: "[pypi]\nusername = __token__\npassword = value\n\n[private]\nrepository = https://pypi.example.com/\nusername = octocat\n", want: obsPlain(2)},
		// The index list is not a server entry.
		{name: "index list only", body: "[distutils]\nindex-servers =\n    pypi\n", want: obsNone},
		{name: "blank file", body: "\n", want: obsNone},
		{name: "bytes with no shape are unclassified", body: "prose in place of configuration\n", want: obsUnk(1)},
	})
}

func TestParseGitCredentials(t *testing.T) {
	runParseCases(t, parseGitCredentials, []parseCase{
		{name: "stored password", body: "https://octocat:secret@github.com\n", want: obsPlain(1)},
		{name: "user with no password is a reference", body: "https://octocat@github.com\n", want: obsExt(1)},
		{name: "comments and blank lines are not entries", body: "# written by a helper\n\nhttps://octocat:secret@github.com\n", want: obsPlain(1)},
		{name: "entries fold to the worst state", body: "https://octocat@github.com\nhttps://octocat:secret@git.example.com\n", want: obsPlain(2)},
		// A secret can hold a character that fails a strict URL parse; the
		// structural fallback keeps that from becoming an inconclusive line.
		{name: "unparseable line that plainly carries a password", body: "https://octocat:sec ret@github.com\n", want: obsPlain(1)},
		{name: "unparseable line with nothing password-shaped", body: "not even a url\n", want: obsUnk(1)},
		{name: "blank file", body: "\n  \n", want: obsNone},
	})
}

func TestHasInlineURLPassword(t *testing.T) {
	tests := map[string]bool{
		"https://octocat:secret@github.com": true,
		"https://octocat@github.com":        false,
		"https://octocat:@github.com":       false,
		"https://github.com":                false,
		"octocat:secret@github.com":         false,
	}
	for line, want := range tests {
		if got := hasInlineURLPassword(line); got != want {
			t.Errorf("hasInlineURLPassword(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestParseNetrc(t *testing.T) {
	runParseCases(t, parseNetrc, []parseCase{
		{name: "machine with a password", body: "machine example.com login octocat password secret\n", want: obsPlain(1)},
		{name: "machine without a password is a reference", body: "machine example.com login octocat\n", want: obsExt(1)},
		{name: "default entry counts", body: "default login octocat password secret\n", want: obsPlain(1)},
		// Entries legally wrap across lines, so the tokeniser carries state
		// through the line loop rather than resetting on it.
		{name: "entry wrapped across lines", body: "machine example.com\n  login octocat\n  password secret\n", want: obsPlain(1)},
		{name: "several machines fold", body: "machine a.example.com login u password p\nmachine b.example.com login u\n", want: obsPlain(2)},
		{name: "blank file", body: "\n\n", want: obsNone},
		{name: "prose with no entry keyword", body: "nothing here resembles an entry\n", want: obsNone},
	})
}

// TestParseNetrc_MacroBodyIsNotConfiguration holds because a macro body is arbitrary
// commands that may contain the same words entries are built from. Tokenising it
// would invent entries, and the entry after the macro must still be found.
func TestParseNetrc_MacroBodyIsNotConfiguration(t *testing.T) {
	body := "machine first.example.com login octocat password secret\n" +
		"\n" +
		"macdef upload\n" +
		"machine ignored.example.com login decoy password decoy\n" +
		"put file\n" +
		"\n" +
		"machine second.example.com login octocat\n"

	got := parseNetrc([]byte(body))
	want := obsPlain(2)
	if got != want {
		t.Errorf("got %+v, want %+v — the macro body must not become an entry", got, want)
	}
}

func TestParseGitconfigHelper(t *testing.T) {
	runParseCases(t, parseGitconfigHelper, []parseCase{
		{name: "the plaintext-storing helper", body: "[credential]\n\thelper = store\n", want: obsPlain(1)},
		{name: "the helper with arguments is still that helper", body: "[credential]\n\thelper = store --file=/home/octocat/.git-credentials\n", want: obsPlain(1)},
		{name: "an operating-system keystore", body: "[credential]\n\thelper = osxkeychain\n", want: obsExt(1)},
		{name: "a helper given as a program path", body: "[credential]\n\thelper = /usr/local/bin/git-credential-manager\n", want: obsExt(1)},
		{name: "a helper given as a shell fragment", body: "[credential]\n\thelper = !aws codecommit credential-helper $@\n", want: obsExt(1)},
		{name: "the per-url form is a helper too", body: "[credential \"https://github.com\"]\n\thelper = store\n", want: obsPlain(1)},
		// The setting is a list, so the same name repeats inside one section.
		{name: "helpers fold to the worst state", body: "[credential]\n\thelper = osxkeychain\n\thelper = store\n", want: obsPlain(2)},
		{name: "a configuration file with no helper", body: "[user]\n\tname = Octocat\n\temail = octocat@example.com\n", want: obsNone},
		{name: "an empty helper configures nothing", body: "[credential]\n\thelper =\n", want: obsNone},
		{name: "bytes with no shape are unclassified", body: "prose in place of configuration\n", want: obsUnk(1)},
	})
}

func TestIsCredentialSection(t *testing.T) {
	tests := map[string]bool{
		"credential":                    true,
		"Credential":                    true,
		`credential "https://host"`:     true,
		`credential "https://Host.COM"`: true,
		"credentials":                   false,
		"user":                          false,
	}
	for name, want := range tests {
		if got := isCredentialSection(name); got != want {
			t.Errorf("isCredentialSection(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestClassifyGitHelper_UnknownHelperIsExternal is deliberate rather than permissive:
// whatever an unrecognised helper does, it is a redirection, and the file holds
// no material of its own.
func TestClassifyGitHelper_UnknownHelperIsExternal(t *testing.T) {
	for _, value := range []string{"manager", "libsecret", "wincred", "cache --timeout=3600", "some-vendor-helper"} {
		if got := classifyGitHelper(value); got != model.CredentialProtectionExternal {
			t.Errorf("classifyGitHelper(%q) = %q, want %q", value, got, model.CredentialProtectionExternal)
		}
	}
	for _, value := range []string{"store", "Store", "git-credential-store", `C:\Git\cmd\git-credential-store.exe`} {
		if got := classifyGitHelper(value); got != model.CredentialProtectionPlaintext {
			t.Errorf("classifyGitHelper(%q) = %q, want %q", value, got, model.CredentialProtectionPlaintext)
		}
	}
}
