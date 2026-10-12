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
// location holding no credential material; obsUnrec is one this build could not
// interpret, which is never a finding and always costs the scan its completeness.
func obsPlain(n int) observation {
	return observation{Count: n, Protection: model.CredentialProtectionPlaintext}
}
func obsProt(n int) observation {
	return observation{Count: n, Protection: model.CredentialProtectionProtected}
}

var (
	obsNone  observation
	obsUnrec = observation{Unrecognized: true}
)

// alsoUnrec is the mixed result: confirmed material beside something that could
// not be read. The finding stands and the source is still incomplete.
func alsoUnrec(o observation) observation {
	o.Unrecognized = true
	return o
}

// runParseCases drives one format over its table. Every format answers the same
// three questions — how much material, guarded how, and was any of the file
// uninterpretable — so they share one harness and each table carries only what
// differs.
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
`)

	sections, malformed := parseINI(data, true)
	if malformed {
		t.Error("every line here has an interpretation")
	}
	if len(sections) != 3 {
		t.Fatalf("sections = %d, want 3 (leading + two headers)", len(sections))
	}
	if v, ok := get(sections[0], "leading"); !ok || v != "before any header" {
		t.Errorf("leading pair = %q/%v, want %q/true", v, ok, "before any header")
	}
	if sections[1].Name != "first" {
		t.Errorf("section name = %q, want %q", sections[1].Name, "first")
	}
	// Keys are matched case-insensitively by the formats this serves, so the
	// parser lowercases them and a caller only ever asks in lower case.
	if v, _ := get(sections[1], "key"); v != "value" {
		t.Errorf("key = %q, want %q", v, "value")
	}
	if v, _ := get(sections[1], "quoted"); v != "  spaced  " {
		t.Errorf("quoted value = %q, want the inner spacing preserved", v)
	}
	// Both statements of a repeated key are retained, in the order the file
	// makes them, so a reader can decide for itself which one it acts on.
	if v, _ := get(sections[1], "repeated"); v != "one" {
		t.Errorf("repeated = %q, want %q", v, "one")
	}
	if len(sections[1].Pairs) != 4 {
		t.Errorf("pairs = %d, want 4 — a repeated key is a second pair", len(sections[1].Pairs))
	}
	// A bare word is one format's boolean setting: a recognised line that holds
	// no value and can therefore never be material.
	if v, ok := get(sections[2], "bare"); !ok || v != "" {
		t.Errorf("bare key = %q/%v, want an empty value", v, ok)
	}
}

// get returns the first value a section states for a key. The parsers ask
// whether a key was filled in rather than what it was filled in with, so this
// lives here: it exists to read back what the line walk recorded.
func get(s iniSection, key string) (string, bool) {
	for _, p := range s.Pairs {
		if p.Key == key {
			return p.Value, true
		}
	}
	return "", false
}

// TestParseINI_ReportsWhatItCannotRead is the reason the second return exists. A
// skipped line used to vanish, which let a file this build cannot read resolve to
// "holds no credential" — the one wrong answer an inventory must not give.
//
// A valueless word is a line only where a format spells a boolean that way.
// Admitting it everywhere would let a stray word in a file with no such spelling
// pass as a line that was understood.
func TestParseINI_ReportsWhatItCannotRead(t *testing.T) {
	tests := []struct {
		body     string
		bareKeys bool
		want     bool
	}{
		{body: "[default]\naws_secret_access_key value\n", want: true},
		{body: "= novalue\n", want: true},
		{body: "not configuration at all, just prose\n", want: true},
		{body: "[default]\nkey = value\n"},
		{body: "; comment only\n"},
		{body: "[section]\n"},
		{body: "engine-strict\n", bareKeys: true},
		{body: "engine-strict\n", want: true},
		// A value written across several lines carries on under the key it
		// belongs to, which is how one of these formats spells a list.
		{body: "[distutils]\nindex-servers =\n    first\n    second\n"},
		// The same word under a fresh header continues nothing.
		{body: "[distutils]\n    first\n", want: true},
		// A header missing one of its brackets is a section boundary that cannot
		// be placed, whether or not the format admits valueless words.
		{body: "[broken\n", want: true},
		{body: "[broken\n", bareKeys: true, want: true},
		{body: "broken]\n", bareKeys: true, want: true},
		// A torn header can hold an equals sign of its own, which would otherwise
		// file the header text away as a setting.
		{body: "[broken = 1\n", want: true},
		// A value is free to end in a bracket, and a line stating one is a
		// setting rather than a header.
		{body: "[default]\nkey = value]\n"},
	}
	for _, tt := range tests {
		if _, got := parseINI([]byte(tt.body), tt.bareKeys); got != tt.want {
			t.Errorf("parseINI(%q, bareKeys=%v) malformed = %v, want %v", tt.body, tt.bareKeys, got, tt.want)
		}
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
		{"no recognised shape", "prose", func([]byte, *fold) bool { return false }, obsUnrec},
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
		// The mixed result the whole three-state design exists for.
		{
			name: "material beside something unreadable",
			data: "key = value\n",
			fill: func(_ []byte, f *fold) bool {
				f.add(model.CredentialProtectionPlaintext)
				f.unrecognized = true
				return true
			},
			want: alsoUnrec(obsPlain(1)),
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

// TestIsEnvRef matches the whole value and not a substring. A value that merely
// embeds a reference still carries characters of its own, so calling it a
// reference would drop a configured credential out of the inventory.
func TestIsEnvRef(t *testing.T) {
	tests := map[string]bool{
		"${NPM_TOKEN}":      true,
		"$NPM_TOKEN":        true,
		"  ${NPM_TOKEN}  ":  true,
		"$_LEADING":         true,
		"prefix-${TOKEN}":   false,
		"${TOKEN}-suffix":   false,
		"${TOKEN} ${OTHER}": false,
		"${}":               false,
		"${1BAD}":           false,
		"$":                 false,
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

// TestConcrete is the whole test this package applies to a value: was the field
// filled in, and does what filled it defer somewhere else.
func TestConcrete(t *testing.T) {
	tests := map[string]bool{
		"value":          true,
		"YOUR_TOKEN":     true,
		"prefix-${X}":    true,
		"":               false,
		"${VAULT_TOKEN}": false,
		"$VAULT_TOKEN":   false,
	}
	for value, want := range tests {
		if got := concrete(value); got != want {
			t.Errorf("concrete(%q) = %v, want %v", value, got, want)
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
		{name: "yaml host map", body: "github.com:\n    oauth_token: value\n", parse: parseGitHubCLIHosts, want: obsPlain(1)},
		{name: "whole-file token", body: "a-token\n", parse: parseVaultToken, want: obsPlain(1)},
		{name: "json lines", body: `{"_id":"req_1","type":"Request","authentication":{"type":"bearer","token":"value"}}` + "\n", parse: parseInsomnia, want: obsPlain(1)},
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

// TestFold pins the two-value vocabulary and the way it fails. A state outside it
// is not a safer reading of the file, it is a parser this build does not
// understand — so it adds no credential and marks the source uninterpreted, and a
// new case someone forgets to map cannot improve a file's protection by accident.
func TestFold(t *testing.T) {
	tests := []struct {
		name         string
		states       []string
		want         string
		count        int
		unrecognized bool
	}{
		{"protected alone", []string{model.CredentialProtectionProtected}, model.CredentialProtectionProtected, 1, false},
		{"plaintext alone", []string{model.CredentialProtectionPlaintext}, model.CredentialProtectionPlaintext, 1, false},
		{"plaintext outranks protected", []string{model.CredentialProtectionProtected, model.CredentialProtectionPlaintext}, model.CredentialProtectionPlaintext, 2, false},
		{"plaintext outranks protected either order", []string{model.CredentialProtectionPlaintext, model.CredentialProtectionProtected}, model.CredentialProtectionPlaintext, 2, false},
		// Both retired states, and a state a later parser might invent, all fail
		// the same way: no count, no protection, and the source marked incomplete.
		{"a retired redirection state fails closed", []string{"external"}, "", 0, true},
		{"a retired unclassified state fails closed", []string{"unknown"}, "", 0, true},
		{"an invented state fails closed", []string{"something-a-later-parser-invented"}, "", 0, true},
		// The confirmed credential beside it still counts.
		{"an unmapped state beside a credential", []string{model.CredentialProtectionPlaintext, "external"}, model.CredentialProtectionPlaintext, 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f fold
			for _, state := range tt.states {
				f.add(state)
			}
			got := f.result()
			if got.Protection != tt.want || got.Count != tt.count || got.Unrecognized != tt.unrecognized {
				t.Errorf("got %+v, want %d/%q unrecognized=%v", got, tt.count, tt.want, tt.unrecognized)
			}
		})
	}
}

// TestUnparseable_IsNotAFinding is the boundary the whole inventory rests on: a
// file that exists and could not be read says nothing about what is in it, so it
// travels as an error rather than as a credential nobody can confirm.
func TestUnparseable_IsNotAFinding(t *testing.T) {
	got := unparseable()
	if got.Count != 0 || got.Protection != "" || !got.Unrecognized {
		t.Errorf("got %+v, want no finding and unrecognized", got)
	}
}

func TestParseAWSProfiles(t *testing.T) {
	runParseCases(t, parseAWSProfiles, []parseCase{
		{name: "inline secret is plaintext", body: "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = value\n", want: obsPlain(1)},
		{name: "session token alone is material", body: "[default]\naws_session_token = value\n", want: obsPlain(1)},
		// One profile is one credential: the secret and its session token are
		// halves of the same grant.
		{name: "both fields on one profile count once", body: "[default]\naws_secret_access_key = value\naws_session_token = value\n", want: obsPlain(1)},
		{name: "profiles count separately", body: "[default]\naws_secret_access_key = value\n\n[profile work]\naws_secret_access_key = value\n", want: obsPlain(2)},
		// Every external mechanism names a credential fetched at run time. None
		// of them puts material in this file, so none is a finding.
		{name: "single sign-on is not material", body: "[profile work]\nsso_start_url = https://example.awsapps.com/start\nsso_account_id = 123456789012\nregion = us-east-1\n", want: obsNone},
		{name: "helper process is not material", body: "[profile ci]\ncredential_process = /usr/local/bin/issue-credentials\n", want: obsNone},
		{name: "assumed role is not material", body: "[profile admin]\nrole_arn = arn:aws:iam::123456789012:role/Admin\nsource_profile = default\n", want: obsNone},
		{name: "web identity token path is not material", body: "[profile ci]\nweb_identity_token_file = /var/run/secrets/token\n", want: obsNone},
		// The identifier names a credential; it is not one.
		{name: "access key identifier alone is not material", body: "[default]\naws_access_key_id = AKIAEXAMPLE\n", want: obsNone},
		{name: "environment reference is not material", body: "[default]\naws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}\n", want: obsNone},
		{name: "empty value is not material", body: "[default]\naws_secret_access_key =\n", want: obsNone},
		// A key whose value sits on the line below it is a layout this format's
		// own reader accepts, so the field is filled in and the file holds
		// material — reading it as empty would report a real secret as absent.
		{name: "a value written on the line below its key", body: "[default]\naws_secret_access_key =\n  value\n", want: obsPlain(1)},
		{name: "profile with settings and no credential", body: "[profile scratch]\nregion = eu-west-1\noutput = json\n", want: obsNone},
		{name: "blank file", body: "\n\n   \n", want: obsNone},
		{name: "bytes with no shape", body: "this is not a configuration file at all\n", want: obsUnrec},
		{name: "a pair with no separator", body: "[default]\naws_secret_access_key value\n", want: obsUnrec},
		// This format has no spelling for a valueless setting, so a bare word in
		// it is a line with no interpretation rather than one that was understood.
		{name: "a bare word", body: "[default]\naws_secret_access_key\n", want: obsUnrec},
		// The mixed case: what was confirmed still counts, and the source is
		// still incomplete.
		{name: "material beside an unreadable line", body: "[default]\naws_secret_access_key = value\n\n[profile broken]\nkey without separator\n", want: alsoUnrec(obsPlain(1))},
	})
}

func TestParseNPMRC(t *testing.T) {
	runParseCases(t, parseNPMRC, []parseCase{
		{name: "scoped registry token", body: "//registry.example.com/:_authToken=value\n", want: obsPlain(1)},
		{name: "unscoped basic credential", body: "_auth=dXNlcjpwYXNz\n", want: obsPlain(1)},
		{name: "password key counts", body: "//registry.example.com/:_password=dmFsdWU=\n", want: obsPlain(1)},
		{name: "registries count separately", body: "//a.example.com/:_authToken=one\n//b.example.com/:_authToken=two\n", want: obsPlain(2)},
		{name: "environment reference is not material", body: "//registry.example.com/:_authToken=${NPM_TOKEN}\n", want: obsNone},
		{name: "a value merely embedding a reference is material", body: "//registry.example.com/:_authToken=npm_${SUFFIX}\n", want: obsPlain(1)},
		// A path to TLS material is not a secret, so counting one would report a
		// credential that is not in this file.
		{name: "certificate paths are not credentials", body: "cafile=/etc/ssl/corp.pem\nkeyfile=/home/octocat/.certs/client.key\n", want: obsNone},
		{name: "settings with no credential", body: "registry=https://registry.example.com/\nsave-exact=true\n", want: obsNone},
		// A setting merely ending in a credential field's name is a different
		// setting, so counting it would report a credential the file does not hold.
		{name: "a setting ending in a credential name is not one", body: "not_auth=value\nlegacy_password=value\n", want: obsNone},
		// This format spells a boolean setting as a bare word, which is a line
		// with an interpretation and no value.
		{name: "a bare boolean setting is recognised", body: "engine-strict\n", want: obsNone},
		// A header missing one of its brackets is not a valueless setting: it is a
		// section boundary this build cannot place, and every pair behind it would
		// be attributed to whatever section came before.
		{name: "a header missing a bracket is not a bare setting", body: "[broken\n", want: obsUnrec},
		{name: "empty value is not material", body: "//registry.example.com/:_authToken=\n", want: obsNone},
		{name: "comments are not settings", body: "; written by the package manager\n# and another form\nregistry=https://registry.example.com/\n", want: obsNone},
		{name: "blank file", body: "\n \n", want: obsNone},
		{name: "bytes with no setting at all", body: "prose in place of configuration\n", want: obsUnrec},
		{name: "material beside an unreadable line", body: "//registry.example.com/:_authToken=value\nprose in place of configuration\n", want: alsoUnrec(obsPlain(1))},
	})
}

// TestIsNPMAuthKey reads the segment after the final colon, because these keys
// are scoped by a registry URI prefix and the part saying "credential" is what
// follows it. That segment is then compared whole: a setting merely ending in one
// of these words is a different setting, and counting it would report a
// credential the file does not hold.
func TestIsNPMAuthKey(t *testing.T) {
	tests := map[string]bool{
		"//registry.example.com/:_authtoken": true,
		"//registry.example.com/:_password":  true,
		"//registry.example.com/:_auth":      true,
		"@scope:registry:_authtoken":         true,
		"_authtoken":                         true,
		"_auth":                              true,
		"//registry.example.com/:email":      false,
		"registry":                           false,
		"cafile":                             false,
		"strict-ssl":                         false,
		"-authtoken":                         false,
		"not_auth":                           false,
		"legacy_password":                    false,
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
		{name: "servers count separately", body: "[pypi]\npassword = one\n\n[private]\npassword = two\n", want: obsPlain(2)},
		{name: "environment reference is not material", body: "[pypi]\nusername = __token__\npassword = ${PYPI_TOKEN}\n", want: obsNone},
		// A server configured without a password is a login the tool completes
		// from a keyring or a prompt when it runs.
		{name: "username and repository without a password", body: "[private]\nrepository = https://pypi.example.com/simple/\nusername = octocat\n", want: obsNone},
		{name: "empty password is not material", body: "[pypi]\npassword =\n", want: obsNone},
		{name: "a password written on the line below its key", body: "[pypi]\npassword =\n  value\n", want: obsPlain(1)},
		// A key stated twice can state the empty one first. Reading only the first
		// would describe a filled-in field as blank, which is the file's
		// credential going unreported.
		{name: "a repeated password whose first statement is empty", body: "[pypi]\npassword =\npassword = value\n", want: obsPlain(1)},
		{name: "a repeated password counts its server once", body: "[pypi]\npassword = one\npassword = two\n", want: obsPlain(1)},
		{name: "index list only", body: "[distutils]\nindex-servers =\n    pypi\n", want: obsNone},
		// A password belongs to the server whose section holds it. The section
		// naming the set is a login to none of them, and the leading section names
		// no server at all.
		{name: "a password in the index list section", body: "[distutils]\nindex-servers =\n    pypi\npassword = value\n", want: obsNone},
		{name: "a password before any section", body: "password = value\n", want: obsNone},
		{name: "blank file", body: "\n", want: obsNone},
		{name: "bytes with no shape", body: "prose in place of configuration\n", want: obsUnrec},
	})
}

func TestParseGitCredentials(t *testing.T) {
	runParseCases(t, parseGitCredentials, []parseCase{
		{name: "stored password", body: "https://octocat:secret@github.com\n", want: obsPlain(1)},
		{name: "comments and blank lines are not entries", body: "# written by a helper\n\nhttps://octocat:secret@github.com\n", want: obsPlain(1)},
		{name: "entries count separately", body: "https://octocat:one@github.com\nhttps://octocat:two@git.example.com\n", want: obsPlain(2)},
		// A secret can hold a character that fails a strict URL parse; the
		// structural reading keeps that from dropping a plaintext credential.
		{name: "a password a strict parse rejects", body: "https://octocat:sec ret@github.com\n", want: obsPlain(1)},
		// Each of these is a real, readable entry that holds no material.
		{name: "user with no password", body: "https://octocat@github.com\n", want: obsNone},
		{name: "explicit empty password", body: "https://octocat:@github.com\n", want: obsNone},
		{name: "host only", body: "https://github.com\n", want: obsNone},
		{name: "environment reference is not material", body: "https://octocat:${GIT_PASSWORD}@github.com\n", want: obsNone},
		{name: "blank file", body: "\n  \n", want: obsNone},
		// This file has one shape, so a line that is neither reading is text this
		// build cannot account for — and calling it clean would be a guess.
		{name: "a line that is not a credential url", body: "not even a url\n", want: obsUnrec},
		{name: "userinfo with no host", body: "https://u:p@\n", want: obsUnrec},
		{name: "an unparseable host", body: "https://u:${PASSWORD}@bad[host\n", want: obsUnrec},
		{name: "material beside an unreadable line", body: "https://octocat:secret@github.com\nnot even a url\n", want: alsoUnrec(obsPlain(1))},
	})
}

func TestStructuralURLPassword(t *testing.T) {
	tests := []struct {
		line       string
		want       string
		recognized bool
	}{
		{"https://octocat:sec ret@github.com", "sec ret", true},
		{"https://octocat:a@b@github.com", "a@b", true},
		{"https://octocat@github.com", "", true},
		{"https://github.com", "", false},
		{"octocat:secret@github.com", "", false},
		{"https://octocat:secret@", "", false},
		{"https://u:p@bad[host", "", false},
	}
	for _, tt := range tests {
		got, recognized := structuralURLPassword(tt.line)
		if got != tt.want || recognized != tt.recognized {
			t.Errorf("structuralURLPassword(%q) = %q/%v, want %q/%v", tt.line, got, recognized, tt.want, tt.recognized)
		}
	}
}

func TestParseNetrc(t *testing.T) {
	runParseCases(t, parseNetrc, []parseCase{
		{name: "machine with a password", body: "machine example.com login octocat password secret\n", want: obsPlain(1)},
		{name: "default entry counts", body: "default login octocat password secret\n", want: obsPlain(1)},
		// Entries legally wrap across lines, so the tokeniser carries state
		// through the line loop rather than resetting on it.
		{name: "entry wrapped across lines", body: "machine example.com\n  login octocat\n  password secret\n", want: obsPlain(1)},
		{name: "several machines count separately", body: "machine a.example.com login u password one\nmachine b.example.com login u password two\n", want: obsPlain(2)},
		{name: "machine without a password", body: "machine example.com login octocat\n", want: obsNone},
		{name: "environment reference is not material", body: "machine example.com login octocat password ${NETRC_PASSWORD}\n", want: obsNone},
		// Comments are stripped before tokenising, so text after a mark cannot
		// supply the value the directive above it is waiting for.
		{name: "a comment cannot invent a password", body: "machine example.com login octocat # password decoy\n", want: obsNone},
		{name: "blank file", body: "\n\n", want: obsNone},
		// The file ended where a value was owed, so the entry was never completed.
		{name: "an unterminated directive", body: "machine example.com login octocat password", want: obsUnrec},
		// A directive where a value belongs would otherwise be swallowed as one.
		{name: "a directive consumed as a value", body: "machine example.com login password secret\n", want: alsoUnrec(obsNone)},
		// An entry that stops mid-directive is one this build cannot say it read,
		// so its password goes with the rest of it.
		{name: "a password in an entry the file cut short", body: "machine example.com password secret login", want: obsUnrec},
		{name: "text outside the grammar", body: "nothing here resembles an entry\n", want: obsUnrec},
		{name: "material beside text outside the grammar", body: "machine example.com login u password secret\nstray words\n", want: alsoUnrec(obsPlain(1))},
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
		"machine second.example.com login octocat password secret\n"

	got := parseNetrc([]byte(body))
	want := obsPlain(2)
	if got != want {
		t.Errorf("got %+v, want %+v — the macro body must not become an entry", got, want)
	}
}

// TestParseVaultToken covers the one source whose whole contents are the
// credential. Nothing about the value is read beyond whether the file was filled
// in with something that is not a reference.
func TestParseVaultToken(t *testing.T) {
	runParseCases(t, parseVaultToken, []parseCase{
		{name: "a token", body: "a-token-value\n", want: obsPlain(1)},
		{name: "surrounding whitespace is trimmed", body: "  a-token-value  \n\n", want: obsPlain(1)},
		{name: "blank file", body: " \n", want: obsNone},
		{name: "empty file", body: "", want: obsNone},
		{name: "environment reference is not material", body: "${VAULT_TOKEN}\n", want: obsNone},
	})
}
