package configaudit

import (
	"strings"
	"testing"
)

// --- yarn classic parser edge cases ---------------------------------------

func TestParseYarnClassic_CommentOnly(t *testing.T) {
	entries := parseYarnClassic([]byte("# only comments\n; another\n"))
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from comment-only file, got %+v", entries)
	}
}

func TestParseYarnClassic_KeyWithNoValue(t *testing.T) {
	entries := parseYarnClassic([]byte("registry\nstrict-ssl\n"))
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", len(entries), entries)
	}
	for _, e := range entries {
		if e.DisplayValue != "" || e.Quoted {
			t.Errorf("bare key should have empty value, got %+v", e)
		}
	}
}

func TestParseYarnClassic_UnclosedQuote(t *testing.T) {
	// A leading-only quote isn't matched by `outer-quoted` heuristic so the
	// raw value is kept verbatim — important for audit fidelity.
	entries := parseYarnClassic([]byte(`registry "https://broken`))
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if entries[0].Quoted {
		t.Errorf("unclosed quote should not set Quoted=true")
	}
	if !strings.HasPrefix(entries[0].DisplayValue, `"https://broken`) {
		t.Errorf("raw value should be preserved, got %q", entries[0].DisplayValue)
	}
}

func TestParseYarnClassic_TabSeparator(t *testing.T) {
	// yarn v1 accepts tab between key/value too.
	entries := parseYarnClassic([]byte("registry\thttps://npm.example.com\n"))
	if len(entries) != 1 || entries[0].Key != "registry" || entries[0].DisplayValue != "https://npm.example.com" {
		t.Errorf("tab-separated kv mis-parsed: %+v", entries)
	}
}

func TestYarnFlavorFromFilename_Table(t *testing.T) {
	cases := []struct{ in, want string }{
		{".yarnrc.yml", "berry"},
		{".yarnrc", "classic"},
		{"yarn.lock", "classic"}, // unknown → fall through to classic; documents behavior
	}
	for _, tc := range cases {
		if got := yarnFlavorFromFilename(tc.in); got != tc.want {
			t.Errorf("yarnFlavorFromFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- yarn berry parser edge cases -----------------------------------------

func TestParseYarnBerry_TopLevelScalar(t *testing.T) {
	entries, err := parseYarnBerry([]byte(`npmRegistryServer: "https://registry.yarnpkg.com"` + "\n"))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(entries) != 1 || entries[0].Key != "npmRegistryServer" {
		t.Errorf("top-level scalar should produce one entry, got %+v", entries)
	}
}

func TestParseYarnBerry_EmptyFile(t *testing.T) {
	entries, err := parseYarnBerry(nil)
	if err != nil || len(entries) != 0 {
		t.Errorf("empty input → expected (nil, nil); got (%+v, %v)", entries, err)
	}
}

func TestParseYarnBerry_BooleanAndNumberValues(t *testing.T) {
	entries, err := parseYarnBerry([]byte("enableScripts: false\nnetworkTimeout: 60000\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gotByKey := map[string]string{}
	for _, e := range entries {
		gotByKey[e.Key] = e.DisplayValue
	}
	if gotByKey["enableScripts"] != "false" || gotByKey["networkTimeout"] != "60000" {
		t.Errorf("scalar coercion: %+v", gotByKey)
	}
}

// --- bunfig parser edge cases ---------------------------------------------

func TestParseBunfig_ScalarTypes(t *testing.T) {
	toml := `
[install]
optional = true
networkTimeout = 60000
ratio = 0.5
registry = "https://npm.example.com/"
`
	sections, err := parseBunfig([]byte(toml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, s := range sections {
		if s.Name != "install" {
			continue
		}
		gotByKey := map[string]string{}
		for _, e := range s.Entries {
			gotByKey[e.Key] = e.DisplayValue
		}
		if gotByKey["optional"] != "true" {
			t.Errorf("bool not stringified: %v", gotByKey)
		}
		if gotByKey["networkTimeout"] != "60000" {
			t.Errorf("int not stringified: %v", gotByKey)
		}
		if !strings.HasPrefix(gotByKey["ratio"], "0.5") {
			t.Errorf("float not stringified: %v", gotByKey)
		}
		if gotByKey["registry"] != "https://npm.example.com/" {
			t.Errorf("string not preserved: %v", gotByKey)
		}
		return
	}
	t.Fatalf("install section not found: %+v", sections)
}

func TestParseBunfig_ArrayValue(t *testing.T) {
	// Bun's bunfig.toml rarely uses arrays of strings outside install.deps,
	// but the parser must serialize them stably.
	toml := `
[install]
trustedDependencies = ["foo", "bar"]
`
	sections, err := parseBunfig([]byte(toml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, s := range sections {
		for _, e := range s.Entries {
			if e.Key == "trustedDependencies" {
				if !strings.Contains(e.DisplayValue, "foo") || !strings.Contains(e.DisplayValue, "bar") {
					t.Errorf("array value not serialized: %q", e.DisplayValue)
				}
				return
			}
		}
	}
	t.Fatalf("trustedDependencies key not found")
}

func TestParseBunfig_EmptyFile(t *testing.T) {
	sections, err := parseBunfig(nil)
	if err != nil {
		t.Errorf("empty file should not error: %v", err)
	}
	if len(sections) != 0 {
		t.Errorf("empty file should yield 0 sections, got %+v", sections)
	}
}

// --- auth-key suffix coverage ---------------------------------------------

func TestIsYarnClassicAuthKey_AllSuffixes(t *testing.T) {
	for _, key := range []string{
		"//npm.example.com/:_authToken",
		"//npm.example.com/:_password",
		"//npm.example.com/:_auth",
		"npmAuthToken",
		"//x.example/:_AUTHTOKEN", // case-insensitive
	} {
		if !isYarnClassicAuthKey(key) {
			t.Errorf("expected %q to be classic auth key", key)
		}
	}
	for _, key := range []string{"registry", "strict-ssl", "//host/:other"} {
		if isYarnClassicAuthKey(key) {
			t.Errorf("expected %q to NOT be classic auth key", key)
		}
	}
}

func TestIsYarnBerryAuthKey_LeafMatchOnly(t *testing.T) {
	for _, key := range []string{
		"npmScopes.@foo.npmAuthToken",
		"npmRegistries.https://x/.npmAuthIdent",
		"npmAuthToken",
		"users.alice.password",
	} {
		if !isYarnBerryAuthKey(key) {
			t.Errorf("expected %q to be berry auth key", key)
		}
	}
	if isYarnBerryAuthKey("npmRegistryServer") {
		t.Errorf("npmRegistryServer should not be flagged auth")
	}
	if isYarnBerryAuthKey("password.notSecret") {
		t.Errorf("non-leaf match should not trigger")
	}
}

func TestIsBunAuthKey_Leaves(t *testing.T) {
	for _, k := range []string{"token", "password", "username", "TOKEN", "Password"} {
		if !isBunAuthKey(k) {
			t.Errorf("expected %q auth", k)
		}
	}
	for _, k := range []string{"registry", "url", "cache", "tokenName"} {
		if isBunAuthKey(k) {
			t.Errorf("expected %q not auth", k)
		}
	}
}
