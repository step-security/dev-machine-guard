package configedit

import (
	"strings"
	"testing"
)

func TestNormalizeJSONObjectAcceptsEmpty(t *testing.T) {
	out, err := NormalizeJSONObject(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{}` {
		t.Errorf("empty input should normalize to {}; got %q", out)
	}
	out, err = NormalizeJSONObject([]byte("   \n\t "))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{}` {
		t.Errorf("whitespace input should normalize to {}; got %q", out)
	}
}

func TestNormalizeJSONObjectRejectsNonObject(t *testing.T) {
	if _, err := NormalizeJSONObject([]byte(`[]`)); err == nil {
		t.Error("array root must be rejected")
	}
	if _, err := NormalizeJSONObject([]byte(`"x"`)); err == nil {
		t.Error("scalar root must be rejected")
	}
	if _, err := NormalizeJSONObject([]byte(`{not json`)); err == nil {
		t.Error("malformed JSON must be rejected")
	}
}

func TestNormalizeJSONObjectPassesObjectThrough(t *testing.T) {
	in := []byte(`{"theme":"dark"}`)
	out, err := NormalizeJSONObject(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Errorf("object input should pass through unchanged; got %q", out)
	}
}

func TestEscapePathKeyEscapesSpecials(t *testing.T) {
	cases := map[string]string{
		"PreToolUse":  "PreToolUse",
		"first.name":  `first\.name`,
		`back\slash`:  `back\\slash`,
		"star*?":      `star\*\?`,
		"":            "",
		"plain_key-1": "plain_key-1",
	}
	for in, want := range cases {
		if got := EscapePathKey(in); got != want {
			t.Errorf("EscapePathKey(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestPathJoinsAndEscapes(t *testing.T) {
	got := Path("hooks", "Pre.Tool")
	want := `hooks.Pre\.Tool`
	if got != want {
		t.Errorf("Path = %q; want %q", got, want)
	}
}

func TestSetRawPreservesUnrelatedRootBytes(t *testing.T) {
	in := []byte("{\n\t\"theme\":     \"dark\"   ,\n\t\"hooks\": {}\n}")
	out, err := SetRaw(in, Path("hooks", "PreToolUse"), `[]`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "\t\"theme\":     \"dark\"   ,") {
		t.Fatalf("unrelated root bytes changed:\n%s", out)
	}
}

func TestDeletePreservesTrailingNewlineState(t *testing.T) {
	in := []byte(`{"hooks":{"PreToolUse":[]},"theme":"dark"}`)
	out, err := Delete(in, Path("hooks", "PreToolUse"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 0 && out[len(out)-1] == '\n' {
		t.Fatalf("Delete must not add a final newline: %q", out)
	}
}

func TestRawArrayJoinsRawItems(t *testing.T) {
	if got := RawArray(nil); got != `[]` {
		t.Errorf("RawArray(nil) = %q; want []", got)
	}
	got := RawArray([]string{`{"a":1}`, `{"b":2}`})
	want := `[{"a":1},{"b":2}]`
	if got != want {
		t.Errorf("RawArray = %q; want %q", got, want)
	}
}

func TestMarshalRawJSONStruct(t *testing.T) {
	v := struct {
		Type    string `json:"type"`
		Command string `json:"command"`
	}{Type: "command", Command: "stepsecurity-dev-machine-guard _hook claude-code PreToolUse"}
	got, err := MarshalRawJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"command","command":"stepsecurity-dev-machine-guard _hook claude-code PreToolUse"}`
	if got != want {
		t.Errorf("MarshalRawJSON = %q; want %q", got, want)
	}
}
