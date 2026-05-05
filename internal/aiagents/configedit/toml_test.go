package configedit

import (
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

func TestEnsureCodexHooksFlagAppendsWhenAbsent(t *testing.T) {
	in := []byte(`model = "gpt-5"
`)
	out, changed, err := EnsureCodexHooksFlag(in)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Errorf("expected changed=true")
	}
	s := string(out)
	if !strings.Contains(s, "[features]") {
		t.Errorf("missing [features]: %s", s)
	}
	if !strings.Contains(s, "codex_hooks = true") {
		t.Errorf("missing codex_hooks: %s", s)
	}
	// Original line preserved.
	if !strings.HasPrefix(s, `model = "gpt-5"`) {
		t.Errorf("unrelated content lost: %s", s)
	}
	// Validates as TOML.
	var probe map[string]any
	if err := toml.Unmarshal(out, &probe); err != nil {
		t.Errorf("invalid TOML: %v", err)
	}
}

func TestEnsureCodexHooksFlagInsertsIntoExistingFeatures(t *testing.T) {
	in := []byte(`model = "gpt-5"
[features]
other_flag = true
`)
	out, changed, err := EnsureCodexHooksFlag(in)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Errorf("expected changed=true")
	}
	s := string(out)
	if !strings.Contains(s, "codex_hooks = true") {
		t.Errorf("missing codex_hooks: %s", s)
	}
	// Original keys still present and order preserved.
	if !strings.Contains(s, "other_flag = true") {
		t.Errorf("unrelated key lost: %s", s)
	}
	if !strings.Contains(s, `model = "gpt-5"`) {
		t.Errorf("unrelated table lost: %s", s)
	}
}

func TestEnsureCodexHooksFlagFlipsFalseToTrue(t *testing.T) {
	in := []byte(`[features]
codex_hooks = false
`)
	out, changed, err := EnsureCodexHooksFlag(in)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Errorf("expected changed=true")
	}
	if !strings.Contains(string(out), "codex_hooks = true") {
		t.Errorf("flag not flipped: %s", out)
	}
	if strings.Contains(string(out), "codex_hooks = false") {
		t.Errorf("old false value still present: %s", out)
	}
}

func TestEnsureCodexHooksFlagNoOpWhenTrue(t *testing.T) {
	in := []byte(`[features]
codex_hooks = true
other = false
`)
	out, changed, err := EnsureCodexHooksFlag(in)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Errorf("expected changed=false")
	}
	if string(out) != string(in) {
		t.Errorf("bytes changed despite no-op:\n  in  %s\n  out %s", in, out)
	}
}

func TestEnsureCodexHooksFlagPreservesCommentsAndAdjacentTables(t *testing.T) {
	in := []byte(`# user header comment
model = "gpt-5"

[features]
# upstream comment
sandbox = "workspace-write"

[telemetry]
enabled = true
`)
	out, changed, err := EnsureCodexHooksFlag(in)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Errorf("expected changed=true")
	}
	s := string(out)
	for _, want := range []string{
		"# user header comment",
		`model = "gpt-5"`,
		"# upstream comment",
		`sandbox = "workspace-write"`,
		"[telemetry]",
		"enabled = true",
		"codex_hooks = true",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected output to contain %q; got %s", want, s)
		}
	}
	// codex_hooks must land in [features], not [telemetry].
	featStart := strings.Index(s, "[features]")
	telStart := strings.Index(s, "[telemetry]")
	codexAt := strings.Index(s, "codex_hooks")
	if !(featStart < codexAt && codexAt < telStart) {
		t.Errorf("codex_hooks landed outside [features]: %s", s)
	}
}

func TestEnsureCodexHooksFlagIgnoresLiteralsInsideMultilineStrings(t *testing.T) {
	// The literal text `[features]` and `codex_hooks = true` appear
	// inside a triple-quoted string. The patcher must NOT treat them as
	// real TOML structure, and must still append a real [features] table.
	in := []byte("docstring = \"\"\"\n[features]\ncodex_hooks = true\n\"\"\"\n")
	out, changed, err := EnsureCodexHooksFlag(in)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Errorf("expected changed=true; multiline-string content must not be treated as real flag")
	}
	// Output must still contain the docstring intact and a NEW real
	// [features] table at the end.
	s := string(out)
	if !strings.Contains(s, "docstring = \"\"\"\n[features]\ncodex_hooks = true\n\"\"\"") {
		t.Errorf("docstring corrupted: %s", s)
	}
	if !strings.HasSuffix(s, "[features]\ncodex_hooks = true\n") {
		t.Errorf("real [features] table not appended: %s", s)
	}
	// Validates as TOML.
	var probe map[string]any
	if err := toml.Unmarshal(out, &probe); err != nil {
		t.Errorf("invalid TOML: %v", err)
	}
}

func TestCodexHooksEnabledIgnoresLiteralsInsideStrings(t *testing.T) {
	// The flag appears inside a literal multiline string, NOT as a real
	// key. CodexHooksEnabled must report false.
	in := []byte("docstring = \"\"\"\n[features]\ncodex_hooks = true\n\"\"\"\n")
	if CodexHooksEnabled(in) {
		t.Errorf("multiline string content must not be detected as enabled flag")
	}
}

func TestEnsureCodexHooksFlagRejectsPatchProducingInvalidTOML(t *testing.T) {
	// Sanity check: malformed input that would produce a still-malformed
	// output should error out (the patched bytes get validated). We can't
	// easily synthesize a case where our own patch breaks valid input, so
	// just check that obviously-broken input is reported.
	in := []byte("[features\nbroken")
	_, _, err := EnsureCodexHooksFlag(in)
	if err == nil {
		t.Errorf("expected error on malformed TOML input")
	}
}

func TestCodexHooksEnabledIgnoresCommentedFlag(t *testing.T) {
	in := []byte("# [features]\n# codex_hooks = true\n")
	if CodexHooksEnabled(in) {
		t.Fatal("commented flag must not count as enabled")
	}
}

func TestCodexHooksEnabled(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"absent", `model = "gpt-5"`, false},
		{"missing key", "[features]\nother = true\n", false},
		{"false", "[features]\ncodex_hooks = false\n", false},
		{"true", "[features]\ncodex_hooks = true\n", true},
		{"true with comment", "[features]\ncodex_hooks = true # on\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CodexHooksEnabled([]byte(tc.in)); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
