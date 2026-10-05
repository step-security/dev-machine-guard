package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"unicode/utf8"
)

func FuzzGlobMatch(f *testing.F) {
	for _, seed := range [][2]string{{"**/package.json", "package.json"}, {"**/package.json", "node_modules/x/package.json"}, {"a/*/?.json", "a/b/x.json"}, {"**/x", ".hidden/x"}, {"[x]", "[x]"}, {"**", "a/b"}, {"?", "é"}, {"é", "é"}, {"**/café/package.json", "café/package.json"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, path string) {
		if len(pattern) > 96 || len(path) > 128 || !utf8.ValidString(pattern) || !utf8.ValidString(path) {
			t.Skip()
		}
		cg, err := compileGlob(pattern)
		if err != nil || cg.absolute {
			return
		}
		want := referenceGlob([]rune(pattern), []rune(path))
		if got := cg.re.MatchString(path); got != want {
			t.Fatalf("glob %q path %q: got %v want %v", pattern, path, got, want)
		}
	})
}

// Interpret wildcard tokens directly, independently of regex generation. Memoizing
// suffix pairs avoids exponential exploration of adversarial star sequences.
func referenceGlob(pattern, path []rune) bool {
	type point struct{ p, s int }
	memo := map[point]bool{}
	seen := map[point]bool{}
	var match func(int, int) bool
	match = func(p, s int) bool {
		k := point{p, s}
		if seen[k] {
			return memo[k]
		}
		seen[k] = true
		result := false
		switch {
		case p == len(pattern):
			result = s == len(path)
		case pattern[p] == '*':
			if p+1 < len(pattern) && pattern[p+1] == '*' {
				if p+2 < len(pattern) && pattern[p+2] == '/' {
					result = match(p+3, s)
					for i := s; !result && i < len(path); i++ {
						if path[i] == '/' {
							result = match(p+3, i+1)
						}
					}
				} else {
					result = match(p+2, s) || (s < len(path) && match(p, s+1))
				}
			} else {
				result = match(p+1, s) || (s < len(path) && path[s] != '/' && match(p, s+1))
			}
		case s < len(path):
			result = (pattern[p] == path[s] || (pattern[p] == '?' && path[s] != '/')) && match(p+1, s+1)
		}
		memo[k] = result
		return result
	}
	return match(0, 0)
}

func FuzzRuleSetPrepare(f *testing.F) {
	for _, s := range []string{`{"rules":[]}`, `{"rules":[{"id":"r","file_globs":["**/package.json"],"groups":[{"id":"g","conditions":[{"id":"c","kind":"regex","pattern":"test","mandatory":true}]}]}]}`, `{"rules":[{"id":"r","file_globs":["a"],"max_file_size":-1}]}`, `{"rules":[{"id":"r","file_globs":["../x"]}]}`, `{"rules":[{"id":"r","file_globs":["x"]},{"id":"r","file_globs":["y"]}]}`, `{`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 16*1024 {
			t.Skip()
		}
		var rs RuleSet
		if json.Unmarshal(b, &rs) != nil {
			return
		}
		if rs.Prepare() != nil {
			return
		}
		before, err := json.Marshal(rs)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs.Rules {
			if r.MaxFileSize <= 0 || r.MaxFileSize > hardMaxFileSize || len(r.globs) != len(r.FileGlobs) {
				t.Fatal("accepted rule violates prepared bounds")
			}
		}
		if err := rs.Prepare(); err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(rs)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("Prepare is not idempotent")
		}
		var roundtrip RuleSet
		if err := json.Unmarshal(after, &roundtrip); err != nil {
			t.Fatal(err)
		}
		if err := roundtrip.Prepare(); err != nil {
			t.Fatal(err)
		}
		for i, r := range rs.Rules {
			for j, g := range r.globs {
				other := roundtrip.Rules[i].globs[j]
				if g.absolute != other.absolute || (g.re != nil && g.re.String() != other.re.String()) {
					t.Fatal("round trip changed glob semantics")
				}
			}
		}
	})
}

func FuzzRuleScreening(f *testing.F) {
	f.Add([]byte("setup payload"), "setup", uint8(3))
	f.Add([]byte{}, "^$", uint8(0))
	f.Add([]byte("x"), "[", uint8(255))
	f.Fuzz(func(t *testing.T, data []byte, pattern string, flags uint8) {
		if len(data) > 8192 || len(pattern) > 256 {
			t.Skip()
		}
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		expectedHash := hash
		if flags&32 != 0 {
			expectedHash = "0000000000000000000000000000000000000000000000000000000000000000"
		}
		rs := RuleSet{Rules: []Rule{{ID: "r", FileGlobs: []string{"**/x"}, Groups: []ConditionGroup{
			{ID: "regex", Conditions: []Condition{{ID: "a", Kind: condKindRegex, Pattern: pattern, Mandatory: flags&1 != 0, Negate: flags&2 != 0}, {ID: "b", Kind: condKindRegex, Pattern: "payload", Mandatory: flags&4 != 0}}},
			{ID: "hash", Conditions: []Condition{{ID: "c", Kind: condKindSHA256, Pattern: expectedHash, Mandatory: flags&8 != 0, Negate: flags&16 != 0}}},
		}}}}
		if rs.Prepare() != nil {
			return
		}
		r := &rs.Rules[0]
		want := false
		for _, g := range r.Groups {
			a, satisfied := evalGroup(g, data, hash)
			b, again := evalGroup(g, data, hash)
			if !reflect.DeepEqual(a, b) || satisfied != again {
				t.Fatal("non-deterministic evidence")
			}
			want = want || satisfied
		}
		if got := satisfiesRule(r, data, hash); got != want {
			t.Fatalf("screen=%v group satisfaction=%v", got, want)
		}
	})
}
