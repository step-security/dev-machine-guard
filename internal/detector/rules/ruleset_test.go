package rules

import (
	"strings"
	"testing"
)

func TestPrepare(t *testing.T) {
	tests := []struct {
		name    string
		rs      RuleSet
		wantErr bool
	}{
		{
			name: "valid regex + sha256 rule",
			rs: RuleSet{Rules: []Rule{{
				ID: "ok", FileGlobs: []string{"**/setup.js"},
				Groups: []ConditionGroup{{ID: "g", Conditions: []Condition{
					{ID: "a", Kind: condKindRegex, Pattern: `eval\(`},
					{ID: "b", Kind: condKindSHA256, Pattern: strings.Repeat("a", 64)},
				}}},
			}}},
		},
		{
			name: "existence-only rule (no groups)",
			rs:   RuleSet{Rules: []Rule{{ID: "ex", FileGlobs: []string{"**/malware.json"}}}},
		},
		{name: "empty rule id", rs: RuleSet{Rules: []Rule{{ID: "", FileGlobs: []string{"**/x"}}}}, wantErr: true},
		{
			name:    "duplicate rule id",
			rs:      RuleSet{Rules: []Rule{{ID: "dup", FileGlobs: []string{"**/x"}}, {ID: "dup", FileGlobs: []string{"**/y"}}}},
			wantErr: true,
		},
		{name: "no file glob", rs: RuleSet{Rules: []Rule{{ID: "r"}}}, wantErr: true},
		{
			name: "duplicate group id",
			rs: RuleSet{Rules: []Rule{{ID: "r", FileGlobs: []string{"**/x"}, Groups: []ConditionGroup{
				{ID: "g", Conditions: []Condition{{ID: "a", Kind: condKindRegex, Pattern: "x"}}},
				{ID: "g", Conditions: []Condition{{ID: "b", Kind: condKindRegex, Pattern: "y"}}},
			}}}},
			wantErr: true,
		},
		{
			name: "duplicate condition id",
			rs: RuleSet{Rules: []Rule{{ID: "r", FileGlobs: []string{"**/x"}, Groups: []ConditionGroup{
				{ID: "g", Conditions: []Condition{
					{ID: "a", Kind: condKindRegex, Pattern: "x"},
					{ID: "a", Kind: condKindRegex, Pattern: "y"},
				}},
			}}}},
			wantErr: true,
		},
		{
			name: "empty group conditions",
			rs: RuleSet{Rules: []Rule{{ID: "r", FileGlobs: []string{"**/x"}, Groups: []ConditionGroup{
				{ID: "g"},
			}}}},
			wantErr: true,
		},
		{
			name: "bad regex",
			rs: RuleSet{Rules: []Rule{{ID: "r", FileGlobs: []string{"**/x"}, Groups: []ConditionGroup{
				{ID: "g", Conditions: []Condition{{ID: "a", Kind: condKindRegex, Pattern: "("}}},
			}}}},
			wantErr: true,
		},
		{
			name: "sha256 not 64 hex",
			rs: RuleSet{Rules: []Rule{{ID: "r", FileGlobs: []string{"**/x"}, Groups: []ConditionGroup{
				{ID: "g", Conditions: []Condition{{ID: "a", Kind: condKindSHA256, Pattern: "abc"}}},
			}}}},
			wantErr: true,
		},
		{
			name: "unknown kind",
			rs: RuleSet{Rules: []Rule{{ID: "r", FileGlobs: []string{"**/x"}, Groups: []ConditionGroup{
				{ID: "g", Conditions: []Condition{{ID: "a", Kind: "json", Pattern: "x"}}},
			}}}},
			wantErr: true,
		},
		{name: "glob with backslash", rs: RuleSet{Rules: []Rule{{ID: "r", FileGlobs: []string{`**\x`}}}}, wantErr: true},
		{name: "glob with dotdot", rs: RuleSet{Rules: []Rule{{ID: "r", FileGlobs: []string{"../x"}}}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rs.Prepare()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Prepare() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestPrepareClampsMaxFileSize(t *testing.T) {
	rs := RuleSet{Rules: []Rule{
		{ID: "zero", FileGlobs: []string{"**/x"}, MaxFileSize: 0},
		{ID: "huge", FileGlobs: []string{"**/y"}, MaxFileSize: 1 << 40},
		{ID: "ok", FileGlobs: []string{"**/z"}, MaxFileSize: 1024},
	}}
	if err := rs.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if rs.Rules[0].MaxFileSize != hardMaxFileSize {
		t.Errorf("zero max_file_size: got %d, want clamp to %d", rs.Rules[0].MaxFileSize, hardMaxFileSize)
	}
	if rs.Rules[1].MaxFileSize != hardMaxFileSize {
		t.Errorf("huge max_file_size: got %d, want clamp to %d", rs.Rules[1].MaxFileSize, hardMaxFileSize)
	}
	if rs.Rules[2].MaxFileSize != 1024 {
		t.Errorf("in-bounds max_file_size: got %d, want 1024", rs.Rules[2].MaxFileSize)
	}
}

func TestGlobMatching(t *testing.T) {
	tests := []struct {
		glob     string
		rel      string
		want     bool
		absolute bool
	}{
		{glob: "**/.github/setup.js", rel: "acme/.github/setup.js", want: true},
		{glob: "**/.github/setup.js", rel: ".github/setup.js", want: true},
		{glob: "**/.github/setup.js", rel: "a/b/c/.github/setup.js", want: true},
		{glob: "**/.github/setup.js", rel: "acme/.github/other.js", want: false},
		{glob: ".github/setup.js", rel: ".github/setup.js", want: true},
		{glob: ".github/setup.js", rel: "acme/.github/setup.js", want: false},
		{glob: "**/*.mjs", rel: "deep/dir/x.mjs", want: true},
		{glob: "**/*.mjs", rel: "deep/dir/x.js", want: false},
		{glob: "/usr/bin/bad", absolute: true},
		{glob: "C:/Windows/bad.exe", absolute: true},
		{glob: "//host/share/bad", absolute: true},
	}
	for _, tt := range tests {
		t.Run(tt.glob+"|"+tt.rel, func(t *testing.T) {
			cg, err := compileGlob(tt.glob)
			if err != nil {
				t.Fatalf("compileGlob(%q): %v", tt.glob, err)
			}
			if cg.absolute != tt.absolute {
				t.Fatalf("absolute = %v, want %v", cg.absolute, tt.absolute)
			}
			if tt.absolute {
				return // relative-match assertion is N/A
			}
			if got := cg.re.MatchString(tt.rel); got != tt.want {
				t.Errorf("match(%q, %q) = %v, want %v", tt.glob, tt.rel, got, tt.want)
			}
		})
	}
}
