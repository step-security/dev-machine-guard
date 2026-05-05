package policy

import "testing"

func TestBuiltinParses(t *testing.T) {
	p := Builtin()
	if p.Version == 0 {
		t.Errorf("builtin policy: version 0")
	}
	npm, ok := p.Ecosystems[EcosystemNPM]
	if !ok {
		t.Fatalf("builtin policy: missing npm block")
	}
	if !npm.Enabled {
		t.Errorf("builtin policy: npm block must ship enabled")
	}
	if len(npm.Registry.Allowlist) == 0 {
		t.Errorf("builtin policy: expected allowlist")
	}
}

func TestBuiltinDefaultsToAuditMode(t *testing.T) {
	p := Builtin()
	if got := ResolveMode(p); got != ModeAudit {
		t.Errorf("builtin policy: expected audit mode, got %q", got)
	}
}

func TestResolveModeFallsBackToAudit(t *testing.T) {
	cases := []struct {
		name string
		in   Mode
	}{
		{"empty", ""},
		{"unknown", "garbage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveMode(Policy{Mode: tc.in}); got != ModeAudit {
				t.Errorf("ResolveMode(%q) = %q, want %q", tc.in, got, ModeAudit)
			}
		})
	}
}

func TestResolveModeHonorsBlock(t *testing.T) {
	if got := ResolveMode(Policy{Mode: ModeBlock}); got != ModeBlock {
		t.Errorf("ResolveMode(block) = %q, want %q", got, ModeBlock)
	}
}
