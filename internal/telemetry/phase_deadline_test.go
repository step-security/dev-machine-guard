package telemetry

import (
	"context"
	"testing"
	"time"
)

// resolvePhaseBudget honors STEPSEC_PHASE_BUDGET_<NAME> > map entry > default,
// and treats an env "0"/"off" or an explicit map 0 as "no deadline". Every
// subtest sets the env var explicitly (to "" when it shouldn't apply) so an
// inherited host/CI value can't make the result nondeterministic.
func TestResolvePhaseBudget(t *testing.T) {
	cases := []struct {
		name        string
		phase       string
		env         string // value for STEPSEC_PHASE_BUDGET_<PHASE>
		wantBudget  time.Duration
		wantEnabled bool
	}{
		{"env override wins over map", "node_scan", "20m", 20 * time.Minute, true},
		{"env off disables", "node_scan", "off", 0, false},
		{"env 0 disables", "node_scan", "0", 0, false},
		{"env junk ignored, falls to map", "node_scan", "junk", 15 * time.Minute, true},
		{"env negative ignored, falls to map", "node_scan", "-5m", 15 * time.Minute, true},
		{"map entry used when env empty", "ide_scan", "", 2 * time.Minute, true},
		{"unlisted phase falls to default", "totally_made_up_phase", "", defaultPhaseBudget, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Hermetic: set the exact env key this phase reads (to "" when the
			// case shouldn't have an override).
			t.Setenv("STEPSEC_PHASE_BUDGET_"+upper(tc.phase), tc.env)
			gotBudget, gotEnabled := resolvePhaseBudget(tc.phase)
			if gotEnabled != tc.wantEnabled {
				t.Fatalf("enabled = %v, want %v", gotEnabled, tc.wantEnabled)
			}
			if tc.wantEnabled && gotBudget != tc.wantBudget {
				t.Errorf("budget = %v, want %v", gotBudget, tc.wantBudget)
			}
		})
	}
}

// An explicit 0 in the phaseBudgets map disables the deadline — distinct from a
// missing entry, which falls back to the default. (Copilot finding: the old
// `if budget == 0 { budget = default }` conflated the two.)
func TestResolvePhaseBudget_ExplicitZeroInMapDisables(t *testing.T) {
	const phase = "zzz_explicit_zero_phase"
	phaseBudgets[phase] = 0
	t.Cleanup(func() { delete(phaseBudgets, phase) })
	t.Setenv("STEPSEC_PHASE_BUDGET_"+upper(phase), "") // no env override

	d, enabled := resolvePhaseBudget(phase)
	if enabled || d != 0 {
		t.Errorf("explicit map 0 must disable the deadline: got (%v, enabled=%v)", d, enabled)
	}
}

// startPhase must produce a context with NO deadline when the budget is
// disabled (only the parent scan deadline applies), and a deadline bounded by
// the budget otherwise.
func TestStartPhase_DeadlineWiring(t *testing.T) {
	tracker := NewPhaseTracker()

	t.Run("disabled budget → no phase deadline", func(t *testing.T) {
		t.Setenv("STEPSEC_PHASE_BUDGET_NODE_SCAN", "off")
		ctx, cancel := startPhase(context.Background(), tracker, "node_scan")
		defer cancel()
		if _, ok := ctx.Deadline(); ok {
			t.Error("disabled phase budget must not set a context deadline")
		}
	})

	t.Run("enabled budget → bounded deadline", func(t *testing.T) {
		t.Setenv("STEPSEC_PHASE_BUDGET_NODE_SCAN", "20m")
		ctx, cancel := startPhase(context.Background(), tracker, "node_scan")
		defer cancel()
		dl, ok := ctx.Deadline()
		if !ok {
			t.Fatal("enabled phase budget must set a context deadline")
		}
		if remaining := time.Until(dl); remaining <= 0 || remaining > 20*time.Minute {
			t.Errorf("deadline %v out of expected ~20m window", remaining)
		}
	})
}

// upper uppercases an ASCII phase name for the env-var key, mirroring
// strings.ToUpper without importing it into the test for one call.
func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}
