package rungate

import "testing"

// TestWSLWithOverride pins the local escape hatch: STEPSEC_FORCE_WSL_SCAN is the
// only way to enable distro scanning without a backend directive, and it must
// not disturb a directive that is already on.
func TestWSLWithOverride(t *testing.T) {
	if got := wslWithOverride(WSLDirective{}); got.Enabled {
		t.Error("no directive, no env: want disabled")
	}

	t.Setenv("STEPSEC_FORCE_WSL_SCAN", "1")
	got := wslWithOverride(WSLDirective{})
	if !got.Enabled {
		t.Error("env override did not enable WSL scanning")
	}
	if got.Reason != "env_override" {
		t.Errorf("reason = %q, want env_override", got.Reason)
	}

	// A real directive keeps its own reason.
	got = wslWithOverride(WSLDirective{Enabled: true, Reason: "tenant_opt_in"})
	if !got.Enabled || got.Reason != "tenant_opt_in" {
		t.Errorf("override clobbered a live directive: %+v", got)
	}
}

// TestWSLWithOverrideIgnoresOtherValues: only "1" enables it, so an empty or
// stray value cannot switch on scanning inside a developer's Linux environment.
func TestWSLWithOverrideIgnoresOtherValues(t *testing.T) {
	for _, v := range []string{"", "0", "true", "yes"} {
		t.Setenv("STEPSEC_FORCE_WSL_SCAN", v)
		if wslWithOverride(WSLDirective{}).Enabled {
			t.Errorf("STEPSEC_FORCE_WSL_SCAN=%q enabled scanning; only \"1\" should", v)
		}
	}
}
