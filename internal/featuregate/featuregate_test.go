package featuregate

import (
	"strings"
	"testing"
)

func TestIsEnabled_DefaultDeny(t *testing.T) {
	resetOverride(t)
	for _, f := range []Feature{FeatureAIAgentHooks} {
		if IsEnabled(f) {
			t.Errorf("%s should be gated by default", f)
		}
	}
}

func TestIsEnabled_OverrideEnablesEverything(t *testing.T) {
	resetOverride(t)
	EnableOverride()
	for _, f := range []Feature{FeatureAIAgentHooks, FeatureNPMRCAudit, FeaturePipConfigAudit} {
		if !IsEnabled(f) {
			t.Errorf("%s should be enabled when override is set", f)
		}
	}
}

func TestUnavailableMessage(t *testing.T) {
	msg := UnavailableMessage("hooks install")
	if !strings.Contains(msg, "hooks install") {
		t.Errorf("message %q should name the command", msg)
	}
	if !strings.Contains(msg, "beta") {
		t.Errorf("message %q should mention beta", msg)
	}
}

func resetOverride(t *testing.T) {
	t.Helper()
	prev := override
	t.Cleanup(func() { override = prev })
	override = false
}
