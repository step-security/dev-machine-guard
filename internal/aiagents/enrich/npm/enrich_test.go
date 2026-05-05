package npm

import (
	"context"
	"strings"
	"testing"
)

func TestEnrichCapturesNPMRegistryAndConfigSources(t *testing.T) {
	if !canLookPath("npm") {
		t.Skip("npm not on PATH")
	}
	stubRun(t, func(_ context.Context, _, _ string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "config get registry":
			return "https://registry.npmjs.org/\n", nil
		case "config ls -l":
			return "; project config from /tmp/project/.npmrc\n", nil
		}
		return "", nil
	})

	info, timedOut := Enrich(context.Background(), "npm install lodash", "")

	if timedOut {
		t.Fatal("unexpected timeout")
	}
	if info == nil {
		t.Fatal("expected package manager info")
	}
	if info.Registry != "https://registry.npmjs.org/" {
		t.Errorf("registry: %q", info.Registry)
	}
	if len(info.ConfigSources) != 1 || info.ConfigSources[0] != "/tmp/project/.npmrc" {
		t.Errorf("config sources: %v", info.ConfigSources)
	}
}
