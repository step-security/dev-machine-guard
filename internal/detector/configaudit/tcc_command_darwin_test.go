//go:build darwin

package configaudit

import (
	"context"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"testing"
)

func TestTCCPreservesEffectiveNPMConfig(t *testing.T) {
	e := executor.NewMock()
	e.SetGOOS("darwin")
	e.SetPath("npm", "/usr/local/bin/npm")
	e.SetCommand(`{"registry":"https://registry.npmjs.org/"}`, "", 0, "npm", "config", "ls", "-l", "--json")
	e.SetCommand("registry = https://registry.npmjs.org/", "", 0, "npm", "config", "ls", "-l")
	got := NewNPMRCDetector(e).WithSkipper(tcc.New(t.TempDir())).captureEffective(context.Background())
	if got == nil || got.Error != "" || got.Config["registry"] != "https://registry.npmjs.org/" {
		t.Fatalf("lost effective npm config: %+v", got)
	}
}
