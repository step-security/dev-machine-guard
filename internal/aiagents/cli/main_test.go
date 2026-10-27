package cli

import (
	"fmt"
	"os"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/proctest"
)

// TestMain keeps the package off the real host: a temp HOME/USERPROFILE so
// nothing reads or writes the developer's ~/.claude, ~/.codex or
// ~/.stepsecurity, and a mock executor so RunHook spawns no host probes.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "aiagents-cli-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, k := range []string{"HOME", "USERPROFILE"} {
		_ = os.Setenv(k, home)
	}
	newHookExecutor = func() executor.Executor { return executor.NewMock() }
	code := proctest.Main(m)
	_ = os.RemoveAll(home)
	os.Exit(code)
}
