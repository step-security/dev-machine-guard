package selfupdate

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

// Helpers dispatched from TestMain never arm -test.timeout; each must stop
// at the deadline its test passed down.
func TestHelpersExitAtDeadline(t *testing.T) {
	for name, env := range map[string][]string{
		"sleep role":      {envRole + "=sleep"},
		"hung self-check": {envHelper + "=1", "DMG_SU_SMOKE_HANG=1"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cmd := proctest.Command(t, os.Args[0], "self-check")
			cmd.Env = append(append(cmd.Env, env...),
				proctest.EnvDeadline+"="+strconv.FormatInt(time.Now().Add(time.Second).UnixNano(), 10))
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
				if code := cmd.ProcessState.ExitCode(); code != proctest.ExitGuard {
					t.Fatalf("exit %d, want %d", code, proctest.ExitGuard)
				}
			case <-time.After(15 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Fatal("helper ignored its deadline")
			}
		})
	}
}
