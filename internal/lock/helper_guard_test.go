package lock

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

// middleEnv makes the test binary start a holder, print its pid, and block:
// the holder's parent, for the test to kill.
const middleEnv = "DMG_LOCK_TEST_MIDDLE"

func runMiddle(target string) {
	cmd := exec.Command(os.Args[0], "-test.run=^$") // #nosec G204 -- the test binary
	cmd.Env = append(os.Environ(), helperEnv+"="+target, middleEnv+"=")
	out, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		os.Exit(1)
	}
	if line, _ := bufio.NewReader(out).ReadString('\n'); strings.TrimSpace(line) != "ready" {
		os.Exit(1)
	}
	fmt.Println(cmd.Process.Pid)
	time.Sleep(time.Hour)
	os.Exit(0)
}

// A holder whose test process died (killed, timed out) must not live on.
func TestHolderExitsWhenParentDies(t *testing.T) {
	cmd := proctest.Command(t, os.Args[0], "-test.run=^$")
	cmd.Env = append(cmd.Env, middleEnv+"="+testLockTarget(t))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(out).ReadString('\n')
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("middle said %q", line)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if !proctest.WaitGone(pid, 10*time.Second) {
		proctest.KillPid(pid)
		t.Fatalf("holder %d outlived its parent", pid)
	}
}

// A holder stops at the deadline its test passed down.
func TestHolderExitsAtDeadline(t *testing.T) {
	cmd := proctest.Command(t, os.Args[0], "-test.run=^$")
	cmd.Env = append(cmd.Env, helperEnv+"="+testLockTarget(t),
		proctest.EnvDeadline+"="+strconv.FormatInt(time.Now().Add(time.Second).UnixNano(), 10))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
		if code := cmd.ProcessState.ExitCode(); code != proctest.ExitGuard {
			t.Fatalf("holder exit %d, want %d", code, proctest.ExitGuard)
		}
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("holder ignored its deadline")
	}
}
