package lock

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

// helperEnv makes the test binary act as a lock holder: acquire, print
// "ready", then block until killed.
const helperEnv = "DMG_LOCK_TEST_HOLDER"

func TestMain(m *testing.M) {
	if target := os.Getenv(middleEnv); target != "" {
		proctest.Guard()
		runMiddle(target)
	}
	if target := os.Getenv(helperEnv); target != "" {
		proctest.Guard()
		setLockTarget(target)
		lk, err := Acquire(nil)
		if err != nil {
			fmt.Println("acquire failed:", err)
			os.Exit(1)
		}
		defer lk.Release() // keeps the lock reachable; never runs on kill
		fmt.Println("ready")
		time.Sleep(time.Hour)
		os.Exit(0)
	}
	os.Exit(proctest.Main(m))
}

func TestAcquireHeldInProcess(t *testing.T) {
	setLockTarget(testLockTarget(t))

	lk, err := Acquire(nil)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if _, err := Acquire(nil); !errors.Is(err, ErrHeld) {
		t.Fatalf("second Acquire while held: err=%v, want ErrHeld", err)
	}
	lk.Release()
	lk.Release() // idempotent

	lk2, err := Acquire(nil)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	lk2.Release()
}

func TestAcquireAfterHolderKilled(t *testing.T) {
	target := testLockTarget(t)
	setLockTarget(target)

	cmd := proctest.Command(t, os.Args[0], "-test.run=^$")
	cmd.Env = append(cmd.Env, helperEnv+"="+target)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	line, err := bufio.NewReader(out).ReadString('\n')
	if strings.TrimSpace(line) != "ready" {
		t.Fatalf("holder did not acquire: %q %v", line, err)
	}

	if _, err := Acquire(nil); !errors.Is(err, ErrHeld) {
		t.Fatalf("Acquire while subprocess holds: err=%v, want ErrHeld", err)
	}

	// SIGKILL / TerminateProcess: no chance to run any release code.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()

	lk, err := Acquire(nil)
	if err != nil {
		t.Fatalf("Acquire after holder killed: %v", err)
	}
	lk.Release()
}
