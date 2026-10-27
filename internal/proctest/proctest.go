// Package proctest keeps the processes tests start from outliving them.
//
//   - Command (test side) ties a child to the test: it is killed, with its
//     process group, when the test ends or its deadline passes, and it gets
//     that deadline in EnvDeadline.
//   - Guard (child side) is a helper's first call: the helper exits at the
//     deadline, or as soon as the process that started it is gone, even when
//     the test binary was killed and no cleanup ran.
//   - Main (package side) kills any child still running shortly before
//     -test.timeout and after the tests.
//
// -test.timeout alone is not enough: helpers dispatched from TestMain never
// arm it, -test.run helpers are started without it, and a child stuck
// between fork and exec runs no Go code at all (seen with -race on macOS:
// the fork child spins in the race runtime with signals blocked).
package proctest

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	// EnvDeadline carries a helper's deadline (Unix nanoseconds).
	EnvDeadline = "DMG_PROCTEST_DEADLINE"
	// DefaultTimeout bounds a helper started without a deadline.
	DefaultTimeout = 10 * time.Minute
	// ExitGuard is a helper's exit code when Guard ends it.
	ExitGuard = 86
)

// Command is exec.Command bound to t. Add to cmd.Env rather than
// replacing it, so the helper keeps its deadline.
func Command(t testing.TB, name string, args ...string) *exec.Cmd {
	t.Helper()
	deadline := time.Now().Add(DefaultTimeout)
	if d, ok := t.(interface{ Deadline() (time.Time, bool) }); ok {
		if dl, ok := d.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
	}
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- test subprocess
	cmd.Env = append(os.Environ(), EnvDeadline+"="+strconv.FormatInt(deadline.UnixNano(), 10))
	killTreeOnCancel(cmd)
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// Guard ends this helper process at its deadline or when its parent exits.
func Guard() { guard(true) }

// GuardDeadline is Guard without the parent watch, for helpers whose test
// checks that something else kills them once their parent is gone.
func GuardDeadline() { guard(false) }

func guard(parent bool) {
	deadline := time.Now().Add(DefaultTimeout)
	if n, err := strconv.ParseInt(os.Getenv(EnvDeadline), 10, 64); err == nil {
		deadline = time.Unix(0, n)
	}
	time.AfterFunc(time.Until(deadline), func() { exit("deadline passed") })
	if parent {
		watchParent(func() { exit("parent exited") })
	}
}

func exit(why string) {
	fmt.Fprintf(os.Stderr, "proctest: helper %d exiting: %s\n", os.Getpid(), why)
	os.Exit(ExitGuard)
}

// Main runs the tests for TestMain, killing children still running shortly
// before -test.timeout (failing the run) and after the tests.
func Main(m *testing.M) int {
	if !flag.Parsed() {
		flag.Parse()
	}
	var timeout time.Duration
	if f := flag.Lookup("test.timeout"); f != nil {
		if g, ok := f.Value.(flag.Getter); ok {
			timeout, _ = g.Get().(time.Duration)
		}
	}
	var reaped atomic.Int64
	if timeout > 5*time.Second {
		// Early enough for a test blocked on a stuck child to fail cleanly.
		margin := min(timeout/10, 30*time.Second)
		t1 := time.AfterFunc(timeout-margin, func() { reaped.Add(int64(reap("%s before -test.timeout", margin))) })
		defer t1.Stop()
		// Just before the timeout panic: stop new forks, then reap, so no
		// child is left to be orphaned by it.
		t2 := time.AfterFunc(timeout-time.Second, func() {
			syscall.ForkLock.Lock() // never released: the run is ending
			reaped.Add(int64(reap("1s before -test.timeout")))
		})
		defer t2.Stop()
	}
	code := m.Run()
	reap("after the tests")
	if reaped.Load() > 0 && code == 0 {
		code = 1
	}
	return code
}

func reap(when string, a ...any) int {
	n := KillChildren()
	if n > 0 {
		fmt.Fprintf(os.Stderr, "proctest: killed %d child process(es) still running "+when+"\n", append([]any{n}, a...)...)
	}
	return n
}

// KillChildren kills every live child of this process (and, on Unix, its
// process group) and returns how many it found.
func KillChildren() int {
	pids, err := children()
	if err != nil {
		fmt.Fprintf(os.Stderr, "proctest: listing child processes: %v\n", err)
		return 0
	}
	for _, pid := range pids {
		killTree(pid)
	}
	return len(pids)
}

// KillPid kills pid and, on Unix, the process group it leads.
func KillPid(pid int) { killTree(pid) }
