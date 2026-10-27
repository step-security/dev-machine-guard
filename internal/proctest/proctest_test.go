package proctest

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const envRole = "DMG_PROCTEST_ROLE"

func TestMain(m *testing.M) {
	switch os.Getenv(envRole) {
	case "sleep": // guarded
		Guard()
		time.Sleep(time.Hour)
	case "sleep-raw": // unguarded
		time.Sleep(time.Hour)
	case "spawn", "spawn-raw": // start a sleeper, print its pid, sleep
		role := "sleep"
		if os.Getenv(envRole) == "spawn-raw" {
			role = "sleep-raw"
		} else {
			Guard()
		}
		c := exec.Command(os.Args[0]) // #nosec G204 -- the test binary
		c.Env = append(os.Environ(), envRole+"="+role)
		if c.Start() != nil {
			os.Exit(1)
		}
		fmt.Println(c.Process.Pid)
		time.Sleep(time.Hour)
	}
	os.Exit(Main(m))
}

func start(t *testing.T, role string) (*exec.Cmd, int) {
	t.Helper()
	cmd := Command(t, os.Args[0])
	cmd.Env = append(cmd.Env, envRole+"="+role)
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
		t.Fatalf("%s said %q", role, line)
	}
	return cmd, pid
}

func TestGuardExitsAtDeadline(t *testing.T) {
	cmd := Command(t, os.Args[0])
	cmd.Env = append(cmd.Env, envRole+"=sleep", EnvDeadline+"="+strconv.FormatInt(time.Now().Add(time.Second).UnixNano(), 10))
	t0 := time.Now()
	_ = cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != ExitGuard || time.Since(t0) > 10*time.Second {
		t.Fatalf("exit %d after %s", code, time.Since(t0))
	}
}

func TestGuardExitsWhenParentDies(t *testing.T) {
	cmd, pid := start(t, "spawn")
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if !WaitGone(pid, 5*time.Second) {
		KillPid(pid)
		t.Fatalf("guarded helper %d outlived its parent", pid)
	}
}

// Unguarded grandchildren die with the test's process group.
func TestCommandKillsTreeWhenTestEnds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no process groups; Windows helpers rely on Guard")
	}
	var mid, leaf int
	t.Run("start", func(t *testing.T) {
		var cmd *exec.Cmd
		cmd, leaf = start(t, "spawn-raw")
		mid = cmd.Process.Pid
		t.Cleanup(func() { _ = cmd.Wait() })
	})
	for _, pid := range []int{mid, leaf} {
		if !WaitGone(pid, 5*time.Second) {
			KillPid(pid)
			t.Fatalf("%d outlived its test", pid)
		}
	}
}

func TestKillChildren(t *testing.T) {
	cmd := exec.Command(os.Args[0]) // #nosec G204 -- the test binary
	cmd.Env = append(os.Environ(), envRole+"=sleep-raw")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	if n := KillChildren(); n < 1 {
		_ = cmd.Process.Kill()
		t.Fatalf("KillChildren found %d", n)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child survived KillChildren")
	}
}
