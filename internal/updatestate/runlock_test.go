package updatestate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

const raceFiles = 40

// TestRunRaceHelper is one side of TestAgentMarkerVsBootstrapFinalize:
// "agent" marks record a in every file, "bootstrap" finalizes record b
// under the run-record lock (as dmg-boot's bootstrap does, 544d1ee).
func TestRunRaceHelper(t *testing.T) {
	dir, role := os.Getenv("RUNRACE_DIR"), os.Getenv("RUNRACE_ROLE")
	if dir == "" {
		t.Skip("helper")
	}
	proctest.Guard()
	for time.Now().Before(mustUnix(os.Getenv("RUNRACE_START"))) {
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < raceFiles; i++ {
		path := filepath.Join(dir, fmt.Sprintf("%d.json", i))
		var err error
		switch role {
		case "agent":
			err = MarkRunStartedLocked(path, "a", 5*time.Second)
		case "agent-unlocked":
			err = MarkRunStarted(path, "a")
		case "bootstrap":
			err = withTestRunLock(path+".lock", func() error {
				return FinalizeRun(path, "b", 0, false, time.Now())
			})
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, role, i, err)
		}
	}
	os.Exit(0)
}

func mustUnix(s string) time.Time {
	n, _ := strconv.ParseInt(s, 10, 64)
	return time.Unix(0, n)
}

// withTestRunLock mirrors the bootstrap's withRunLock.
func withTestRunLock(lockPath string, fn func() error) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err := AcquireLock(lockPath)
		if err == nil {
			defer l.Release()
			return fn()
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

// race runs the agent role against a locked bootstrap finalizer and
// returns how many files lost the marker or the finalization.
func race(t *testing.T, agentRole string) int {
	t.Helper()
	dir := t.TempDir()
	for i := 0; i < raceFiles; i++ {
		path := filepath.Join(dir, fmt.Sprintf("%d.json", i))
		for _, id := range []string{"a", "b"} {
			if err := AppendRun(path, RunRecord{RunID: id, Version: "1.19.0"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	start := strconv.FormatInt(time.Now().Add(300*time.Millisecond).UnixNano(), 10)
	var cmds []*exec.Cmd
	for _, role := range []string{agentRole, "bootstrap"} {
		cmd := proctest.Command(t, os.Args[0], "-test.run=^TestRunRaceHelper$")
		cmd.Env = append(cmd.Env, "RUNRACE_DIR="+dir, "RUNRACE_ROLE="+role, "RUNRACE_START="+start)
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, cmd)
	}
	for _, c := range cmds {
		_ = c.Wait()
	}
	lost := 0
	for i := 0; i < raceFiles; i++ {
		got := map[string]RunRecord{}
		for _, r := range ReadRuns(filepath.Join(dir, fmt.Sprintf("%d.json", i))) {
			got[r.RunID] = r
		}
		if !got["a"].Started || got["b"].ExitCode == nil {
			lost++
		}
	}
	return lost
}

// D17: the agent's started marker and the bootstrap's finalize of another
// record in the same file, from two processes, must both survive.
func TestAgentMarkerVsBootstrapFinalize(t *testing.T) {
	if lost := race(t, "agent"); lost != 0 {
		t.Fatalf("%d of %d files lost an update with the agent under the run lock", lost, raceFiles)
	}
	// Evidence for the bug the lock fixes (not asserted: it is a race).
	t.Logf("without the agent taking the lock: %d of %d files lost an update", race(t, "agent-unlocked"), raceFiles)
}

func TestMarkRunStartedLockedTimesOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.19.0.json")
	if err := AppendRun(path, RunRecord{RunID: "a", Version: "1.19.0"}); err != nil {
		t.Fatal(err)
	}
	held, err := AcquireLock(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	start := time.Now()
	if err := MarkRunStartedLocked(path, "a", 200*time.Millisecond); err == nil {
		t.Fatal("marked while the bootstrap held the run lock")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("wait not bounded")
	}
	if ReadRuns(path)[0].Started {
		t.Fatal("marker written without the lock")
	}
}

// B4(a): the agent's marker and the bootstrap use one lock path helper: a
// holder of Layout.RunLockFile blocks MarkRunStartedLocked on RunFile.
func TestMarkerAndBootstrapShareTheRunLock(t *testing.T) {
	l := Layout{InstallRoot: t.TempDir(), DataRoot: t.TempDir()}
	v, _ := ParseVersion("1.20.0")
	if err := AppendRun(l.RunFile(v), RunRecord{RunID: "a", Version: "1.20.0"}); err != nil {
		t.Fatal(err)
	}
	if l.RunFile(v)+".lock" != l.RunLockFile(v) {
		t.Fatalf("lock paths differ")
	}
	held, err := AcquireLock(l.RunLockFile(v))
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkRunStartedLocked(l.RunFile(v), "a", 100*time.Millisecond); err == nil {
		t.Fatal("marker written while the bootstrap held the run lock")
	}
	held.Release()
	if err := MarkRunStartedLocked(l.RunFile(v), "a", time.Second); err != nil {
		t.Fatal(err)
	}
}
