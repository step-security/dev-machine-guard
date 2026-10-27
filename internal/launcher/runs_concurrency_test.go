package launcher

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/updatestate"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

const envRunLoopRoot = "DMG_TEST_RUNLOOP_ROOT"

// TestHelperRunLoop is the subprocess body of
// TestRun_ConcurrentProcessesKeepEveryRecord; it does nothing otherwise.
func TestHelperRunLoop(t *testing.T) {
	root := os.Getenv(envRunLoopRoot)
	if root == "" {
		t.Skip("subprocess helper")
	}
	proctest.Guard()
	l := updatestate.Layout{InstallRoot: filepath.Join(root, "install"), DataRoot: filepath.Join(root, "data")}
	seq, last := 0, ""
	logBuf := &bytes.Buffer{}
	b := &Bootstrap{
		Layout: l,
		Spawn: func(string, []string, []string, time.Duration, func()) SpawnResult {
			time.Sleep(time.Duration(rand.IntN(3000)) * time.Microsecond)
			return SpawnResult{Started: true}
		},
		IsSystem: func() bool { return false },
		Now:      time.Now,
		Sleep:    time.Sleep,
		Getenv:   func(string) string { return "" },
		Environ:  func() []string { return nil },
		Out:      logBuf,
		NewRunID: func() string {
			seq++
			last = fmt.Sprintf("%d-%d", os.Getpid(), seq)
			return last
		},
		LockPoll: time.Millisecond,
	}
	runFile := l.RunFile(updatestate.Version{Major: 1, Minor: 2})
	missing := 0
	for i := 0; i < 40; i++ {
		b.Run([]string{"send-telemetry", "--install-dir=" + l.DataRoot})
		found := false
		for _, r := range updatestate.ReadRuns(runFile) {
			if r.RunID == last && r.ExitCode != nil {
				found = true
			}
		}
		if !found {
			missing++
		}
		// Pace the loop like real overlapping tasks: one process must not
		// run MaxRunRecords launches during the other's single launch, or
		// the cap (not a lost update) evicts the other's open record.
		time.Sleep(2 * time.Millisecond)
	}
	if missing > 0 {
		fmt.Printf("lost %d of 40 run records\n%s", missing, logBuf)
		os.Exit(1)
	}
}

// R-B-2: two bootstrap processes (the hourly and Logon tasks firing together)
// append and finalize records in the same runs\<v>.json concurrently; no
// record may be lost.
func TestRun_ConcurrentProcessesKeepEveryRecord(t *testing.T) {
	if os.Getenv(envRunLoopRoot) != "" {
		t.Skip("inside the helper")
	}
	root := t.TempDir()
	l := updatestate.Layout{InstallRoot: filepath.Join(root, "install"), DataRoot: filepath.Join(root, "data")}
	if err := os.MkdirAll(l.StateDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.StateFile(), []byte(`{"schema":1,"current":"1.2.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mkVersionDir(t, filepath.Join(l.VersionsDir(), "1.2.0"))
	var cmds []*exec.Cmd
	var outs []*bytes.Buffer
	for i := 0; i < 2; i++ {
		cmd := proctest.Command(t, os.Args[0], "-test.run=^TestHelperRunLoop$", "-test.count=1")
		cmd.Env = append(cmd.Env, envRunLoopRoot+"="+root)
		out := &bytes.Buffer{}
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds, outs = append(cmds, cmd), append(outs, out)
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Errorf("process %d: %v\n%s", i, err, outs[i])
		}
	}
}
