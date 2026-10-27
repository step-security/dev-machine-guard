package updatestate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

// TestCrashHelper is the subprocess body: it saves the "new" state and is
// killed at the requested checkpoint, either by a stubbed checkpoint
// (UPDATESTATE_HOOK=1) or by a real faultinject DMG_FAULT (tagged builds).
func TestCrashHelper(t *testing.T) {
	path := os.Getenv("UPDATESTATE_CRASH_PATH")
	if path == "" {
		t.Skip("helper")
	}
	proctest.Guard()
	if phase := os.Getenv("UPDATESTATE_HOOK_PHASE"); phase != "" {
		checkpoint = func(name string) error {
			if name == phase {
				os.Exit(137)
			}
			return nil
		}
	}
	if err := SaveCheckpointed(path, newCrashState(), os.Getenv("UPDATESTATE_PREFIX")); err != nil {
		os.Exit(91)
	}
	os.Exit(0)
}

func oldCrashState() *State { return &State{Current: "1.18.2", Previous: "1.17.0"} }

func newCrashState() *State {
	return &State{
		Current:   "1.19.0",
		Previous:  "1.18.2",
		Probation: &Probation{Version: "1.19.0", Since: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)},
	}
}

// runCrash saves the old state, runs the helper with env, and returns the
// helper's exit code and the state Load then sees.
func runCrash(t *testing.T, prefix string, env ...string) (int, *State) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, oldCrashState()); err != nil {
		t.Fatal(err)
	}
	cmd := proctest.Command(t, os.Args[0], "-test.run=^TestCrashHelper$")
	cmd.Env = append(cmd.Env, append(env, "UPDATESTATE_CRASH_PATH="+path, "UPDATESTATE_PREFIX="+prefix)...)
	_ = cmd.Run()
	st, corrupt, err := Load(path)
	if err != nil || corrupt || st == nil {
		t.Fatalf("Load after crash: %+v corrupt=%v err=%v (torn state)", st, corrupt, err)
	}
	SweepTemps(path)
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("SweepTemps left %v", entries)
	}
	return cmd.ProcessState.ExitCode(), st
}

func TestSaveAtomicUnderKill(t *testing.T) {
	for _, tc := range []struct {
		phase   string
		wantNew bool
	}{
		{"S6.state-temp", false},
		{"S6.state-renamed", true},
	} {
		t.Run(tc.phase, func(t *testing.T) {
			code, st := runCrash(t, "S6", "UPDATESTATE_HOOK_PHASE="+tc.phase)
			if code != 137 {
				t.Fatalf("helper exit %d, want 137", code)
			}
			if want := map[bool]string{false: "1.18.2", true: "1.19.0"}[tc.wantNew]; st.Current != want {
				t.Fatalf("current = %s, want %s", st.Current, want)
			}
		})
	}
	t.Run("no crash", func(t *testing.T) {
		if code, st := runCrash(t, "S6", "UPDATESTATE_HOOK_PHASE=none"); code != 0 || st.Current != "1.19.0" {
			t.Fatalf("exit %d current %s", code, st.Current)
		}
	})
}
