package launcher

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

type spawnCall struct {
	path     string
	args     []string
	env      []string
	deadline time.Duration
}

type fakeSpawner struct {
	calls   []spawnCall
	results []SpawnResult // consumed in order; default exit 0
	during  func(call spawnCall)
}

func (f *fakeSpawner) spawn(path string, args, env []string, deadline time.Duration, onStart func()) SpawnResult {
	c := spawnCall{path, append([]string(nil), args...), env, deadline}
	f.calls = append(f.calls, c)
	res := SpawnResult{Started: true}
	if len(f.results) > 0 {
		res, f.results = f.results[0], f.results[1:]
	}
	if res.Started {
		onStart()
		if f.during != nil {
			f.during(c)
		}
	}
	return res
}

func (c spawnCall) envValue(key string) (string, bool) {
	for _, kv := range c.env {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			return v, true
		}
	}
	return "", false
}

type fixture struct {
	t      *testing.T
	b      *Bootstrap
	sp     *fakeSpawner
	out    *bytes.Buffer
	layout updatestate.Layout
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	l := updatestate.Layout{InstallRoot: filepath.Join(root, "install"), DataRoot: filepath.Join(root, "data")}
	for _, d := range []string{l.VersionsDir(), l.StateDir(), l.DataRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sp := &fakeSpawner{}
	out := &bytes.Buffer{}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	runSeq := 0
	b := &Bootstrap{
		Layout:   l,
		Spawn:    sp.spawn,
		IsSystem: func() bool { return true },
		Now:      func() time.Time { return now },
		Sleep:    func(d time.Duration) { now = now.Add(d) },
		Getenv:   func(string) string { return "" },
		Environ: func() []string {
			return []string{"PATH=/bin", "STEPSEC_RUN_RECORD=stale", "STEPSEC_BOOTSTRAP_FALLBACK=stale"}
		},
		Out: out,
		NewRunID: func() string {
			runSeq++
			return fmt.Sprintf("run-%d", runSeq)
		},
		AdoptLockWait:  2 * time.Second,
		RecordLockWait: time.Second,
		LockPoll:       500 * time.Millisecond,
		UpdateDeadline: defaultUpdateDeadline,
	}
	return &fixture{t: t, b: b, sp: sp, out: out, layout: l}
}

func mkVersionDir(t *testing.T, dir string, files ...string) {
	t.Helper()
	if len(files) == 0 {
		files = updatestate.VersionFiles
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("bin:"+filepath.Base(dir)+":"+f), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) version(v string, files ...string) {
	mkVersionDir(f.t, filepath.Join(f.layout.VersionsDir(), v), files...)
}

func (f *fixture) seed(v string) string {
	d := filepath.Join(f.layout.InstallRoot, "seed", v)
	mkVersionDir(f.t, d)
	return d
}

func (f *fixture) state(body string) {
	if err := os.WriteFile(f.layout.StateFile(), []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) load() *updatestate.State {
	st, corrupt, err := updatestate.Load(f.layout.StateFile())
	if err != nil || corrupt || st == nil {
		f.t.Fatalf("load state: st=%v corrupt=%v err=%v", st, corrupt, err)
	}
	return st
}

func scanArgs(dataRoot string) []string {
	return []string{"send-telemetry", "--install-dir=" + dataRoot}
}

// TestRun_BootstrapMatrix: every state.json / directory corruption case
// must still launch something (harness §2 "Bootstrap matrix").
func TestRun_BootstrapMatrix(t *testing.T) {
	huge := `{"schema":1,"current":"1.2.0","pad":"` + strings.Repeat("x", 2<<20) + `"}`
	cases := []struct {
		name       string
		state      *string // nil = no file
		versions   map[string][]string
		seed       bool
		wantDir    string // "seed" or a version
		wantReason string
	}{
		{"healthy current", ptr(`{"schema":1,"current":"1.2.0","previous":"1.1.0"}`), map[string][]string{"1.2.0": nil, "1.1.0": nil}, true, "1.2.0", ""},
		{"state missing", nil, map[string][]string{"1.2.0": nil}, true, "seed", ReasonStateMissing},
		{"state empty", ptr(``), map[string][]string{"1.2.0": nil}, true, "seed", ReasonStateCorrupt},
		{"state garbage", ptr(`{{{`), map[string][]string{"1.2.0": nil}, true, "seed", ReasonStateCorrupt},
		{"state unknown old schema", ptr(`{"schema":0,"current":"1.2.0"}`), map[string][]string{"1.2.0": nil}, true, "seed", ReasonStateCorrupt},
		{"schema 2 with extra fields reads current/previous", ptr(`{"schema":2,"current":"1.2.0","previous":"1.1.0","probation":{"weird":true},"quarantine":[1],"updater":"x","new":{"a":[1]}}`),
			map[string][]string{"1.1.0": nil}, true, "1.1.0", ReasonCurrentMissing + ":1.2.0"},
		{"state newer schema still read", ptr(`{"schema":9,"current":"1.2.0","previous":"1.1.0","new":{"x":1}}`), map[string][]string{"1.2.0": nil}, true, "1.2.0", ""},
		{"state huge", &huge, map[string][]string{"1.2.0": nil}, true, "seed", ReasonStateCorrupt},
		{"current traversal", ptr(`{"schema":1,"current":"..\\x","previous":"1.1.0"}`), map[string][]string{"1.1.0": nil}, true, "seed", ReasonStateCorrupt},
		{"newer schema traversal", ptr(`{"schema":2,"current":"../x"}`), nil, true, "seed", ReasonStateCorrupt},
		{"current dir missing", ptr(`{"schema":1,"current":"1.2.0","previous":"1.1.0"}`), map[string][]string{"1.1.0": nil}, true, "1.1.0", ReasonCurrentMissing + ":1.2.0"},
		{"current missing task.exe", ptr(`{"schema":1,"current":"1.2.0","previous":"1.1.0"}`), map[string][]string{"1.2.0": {updatestate.AgentFile}, "1.1.0": nil}, true, "1.1.0", ReasonCurrentIncomplete + ":1.2.0"},
		{"current missing agent.exe", ptr(`{"schema":1,"current":"1.2.0","previous":"1.1.0"}`), map[string][]string{"1.2.0": {updatestate.LauncherFile}, "1.1.0": nil}, true, "1.1.0", ReasonCurrentIncomplete + ":1.2.0"},
		{"current and previous missing", ptr(`{"schema":1,"current":"1.2.0","previous":"1.1.0"}`), nil, true, "seed", ReasonCurrentMissing + ":1.2.0"},
		{"no previous", ptr(`{"schema":1,"current":"1.2.0"}`), nil, true, "seed", ReasonCurrentMissing + ":1.2.0"},
		{"seed missing, current fine", ptr(`{"schema":1,"current":"1.2.0"}`), map[string][]string{"1.2.0": nil}, false, "1.2.0", ""},
		{"seed missing, previous used", ptr(`{"schema":1,"current":"1.2.0","previous":"1.1.0"}`), map[string][]string{"1.1.0": nil}, false, "1.1.0", ReasonCurrentMissing + ":1.2.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.state != nil {
				f.state(*tc.state)
			}
			for v, files := range tc.versions {
				f.version(v, files...)
			}
			seedDir := ""
			if tc.seed {
				seedDir = f.seed("1.0.0")
			}
			code := f.b.Run(scanArgs(f.layout.DataRoot))
			if code != 0 {
				t.Fatalf("exit = %d; log:\n%s", code, f.out)
			}
			if len(f.sp.calls) != 1 {
				t.Fatalf("spawned %d times", len(f.sp.calls))
			}
			c := f.sp.calls[0]
			wantDir, wantVer := seedDir, "1.0.0"
			if tc.wantDir != "seed" {
				wantDir, wantVer = filepath.Join(f.layout.VersionsDir(), tc.wantDir), tc.wantDir
			}
			if c.path != filepath.Join(wantDir, updatestate.LauncherFile) {
				t.Fatalf("launched %s, want under %s", c.path, wantDir)
			}
			if strings.Join(c.args, " ") != strings.Join(scanArgs(f.layout.DataRoot), " ") {
				t.Fatalf("args = %v", c.args)
			}
			got, ok := c.envValue(EnvBootstrapFallback)
			if tc.wantReason == "" && ok {
				t.Fatalf("unexpected fallback %q", got)
			}
			if tc.wantReason != "" && got != tc.wantReason {
				t.Fatalf("fallback = %q, want %q", got, tc.wantReason)
			}
			if v, _ := c.envValue(EnvBootstrapVersion); v != wantVer {
				t.Fatalf("version env = %q", v)
			}
			runFile := filepath.Join(f.layout.DataRoot, "runs", wantVer+".json")
			if v, _ := c.envValue(EnvRunRecord); v != runFile {
				t.Fatalf("run record env = %q, want %q", v, runFile)
			}
			for _, kv := range c.env {
				if strings.Contains(kv, "stale") {
					t.Fatalf("stale env leaked: %v", c.env)
				}
			}
			recs := updatestate.ReadRuns(runFile)
			if len(recs) != 1 || recs[0].ExitCode == nil || *recs[0].ExitCode != 0 {
				t.Fatalf("run records = %+v", recs)
			}
			if id, _ := c.envValue(EnvRunID); id == "" || recs[0].RunID != id {
				t.Fatalf("run_id env %q vs record %q", id, recs[0].RunID)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestRun_NothingLaunchableExits70(t *testing.T) {
	f := newFixture(t)
	f.state(`garbage`)
	if code := f.b.Run(scanArgs(f.layout.DataRoot)); code != ExitCannotStart {
		t.Fatalf("exit = %d", code)
	}
	if len(f.sp.calls) != 0 {
		t.Fatal("spawned with nothing launchable")
	}
}

func TestRun_StartFailureFallsThroughAndRecords70(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.2.0"}`)
	f.version("1.2.0")
	f.seed("1.0.0")
	f.sp.results = []SpawnResult{{Err: errors.New("access denied")}, {Started: true, ExitCode: 0}}
	if code := f.b.Run(scanArgs(f.layout.DataRoot)); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	recs := updatestate.ReadRuns(f.layout.RunFile(updatestate.Version{Major: 1, Minor: 2}))
	if len(recs) != 1 || *recs[0].ExitCode != ExitCannotStart || updatestate.ClassifyRun(recs[0]) != updatestate.RunBad {
		t.Fatalf("1.2.0 records = %+v", recs)
	}
	if r, _ := f.sp.calls[1].envValue(EnvBootstrapFallback); r != ReasonStartFailed+":1.2.0" {
		t.Fatalf("fallback = %q", r)
	}
}

func TestRun_AllStartsFailExit70(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.2.0"}`)
	f.version("1.2.0")
	f.seed("1.0.0")
	f.sp.results = []SpawnResult{{Err: errors.New("x")}, {Err: errors.New("y")}}
	if code := f.b.Run(scanArgs(f.layout.DataRoot)); code != ExitCannotStart {
		t.Fatalf("exit = %d", code)
	}
}

func TestRun_ChildExitAndWatchdogRecorded(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.2.0"}`)
	f.version("1.2.0")
	runFile := f.layout.RunFile(updatestate.Version{Major: 1, Minor: 2})
	// The agent marks started while it runs.
	f.sp.during = func(c spawnCall) {
		id, _ := c.envValue(EnvRunID)
		if err := updatestate.MarkRunStarted(runFile, id); err != nil {
			t.Fatal(err)
		}
	}
	f.sp.results = []SpawnResult{{Started: true, ExitCode: 0}, {Started: true, Killed: true, ExitCode: 1}}
	f.b.Run(scanArgs(f.layout.DataRoot))
	if code := f.b.Run(scanArgs(f.layout.DataRoot)); code != ExitKilled {
		t.Fatalf("killed exit = %d", code)
	}
	recs := updatestate.ReadRuns(runFile)
	if len(recs) != 2 {
		t.Fatalf("records = %+v", recs)
	}
	if updatestate.ClassifyRun(recs[0]) != updatestate.RunHealthy {
		t.Fatalf("first = %+v", recs[0])
	}
	if !recs[1].WatchdogKilled || updatestate.ClassifyRun(recs[1]) != updatestate.RunBad {
		t.Fatalf("second = %+v", recs[1])
	}
}

// AppendRun failing (here: runs\ is a file) must not block the scan; the
// child gets no run id, so the agent skips the started marker (D13).
func TestRun_UnwritableRunsDirStillLaunches(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.2.0"}`)
	f.version("1.2.0")
	// A file where runs\ should be: records can't be written.
	if err := os.WriteFile(f.layout.RunsDir(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.sp.results = []SpawnResult{{Started: true, ExitCode: 3}}
	if code := f.b.Run(scanArgs(f.layout.DataRoot)); code != 3 {
		t.Fatalf("exit = %d", code)
	}
	c := f.sp.calls[0]
	if _, ok := c.envValue(EnvRunID); ok {
		t.Fatal("STEPSEC_RUN_ID passed without a run record")
	}
	if v, _ := c.envValue(EnvBootstrapVersion); v != "1.2.0" {
		t.Fatalf("version env = %q", v)
	}
}

func TestRunDeadline(t *testing.T) {
	f := newFixture(t)
	if d := f.b.runDeadline(f.layout.DataRoot); d != defaultExecutionDeadline+runDeadlineSlack {
		t.Fatalf("default = %s", d)
	}
	if err := os.WriteFile(filepath.Join(f.layout.DataRoot, "config.json"), []byte(`{"max_execution_duration":"2h"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := f.b.runDeadline(f.layout.DataRoot); d != 2*time.Hour+runDeadlineSlack {
		t.Fatalf("config = %s", d)
	}
	f.b.Getenv = func(k string) string {
		if k == envMaxExecution {
			return "off"
		}
		return ""
	}
	if d := f.b.runDeadline(f.layout.DataRoot); d != 0 {
		t.Fatalf("off = %s", d)
	}
	f.b.Getenv = func(k string) string {
		if k == envMaxExecution {
			return "3s"
		}
		return ""
	}
	f.state(`{"schema":1,"current":"1.2.0"}`)
	f.version("1.2.0")
	f.b.Run(scanArgs(f.layout.DataRoot))
	if got := f.sp.calls[0].deadline; got != 3*time.Second+runDeadlineSlack {
		t.Fatalf("spawn deadline = %s", got)
	}
}

func TestMain_Dispatch(t *testing.T) {
	f := newFixture(t)
	if code := f.b.Main(nil); code != exitUsage {
		t.Fatalf("no verb = %d", code)
	}
	if code := f.b.Main([]string{"bogus"}); code != exitUsage {
		t.Fatalf("bogus verb = %d", code)
	}
}

func TestIsBootstrapBinary(t *testing.T) {
	for in, want := range map[string]bool{
		`C:\Program Files\StepSecurity\stepsecurity-dev-machine-guard-bootstrap.exe`: true,
		`C:\x\STEPSECURITY-DEV-MACHINE-GUARD-BOOTSTRAP.EXE`:                          true,
		`C:\x\versions\1.2.0\task.exe`:                                               false,
		`/tmp/stepsecurity-dev-machine-guard-task.exe`:                               false,
	} {
		if got := IsBootstrapBinary(in); got != want {
			t.Errorf("%s = %v", in, got)
		}
	}
}

// --- update ---

func (f *fixture) updaterRan() string {
	f.t.Helper()
	if len(f.sp.calls) != 1 {
		f.t.Fatalf("spawned %d times; log:\n%s", len(f.sp.calls), f.out)
	}
	c := f.sp.calls[0]
	if filepath.Base(c.path) != updatestate.AgentFile || strings.Join(c.args, " ") != "self-update --system" {
		f.t.Fatalf("call = %+v", c)
	}
	rel, _ := filepath.Rel(f.layout.InstallRoot, filepath.Dir(c.path))
	return filepath.ToSlash(rel)
}

func TestUpdate_Selection(t *testing.T) {
	cases := []struct {
		name     string
		state    *string
		versions []string
		want     string
	}{
		{"fresh install no state", nil, nil, "seed/1.0.0"},
		{"corrupt state", ptr(`nope`), []string{"1.2.0"}, "seed/1.0.0"},
		{"confirmed current", ptr(`{"schema":1,"current":"1.2.0","previous":"1.1.0"}`), []string{"1.2.0", "1.1.0"}, "versions/1.2.0"},
		{"probation uses previous", ptr(`{"schema":1,"current":"1.2.0","previous":"1.1.0","probation":{"version":"1.2.0"}}`), []string{"1.2.0", "1.1.0"}, "versions/1.1.0"},
		{"probation without previous uses seed", ptr(`{"schema":1,"current":"1.2.0","probation":{"version":"1.2.0"}}`), []string{"1.2.0"}, "seed/1.0.0"},
		{"current dir missing", ptr(`{"schema":1,"current":"1.2.0","previous":"1.1.0"}`), []string{"1.1.0"}, "seed/1.0.0"},
		{"two failures keep current", ptr(`{"schema":1,"current":"1.2.0","updater":{"version":"1.2.0","consecutive_failures":2}}`), []string{"1.2.0"}, "versions/1.2.0"},
		{"three failures use seed", ptr(`{"schema":1,"current":"1.2.0","updater":{"version":"1.2.0","consecutive_failures":3}}`), []string{"1.2.0"}, "seed/1.0.0"},
		{"failures of another version ignored", ptr(`{"schema":1,"current":"1.3.0","updater":{"version":"1.2.0","consecutive_failures":5}}`), []string{"1.3.0"}, "versions/1.3.0"},
		{"newer schema reads current", ptr(`{"schema":4,"current":"1.2.0"}`), []string{"1.2.0"}, "versions/1.2.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.state != nil {
				f.state(*tc.state)
			}
			for _, v := range tc.versions {
				f.version(v)
			}
			f.seed("1.0.0")
			if code := f.b.Update(); code != 0 {
				t.Fatalf("exit = %d", code)
			}
			if got := f.updaterRan(); got != tc.want {
				t.Fatalf("updater = %s, want %s", got, tc.want)
			}
			if f.sp.calls[0].deadline != defaultUpdateDeadline {
				t.Fatalf("deadline = %s", f.sp.calls[0].deadline)
			}
		})
	}
}

func TestUpdate_RequiresSystem(t *testing.T) {
	f := newFixture(t)
	f.b.IsSystem = func() bool { return false }
	if code := f.b.Update(); code == 0 || len(f.sp.calls) != 0 {
		t.Fatalf("code=%d calls=%d", code, len(f.sp.calls))
	}
}

func TestUpdate_NoUpdaterExit70(t *testing.T) {
	f := newFixture(t)
	if code := f.b.Update(); code != ExitCannotStart {
		t.Fatalf("exit = %d", code)
	}
}

func TestUpdate_RecordsConsecutiveFailures(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.2.0","future":"kept"}`)
	f.version("1.2.0")
	f.seed("1.0.0")
	for i, res := range []SpawnResult{
		{Started: true, ExitCode: 1},
		{Started: true, Killed: true},
		{Err: errors.New("gone")}, // start failure counts, then seed runs
	} {
		f.sp.calls = nil
		f.sp.results = []SpawnResult{res, {Started: true}}
		f.b.Update()
		if got := f.load().Updater; got.Version != "1.2.0" || got.ConsecutiveFailures != i+1 {
			t.Fatalf("after failure %d: %+v", i+1, got)
		}
	}
	// Threshold reached: the seed runs and the record is left alone.
	f.sp.calls = nil
	f.sp.results = nil
	f.b.Update()
	if got := f.updaterRan(); got != "seed/1.0.0" {
		t.Fatalf("updater = %s", got)
	}
	if got := f.load().Updater; got.ConsecutiveFailures != 3 {
		t.Fatalf("seed run changed the record: %+v", got)
	}
	// A new current resets selection; success clears the counter.
	f.state(`{"schema":1,"current":"1.3.0","updater":{"version":"1.2.0","consecutive_failures":3}}`)
	f.version("1.3.0")
	f.sp.calls = nil
	f.b.Update()
	if got := f.load().Updater; got.Version != "1.3.0" || got.ConsecutiveFailures != 0 {
		t.Fatalf("after success: %+v", got)
	}
}

func TestUpdate_KeepsUnknownStateFields(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.2.0","future":"kept"}`)
	f.version("1.2.0")
	f.sp.results = []SpawnResult{{Started: true, ExitCode: 4}}
	if code := f.b.Update(); code != 4 {
		t.Fatalf("exit = %d", code)
	}
	data, _ := os.ReadFile(f.layout.StateFile())
	if !strings.Contains(string(data), `"future"`) {
		t.Fatalf("unknown field dropped: %s", data)
	}
}

func TestUpdate_LockHeldSkipsRecord(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.2.0"}`)
	f.version("1.2.0")
	l, err := updatestate.AcquireLock(f.layout.LockFile())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	f.sp.results = []SpawnResult{{Started: true, ExitCode: 1}}
	f.b.Update()
	if got := f.load().Updater; got.ConsecutiveFailures != 0 {
		t.Fatalf("recorded under a held lock: %+v", got)
	}
}

// --- adopt-seed ---

func (f *fixture) adopt(seedDir string) {
	f.t.Helper()
	if code := f.b.AdoptSeed([]string{"--seed-dir", seedDir}); code != 0 {
		f.t.Fatalf("adopt-seed exit = %d", code)
	}
}

func TestAdoptSeed_FreshInstall(t *testing.T) {
	f := newFixture(t)
	if err := os.RemoveAll(f.layout.VersionsDir()); err != nil {
		t.Fatal(err)
	}
	seed := f.seed("1.5.0")
	f.adopt(seed + string(filepath.Separator))
	dst := filepath.Join(f.layout.VersionsDir(), "1.5.0")
	if err := updatestate.VerifyVersionDir(dst, updatestate.Version{Major: 1, Minor: 5}); err != nil {
		t.Fatalf("adopted seed does not verify against its manifest: %v", err)
	}
	for _, n := range updatestate.VersionFiles {
		got, err := os.ReadFile(filepath.Join(dst, n))
		want, _ := os.ReadFile(filepath.Join(seed, n))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s not copied: %v", n, err)
		}
	}
	if st := f.load(); st.Current != "1.5.0" || st.Previous != "" {
		t.Fatalf("state = %+v", st)
	}
	entries, _ := os.ReadDir(f.layout.VersionsDir())
	if len(entries) != 1 {
		t.Fatalf("leftovers in versions: %v", entries)
	}
}

func TestAdoptSeed_StateRules(t *testing.T) {
	cases := []struct {
		name          string
		state         string
		versions      []string
		wantCurrent   string
		wantPrevious  string
		wantUnchanged bool
	}{
		{"seed newer upgrades", `{"schema":1,"current":"1.4.0","probation":{"version":"1.4.0"}}`, []string{"1.4.0"}, "1.5.0", "1.4.0", false},
		{"seed older never downgrades", `{"schema":1,"current":"1.6.0","previous":"1.5.0"}`, []string{"1.6.0"}, "1.6.0", "1.5.0", true},
		{"seed equal keeps", `{"schema":1,"current":"1.5.0","previous":"1.4.0"}`, nil, "1.5.0", "1.4.0", true},
		{"current missing repaired", `{"schema":1,"current":"1.6.0","previous":"1.4.0","probation":{"version":"1.6.0"}}`, nil, "1.5.0", "1.4.0", false},
		{"current incomplete repaired", `{"schema":1,"current":"1.6.0"}`, nil, "1.5.0", "", false},
		{"quarantined seed not adopted", `{"schema":1,"current":"1.4.0","quarantine":{"1.5.0":{"reason":"bad_runs","at":"2026-01-01T00:00:00Z"}}}`, []string{"1.4.0"}, "1.4.0", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.state(tc.state)
			for _, v := range tc.versions {
				f.version(v)
			}
			if tc.name == "current incomplete repaired" {
				f.version("1.6.0", updatestate.AgentFile)
			}
			seed := f.seed("1.5.0")
			f.adopt(seed)
			st := f.load()
			if st.Current != tc.wantCurrent || st.Previous != tc.wantPrevious {
				t.Fatalf("state = %+v", st)
			}
			if !tc.wantUnchanged && st.Probation != nil {
				t.Fatalf("probation kept: %+v", st.Probation)
			}
			if !updatestate.VersionDirUsable(filepath.Join(f.layout.VersionsDir(), "1.5.0")) {
				t.Fatal("seed not copied")
			}
		})
	}
}

func TestAdoptSeed_IncompleteSeedVersionReplaced(t *testing.T) {
	f := newFixture(t)
	f.version("1.5.0", updatestate.LauncherFile)
	f.adopt(f.seed("1.5.0"))
	if !updatestate.VersionDirUsable(filepath.Join(f.layout.VersionsDir(), "1.5.0")) {
		t.Fatal("incomplete version dir not replaced")
	}
}

func TestAdoptSeed_NewerSchemaUntouched(t *testing.T) {
	f := newFixture(t)
	body := `{"schema":2,"current":"1.4.0"}`
	f.state(body)
	f.version("1.4.0")
	f.adopt(f.seed("1.5.0"))
	if got, _ := os.ReadFile(f.layout.StateFile()); string(got) != body {
		t.Fatalf("schema-2 state rewritten: %s", got)
	}
}

func TestAdoptSeed_NoOpCases(t *testing.T) {
	t.Run("lock held", func(t *testing.T) {
		f := newFixture(t)
		l, err := updatestate.AcquireLock(f.layout.LockFile())
		if err != nil {
			t.Fatal(err)
		}
		defer l.Release()
		f.adopt(f.seed("1.5.0"))
		if _, err := os.Stat(f.layout.StateFile()); !os.IsNotExist(err) {
			t.Fatal("state written without the lock")
		}
		if !strings.Contains(f.out.String(), "lock not taken") {
			t.Fatalf("log:\n%s", f.out)
		}
	})
	t.Run("not system", func(t *testing.T) {
		f := newFixture(t)
		f.b.IsSystem = func() bool { return false }
		f.adopt(f.seed("1.5.0"))
		if _, err := os.Stat(f.layout.StateFile()); !os.IsNotExist(err) {
			t.Fatal("state written")
		}
	})
	t.Run("seed outside install root", func(t *testing.T) {
		f := newFixture(t)
		other := filepath.Join(t.TempDir(), "seed", "1.5.0")
		mkVersionDir(t, other)
		f.adopt(other)
		if _, err := os.Stat(f.layout.StateFile()); !os.IsNotExist(err) {
			t.Fatal("adopted a foreign seed dir")
		}
	})
	t.Run("incomplete seed", func(t *testing.T) {
		f := newFixture(t)
		d := filepath.Join(f.layout.InstallRoot, "seed", "1.5.0")
		mkVersionDir(t, d, updatestate.AgentFile)
		f.adopt(d)
		if _, err := os.Stat(f.layout.StateFile()); !os.IsNotExist(err) {
			t.Fatal("adopted an incomplete seed")
		}
	})
	t.Run("missing flag", func(t *testing.T) {
		f := newFixture(t)
		if code := f.b.AdoptSeed(nil); code != 0 {
			t.Fatalf("exit = %d", code)
		}
	})
}

func TestChildEnv_ReplacesOurVars(t *testing.T) {
	f := newFixture(t)
	env := f.b.childEnv(map[string]string{EnvRunRecord: "r", EnvBootstrapVersion: "1.2.0"})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "stale") || !strings.Contains(joined, "STEPSEC_RUN_RECORD=r") || strings.Contains(joined, EnvBootstrapFallback) {
		t.Fatalf("env = %v", env)
	}
}

// Overlapping hourly + Logon runs of one version: each run finalizes only its
// own record (run_id), never the newest one.
func TestRun_OverlappingRunsKeepTheirOwnRecords(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.2.0"}`)
	f.version("1.2.0")
	nested := false
	f.sp.during = func(spawnCall) {
		if nested {
			return
		}
		nested = true
		// The Logon task fires while the hourly scan is still running.
		if code := f.b.Run(scanArgs(f.layout.DataRoot)); code != 0 {
			t.Errorf("inner run exit = %d", code)
		}
	}
	f.sp.results = []SpawnResult{{Started: true, ExitCode: 5}, {Started: true, ExitCode: 0}}
	if code := f.b.Run(scanArgs(f.layout.DataRoot)); code != 5 {
		t.Fatalf("outer run exit = %d", code)
	}
	recs := updatestate.ReadRuns(f.layout.RunFile(updatestate.Version{Major: 1, Minor: 2}))
	if len(recs) != 2 {
		t.Fatalf("records = %+v", recs)
	}
	got := map[string]int{}
	for _, r := range recs {
		if r.ExitCode == nil {
			t.Fatalf("open record left: %+v", r)
		}
		got[r.RunID] = *r.ExitCode
	}
	outer, _ := f.sp.calls[0].envValue(EnvRunID)
	inner, _ := f.sp.calls[1].envValue(EnvRunID)
	if outer == inner || got[outer] != 5 || got[inner] != 0 {
		t.Fatalf("outer %s inner %s records %v", outer, inner, got)
	}
}

func TestAdoptSeed_UnverifiableSeedVersionReplaced(t *testing.T) {
	f := newFixture(t)
	f.version("1.5.0") // all files, no manifest
	f.adopt(f.seed("1.5.0"))
	if err := updatestate.VerifyVersionDir(filepath.Join(f.layout.VersionsDir(), "1.5.0"), updatestate.Version{Major: 1, Minor: 5}); err != nil {
		t.Fatalf("not replaced by a verified copy: %v", err)
	}
}

// R-B-1: a schema-1 state that a future writer filled with RC versions
// outside current/previous still resolves current, for run and update.
func TestFrozenSchema1_RCFieldsStillResolveCurrent(t *testing.T) {
	body := `{"schema":1,"current":"1.21.0","previous":"1.20.0","quarantine":{"1.22.0-rc.1":{"reason":"bad_runs"}},"updater":{"version":"1.22.0-rc.1","consecutive_failures":0},"probation":{"version":"1.22.0-rc.1"}}`
	f := newFixture(t)
	f.state(body)
	f.version("1.21.0")
	f.version("1.20.0")
	f.seed("1.19.0")
	f.b.Run(scanArgs(f.layout.DataRoot))
	c := f.sp.calls[0]
	if !strings.Contains(c.path, filepath.Join("versions", "1.21.0")) {
		t.Fatalf("run launched %s", c.path)
	}
	if r, ok := c.envValue(EnvBootstrapFallback); ok {
		t.Fatalf("unexpected fallback %q", r)
	}
	f.sp.calls = nil
	f.b.Update()
	if got := f.updaterRan(); got != "versions/1.21.0" {
		t.Fatalf("updater = %s", got)
	}
}

// R-B-1: adopt-seed never replaces an existing state with a fresh one. It
// changes current/previous through the preserving Save, and leaves a state it
// can't round-trip (odd fields, unreadable pointers) byte-for-byte alone.
func TestAdoptSeed_PreservesExistingState(t *testing.T) {
	t.Run("unknown fields kept", func(t *testing.T) {
		f := newFixture(t)
		f.state(`{"schema":1,"current":"1.4.0","future_top":{"a":1},"updater":{"version":"1.4.0","consecutive_failures":0,"future_nested":true}}`)
		f.version("1.4.0")
		f.adopt(f.seed("1.5.0"))
		data, _ := os.ReadFile(f.layout.StateFile())
		if !strings.Contains(string(data), "future_top") || !strings.Contains(string(data), "future_nested") {
			t.Fatalf("unknown fields dropped: %s", data)
		}
		if st := f.load(); st.Current != "1.5.0" || st.Previous != "1.4.0" {
			t.Fatalf("state = %+v", st)
		}
	})
	for name, body := range map[string]string{
		"rc fields":           `{"schema":1,"current":"1.4.0","quarantine":{"1.6.0-rc.1":{"reason":"x"}}}`,
		"unreadable pointers": `{"schema":1,"current":"zz"}`,
		"garbage":             `not json`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.state(body)
			f.version("1.4.0")
			f.adopt(f.seed("1.5.0"))
			if got, _ := os.ReadFile(f.layout.StateFile()); string(got) != body {
				t.Fatalf("state rewritten to %s", got)
			}
		})
	}
}

// R-B-4: adopt-seed sets RunningVersion whenever it sets current, and only then.
func TestAdoptSeed_SetsRunningVersionWithCurrent(t *testing.T) {
	cases := []struct {
		name  string
		state string
		ver   []string
		want  []string
	}{
		{"fresh install", "", nil, []string{"1.5.0"}},
		{"seed newer", `{"schema":1,"current":"1.4.0"}`, []string{"1.4.0"}, []string{"1.5.0"}},
		{"current unusable", `{"schema":1,"current":"1.6.0"}`, nil, []string{"1.5.0"}},
		{"seed older: unchanged", `{"schema":1,"current":"1.6.0"}`, []string{"1.6.0"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			var got []string
			f.b.SetRunningVersion = func(v string) error { got = append(got, v); return nil }
			if tc.state != "" {
				f.state(tc.state)
			}
			for _, v := range tc.ver {
				f.version(v)
			}
			f.adopt(f.seed("1.5.0"))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("RunningVersion writes = %v, want %v", got, tc.want)
			}
		})
	}
}

// R-B-6: only an unexpired quarantine of the seed's own version blocks
// adopting it; an expired one (D5 until) or other versions' entries don't.
func TestAdoptSeed_QuarantineExpiry(t *testing.T) {
	// The fixture clock is 2026-10-19T12:00:00Z.
	cases := map[string]struct {
		quarantine string
		want       string
	}{
		"permanent seed entry blocks": {`{"1.5.0":{"reason":"bad_runs","at":"2026-10-01T00:00:00Z"}}`, "1.4.0"},
		"unexpired seed entry blocks": {`{"1.5.0":{"reason":"inconclusive","at":"2026-10-15T00:00:00Z","until":"2026-10-22T00:00:00Z"}}`, "1.4.0"},
		"expired seed entry allows":   {`{"1.5.0":{"reason":"inconclusive","at":"2026-10-01T00:00:00Z","until":"2026-10-08T00:00:00Z"}}`, "1.5.0"},
		"other version never blocks":  {`{"1.4.5":{"reason":"bad_runs","at":"2026-10-01T00:00:00Z"}}`, "1.5.0"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.state(`{"schema":1,"current":"1.4.0","quarantine":` + tc.quarantine + `}`)
			f.version("1.4.0")
			f.adopt(f.seed("1.5.0"))
			if got := f.load().Current; got != tc.want {
				t.Fatalf("current = %s, want %s", got, tc.want)
			}
		})
	}
}

// D18: a schema-1 state with values this build's Load rejects (RC versions
// outside the pointers) must not stop the failure count, or the seed-updater
// fallback never triggers and a broken updater is never recovered.
func TestUpdate_RCStateStillCountsFailuresAndFallsBack(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.21.0","previous":"1.20.0","quarantine":{"1.22.0-rc.1":{"reason":"bad_runs","future":1}},"probation":{"version":"1.22.0-rc.2"},"future_top":{"x":[1]}}`)
	f.version("1.21.0")
	f.version("1.20.0")
	f.seed("1.19.0")
	for i := 1; i <= 3; i++ {
		f.sp.calls = nil
		f.sp.results = []SpawnResult{{Started: true, ExitCode: 1}}
		f.b.Update()
		if got := f.updaterRan(); got != "versions/1.21.0" {
			t.Fatalf("tick %d: updater = %s", i, got)
		}
	}
	f.sp.calls = nil
	f.sp.results = nil
	f.b.Update()
	if got := f.updaterRan(); got != "seed/1.19.0" {
		t.Fatalf("4th tick: updater = %s, want the seed", got)
	}
	data, _ := os.ReadFile(f.layout.StateFile())
	for _, keep := range []string{`"1.22.0-rc.1"`, `"future": 1`, `"1.22.0-rc.2"`, `"future_top"`, `"consecutive_failures": 3`} {
		if !strings.Contains(string(data), keep) {
			t.Fatalf("missing %s in %s", keep, data)
		}
	}
}

// D18 follow-up: on a schema-2 state the failure count still increments (the
// updater fields keep their meaning in every schema) and the 4th tick picks
// the seed; schema and every other field stay as they were.
func TestUpdate_Schema2StateStillCountsFailuresAndFallsBack(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":2,"current":"1.21.0","previous":"1.20.0","brand_new":{"x":[1]},"updater":{"version":"","consecutive_failures":0,"extra":true}}`)
	f.version("1.21.0")
	f.version("1.20.0")
	f.seed("1.19.0")
	for i := 1; i <= 3; i++ {
		f.sp.calls = nil
		f.sp.results = []SpawnResult{{Started: true, ExitCode: 1}}
		f.b.Update()
		if got := f.updaterRan(); got != "versions/1.21.0" {
			t.Fatalf("tick %d: updater = %s", i, got)
		}
	}
	f.sp.calls = nil
	f.sp.results = nil
	f.b.Update()
	if got := f.updaterRan(); got != "seed/1.19.0" {
		t.Fatalf("4th tick: updater = %s, want the seed", got)
	}
	data, _ := os.ReadFile(f.layout.StateFile())
	for _, keep := range []string{`"schema": 2`, `"brand_new"`, `"extra": true`, `"consecutive_failures": 3`, `"version": "1.21.0"`} {
		if !strings.Contains(string(data), keep) {
			t.Fatalf("missing %s in %s", keep, data)
		}
	}
}

// FR1-7: a deadline kill is a watchdog kill (Bad) even if the system slept
// meanwhile: the deadline already counts awake time only.
func TestRunOutcomeKillIsWatchdog(t *testing.T) {
	code, killed := runOutcome(SpawnResult{Started: true, Killed: true})
	exit := code
	if !killed || code != ExitKilled || updatestate.ClassifyRun(updatestate.RunRecord{Version: "1.20.0", Started: true, ExitCode: &exit, WatchdogKilled: killed}) != updatestate.RunBad {
		t.Fatalf("kill: code %d killed %v", code, killed)
	}
	if code, killed := runOutcome(SpawnResult{Started: true, ExitCode: 3}); code != 3 || killed {
		t.Fatalf("exit 3: code %d killed %v", code, killed)
	}
}

// Copilot 4356483380: the updater, run from versions\<v>\, resolves the
// same install root as the bootstrap that launched it, wherever the MSI
// put INSTALLFOLDER.
func TestUpdaterRootMatchesBootstrapRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "D", "Apps", "StepSecurity")
	exe := filepath.Join(root, BootstrapBinary)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBootstrap(exe, func() bool { return true })
	v, _ := updatestate.ParseVersion("1.20.0")
	updater := b.Layout.VersionDir(v)
	got, ok := updatestate.BootstrapRoot(filepath.Join(updater, updatestate.AgentFile), func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	})
	if !ok || got != b.Layout.InstallRoot {
		t.Fatalf("updater root = %q (%v), bootstrap root = %q", got, ok, b.Layout.InstallRoot)
	}
}
