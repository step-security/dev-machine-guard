//go:build selfupdate_faults && selfupdate_testkeys

package selfupdate

// U0: the trace-driven kill matrix. A clean run of
// each scenario under DMG_FAULT_TRACE lists every checkpoint the updater
// passes, per tick. Then, for every traced (tick, checkpoint) and every
// action in {kill, err, hang, diskfull}, a fresh install is driven to that
// tick, the faulted tick runs as a subprocess (hang is killed once the
// trace shows it hanging, standing in for the task's ExecutionTimeLimit),
// and clean ticks follow. U2 (convergence + its event), U6 (hygiene), U8
// (no flip-flop) and U9 (the frozen bootstrap read) are asserted on the
// filesystem and on the events the in-process fake API received. A
// checkpoint added later is covered without editing this file.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/faultinject"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/proctest"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

const (
	h1Base   = "1.19.0" // N: current, seed and the updater's own version
	h1Target = "1.20.0" // N+1
	// cleanTicks is M (U2): ticks allowed after the last fault.
	cleanTicks = 3
)

func init() { helperRoles["updater"] = helperUpdater }

// helperUpdater runs one tick with everything taken from env.
func helperUpdater() int {
	g := os.Getenv
	if t := g("DMG_SU_INSTANCE_LOCK"); t != "" {
		lock.SetTargetForTest(t)
	}
	config.APIEndpoint, config.CustomerID, config.APIKey = g("DMG_SU_API"), "cust", "key"
	self, err := updatestate.ParseVersion(g("DMG_SU_SELF"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 99
	}
	L := updatestate.Layout{InstallRoot: g("DMG_SU_INSTALL"), DataRoot: g("DMG_SU_DATA")}
	d := &Deps{
		Layout: L, Self: self, SelfExe: filepath.Join(L.VersionDir(self), updatestate.AgentFile),
		Client: &Client{
			HTTP: http.DefaultClient, APIEndpoint: g("DMG_SU_API"), CustomerID: "cust", APIKey: "key",
			AgentVersion: self.String(), Arch: testArch,
		},
		AutoUpdate: true,
		// Authenticode is C2's own test; here every staged exe "verifies".
		VerifyPublisher: func(p string) error { _, err := os.Stat(p); return err },
		Smoke:           RunSmoke,
		AcquireInstance: func() (func(), error) {
			lk, err := lock.Acquire(nil)
			if err != nil {
				return nil, err
			}
			return lk.Release, nil
		},
		Send: func(ctx context.Context, ev updatestate.OutboxEvent) error {
			err := telemetry.PostUpdateEvent(ctx, http.DefaultClient, telemetry.UpdateEvent{
				ExecutionID: ev.ExecutionID, DeviceID: "dev-h1", InstallChannel: "msi",
				Event: ev.Event, From: ev.From, To: ev.To, Error: ev.Error,
			})
			if err != nil && strings.Contains(err.Error(), "rejected") {
				return fmt.Errorf("%w: %w", ErrEventRejected, err)
			}
			return err
		},
		FreeBytes: FreeBytes,
		Now:       time.Now,
		Logf:      func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	}
	return Run(context.Background(), d)
}

var h1EnvSeq atomic.Int64

var (
	selfBytesOnce sync.Once
	selfBytes     []byte
)

func testBinaryBytes(t testing.TB) []byte {
	selfBytesOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		selfBytes, err = os.ReadFile(exe)
		if err != nil {
			t.Fatal(err)
		}
	})
	return selfBytes
}

// h1Env is one install driven by subprocess ticks.
type h1Env struct {
	t    *testing.T
	L    updatestate.Layout
	api  *fakeAPI
	lock string
	logs []string
}

// scenario prepares an install and names the outcome it must converge to.
type scenario struct {
	name  string
	setup func(e *h1Env)
	// converged reports whether the install reached its terminal state.
	converged func(e *h1Env, st *updatestate.State) bool
	// event must have reached the backend by convergence.
	event, from, to string
	// neverCurrent may not be current after it was quarantined (U8).
	neverCurrent string
}

func newH1Env(t *testing.T) *h1Env {
	t.Helper()
	root := t.TempDir()
	e := &h1Env{t: t, L: updatestate.Layout{InstallRoot: filepath.Join(root, "pf"), DataRoot: filepath.Join(root, "pd")}}
	e.api = startFakeAPI(t, false)
	e.api.addRelease(h1Base, testArch, payload("agent", h1Base), payload("task", h1Base), payload("linux", h1Base))
	e.api.addRelease(h1Target, testArch, testBinaryBytes(t), payload("task", h1Target), payload("linux", h1Target))
	e.api.setTarget(h1Target)
	if runtime.GOOS == "windows" {
		// A counter, not the clock: parallel cases created within one
		// Windows clock tick would otherwise share a mutex and defer.
		e.lock = fmt.Sprintf("DMGTestH1-%d-%d", os.Getpid(), h1EnvSeq.Add(1))
	} else {
		e.lock = filepath.Join(root, "instance.flock")
	}
	// seed + versions\N + state {current: N}
	seed := e.L.SeedDir(mustV(h1Base))
	must(t, os.MkdirAll(seed, 0o755))
	vdir := e.L.VersionDir(mustV(h1Base))
	must(t, os.MkdirAll(vdir, 0o755))
	m := updatestate.Manifest{Version: h1Base, Files: map[string]string{}}
	for _, f := range []struct{ name, kind string }{{updatestate.AgentFile, "agent"}, {updatestate.LauncherFile, "task"}, {updatestate.LinuxFile, "linux"}} {
		b := payload(f.kind, h1Base)
		must(t, os.WriteFile(filepath.Join(seed, f.name), b, 0o755))
		must(t, os.WriteFile(filepath.Join(vdir, f.name), b, 0o755))
		m.Files[f.name] = sum(b)
	}
	must(t, updatestate.WriteManifest(vdir, m))
	must(t, os.MkdirAll(e.L.StateDir(), 0o755))
	must(t, updatestate.Save(e.L.StateFile(), &updatestate.State{Schema: 1, Current: h1Base}))
	return e
}

// tick runs one updater subprocess. fault is a DMG_FAULT spec ("" = clean).
// A hang is killed as soon as the trace shows the hanging checkpoint.
func (e *h1Env) tick(fault, trace string) (exit int) {
	e.t.Helper()
	if err := faultinject.Validate(fault); err != nil {
		e.t.Fatalf("bad fault spec %q: %v", fault, err)
	}
	if trace == "" {
		trace = filepath.Join(e.t.TempDir(), "trace")
	}
	cmd := proctest.Command(e.t, os.Args[0], "-test.run=^$")
	cmd.Env = append(cmd.Env, e.childEnv(fault, trace)...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	tickStart := time.Now()
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	hangAt := ""
	if cp, ok := strings.CutSuffix(fault, ":hang"); ok {
		hangAt = cp
	}
	deadline := time.After(3 * time.Minute)
	poll := time.NewTicker(50 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case err := <-done:
			e.logs = append(e.logs, fmt.Sprintf("--- tick fault=%q exit=%v took=%s\n%s", fault, err, time.Since(tickStart), out.String()))
			if strings.Contains(out.String(), faultinject.MalformedMarker) {
				e.dumpLogs()
				e.t.Fatalf("tick fault=%q: malformed fault spec at runtime", fault)
			}
			if cmd.ProcessState != nil {
				return cmd.ProcessState.ExitCode()
			}
			return -1
		case <-poll.C:
			if hangAt != "" && slices.Contains(readTrace(trace), hangAt) {
				time.Sleep(100 * time.Millisecond)
				_ = cmd.Process.Kill()
				hangAt = ""
			}
		case <-deadline:
			_ = cmd.Process.Kill()
			e.t.Fatalf("tick fault=%q did not finish", fault)
		}
	}
}

// childEnv is what the updater subprocess adds to its environment (the
// smoke self-check it starts inherits it).
func (e *h1Env) childEnv(fault, trace string) []string {
	return append([]string{},
		envRole+"=updater", envHelper+"=1",
		"DMG_SU_API="+e.api.URL(), "DMG_SU_SELF="+h1Base,
		"DMG_SU_INSTALL="+e.L.InstallRoot, "DMG_SU_DATA="+e.L.DataRoot,
		"DMG_SU_INSTANCE_LOCK="+e.lock,
		"DMG_TEST_SSHSIG_PUBKEY="+e.api.signer.pubB64,
		"DMG_TEST_RELEASE_BASE_URL="+e.api.URL()+"/releases",
		"DMG_TEST_CHECK_INTERVAL=0s", "DMG_TEST_SWITCH_WAIT=0s",
		"DMG_TEST_DEDUPE_WINDOW=0s", "DMG_TEST_PROBATION_WINDOW=0s",
		"DMG_TEST_SMOKE_TIMEOUT=60s", "DMG_TEST_SEND_BACKOFF=0s",
		"DMG_FAULT="+fault, "DMG_FAULT_TRACE="+trace,
		// A -race binary sleeps 1 s at exit by default; every tick starts
		// two of them (the updater and its smoke self-check), which made the
		// matrix spend most of its time asleep.
		"GORACE=atexit_sleep_ms=0",
	)
}

func readTrace(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func (e *h1Env) dumpLogs() {
	e.t.Helper()
	for _, l := range e.logs {
		e.t.Log(l)
	}
}

// state loads state.json; it must always parse (U9 for the full reader).
func (e *h1Env) state() *updatestate.State {
	e.t.Helper()
	st, corrupt, err := updatestate.Load(e.L.StateFile())
	if err != nil || corrupt || st == nil {
		e.dumpLogs()
		e.t.Fatalf("state.json unreadable: err=%v corrupt=%v nil=%v", err, corrupt, st == nil)
	}
	return st
}

// assertBootstrapRead is U9: the frozen bootstrap contract reads only
// schema/current/previous, and must resolve something launchable.
func (e *h1Env) assertBootstrapRead() {
	e.t.Helper()
	data, err := os.ReadFile(e.L.StateFile())
	if err != nil {
		e.t.Fatalf("U9: %v", err)
	}
	var frozen struct {
		Schema   int    `json:"schema"`
		Current  string `json:"current"`
		Previous string `json:"previous"`
	}
	if err := json.Unmarshal(data, &frozen); err != nil || frozen.Schema < 1 {
		e.t.Fatalf("U9: frozen reader can't parse state.json: %v (%s)", err, data)
	}
	for _, v := range []string{frozen.Current, frozen.Previous} {
		pv, err := updatestate.ParseVersion(v)
		if err == nil && updatestate.VersionDirComplete(e.L.VersionDir(pv)) == nil {
			return
		}
	}
	if len(seedVersions(e.L)) == 0 {
		e.t.Fatalf("U9: nothing launchable: state %s, no seed", data)
	}
}

// assertHygiene is U6.
func (e *h1Env) assertHygiene(st *updatestate.State) {
	e.t.Helper()
	allowed := map[string]bool{st.Current: true, st.Previous: true, h1Base: true}
	if st.Probation != nil {
		allowed[st.Probation.Version] = true
	}
	if st.PendingSwitch != "" {
		allowed[st.PendingSwitch] = true
	}
	entries, _ := os.ReadDir(e.L.VersionsDir())
	for _, en := range entries {
		if updatestate.IsSweepable(en.Name()) || !allowed[en.Name()] {
			e.dumpLogs()
			e.t.Fatalf("U6: leftover versions\\%s (state %+v)", en.Name(), st)
		}
	}
	sentries, _ := os.ReadDir(e.L.StateDir())
	for _, en := range sentries {
		if strings.HasPrefix(en.Name(), ".state.json.tmp-") {
			e.t.Fatalf("U6: leftover %s", en.Name())
		}
	}
	lk, err := updatestate.AcquireLock(e.L.LockFile())
	if err != nil {
		e.t.Fatalf("U6: update lock not acquirable: %v", err)
	}
	lk.Release()
	if len(st.Outbox) != 0 {
		e.t.Fatalf("U6: undelivered events after convergence: %+v", st.Outbox)
	}
}

func (e *h1Env) sawEvent(event, from, to string) bool {
	e.api.mu.Lock()
	defer e.api.mu.Unlock()
	for _, ev := range e.api.events {
		if ev["status"] == "update" && ev["update_event"] == event &&
			(from == "" || ev["update_from"] == from) && (to == "" || ev["update_to"] == to) {
			if ev["device_id"] != "dev-h1" || ev["invocation_method"] != "update" {
				e.t.Fatalf("event fields: %v", ev)
			}
			return true
		}
	}
	return false
}

// installDir writes a complete versions\<v> with small payloads.
func (e *h1Env) installDir(v string) {
	pv := mustV(v)
	dir := e.L.VersionDir(pv)
	must(e.t, os.MkdirAll(dir, 0o755))
	m := updatestate.Manifest{Version: v, Files: map[string]string{}}
	for _, f := range []string{updatestate.AgentFile, updatestate.LauncherFile, updatestate.LinuxFile} {
		b := []byte(f + v)
		must(e.t, os.WriteFile(filepath.Join(dir, f), b, 0o755))
		m.Files[f] = sum(b)
	}
	must(e.t, updatestate.WriteManifest(dir, m))
}

func (e *h1Env) writeSeedDir(v string) {
	dir := e.L.SeedDir(mustV(v))
	must(e.t, os.MkdirAll(dir, 0o755))
	for _, f := range []string{updatestate.AgentFile, updatestate.LauncherFile, updatestate.LinuxFile} {
		must(e.t, os.WriteFile(filepath.Join(dir, f), []byte(f+v), 0o755))
	}
}

// holdInstanceMu serializes the global lock target swap below.
var holdInstanceMu sync.Mutex

// holdInstance takes this install's scan instance mutex in the test
// process, as a running scan would.
func (e *h1Env) holdInstance() (release func()) {
	e.t.Helper()
	holdInstanceMu.Lock()
	restore := lock.SetTargetForTest(e.lock)
	lk, err := lock.Acquire(nil)
	restore()
	holdInstanceMu.Unlock()
	if err != nil {
		e.t.Fatalf("hold instance mutex: %v", err)
	}
	return lk.Release
}

func scenarios() []scenario {
	return []scenario{
		{
			name:  "update",
			setup: func(*h1Env) {},
			converged: func(_ *h1Env, st *updatestate.State) bool {
				return st.Current == h1Target && st.Probation == nil
			},
			event: EventOK, from: h1Base, to: h1Target,
		},
		{
			// previous (1.18.0), the seed (1.17.0) and the updater (N) all
			// differ, so GC mistakes on previous are visible.
			name: "update-distinct-previous",
			setup: func(e *h1Env) {
				must(e.t, os.RemoveAll(filepath.Join(e.L.InstallRoot, "seed")))
				e.writeSeedDir("1.17.0")
				e.installDir("1.18.0")
				must(e.t, updatestate.Save(e.L.StateFile(), &updatestate.State{Schema: 1, Current: h1Base, Previous: "1.18.0"}))
			},
			converged: func(_ *h1Env, st *updatestate.State) bool {
				return st.Current == h1Target && st.Probation == nil
			},
			event: EventOK, from: h1Base, to: h1Target,
		},
		{
			// A probation on N+1 with two crashed scans: the tick rolls back.
			name: "rollback",
			setup: func(e *h1Env) {
				pv := mustV(h1Target)
				e.api.setTarget(h1Target)
				dir := e.L.VersionDir(pv)
				must(e.t, os.MkdirAll(dir, 0o755))
				m := updatestate.Manifest{Version: h1Target, Files: map[string]string{}}
				for _, f := range []string{updatestate.AgentFile, updatestate.LauncherFile, updatestate.LinuxFile} {
					b := []byte("crashing-" + f)
					must(e.t, os.WriteFile(filepath.Join(dir, f), b, 0o755))
					m.Files[f] = sum(b)
				}
				must(e.t, updatestate.WriteManifest(dir, m))
				since := time.Now().Add(-time.Minute).UTC()
				must(e.t, updatestate.Save(e.L.StateFile(), &updatestate.State{
					Schema: 1, Current: h1Target, Previous: h1Base,
					Probation: &updatestate.Probation{Version: h1Target, Since: since, SmokeOK: true},
				}))
				for i := 0; i < 2; i++ {
					code := 0xC0000005
					must(e.t, updatestate.AppendRun(e.L.RunFile(pv), updatestate.RunRecord{RunID: fmt.Sprintf("crash-%d", i), Version: h1Target, ExitCode: &code, At: time.Now().UTC()}))
				}
			},
			converged: func(_ *h1Env, st *updatestate.State) bool {
				q, ok := st.Quarantine[h1Target]
				return st.Current == h1Base && st.Probation == nil && ok && q.Reason == ReasonBadRuns
			},
			event: EventRolledBack, from: h1Target, to: h1Base,
			neverCurrent: h1Target,
		},
	}
}

// traceScenario runs sc cleanly to convergence and returns each tick's
// checkpoints.
func traceScenario(t *testing.T, sc scenario) [][]string {
	t.Helper()
	e := newH1Env(t)
	sc.setup(e)
	var ticks [][]string
	for i := 0; i < cleanTicks+2; i++ {
		trace := filepath.Join(t.TempDir(), "trace")
		if code := e.tick("", trace); code != ExitOK {
			e.dumpLogs()
			t.Fatalf("clean %s tick %d exit %d", sc.name, i, code)
		}
		ticks = append(ticks, readTrace(trace))
		if sc.converged(e, e.state()) {
			if !e.sawEvent(sc.event, sc.from, sc.to) {
				t.Fatalf("clean %s: no %s", sc.name, sc.event)
			}
			return ticks
		}
	}
	e.dumpLogs()
	t.Fatalf("clean %s run did not converge", sc.name)
	return nil
}

func TestKillMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("kill matrix is long")
	}
	actions := []string{"kill", "err", "hang", "diskfull", "panic"}
	for _, sc := range scenarios() {
		ticks := traceScenario(t, sc)
		total := 0
		for ti, cps := range ticks {
			seen := map[string]bool{}
			for _, cp := range cps {
				if seen[cp] {
					continue // DMG_FAULT acts on the first hit
				}
				seen[cp] = true
				for _, action := range actions {
					total++
					name := fmt.Sprintf("%s/tick%d/%s/%s", sc.name, ti, cp, action)
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						runFaultCase(t, sc, ti, cp+":"+action)
					})
				}
			}
		}
		t.Logf("%s: %d ticks traced, %d fault cases", sc.name, len(ticks), total)
	}
}

func runFaultCase(t *testing.T, sc scenario, faultTick int, fault string) {
	e := newH1Env(t)
	sc.setup(e)
	quarantinedSeen := false
	pendingIDs := map[string]bool{} // outbox execution_ids ever persisted (U3)
	check := func() *updatestate.State {
		st := e.state()
		e.assertBootstrapRead()
		e.assertPointersIntact(st)
		for _, ev := range st.Outbox {
			pendingIDs[ev.ExecutionID] = true
		}
		if sc.neverCurrent != "" {
			if _, q := st.Quarantine[sc.neverCurrent]; q {
				quarantinedSeen = true
			}
			if quarantinedSeen && st.Current == sc.neverCurrent {
				e.dumpLogs()
				t.Fatalf("U8: quarantined %s is current again", sc.neverCurrent)
			}
		}
		return st
	}
	for i := 0; i < faultTick; i++ {
		e.tick("", "")
		check()
	}
	// The faulted tick also can't deliver events (U3: they must survive).
	e.api.mu.Lock()
	e.api.eventStatus = http.StatusServiceUnavailable
	e.api.mu.Unlock()
	trace := filepath.Join(t.TempDir(), "fault-trace")
	code := e.tick(fault, trace)
	e.api.mu.Lock()
	e.api.eventStatus = 0
	e.api.mu.Unlock()
	cp := fault[:strings.LastIndexByte(fault, ':')]
	if !slices.Contains(readTrace(trace), cp) {
		e.dumpLogs()
		t.Fatalf("fault %s never reached its checkpoint", fault)
	}
	switch {
	case strings.HasSuffix(fault, ":kill") && code != 137:
		t.Fatalf("kill: exit %d, want 137", code)
	case strings.HasSuffix(fault, ":panic") && code != 2:
		t.Fatalf("panic: exit %d, want 2 (a crash)", code)
	case strings.HasSuffix(fault, ":hang") && code == 0:
		t.Fatalf("hang: process was not killed (exit %d)", code)
	}
	before := check()
	// U5: a tick while a scan holds the instance mutex never switches.
	release := e.holdInstance()
	e.tick("", "")
	release()
	if after := check(); after.Current != before.Current && after.Current == h1Target {
		e.dumpLogs()
		t.Fatalf("U5: switched to %s while a scan held the instance mutex", after.Current)
	}
	for i := 0; i < cleanTicks; i++ {
		e.tick("", "")
		st := check()
		if sc.converged(e, st) && len(st.Outbox) == 0 {
			if !e.sawEvent(sc.event, sc.from, sc.to) {
				e.dumpLogs()
				t.Fatalf("U2/U3: converged without %s %s->%s", sc.event, sc.from, sc.to)
			}
			e.assertHygiene(st)
			e.assertEventsDelivered(pendingIDs)
			e.assertUniqueExecutionIDs()
			if os.Getenv("DMG_SU_DUMP") == "1" {
				e.dumpLogs()
			}
			return
		}
	}
	e.dumpLogs()
	t.Fatalf("U2: not converged within %d clean ticks after %s: %+v", cleanTicks, fault, e.state())
}

// assertPointersIntact: current and previous always name a complete
// version dir, or a seed (GC must never delete what state points at).
func (e *h1Env) assertPointersIntact(st *updatestate.State) {
	e.t.Helper()
	seeds := map[string]bool{}
	for _, s := range seedVersions(e.L) {
		seeds[s.String()] = true
	}
	for _, v := range []string{st.Current, st.Previous} {
		if v == "" || seeds[v] {
			continue
		}
		pv, _ := updatestate.ParseVersion(v)
		if err := updatestate.VersionDirComplete(e.L.VersionDir(pv)); err != nil {
			e.dumpLogs()
			e.t.Fatalf("GC removed a pointed-at version %s: %v (state %+v)", v, err, st)
		}
	}
}

// assertEventsDelivered is U3: every event that was ever pending reached
// the backend (2xx) by convergence.
func (e *h1Env) assertEventsDelivered(ids map[string]bool) {
	e.t.Helper()
	got := map[string]bool{}
	e.api.mu.Lock()
	for _, ev := range e.api.events {
		got[fmt.Sprint(ev["execution_id"])] = true
	}
	e.api.mu.Unlock()
	for id := range ids {
		if !got[id] {
			e.dumpLogs()
			e.t.Fatalf("U3: pending event %s was cleared without a 2xx", id)
		}
	}
}

// assertUniqueExecutionIDs is D9: an execution_id is only ever reused by
// retries of the same event.
func (e *h1Env) assertUniqueExecutionIDs() {
	e.t.Helper()
	seen := map[string]string{}
	e.api.mu.Lock()
	defer e.api.mu.Unlock()
	for _, ev := range e.api.events {
		id := fmt.Sprint(ev["execution_id"])
		body := fmt.Sprint(ev["update_event"], ev["update_from"], ev["update_to"], ev["error_message"])
		if prev, ok := seen[id]; ok && prev != body {
			e.t.Fatalf("D9: execution_id %s reused by different events: %q / %q", id, prev, body)
		}
		seen[id] = body
	}
}

// TestStateCorruptionMatrix is the updater half of the U0 bootstrap matrix:
// every state.json / version-dir corruption must converge to the target and
// be reported when the state itself was bad. (The `bootstrap run` half
// belongs to the bootstrap, B1.)
func TestStateCorruptionMatrix(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(e *h1Env)
		event   string // expected besides update_ok, "" = none
	}{
		{"missing", func(e *h1Env) { must(t, os.Remove(e.L.StateFile())) }, EventStateCorrupt},
		{"empty", func(e *h1Env) { must(t, os.WriteFile(e.L.StateFile(), nil, 0o644)) }, EventStateCorrupt},
		{"garbage", func(e *h1Env) { must(t, os.WriteFile(e.L.StateFile(), []byte("\x00{nope"), 0o644)) }, EventStateCorrupt},
		{"higher schema (read, not rebuilt)", func(e *h1Env) {
			must(t, os.WriteFile(e.L.StateFile(), []byte(`{"schema":2,"current":"1.19.0","v2":true}`), 0o644))
		}, ""},
		{"current dir missing the launcher", func(e *h1Env) {
			must(t, os.Remove(filepath.Join(e.L.VersionDir(mustV(h1Base)), updatestate.LauncherFile)))
		}, ""},
		{"huge", func(e *h1Env) {
			must(t, os.WriteFile(e.L.StateFile(), []byte(`{"schema":1,"current":"1.19.0","pad":"`+strings.Repeat("x", 2<<20)+`"}`), 0o644))
		}, EventStateCorrupt},
		{"traversal current", func(e *h1Env) {
			must(t, os.WriteFile(e.L.StateFile(), []byte(`{"schema":1,"current":"..\\x"}`), 0o644))
		}, EventStateCorrupt},
		{"current dir missing", func(e *h1Env) { must(t, os.RemoveAll(e.L.VersionDir(mustV(h1Base)))) }, ""},
		{"current dir missing agent", func(e *h1Env) {
			must(t, os.Remove(filepath.Join(e.L.VersionDir(mustV(h1Base)), updatestate.AgentFile)))
		}, ""},
		{"previous missing", func(e *h1Env) {
			must(t, updatestate.Save(e.L.StateFile(), &updatestate.State{Schema: 1, Current: h1Base, Previous: "1.18.5"}))
		}, ""},
		{"seed missing", func(e *h1Env) { must(t, os.RemoveAll(filepath.Join(e.L.InstallRoot, "seed"))) }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newH1Env(t)
			tc.corrupt(e)
			for i := 0; i < cleanTicks; i++ {
				e.tick("", "")
				st := e.state()
				if st.Current == h1Target && st.Probation == nil && len(st.Outbox) == 0 {
					if tc.event != "" && !e.sawEvent(tc.event, "", "") {
						t.Fatalf("no %s", tc.event)
					}
					if !e.sawEvent(EventOK, "", h1Target) {
						t.Fatal("no update_ok")
					}
					e.assertHygiene(st)
					return
				}
			}
			e.dumpLogs()
			t.Fatalf("not converged: %+v", e.state())
		})
	}
}

// The matrix runs ~1500 subprocess ticks; a -race child sleeps 1 s at exit
// unless GORACE says otherwise, which once pushed the package past its CI
// timeout. Every child the harness starts must turn that sleep off.
func TestHarnessChildrenSkipRaceExitSleep(t *testing.T) {
	e := newH1Env(t)
	env := e.childEnv("", filepath.Join(t.TempDir(), "trace"))
	if !slices.Contains(env, "GORACE=atexit_sleep_ms=0") {
		t.Fatalf("child env lacks GORACE=atexit_sleep_ms=0")
	}
}

// D28: S6.mutex fires with the scan instance mutex held, so
// S6.mutex:sleep<d> keeps a scan out for d (harness U-F3).
func TestSleepAtS6MutexHoldsTheInstanceMutex(t *testing.T) {
	e := newH1Env(t)
	trace := filepath.Join(t.TempDir(), "trace")
	done := make(chan int, 1)
	go func() { done <- e.tick("S6.mutex:sleep3s", trace) }()
	deadline := time.Now().Add(2 * time.Minute)
	for !slices.Contains(readTrace(trace), "S6.mutex") {
		if time.Now().After(deadline) {
			t.Fatal("S6.mutex never reached")
		}
		time.Sleep(20 * time.Millisecond)
	}
	holdInstanceMu.Lock()
	restore := lock.SetTargetForTest(e.lock)
	lk, err := lock.Acquire(nil)
	restore()
	holdInstanceMu.Unlock()
	if err == nil {
		lk.Release()
		t.Fatal("a scan took the instance mutex while the updater slept at S6.mutex")
	}
	if code := <-done; code != ExitOK {
		e.dumpLogs()
		t.Fatalf("tick exit %d", code)
	}
	if e.state().Current != h1Target {
		t.Fatal("switch did not complete after the sleep")
	}
}
