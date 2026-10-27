package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/step-security/dev-machine-guard/internal/launcher"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/step-security/dev-machine-guard/internal/proctest"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// env is one simulated MSI install plus a fake backend.
type env struct {
	t        *testing.T
	L        updatestate.Layout
	api      *fakeAPI
	now      time.Time
	self     string
	auto     bool
	pubErr   error
	smokeErr map[string]error
	busy     int // AcquireInstance fails this many more times
	sendErr  error
	drift    []string

	mu   sync.Mutex
	sent []updatestate.OutboxEvent // since the last events() call
	all  []updatestate.OutboxEvent
}

const testArch = "amd64"

func payload(kind, v string) []byte { return []byte(kind + "-" + v) }

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		t: t, L: updatestate.Layout{InstallRoot: filepath.Join(root, "pf"), DataRoot: filepath.Join(root, "pd")},
		api: newFakeAPI(t), now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
		self: "1.19.0", auto: true, smokeErr: map[string]error{},
	}
	for _, v := range []string{"1.17.0", "1.18.0", "1.19.0", "1.20.0", "1.21.0"} {
		e.api.addRelease(v, testArch, payload("agent", v), payload("task", v), payload("linux", v))
	}
	e.api.setTarget("1.20.0")
	e.writeSeed("1.19.0")
	knobOverrides = map[knob]time.Duration{knobSwitchWait: 0}
	t.Cleanup(func() { knobOverrides = map[knob]time.Duration{} })
	return e
}

func (e *env) writeSeed(v string) {
	pv, _ := updatestate.ParseVersion(v)
	dir := e.L.SeedDir(pv)
	must(e.t, os.MkdirAll(dir, 0o755))
	for _, f := range []struct{ name, kind string }{{updatestate.AgentFile, "agent"}, {updatestate.LauncherFile, "task"}, {updatestate.LinuxFile, "linux"}} {
		must(e.t, os.WriteFile(filepath.Join(dir, f.name), payload(f.kind, v), 0o755))
	}
}

// installVersion writes a complete, manifest-checked versions\<v>.
func (e *env) installVersion(v string) {
	pv, _ := updatestate.ParseVersion(v)
	dir := e.L.VersionDir(pv)
	must(e.t, os.MkdirAll(dir, 0o755))
	m := updatestate.Manifest{Version: v, Files: map[string]string{}}
	for _, f := range []struct{ name, kind string }{{updatestate.AgentFile, "agent"}, {updatestate.LauncherFile, "task"}, {updatestate.LinuxFile, "linux"}} {
		b := payload(f.kind, v)
		must(e.t, os.WriteFile(filepath.Join(dir, f.name), b, 0o755))
		m.Files[f.name] = sum(b)
	}
	must(e.t, updatestate.WriteManifest(dir, m))
}

func (e *env) writeState(st *updatestate.State) {
	must(e.t, os.MkdirAll(e.L.StateDir(), 0o755))
	must(e.t, updatestate.Save(e.L.StateFile(), st))
}

func (e *env) state() *updatestate.State {
	st, corrupt, err := updatestate.Load(e.L.StateFile())
	if err != nil || corrupt || st == nil {
		e.t.Fatalf("state: %v corrupt=%v nil=%v", err, corrupt, st == nil)
	}
	return st
}

func (e *env) deps() *Deps {
	self, _ := updatestate.ParseVersion(e.self)
	return &Deps{
		Layout: e.L, Self: self, SelfExe: filepath.Join(e.L.VersionDir(self), updatestate.AgentFile),
		Client:     e.api.client(testArch),
		AutoUpdate: e.auto,
		VerifyPublisher: func(p string) error {
			if _, err := os.Stat(p); err != nil {
				return err
			}
			return e.pubErr
		},
		Smoke: func(_ context.Context, exe string, want updatestate.Version) error {
			if _, err := os.Stat(exe); err != nil {
				return err
			}
			return e.smokeErr[want.String()]
		},
		AcquireInstance: func() (func(), error) {
			if e.busy > 0 {
				e.busy--
				return nil, errors.New("held")
			}
			return func() {}, nil
		},
		EnsureACLs: func() ([]string, error) { d := e.drift; e.drift = nil; return d, nil },
		Send: func(_ context.Context, ev updatestate.OutboxEvent) error {
			if e.sendErr != nil {
				return e.sendErr
			}
			e.mu.Lock()
			e.sent = append(e.sent, ev)
			e.all = append(e.all, ev)
			e.mu.Unlock()
			return nil
		},
		Now:  func() time.Time { return e.now },
		Logf: func(f string, a ...any) { e.t.Logf("[updater] "+f, a...) },
	}
}

func (e *env) tick() int { e.t.Helper(); return Run(context.Background(), e.deps()) }

// events returns and clears the sent event names.
func (e *env) events() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, ev := range e.sent {
		out = append(out, ev.Event)
	}
	e.sent = nil
	return out
}

func (e *env) lastSent(event string) updatestate.OutboxEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.all) - 1; i >= 0; i-- {
		if e.all[i].Event == event {
			return e.all[i]
		}
	}
	e.t.Fatalf("no %s sent", event)
	return updatestate.OutboxEvent{}
}

// addRun appends a finalized run record for v.
func (e *env) addRun(v string, started bool, exit int) {
	pv, _ := updatestate.ParseVersion(v)
	must(e.t, updatestate.AppendRun(e.L.RunFile(pv), updatestate.RunRecord{RunID: uuid.NewString(), Version: v, Started: started, ExitCode: &exit, At: e.now}))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantEvents(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// assertHygiene is U6 on the versions dir.
func assertHygiene(t *testing.T, e *env) {
	t.Helper()
	st := e.state()
	allowed := map[string]bool{st.Current: true, st.Previous: true, e.self: true}
	if st.Probation != nil {
		allowed[st.Probation.Version] = true
	}
	if st.PendingSwitch != "" {
		allowed[st.PendingSwitch] = true
	}
	for _, s := range seedVersions(e.L) {
		allowed[s.String()] = true
	}
	entries, _ := os.ReadDir(e.L.VersionsDir())
	for _, en := range entries {
		if updatestate.IsSweepable(en.Name()) || !allowed[en.Name()] {
			t.Errorf("leftover in versions: %s", en.Name())
		}
	}
}

func baseState(cur, prev string) *updatestate.State {
	return &updatestate.State{Schema: 1, Current: cur, Previous: prev}
}

func TestFreshInstallUpdatesThenConfirms(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))

	if code := e.tick(); code != ExitOK {
		t.Fatalf("tick = %d", code)
	}
	wantEvents(t, e.events(), EventOK)
	ok := e.lastSent(EventOK)
	_ = ok
	st := e.state()
	if st.Current != "1.20.0" || st.Previous != "1.19.0" || st.Probation == nil || st.Probation.Version != "1.20.0" || len(st.Outbox) != 0 {
		t.Fatalf("after switch: %+v", st)
	}
	if err := updatestate.VerifyVersionDir(e.L.VersionDir(mustV("1.20.0")), mustV("1.20.0")); err != nil {
		t.Fatal(err)
	}

	// Probation open: no target check, no events.
	e.now = e.now.Add(time.Hour)
	e.tick()
	wantEvents(t, e.events())

	e.addRun("1.20.0", true, 0)
	e.now = e.now.Add(time.Hour)
	e.tick()
	wantEvents(t, e.events(), EventConfirmed)
	if st := e.state(); st.Probation != nil || st.Current != "1.20.0" {
		t.Fatalf("after confirm: %+v", st)
	}
	assertHygiene(t, e)
}

func mustV(s string) updatestate.Version {
	v, err := updatestate.ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}

func TestMissingStateRebuildsOnSeed(t *testing.T) {
	e := newEnv(t)
	e.api.setTarget("1.19.0")
	e.tick()
	wantEvents(t, e.events(), EventStateCorrupt)
	if st := e.state(); st.Current != "1.19.0" {
		t.Fatalf("current = %s", st.Current)
	}
	// versions\1.19.0 was absent, so it is staged from the release.
	if err := updatestate.VerifyVersionDir(e.L.VersionDir(mustV("1.19.0")), mustV("1.19.0")); err != nil {
		t.Fatalf("seed version not staged: %v", err)
	}
}

func TestCorruptStateIsReported(t *testing.T) {
	e := newEnv(t)
	must(t, os.MkdirAll(e.L.StateDir(), 0o755))
	must(t, os.WriteFile(e.L.StateFile(), []byte("{garbage"), 0o644))
	e.api.setTarget("1.19.0")
	if code := e.tick(); code != ExitOK {
		t.Fatalf("tick = %d", code)
	}
	wantEvents(t, e.events(), EventStateCorrupt)
	if ev := e.lastSentOrNil(EventStateCorrupt); ev == nil || ev.Error == "" {
		t.Fatal("no reason on update_state_corrupt")
	}
}

func (e *env) lastSentOrNil(event string) *updatestate.OutboxEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.all) - 1; i >= 0; i-- {
		if e.all[i].Event == event {
			ev := e.all[i]
			return &ev
		}
	}
	return nil
}

func probationState(t *testing.T, e *env) {
	t.Helper()
	e.installVersion("1.19.0")
	e.installVersion("1.20.0")
	st := baseState("1.20.0", "1.19.0")
	st.Probation = &updatestate.Probation{Version: "1.20.0", Since: e.now.Add(-time.Minute), SmokeOK: true}
	st.LastCheck = e.now
	e.writeState(st)
}

func TestBadRunsRollBackAndQuarantineForever(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	e.addRun("1.20.0", false, 2)
	e.tick()
	wantEvents(t, e.events())
	e.addRun("1.20.0", false, 0xC0000005)
	e.tick()
	got := e.events()
	if len(got) == 0 || got[0] != EventRolledBack {
		t.Fatalf("events = %v", got)
	}
	rb := e.lastSent(EventRolledBack)
	if rb.From != "1.20.0" || rb.To != "1.19.0" || rb.Error != ReasonBadRuns {
		t.Fatalf("rollback event = %+v", rb)
	}
	st := e.state()
	if st.Current != "1.19.0" || st.Probation != nil || st.Quarantine["1.20.0"].Reason != ReasonBadRuns || !st.Quarantine["1.20.0"].Until.IsZero() {
		t.Fatalf("after rollback: %+v", st)
	}
	// U8: the target stays 1.20.0 for days; it is never current again and
	// never re-staged.
	for i := 0; i < 5; i++ {
		e.now = e.now.Add(7 * time.Hour)
		e.tick()
		if st := e.state(); st.Current != "1.19.0" {
			t.Fatalf("quarantined version came back: %+v", st)
		}
	}
	if _, err := os.Stat(e.L.VersionDir(mustV("1.20.0"))); !os.IsNotExist(err) {
		t.Fatalf("quarantined version dir not collected: %v", err)
	}
	assertHygiene(t, e)
}

func TestNeutralRunsNeverRollBack(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	for i := 0; i < 5; i++ {
		e.addRun("1.20.0", false, 1)
	}
	e.tick()
	if st := e.state(); st.Probation == nil || st.Current != "1.20.0" {
		t.Fatalf("neutral runs closed the probation: %+v", st)
	}
}

func TestInconclusiveProbationQuarantinesForAWeek(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	for i := 0; i < 6; i++ {
		e.addRun("1.20.0", false, 1)
	}
	e.now = e.now.Add(73 * time.Hour)
	e.tick()
	rb := e.lastSent(EventRolledBack)
	if rb.Error != ReasonInconclusive {
		t.Fatalf("rollback = %+v", rb)
	}
	st := e.state()
	q := st.Quarantine["1.20.0"]
	if st.Current != "1.19.0" || q.Until.IsZero() || q.Until.Sub(e.now) != 7*24*time.Hour {
		t.Fatalf("after inconclusive: %+v %+v", st, q)
	}
	e.events()
	// After the quarantine expires the target is taken again.
	e.now = e.now.Add(7*24*time.Hour + time.Minute)
	e.tick()
	if st := e.state(); st.Current != "1.20.0" {
		t.Fatalf("not retried after expiry: %+v", st)
	}
	wantEvents(t, e.events(), EventOK)
}

func TestSmokeOnlyPromotion(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	e.now = e.now.Add(73 * time.Hour)
	e.tick()
	c := e.lastSent(EventConfirmed)
	if c.To != "1.20.0" || c.Error != "smoke_only" {
		t.Fatalf("confirm = %+v", c)
	}
}

func TestReSmokeFailureRollsBack(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	e.smokeErr["1.20.0"] = errors.New("boom")
	e.now = e.now.Add(73 * time.Hour)
	e.tick()
	if rb := e.lastSent(EventRolledBack); rb.Error != ReasonSmokeFailed {
		t.Fatalf("rollback = %+v", rb)
	}
}

func TestPointerInvalidDuringProbation(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	must(t, os.Remove(filepath.Join(e.L.VersionDir(mustV("1.20.0")), updatestate.AgentFile)))
	e.tick()
	if rb := e.lastSent(EventRolledBack); rb.Error != ReasonPointerInvalid || rb.To != "1.19.0" {
		t.Fatalf("rollback = %+v", rb)
	}
}

func TestSmokeFailureQuarantinesWithoutSwitch(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.smokeErr["1.20.0"] = errors.New("exit 3")
	e.tick()
	wantEvents(t, e.events(), EventHealthFailed)
	st := e.state()
	if st.Current != "1.19.0" || st.Quarantine["1.20.0"].Reason != ReasonSmokeFailed {
		t.Fatalf("state = %+v", st)
	}
	e.now = e.now.Add(7 * time.Hour)
	e.tick()
	wantEvents(t, e.events())
	assertHygiene(t, e)
}

func TestPolicyOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(e *env)
		event  string
		code   int
		staged bool
	}{
		{"disabled", func(e *env) { e.auto = false }, EventDisabled, ExitOK, false},
		{"below floor", func(e *env) { e.api.setTarget("1.17.0") }, EventRefusedFloor, ExitOK, false},
		{"1.18.0 is below the floor", func(e *env) { e.api.setTarget("1.18.0") }, EventRefusedFloor, ExitOK, false},
		{"check failed", func(e *env) { e.api.metaStatus = 500 }, EventCheckFailed, ExitFailed, false},
		{"bad signature", func(e *env) {
			e.api.badSig["stepsecurity-dev-machine-guard-1.20.0-windows_amd64.exe"] = true
		}, EventVerifyFailed, ExitOK, false},
		{"wrong publisher", func(e *env) { e.pubErr = errors.New("publisher differs") }, EventVerifyFailed, ExitOK, false},
		{"sha mismatch", func(e *env) {
			e.api.checksumOver["stepsecurity-dev-machine-guard-1.20.0-linux_amd64"] = sum([]byte("other"))
		}, EventVerifyFailed, ExitOK, false},
		{"download failed", func(e *env) { e.api.githubDown = true }, EventDownloadFailed, ExitFailed, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.installVersion("1.19.0")
			e.writeState(baseState("1.19.0", ""))
			tc.setup(e)
			if code := e.tick(); code != tc.code {
				t.Fatalf("tick = %d, want %d", code, tc.code)
			}
			wantEvents(t, e.events(), tc.event)
			if st := e.state(); st.Current != "1.19.0" {
				t.Fatalf("current moved: %+v", st)
			}
			if _, err := os.Stat(e.L.VersionDir(mustV("1.20.0"))); err == nil {
				t.Fatal("target staged")
			}
			if tc.name == "bad signature" {
				for remote, n := range e.api.githubHits {
					if n > 0 {
						t.Fatalf("downloaded %s before verifying signatures", remote)
					}
				}
			}
			// Deduped within the window, reported again after it.
			e.now = e.now.Add(7 * time.Hour)
			e.tick()
			wantEvents(t, e.events())
			e.now = e.now.Add(25 * time.Hour)
			e.tick()
			wantEvents(t, e.events(), tc.event)
			assertHygiene(t, e)
		})
	}
}

func TestCheckIntervalGatesNetwork(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.20.0")
	e.self = "1.20.0"
	e.writeState(baseState("1.20.0", ""))
	e.tick()
	n := len(e.api.latestRequests)
	e.now = e.now.Add(time.Hour)
	e.tick()
	if len(e.api.latestRequests) != n {
		t.Fatal("target checked again within the 6 h interval")
	}
	e.now = e.now.Add(6 * time.Hour)
	e.tick()
	if len(e.api.latestRequests) == n {
		t.Fatal("target not checked after the interval")
	}
}

func TestDowngradeAboveFloor(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.21.0")
	e.self = "1.21.0"
	e.writeState(baseState("1.21.0", "1.19.0"))
	e.tick()
	ok := e.lastSent(EventOK)
	if ok.From != "1.21.0" || ok.To != "1.20.0" {
		t.Fatalf("update_ok = %+v", ok)
	}
}

func TestSwitchDeferredWhileScanRuns(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.busy = 100
	for i := 1; i <= 4; i++ {
		e.now = e.now.Add(time.Hour)
		e.tick()
		if st := e.state(); st.Current != "1.19.0" {
			t.Fatal("switched while the scan held the mutex")
		}
	}
	wantEvents(t, e.events(), EventSwitchDeferred)
	e.busy = 0
	e.now = e.now.Add(time.Hour)
	e.tick()
	wantEvents(t, e.events(), EventOK)
	if st := e.state(); st.Current != "1.20.0" || st.SwitchDeferrals != 0 {
		t.Fatalf("after release: %+v", st)
	}
}

func TestLockHeldExitsQuietly(t *testing.T) {
	e := newEnv(t)
	e.writeState(baseState("1.19.0", ""))
	lk, err := updatestate.AcquireLock(e.L.LockFile())
	must(t, err)
	defer lk.Release()
	if code := e.tick(); code != ExitOK {
		t.Fatalf("tick = %d", code)
	}
	if len(e.api.latestRequests) != 0 {
		t.Fatal("second updater did work")
	}
}

func TestOutboxRetriedNextTick(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.sendErr = errors.New("backend down")
	if code := e.tick(); code != ExitOK {
		t.Fatalf("send failure changed the outcome: %d", code)
	}
	st := e.state()
	if st.Current != "1.20.0" || len(st.Outbox) != 1 || st.Outbox[0].Event != EventOK {
		t.Fatalf("state = %+v", st)
	}
	e.sendErr = nil
	e.now = e.now.Add(time.Hour)
	e.tick()
	wantEvents(t, e.events(), EventOK)
	if st := e.state(); len(st.Outbox) != 0 {
		t.Fatalf("outbox not drained: %+v", st.Outbox)
	}
	// Rejected events are dropped, not retried forever.
	e.drift = []string{"versions"}
	e.sendErr = fmt.Errorf("%w: HTTP 400", ErrEventRejected)
	e.now = e.now.Add(time.Hour)
	e.tick()
	if st := e.state(); len(st.Outbox) != 0 {
		t.Fatalf("rejected event kept: %+v", st.Outbox)
	}
}

func TestACLDriftAndUpdaterFailureReported(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.20.0")
	st := baseState("1.20.0", "")
	st.Updater = updatestate.Updater{Version: "1.20.0", ConsecutiveFailures: 3}
	e.writeState(st)
	e.drift = []string{"versions"}
	e.tick()
	got := e.events()
	slices.Sort(got)
	wantEvents(t, got, EventACLDrift, EventUpdaterFailed)
	uf := e.lastSent(EventUpdaterFailed)
	if uf.From != "1.20.0" || uf.To != "1.19.0" {
		t.Fatalf("update_updater_failed = %+v", uf)
	}
}

func TestGCKeepsPointersAndSweepsLeftovers(t *testing.T) {
	e := newEnv(t)
	for _, v := range []string{"1.18.0", "1.19.0", "1.20.0", "1.21.0"} {
		e.installVersion(v)
	}
	// 1.21.0 was staged long ago (not a recent unrecorded stage): collect it.
	old := e.now.Add(-3 * 24 * time.Hour)
	must(t, os.Chtimes(filepath.Join(e.L.VersionDir(mustV("1.21.0")), updatestate.ManifestName), old, old))
	must(t, os.MkdirAll(filepath.Join(e.L.VersionsDir(), ".staging-1.21.0-x"), 0o755))
	must(t, os.MkdirAll(filepath.Join(e.L.VersionsDir(), ".trash-1.17.0-y"), 0o755))
	st := baseState("1.20.0", "1.19.0")
	st.LastCheck = e.now
	e.writeState(st)
	e.self = "1.19.0"
	e.tick()
	entries, _ := os.ReadDir(e.L.VersionsDir())
	var names []string
	for _, en := range entries {
		names = append(names, en.Name())
	}
	if !slices.Equal(names, []string{"1.19.0", "1.20.0"}) {
		t.Fatalf("versions = %v", names)
	}
}

// D9: every event gets its own execution_id; a retried event (carried in
// the outbox to a later tick) keeps its id.
func TestEventExecutionIDs(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.drift = []string{"versions"}
	e.sendErr = errors.New("backend down")
	e.tick()
	pending := e.state().Outbox
	if len(pending) != 2 {
		t.Fatalf("outbox = %+v", pending)
	}
	if pending[0].ExecutionID == pending[1].ExecutionID || pending[0].ExecutionID == "" {
		t.Fatalf("events share an execution_id: %+v", pending)
	}
	e.sendErr = nil
	e.now = e.now.Add(time.Hour)
	e.tick()
	ids := map[string]bool{}
	for _, ev := range e.all {
		ids[ev.ExecutionID] = true
		if ev.Event == EventRolledBack && ev.From == "" {
			t.Fatal("update_rolled_back without update_from")
		}
	}
	for _, p := range pending {
		if !ids[p.ExecutionID] {
			t.Fatalf("retry of %s used a new execution_id", p.Event)
		}
	}
	if len(ids) != len(e.all) {
		t.Fatalf("delivered events reuse ids: %+v", e.all)
	}
}

func TestMissingLinuxFieldsReportVerifyFailed(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.api.noLinuxFields = true
	if code := e.tick(); code != ExitOK {
		t.Fatalf("tick = %d", code)
	}
	wantEvents(t, e.events(), EventVerifyFailed)
	if len(e.api.githubHits) != 0 {
		t.Fatalf("downloaded before verification: %v", e.api.githubHits)
	}
}

// D11: the fallback updater reports update_updater_failed only on a tick
// where it reached latest-binary itself; during an outage the primary's
// failures prove nothing.
func TestUpdaterFailedOnlyAfterReachingBackend(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.20.0")
	st := baseState("1.20.0", "")
	st.Updater = updatestate.Updater{Version: "1.20.0", ConsecutiveFailures: 3}
	e.writeState(st)
	e.api.metaStatus = 503
	e.tick()
	if got := e.events(); slices.Contains(got, EventUpdaterFailed) {
		t.Fatalf("reported during an outage: %v", got)
	}
	e.api.metaStatus = 0
	e.now = e.now.Add(time.Hour) // no target check due: still not reported
	e.tick()
	if got := e.events(); slices.Contains(got, EventUpdaterFailed) {
		t.Fatalf("reported without reaching the backend: %v", got)
	}
	e.now = e.now.Add(6 * time.Hour)
	e.tick()
	if got := e.events(); !slices.Contains(got, EventUpdaterFailed) {
		t.Fatalf("not reported once the backend answered: %v", got)
	}
}

// failingSaves makes every state write fail without touching the disk
// (landed=false) or write and then fail (landed=true), like a late error.
func failingSaves(t *testing.T, landed bool) {
	t.Helper()
	old := saveState
	saveState = func(path string, st *updatestate.State, prefix string) error {
		if landed {
			if err := old(path, st, prefix); err != nil {
				return err
			}
		}
		return errors.New("injected state write failure")
	}
	t.Cleanup(func() { saveState = old })
}

// R-C2-1: a tick whose state write never lands still reports its events
// (sent directly) instead of dropping them.
func TestUnlandedWriteSendsEventsDirectly(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.pubErr = errors.New("publisher differs")
	failingSaves(t, false)
	if code := e.tick(); code != ExitFailed {
		t.Fatalf("tick = %d, want ExitFailed when state can't be written", code)
	}
	wantEvents(t, e.events(), EventVerifyFailed)
}

func TestSwitchWriteFailureReported(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	failingSaves(t, false)
	e.tick()
	got := e.events()
	if !slices.Contains(got, EventSwitchFailed) || slices.Contains(got, EventOK) {
		t.Fatalf("events = %v, want update_switch_failed and no update_ok", got)
	}
	if st := e.state(); st.Current != "1.19.0" {
		t.Fatalf("current moved: %s", st.Current)
	}
}

// A write that landed but returned an error (late failure) is recognised
// by its generation: the switch counts, and no false switch_failed is sent.
func TestLandedWriteWithErrorIsNotAFailure(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	failingSaves(t, true)
	e.tick()
	got := e.events()
	if slices.Contains(got, EventSwitchFailed) || !slices.Contains(got, EventOK) {
		t.Fatalf("events = %v, want update_ok only", got)
	}
	if st := e.state(); st.Current != "1.20.0" {
		t.Fatalf("current = %s", st.Current)
	}
}

// R-C2-3: a retryable send failure keeps the event with a backoff; the
// outbox is capped at 64, dropping the oldest and counting the drops.
func TestOutboxBackoffAndCap(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.20.0")
	e.self = "1.20.0"
	st := baseState("1.20.0", "")
	st.LastCheck = e.now
	for i := 0; i < 70; i++ {
		enqueueTo(st, e.now, time.Hour, EventCheckFailed, "1.20.0", "", fmt.Sprint(i), "")
	}
	if len(st.Outbox) != 64 || st.OutboxDropped != 6 || st.Outbox[0].Error != "6" {
		t.Fatalf("cap: len=%d dropped=%d first=%q", len(st.Outbox), st.OutboxDropped, st.Outbox[0].Error)
	}
	st.Outbox = st.Outbox[:1]
	e.writeState(st)
	calls := 0
	d := e.deps()
	d.Send = func(context.Context, updatestate.OutboxEvent) error { calls++; return errors.New("HTTP 429") }
	Run(context.Background(), d)
	if calls != 1 {
		t.Fatalf("first attempt calls = %d", calls)
	}
	pending := e.state().Outbox
	if len(pending) != 1 || pending[0].Attempts != 1 || !pending[0].NextAttempt.After(e.now) {
		t.Fatalf("after a 429: %+v", pending)
	}
	// Within the backoff: not retried.
	e.now = e.now.Add(30 * time.Minute)
	Run(context.Background(), d)
	if calls != 1 {
		t.Fatalf("retried inside the backoff (calls=%d)", calls)
	}
	e.now = e.now.Add(2 * time.Hour)
	Run(context.Background(), d)
	if calls != 2 || e.state().Outbox[0].Attempts != 2 {
		t.Fatalf("not retried after the backoff: calls=%d %+v", calls, e.state().Outbox)
	}
}

// R-C2-4: a switch made while the clock ran a year ahead, then corrected
// backwards: crash runs recorded after the correction still roll back.
func TestProbationSurvivesBackwardsClock(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	st := e.state()
	st.Probation.Since = e.now.Add(365 * 24 * time.Hour)
	e.writeState(st)
	for i := 0; i < 3 && e.state().Current == "1.20.0"; i++ {
		e.addRun("1.20.0", false, 0xC0000005)
		e.tick()
		e.now = e.now.Add(time.Hour)
	}
	if st := e.state(); st.Current != "1.19.0" || st.Quarantine["1.20.0"].Reason != ReasonBadRuns {
		t.Fatalf("crashing version kept after a clock correction: %+v", st)
	}
}

// The probation also closes after window/1h update ticks, whatever the
// clock says.
func TestProbationClosesByTickCount(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	st := e.state()
	st.Probation.Ticks = 71
	e.writeState(st)
	e.tick()
	if c := e.lastSent(EventConfirmed); c.Error != "smoke_only" {
		t.Fatalf("confirm = %+v", c)
	}
}

// A quarantine expiry set by a clock far ahead is clamped to 7 days.
func TestQuarantineUntilClamped(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.20.0")
	e.self = "1.20.0"
	st := baseState("1.20.0", "")
	st.LastCheck = e.now
	st.Quarantine = map[string]updatestate.Quarantine{"1.21.0": {Reason: ReasonInconclusive, At: e.now, Until: e.now.Add(2 * 365 * 24 * time.Hour)}}
	e.writeState(st)
	e.tick()
	if u := e.state().Quarantine["1.21.0"].Until; u.After(e.now.Add(7 * 24 * time.Hour)) {
		t.Fatalf("until not clamped: %v", u)
	}
}

// D15/R-C2-5: six runs with no started marker are inconclusive even when
// one of them was Bad; that is not a smoke-only promotion.
func TestInconclusiveCountsBadRuns(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	e.addRun("1.20.0", false, 0xC0000005)
	for i := 0; i < 5; i++ {
		e.addRun("1.20.0", false, 1)
	}
	e.now = e.now.Add(73 * time.Hour)
	e.tick()
	if rb := e.lastSentOrNil(EventRolledBack); rb == nil || rb.Error != ReasonInconclusive {
		t.Fatalf("want an inconclusive rollback, got %v (events %v)", rb, e.events())
	}
}

// D15/R-C2-6: the smoke has its own budget: the tick's context ending
// doesn't cut it, and a smoke that fails because the tick budget ran out is
// retried, never a quarantine.
func TestSmokeBudgetCutoffRetries(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := e.deps()
	smokeCtxAlive := false
	d.Smoke = func(sctx context.Context, _ string, _ updatestate.Version) error {
		cancel() // the tick's budget ends while the smoke runs
		smokeCtxAlive = sctx.Err() == nil
		return fmt.Errorf("self-check timed out: %w", context.DeadlineExceeded)
	}
	Run(ctx, d)
	if !smokeCtxAlive {
		t.Fatal("the smoke context was cut by the tick budget")
	}
	st := e.state()
	if _, q := st.Quarantine["1.20.0"]; q {
		t.Fatalf("budget cutoff quarantined the target: %+v", st.Quarantine)
	}
	if slices.Contains(e.events(), EventHealthFailed) {
		t.Fatal("budget cutoff reported update_health_failed")
	}
	if !st.LastCheck.IsZero() {
		t.Fatal("the target check is not retried on the next tick")
	}
}

// D15/R-C2-8: deferred switches reuse the staged versions\<t> instead of
// re-downloading it every tick.
func TestDeferralReusesStagedDir(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.busy = 5
	for i := 0; i < 5; i++ {
		e.tick()
		e.now = e.now.Add(time.Hour)
	}
	e.tick()
	if st := e.state(); st.Current != "1.20.0" {
		t.Fatalf("not switched: %+v", st)
	}
	for remote, n := range e.api.githubHits {
		if n != 1 {
			t.Fatalf("%s downloaded %d times", remote, n)
		}
	}
}

// The deferral counter belongs to one target: a count left by an abandoned
// target doesn't make the next target's first deferral a report.
func TestDeferralCounterIsPerTarget(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	st := baseState("1.19.0", "")
	st.SwitchDeferrals = 3
	st.PendingSwitch = "1.21.0"
	e.writeState(st)
	e.busy = 1
	e.tick()
	if got := e.events(); slices.Contains(got, EventSwitchDeferred) {
		t.Fatalf("first deferral of a new target reported: %v", got)
	}
	if st := e.state(); st.SwitchDeferrals != 1 || st.PendingSwitch != "1.20.0" {
		t.Fatalf("deferral state: %d %q", st.SwitchDeferrals, st.PendingSwitch)
	}
}

// D15 design fix: during a probation the updater is the OLDER previous; a
// newer schema written by the probation version must not make it rebuild
// on the seed or drop the newer fields.
func TestOlderUpdaterKeepsNewerSchemaState(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	since := e.now.Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	body := `{"schema":2,"current":"1.20.0","previous":"1.19.0","future":{"k":[1]},
	 "probation":{"version":"1.20.0","since":"` + since + `","ok":0,"bad":0,"smoke_ok":true,"p2":"x"},
	 "quarantine":{"1.18.5":{"reason":"bad_runs","at":"` + since + `","q2":1}},"last_check":"` + since + `"}`
	must(t, os.WriteFile(e.L.StateFile(), []byte(body), 0o644))
	e.addRun("1.20.0", false, 2)
	e.tick()
	if got := e.events(); slices.Contains(got, EventStateCorrupt) {
		t.Fatalf("rebuilt a newer-schema state: %v", got)
	}
	var out map[string]any
	data, _ := os.ReadFile(e.L.StateFile())
	_ = json.Unmarshal(data, &out)
	p, _ := out["probation"].(map[string]any)
	q, _ := out["quarantine"].(map[string]any)["1.18.5"].(map[string]any)
	if out["schema"] != float64(2) || out["current"] != "1.20.0" || fmt.Sprint(out["future"]) != "map[k:[1]]" ||
		p == nil || p["p2"] != "x" || p["bad"] != float64(1) || q == nil || q["q2"] != float64(1) {
		t.Fatalf("newer state not preserved: %s", data)
	}
}

// D15 test gap (planted bug "GC deletes previous"): with previous, the seed
// and the running updater all different, GC keeps previous.
func TestGCKeepsPreviousDistinctFromSeedAndUpdater(t *testing.T) {
	e := newEnv(t)
	must(t, os.RemoveAll(filepath.Join(e.L.InstallRoot, "seed")))
	e.writeSeed("1.17.0")
	for _, v := range []string{"1.18.0", "1.21.0"} {
		e.installVersion(v)
	}
	e.self = "1.21.0"
	st := baseState("1.21.0", "1.18.0")
	st.LastCheck = e.now
	e.writeState(st)
	e.tick()
	if err := updatestate.VerifyVersionDir(e.L.VersionDir(mustV("1.18.0")), mustV("1.18.0")); err != nil {
		t.Fatalf("GC removed previous: %v", err)
	}
	if err := updatestate.VerifyVersionDir(e.L.VersionDir(mustV("1.21.0")), mustV("1.21.0")); err != nil {
		t.Fatalf("GC removed current: %v", err)
	}
}

// D15 test gap (planted bug "dedupe key without the event class"): a new
// event class for the same target inside the dedupe window is reported.
func TestDedupeNeverHidesANewEventClass(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.pubErr = errors.New("publisher differs")
	e.tick()
	wantEvents(t, e.events(), EventVerifyFailed)
	e.pubErr = nil
	e.api.githubDown = true
	e.now = e.now.Add(7 * time.Hour)
	e.tick()
	wantEvents(t, e.events(), EventDownloadFailed)
	e.now = e.now.Add(7 * time.Hour)
	e.tick()
	wantEvents(t, e.events()) // same class, same target, same window: deduped
}

// R-F1-8: with 12 abandoned open records in the run file, two crashes are
// still seen and the probation version is rolled back.
func TestRollbackDespiteAbandonedRecords(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	pv := mustV("1.20.0")
	stale := time.Now().Add(-48 * time.Hour)
	exited := proctest.Command(t, os.Args[0], "-test.run=^$")
	must(t, exited.Run())
	for i := 0; i < 12; i++ {
		must(t, updatestate.AppendRun(e.L.RunFile(pv), updatestate.RunRecord{RunID: fmt.Sprintf("dead-%d", i), Version: "1.20.0", StartedAt: stale, OwnerPID: exited.Process.Pid}))
	}
	for i := 0; i < 2 && e.state().Current == "1.20.0"; i++ {
		id := fmt.Sprintf("crash-%d", i)
		must(t, updatestate.AppendRun(e.L.RunFile(pv), updatestate.RunRecord{RunID: id, Version: "1.20.0"}))
		must(t, updatestate.FinalizeRun(e.L.RunFile(pv), id, 2, false, e.now))
		e.tick()
	}
	if rb := e.lastSentOrNil(EventRolledBack); rb == nil || rb.Error != ReasonBadRuns {
		t.Fatalf("crashing version not rolled back: %+v", e.state())
	}
}

// R-C2-11: a deferred target that then fails its smoke is quarantined and
// no longer pending, so GC removes its dir (U6).
func TestQuarantinedPendingTargetIsCollected(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.busy = 1
	e.tick() // staged, switch deferred
	if st := e.state(); st.PendingSwitch != "1.20.0" {
		t.Fatalf("not pending: %+v", st)
	}
	e.smokeErr["1.20.0"] = errors.New("exit 3")
	e.now = e.now.Add(time.Hour)
	e.tick()
	st := e.state()
	if st.PendingSwitch != "" || st.Quarantine["1.20.0"].Reason != ReasonSmokeFailed {
		t.Fatalf("after smoke failure: pending=%q quarantine=%+v", st.PendingSwitch, st.Quarantine)
	}
	e.now = e.now.Add(time.Hour)
	e.tick()
	if _, err := os.Stat(e.L.VersionDir(mustV("1.20.0"))); !os.IsNotExist(err) {
		t.Fatalf("quarantined dir kept: %v", err)
	}
	assertHygiene(t, e)
}

// R-C2-12: while state.json can't be written, repeats of the same event
// carry one deterministic execution_id (the backend collapses them), and a
// release already staged in versions\<t> is not downloaded again.
func TestPersistentWriteFailureIsQuiet(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	failingSaves(t, false)
	for i := 0; i < 3; i++ {
		e.tick()
		e.now = e.now.Add(7 * time.Hour)
	}
	ids := map[string]bool{}
	for _, ev := range e.all {
		if ev.Event == EventSwitchFailed {
			ids[ev.ExecutionID] = true
		}
	}
	if len(ids) != 1 {
		t.Fatalf("update_switch_failed sent with %d distinct execution_ids, want 1", len(ids))
	}
	for remote, n := range e.api.githubHits {
		if n != 1 {
			t.Fatalf("%s downloaded %d times", remote, n)
		}
	}
}

// B4(b): a bootstrap updater-record write between ticks bumps generation;
// the next tick's landed-with-error write is still recognised as landed.
func TestBootstrapRecordThenLandedWrite(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	before := e.state().Generation
	must(t, updatestate.SaveUpdaterRecord(e.L.StateFile(), "boot", func(string, int) (string, int) { return "1.19.0", 2 }))
	if g := e.state().Generation; g != before+1 {
		t.Fatalf("bootstrap record: generation %d, want %d", g, before+1)
	}
	failingSaves(t, true)
	e.tick()
	got := e.events()
	if slices.Contains(got, EventSwitchFailed) || !slices.Contains(got, EventOK) {
		t.Fatalf("events = %v", got)
	}
	if st := e.state(); st.Current != "1.20.0" || st.Updater.ConsecutiveFailures != 2 {
		t.Fatalf("state = %+v", st)
	}
}

// FR1-1: a smoke TIMEOUT is retried; only the third consecutive timeout
// for the target quarantines it.
func TestSmokeTimeoutsQuarantineOnlyAfterThree(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.smokeErr["1.20.0"] = fmt.Errorf("%w after 60s", ErrSmokeTimeout)
	for i := 1; i <= 3; i++ {
		e.tick()
		_, q := e.state().Quarantine["1.20.0"]
		if q != (i == 3) {
			t.Fatalf("after %d timeouts: quarantined=%v", i, q)
		}
		e.now = e.now.Add(time.Hour)
	}
	if hf := e.lastSent(EventHealthFailed); hf.To != "1.20.0" {
		t.Fatalf("health_failed = %+v", hf)
	}
}

// The end-of-probation re-smoke follows the same rule.
func TestReSmokeTimeoutsRollBackOnlyAfterThree(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	e.smokeErr["1.20.0"] = fmt.Errorf("%w after 60s", ErrSmokeTimeout)
	e.now = e.now.Add(73 * time.Hour)
	for i := 1; i <= 3; i++ {
		e.tick()
		rolled := e.state().Current == "1.19.0"
		if rolled != (i == 3) {
			t.Fatalf("after %d re-smoke timeouts: rolled back=%v", i, rolled)
		}
		e.now = e.now.Add(time.Hour)
	}
	if rb := e.lastSent(EventRolledBack); rb.Error != ReasonSmokeFailed {
		t.Fatalf("rollback = %+v", rb)
	}
}

// FR1-6: runs are counted by sequence after the switch, not by time: two
// crashes finalized with timestamps before the probation start (the clock
// went back between the switch and the runs) still roll back.
func TestProbationCountsRunsBySequence(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	pv := mustV("1.20.0")
	must(t, updatestate.AppendRun(e.L.RunFile(pv), updatestate.RunRecord{RunID: "before-switch", Version: "1.20.0"}))
	st := e.state()
	since := updatestate.MaxRunSeq(e.L.RunFile(pv))
	st.Probation.SinceSeq = &since
	e.writeState(st)
	early := st.Probation.Since.Add(-time.Hour)
	for i := 0; i < 2 && e.state().Current == "1.20.0"; i++ {
		id := fmt.Sprintf("crash-%d", i)
		must(t, updatestate.AppendRun(e.L.RunFile(pv), updatestate.RunRecord{RunID: id, Version: "1.20.0"}))
		must(t, updatestate.FinalizeRun(e.L.RunFile(pv), id, 2, false, early))
		e.tick()
	}
	if rb := e.lastSentOrNil(EventRolledBack); rb == nil || rb.Error != ReasonBadRuns {
		t.Fatalf("runs before the probation's timestamp were dropped: %+v", e.state())
	}
}

// The switch records the runs file's current sequence.
func TestSwitchRecordsSinceSeq(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	pv := mustV("1.20.0")
	for _, id := range []string{"a", "b"} {
		must(t, updatestate.AppendRun(e.L.RunFile(pv), updatestate.RunRecord{RunID: id, Version: "1.20.0"}))
	}
	e.tick()
	if p := e.state().Probation; p == nil || p.SinceSeq == nil || *p.SinceSeq != 2 {
		t.Fatalf("probation = %+v, want since_seq 2", p)
	}
}

// A target that never ran (empty runs file) records since_seq 0, and the
// seq rule still applies to its runs.
func TestProbationSeqWithFreshTarget(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.tick() // switch to 1.20.0
	st := e.state()
	if st.Probation == nil || st.Probation.SinceSeq == nil || *st.Probation.SinceSeq != 0 {
		t.Fatalf("probation = %+v", st.Probation)
	}
	pv := mustV("1.20.0")
	early := st.Probation.Since.Add(-time.Hour)
	for i := 0; i < 2 && e.state().Current == "1.20.0"; i++ {
		id := fmt.Sprintf("crash-%d", i)
		must(t, updatestate.AppendRun(e.L.RunFile(pv), updatestate.RunRecord{RunID: id, Version: "1.20.0"}))
		must(t, updatestate.FinalizeRun(e.L.RunFile(pv), id, 2, false, early))
		e.now = e.now.Add(time.Hour)
		e.tick()
	}
	if e.state().Current != "1.19.0" {
		t.Fatalf("not rolled back: %+v", e.state())
	}
}

// D25/R-C2-15: an MSI pushed a newer seed but its adopt-seed CA timed out
// on the update lock; the next updater tick adopts it and reports it.
func TestUpdaterAdoptsNewerSeed(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	st := baseState("1.19.0", "")
	st.LastCheck = e.now // no target check this tick
	e.writeState(st)
	e.writeSeed("1.21.0")
	// The MSI's adopt-seed CA runs while an update tick holds the lock and
	// gives up after its bounded wait.
	held, err := updatestate.AcquireLock(e.L.LockFile())
	must(t, err)
	b := launcher.NewBootstrap(filepath.Join(e.L.InstallRoot, "stepsecurity-dev-machine-guard-bootstrap.exe"), func() bool { return true })
	b.Layout, b.Out, b.AdoptLockWait, b.LockPoll = e.L, io.Discard, 200*time.Millisecond, 20*time.Millisecond
	b.SetRunningVersion = nil
	if code := b.AdoptSeed([]string{"--seed-dir", e.L.SeedDir(mustV("1.21.0"))}); code != 0 {
		t.Fatalf("adopt-seed = %d", code)
	}
	held.Release()
	if got := e.state(); got.Current != "1.19.0" {
		t.Fatalf("adopt-seed adopted despite the held lock: %+v", got)
	}
	e.tick()
	got := e.state()
	if got.Current != "1.21.0" || got.Previous != "1.19.0" || got.Probation != nil {
		t.Fatalf("seed not adopted: %+v", got)
	}
	if err := updatestate.VerifyVersionDir(e.L.VersionDir(mustV("1.21.0")), mustV("1.21.0")); err != nil {
		t.Fatalf("versions\\1.21.0: %v", err)
	}
	ok := e.lastSent(EventOK)
	if ok.From != "1.19.0" || ok.To != "1.21.0" || ok.Error != "seed_adopted" {
		t.Fatalf("event = %+v", ok)
	}
}

func TestUpdaterIgnoresOlderSeed(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.20.0")
	e.self = "1.20.0"
	st := baseState("1.20.0", "")
	st.LastCheck = e.now
	e.writeState(st)
	e.tick() // seed is 1.19.0 (newEnv)
	if got := e.state(); got.Current != "1.20.0" {
		t.Fatalf("older seed adopted: %+v", got)
	}
	if ev := e.lastSentOrNil(EventOK); ev != nil {
		t.Fatalf("event sent: %+v", ev)
	}
}

// DMG-I5-1 at the updater: a missing signed_checksum reports
// update_verify_failed with no download.
func TestMissingSignedChecksumIsVerifyFailed(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.api.metaBody = `{"version":"1.20.0","checksum":"` + strings.Repeat("a", 64) + `","launcher_checksum":"` + strings.Repeat("b", 64) + `","signed_launcher_checksum":"x","linux_checksum":"` + strings.Repeat("c", 64) + `","signed_linux_checksum":"y"}`
	e.tick()
	wantEvents(t, e.events(), EventVerifyFailed)
	if len(e.api.githubHits) != 0 {
		t.Fatalf("downloaded: %v", e.api.githubHits)
	}
}

// FR1-7: a version whose scans hang after posting started (watchdog-killed)
// is rolled back after K=2 such runs.
func TestHangAfterStartedRollsBack(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	pv := mustV("1.20.0")
	for i := 0; i < 2 && e.state().Current == "1.20.0"; i++ {
		id := fmt.Sprintf("hang-%d", i)
		must(t, updatestate.AppendRun(e.L.RunFile(pv), updatestate.RunRecord{RunID: id, Version: "1.20.0"}))
		must(t, updatestate.MarkRunStarted(e.L.RunFile(pv), id))
		must(t, updatestate.FinalizeRun(e.L.RunFile(pv), id, 124, true, e.now))
		e.tick()
	}
	if rb := e.lastSentOrNil(EventRolledBack); rb == nil || rb.Error != ReasonBadRuns {
		t.Fatalf("hung version not rolled back: %+v", e.state())
	}
}

// DMG-I5-2: a stale adopt-seed snapshot (an MSI that never committed or
// rolled back) is swept by the updater; a fresh one is left for the MSI.
func TestUpdaterSweepsStaleAdoptSnapshot(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	st := baseState("1.19.0", "")
	st.LastCheck = e.now
	e.writeState(st)
	snap := e.L.AdoptSnapshotFile()
	must(t, updatestate.WriteAdoptSnapshot(snap, &updatestate.AdoptSnapshot{Seed: "1.19.0"}))
	e.tick()
	if _, err := os.Stat(snap); err != nil {
		t.Fatalf("fresh snapshot swept: %v", err)
	}
	old := time.Now().Add(-2 * time.Hour)
	must(t, os.Chtimes(snap, old, old))
	e.tick()
	if _, err := os.Stat(snap); !os.IsNotExist(err) {
		t.Fatalf("stale snapshot kept: %v", err)
	}
}

// FR1-8: no seed adoption while Windows Installer is mid-transaction; the
// next tick adopts.
func TestNoSeedAdoptionDuringMSI(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	st := baseState("1.19.0", "")
	st.LastCheck = e.now
	e.writeState(st)
	e.writeSeed("1.21.0")
	d := e.deps()
	d.InstallerBusy = func() bool { return true }
	Run(context.Background(), d)
	if e.state().Current != "1.19.0" {
		t.Fatal("adopted a seed while msiexec was running")
	}
	d.InstallerBusy = func() bool { return false }
	Run(context.Background(), d)
	if e.state().Current != "1.21.0" {
		t.Fatalf("seed not adopted after the MSI finished: %+v", e.state())
	}
}

// DMG-I5-5: an AV that keeps deleting a file from the confirmed current
// version gets at most 3 restages in 24 h, then one update_stage_failed
// (av_deleted) and a 24 h pause; the version is not quarantined.
func TestRestageBackoffAfterRepeatedDeletion(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.installVersion("1.20.0")
	e.self = "1.20.0"
	e.writeState(baseState("1.20.0", "1.19.0"))
	agent := filepath.Join(e.L.VersionDir(mustV("1.20.0")), updatestate.AgentFile)
	downloads := func() int { return e.api.githubHits["stepsecurity-dev-machine-guard-1.20.0-windows_amd64.exe"] }
	for i := 0; i < 6; i++ {
		_ = os.Remove(agent) // the AV strikes again (already gone while paused)
		e.tick()
		e.now = e.now.Add(time.Hour)
	}
	if n := downloads(); n != 3 {
		t.Fatalf("restaged %d times in 6 h, want 3", n)
	}
	var avEvents int
	for _, ev := range e.all {
		if ev.Event == EventStageFailed && ev.Error == "av_deleted" {
			avEvents++
		}
	}
	st := e.state()
	if avEvents != 1 || st.RestageBackoff["1.20.0"].IsZero() || st.Current != "1.20.0" {
		t.Fatalf("events=%d backoff=%v current=%s", avEvents, st.RestageBackoff, st.Current)
	}
	if _, q := st.Quarantine["1.20.0"]; q {
		t.Fatal("a healthy version was quarantined")
	}
	// After the backoff it is restaged again.
	e.now = e.now.Add(25 * time.Hour)
	e.tick()
	if n := downloads(); n != 4 {
		t.Fatalf("not restaged after the backoff (downloads %d)", n)
	}
	// Intact for 24 h: the counter resets.
	e.now = e.now.Add(25 * time.Hour)
	e.tick()
	if r, ok := e.state().Restages["1.20.0"]; ok && r.Count != 0 {
		t.Fatalf("restage counter not reset: %+v", r)
	}
}
