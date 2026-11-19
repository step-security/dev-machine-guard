//go:build !windows

package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// unixEnv is one simulated binary-scheduled install (bin/<agent> under an
// install directory that also holds the state) plus a fake backend.
type unixEnv struct {
	t     *testing.T
	api   *fakeAPI
	root  string
	exe   string
	self  string
	goos  string
	now   time.Time
	smoke func(ctx context.Context, exe string, want updatestate.Version) error

	mu     sync.Mutex
	smoked []string
	sent   []updatestate.OutboxEvent
	all    []updatestate.OutboxEvent
}

// unixBinary is a stand-in agent: a shell script whose self-check reports v.
func unixBinary(v string) []byte {
	return []byte("#!/bin/sh\nprintf '{\"version\":\"" + v + "\",\"device_id\":\"dev-1\",\"config_ok\":true}\\n'\n")
}

func newUnixEnv(t *testing.T, self string) *unixEnv {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	e := &unixEnv{
		t: t, api: newFakeAPI(t), root: root, exe: filepath.Join(bin, agentAssetBase),
		self: self, goos: "linux", now: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC),
	}
	e.writeExe(unixBinary(self))
	e.smoke = func(_ context.Context, exe string, want updatestate.Version) error {
		if _, err := os.Stat(exe); err != nil {
			return err
		}
		e.mu.Lock()
		e.smoked = append(e.smoked, want.String())
		e.mu.Unlock()
		return nil
	}
	return e
}

func (e *unixEnv) writeExe(body []byte) {
	e.t.Helper()
	if err := os.WriteFile(e.exe, body, 0o755); err != nil { // #nosec G306 -- test executable
		e.t.Fatal(err)
	}
}

// release publishes version v of the agent for this env's platform.
func (e *unixEnv) release(v string) {
	e.api.addUnixRelease(v, e.goos, testArch, unixBinary(v))
	e.api.setTarget(v)
}

func (e *unixEnv) deps() *UnixDeps {
	return &UnixDeps{
		Self: mustV(e.self), SelfExe: e.exe, GOOS: e.goos, StateDir: e.root,
		Client: e.api.client(testArch),
		Smoke:  func(ctx context.Context, exe string, want updatestate.Version) error { return e.smoke(ctx, exe, want) },
		Send: func(_ context.Context, ev updatestate.OutboxEvent) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.sent = append(e.sent, ev)
			e.all = append(e.all, ev)
			return nil
		},
		Now: func() time.Time { return e.now },
	}
}

func (e *unixEnv) tick() bool { e.t.Helper(); return RunUnix(context.Background(), e.deps()) }

// events returns and clears the sent event names.
func (e *unixEnv) events() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, ev := range e.sent {
		out = append(out, ev.Event)
	}
	e.sent = nil
	return out
}

func (e *unixEnv) lastSent(event string) updatestate.OutboxEvent {
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

func (e *unixEnv) state() *UnixState { return loadUnixState(filepath.Join(e.root, UnixStateFile)) }

func (e *unixEnv) exeIs(v string) {
	e.t.Helper()
	got, err := os.ReadFile(e.exe)
	if err != nil {
		e.t.Fatal(err)
	}
	if string(got) != string(unixBinary(v)) {
		e.t.Fatalf("installed binary reports %q, want %s", firstVersion(got), v)
	}
	fi, _ := os.Stat(e.exe)
	if fi.Mode().Perm() != 0o755 {
		e.t.Errorf("installed binary mode = %o, want 755", fi.Mode().Perm())
	}
}

func firstVersion(b []byte) string {
	_, rest, ok := strings.Cut(string(b), `"version":"`)
	if !ok {
		return "?"
	}
	v, _, _ := strings.Cut(rest, `"`)
	return v
}

func (e *unixEnv) latestCalls() int {
	e.api.mu.Lock()
	defer e.api.mu.Unlock()
	return len(e.api.latestRequests)
}

func (e *unixEnv) downloads() int {
	e.api.mu.Lock()
	defer e.api.mu.Unlock()
	n := 0
	for _, c := range e.api.githubHits {
		n += c
	}
	return n
}

// assertClean checks no staging directory survived the tick.
func (e *unixEnv) assertClean() {
	e.t.Helper()
	entries, _ := os.ReadDir(filepath.Dir(e.exe))
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), unixStagingPrefix) {
			e.t.Errorf("staging directory left behind: %s", en.Name())
		}
	}
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestUnixFreshInstallUpdatesThenConfirms(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")

	if !e.tick() {
		t.Fatal("tick reported no update")
	}
	e.exeIs("1.20.1")
	e.assertClean()
	if prev, _ := os.ReadFile(e.exe + unixPrevSuffix); string(prev) != string(unixBinary("1.20.0")) {
		t.Fatalf("%s.prev does not hold the replaced binary", e.exe)
	}
	if got := e.smoked; len(got) != 1 || got[0] != "1.20.1" {
		t.Fatalf("smoked %v, want [1.20.1]", got)
	}
	wantEvents(t, e.events(), EventOK)
	if ev := e.lastSent(EventOK); ev.From != "1.20.0" || ev.To != "1.20.1" {
		t.Fatalf("update_ok %s -> %s", ev.From, ev.To)
	}
	st := e.state()
	if st.Current != "1.20.1" || st.Previous != "1.20.0" || st.Confirmed || st.SwitchedAt != e.now.Unix() {
		t.Fatalf("state after switch = %+v", st)
	}
	if sum, _ := updatestate.FileSHA256(e.exe); st.CurrentSHA256 != sum || sum == "" {
		t.Fatalf("state current_sha256 = %q, installed file = %q", st.CurrentSHA256, sum)
	}
	if marker, _ := os.ReadFile(filepath.Join(e.root, VersionMarkerFile)); string(marker) != "1.20.1\n" {
		t.Fatalf(".current_version = %q", marker)
	}
	if q := e.api.latestRequests[0]; !strings.Contains(q, "reason=first_check") || !strings.Contains(q, "current=1.20.0") || !strings.Contains(q, "os=linux") {
		t.Fatalf("first check query = %s", q)
	}

	// The next scheduled run is the new binary: it confirms the switch,
	// drops the kept copy and finds itself current without a download.
	e.self = "1.20.1"
	downloads := e.downloads()
	if e.tick() {
		t.Fatal("second tick reported an update")
	}
	wantEvents(t, e.events(), EventConfirmed)
	if ev := e.lastSent(EventConfirmed); ev.From != "1.20.0" || ev.To != "1.20.1" || ev.Error != "first_run" {
		t.Fatalf("update_confirmed = %+v", ev)
	}
	if exists(e.exe + unixPrevSuffix) {
		t.Fatal(".prev kept after the confirmation")
	}
	if st := e.state(); !st.Confirmed || st.Current != "1.20.1" || st.Previous != "1.20.0" {
		t.Fatalf("state after confirmation = %+v", st)
	}
	if e.downloads() != downloads {
		t.Fatal("a current binary was downloaded again")
	}
	if e.latestCalls() != 2 {
		t.Fatalf("latest-binary calls = %d, want 2 (a changed running version checks at once)", e.latestCalls())
	}
}

func TestUnixDarwinUsesTheUniversalAsset(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.goos = "darwin"
	e.release("1.20.1")
	if !e.tick() {
		t.Fatal("tick reported no update")
	}
	e.exeIs("1.20.1")
	e.api.mu.Lock()
	defer e.api.mu.Unlock()
	if e.api.githubHits["stepsecurity-dev-machine-guard-1.20.1-darwin"] != 1 {
		t.Fatalf("downloads = %v, want the darwin asset once", e.api.githubHits)
	}
}

func TestUnixChecksAreSpacedByTheInterval(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.0")
	e.tick()
	if e.latestCalls() != 1 {
		t.Fatalf("latest-binary calls = %d", e.latestCalls())
	}
	e.now = e.now.Add(duration(knobCheckInterval) - time.Minute)
	e.tick()
	if e.latestCalls() != 1 {
		t.Fatal("checked again inside the interval")
	}
	e.now = e.now.Add(2 * time.Minute)
	e.tick()
	if e.latestCalls() != 2 {
		t.Fatal("no check after the interval")
	}
	// A clock that went back is not waited out.
	e.now = e.now.Add(-48 * time.Hour)
	e.tick()
	if e.latestCalls() != 3 {
		t.Fatal("no check after the clock went back")
	}
	if e.downloads() != 0 {
		t.Fatal("a current binary was downloaded")
	}
	wantEvents(t, e.events())
}

func TestUnixRefusesATargetBelowTheFloor(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.19.9")
	if e.tick() {
		t.Fatal("updated below the floor")
	}
	e.exeIs("1.20.0")
	wantEvents(t, e.events(), EventRefusedFloor)
	if ev := e.lastSent(EventRefusedFloor); ev.To != "1.19.9" || !strings.Contains(ev.Error, UnixFloor().String()) {
		t.Fatalf("update_refused_floor = %+v", ev)
	}
	if e.downloads() != 0 {
		t.Fatal("a refused target was downloaded")
	}
	// Repeated every check, reported once per dedupe window.
	e.now = e.now.Add(duration(knobCheckInterval) + time.Minute)
	e.tick()
	wantEvents(t, e.events())
	e.now = e.now.Add(duration(knobDedupeWindow))
	e.tick()
	wantEvents(t, e.events(), EventRefusedFloor)
}

func TestUnixBadSignatureNeverDownloads(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	e.api.badSig["stepsecurity-dev-machine-guard-1.20.1-linux_"+testArch] = true
	if e.tick() {
		t.Fatal("updated on a bad signature")
	}
	e.exeIs("1.20.0")
	wantEvents(t, e.events(), EventVerifyFailed)
	if e.downloads() != 0 {
		t.Fatal("downloaded before the signature check")
	}
	if len(e.smoked) != 0 {
		t.Fatal("smoke ran")
	}
}

func TestUnixDownloadFailureKeepsTheBinary(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	e.api.githubDown = true
	if e.tick() {
		t.Fatal("updated without a download")
	}
	e.exeIs("1.20.0")
	e.assertClean()
	wantEvents(t, e.events(), EventDownloadFailed)
	if exists(e.exe + unixPrevSuffix) {
		t.Fatal(".prev created without a switch")
	}
	if st := e.state(); st.Current != "1.20.0" || st.Previous != "" {
		t.Fatalf("state = %+v", st)
	}
}

func TestUnixCorruptedAssetIsRejected(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	e.api.checksumOver["stepsecurity-dev-machine-guard-1.20.1-linux_"+testArch] = strings.Repeat("ab", 32)
	if e.tick() {
		t.Fatal("installed an asset whose sha256 differs from the signed checksum")
	}
	e.exeIs("1.20.0")
	e.assertClean()
	wantEvents(t, e.events(), EventVerifyFailed)
}

func TestUnixSmokeFailureQuarantinesWithoutSwitch(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	e.smoke = func(context.Context, string, updatestate.Version) error { return errors.New("self-check exit 1") }
	if e.tick() {
		t.Fatal("switched to a version that failed its smoke test")
	}
	e.exeIs("1.20.0")
	e.assertClean()
	wantEvents(t, e.events(), EventHealthFailed)
	if ev := e.lastSent(EventHealthFailed); ev.To != "1.20.1" || !strings.HasPrefix(ev.Error, ReasonSmokeFailed) {
		t.Fatalf("update_health_failed = %+v", ev)
	}
	st := e.state()
	if until := st.Quarantine["1.20.1"]; until != e.now.Add(unixQuarantine).Unix() {
		t.Fatalf("quarantine = %+v", st.Quarantine)
	}
	// Inside the quarantine the target is checked but not staged again.
	downloads := e.downloads()
	e.now = e.now.Add(duration(knobCheckInterval) + time.Minute)
	e.tick()
	if e.downloads() != downloads {
		t.Fatal("quarantined version downloaded again")
	}
	wantEvents(t, e.events())
	// After it, the version gets another chance.
	calls := 0
	e.smoke = func(context.Context, string, updatestate.Version) error { calls++; return nil }
	e.now = e.now.Add(unixQuarantine)
	if !e.tick() {
		t.Fatal("no retry after the quarantine")
	}
	if calls != 1 {
		t.Fatalf("smoke calls after quarantine = %d", calls)
	}
	e.exeIs("1.20.1")
}

func TestUnixSmokeTimeoutIsRetriedWithoutQuarantine(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	e.smoke = func(context.Context, string, updatestate.Version) error {
		return fmt.Errorf("%w after 1s", ErrSmokeTimeout)
	}
	e.tick()
	e.exeIs("1.20.0")
	wantEvents(t, e.events(), EventHealthFailed)
	if st := e.state(); len(st.Quarantine) != 0 {
		t.Fatalf("a timeout quarantined %v", st.Quarantine)
	}
}

func TestUnixRealSmokeRunsTheStagedBinary(t *testing.T) {
	knobOverrides = map[knob]time.Duration{knobSmokeTimeout: 10 * time.Second}
	t.Cleanup(func() { knobOverrides = map[knob]time.Duration{} })
	e := newUnixEnv(t, "1.20.0")
	e.smoke = RunSmoke
	// A release whose self-check reports another version fails the smoke.
	e.api.addUnixRelease("1.20.1", e.goos, testArch, unixBinary("1.20.2"))
	e.api.setTarget("1.20.1")
	if e.tick() {
		t.Fatal("installed a binary whose self-check reports the wrong version")
	}
	wantEvents(t, e.events(), EventHealthFailed)
	e.exeIs("1.20.0")

	e.api.addUnixRelease("1.20.3", e.goos, testArch, unixBinary("1.20.3"))
	e.api.setTarget("1.20.3")
	e.now = e.now.Add(duration(knobCheckInterval) + time.Minute)
	if !e.tick() {
		t.Fatal("a release whose self-check passes was not installed")
	}
	e.exeIs("1.20.3")
	wantEvents(t, e.events(), EventOK)
}

func TestUnixCheckFailureIsReportedOncePerWindow(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.api.metaStatus = 503
	e.tick()
	wantEvents(t, e.events(), EventCheckFailed)
	e.now = e.now.Add(duration(knobCheckInterval) + time.Minute)
	e.tick()
	wantEvents(t, e.events())
	if e.latestCalls() != 2 {
		t.Fatalf("latest-binary calls = %d", e.latestCalls())
	}
	e.exeIs("1.20.0")
}

func TestUnixCorruptStateStartsFresh(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	if err := os.WriteFile(filepath.Join(e.root, UnixStateFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !e.tick() {
		t.Fatal("no update from a corrupt state")
	}
	if st := e.state(); st.SchemaVersion != unixStateSchema || st.Current != "1.20.1" {
		t.Fatalf("state after the tick = %+v", st)
	}
}

func TestUnixStatelessTickUpdates(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	d := e.deps()
	d.StateDir = ""
	if !RunUnix(context.Background(), d) {
		t.Fatal("no update without a state directory")
	}
	e.exeIs("1.20.1")
	if exists(filepath.Join(e.root, UnixStateFile)) || exists(filepath.Join(e.root, VersionMarkerFile)) {
		t.Fatal("state written without a state directory")
	}
}

func TestUnixRestoredBinaryRestartsFromTheRunningVersion(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	e.tick()
	// Someone moved .prev back by hand: 1.20.0 runs while the state names 1.20.1.
	if err := os.Rename(e.exe+unixPrevSuffix, e.exe); err != nil {
		t.Fatal(err)
	}
	e.events()
	e.api.setTarget("1.20.0")
	e.now = e.now.Add(time.Minute)
	e.tick()
	wantEvents(t, e.events())
	if st := e.state(); st.Current != "1.20.0" || st.Previous != "" || !st.Confirmed {
		t.Fatalf("state = %+v", st)
	}
}

// A run that started on the old version (or waited on the update lock) while
// another run switched the file must not treat the newer file as a restore:
// the pending switch, its .prev and its confirmation belong to the installed
// version's first run.
func TestUnixStaleProcessLeavesThePendingSwitch(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	if !e.tick() {
		t.Fatal("tick reported no update")
	}
	e.events()
	checks := e.latestCalls()
	before := e.state()

	// Still 1.20.0 in memory, 1.20.1 on disk.
	e.now = e.now.Add(time.Minute)
	if e.tick() {
		t.Fatal("a stale process reported an update")
	}
	wantEvents(t, e.events())
	if e.latestCalls() != checks {
		t.Fatal("a stale process checked for a target")
	}
	if !exists(e.exe + unixPrevSuffix) {
		t.Fatal(".prev removed by a stale process")
	}
	if st := e.state(); st.Current != before.Current || st.Previous != before.Previous || st.Confirmed != before.Confirmed ||
		st.SwitchedAt != before.SwitchedAt || st.CurrentSHA256 != before.CurrentSHA256 || st.LastCheckAt != before.LastCheckAt {
		t.Fatalf("state touched by a stale process: %+v", st)
	}
	e.exeIs("1.20.1")

	// The installed version's first run still confirms the switch.
	e.self = "1.20.1"
	e.now = e.now.Add(time.Minute)
	e.tick()
	wantEvents(t, e.events(), EventConfirmed)
	if exists(e.exe + unixPrevSuffix) {
		t.Fatal(".prev kept after the confirmation")
	}
	if st := e.state(); !st.Confirmed || st.Current != "1.20.1" || st.Previous != "1.20.0" {
		t.Fatalf("state after confirmation = %+v", st)
	}
}

func TestUnixUnwritableInstallSkipsTheCheck(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	bin := filepath.Dir(e.exe)
	if err := os.Chmod(bin, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bin, 0o755) })
	if e.tick() {
		t.Fatal("updated an unwritable install")
	}
	if e.latestCalls() != 0 {
		t.Fatal("checked a target it could not install")
	}
	wantEvents(t, e.events())
}

func TestUnixNoRoomStopsBeforeTheDownload(t *testing.T) {
	e := newUnixEnv(t, "1.20.0")
	e.release("1.20.1")
	d := e.deps()
	d.FreeBytes = func(string) (uint64, error) { return 1 << 20, nil }
	if RunUnix(context.Background(), d) {
		t.Fatal("updated with no room")
	}
	wantEvents(t, e.events(), EventStageFailed)
	if e.downloads() != 0 {
		t.Fatal("downloaded with no room")
	}
}

func TestLatestForOSAssets(t *testing.T) {
	api := newFakeAPI(t)
	api.addUnixRelease("1.20.1", "darwin", testArch, []byte("mac"))
	api.addUnixRelease("1.20.1", "linux", "arm64", []byte("linux"))
	api.setTarget("1.20.1")
	tests := []struct{ goos, arch, remote string }{
		{"darwin", testArch, "stepsecurity-dev-machine-guard-1.20.1-darwin"},
		{"linux", "arm64", "stepsecurity-dev-machine-guard-1.20.1-linux_arm64"},
	}
	for _, tc := range tests {
		t.Run(tc.goos, func(t *testing.T) {
			rel, err := api.client(tc.arch).LatestForOS(context.Background(), tc.goos, CheckInfo{})
			if err != nil {
				t.Fatal(err)
			}
			if len(rel.Assets) != 1 || rel.Assets[0].Remote != tc.remote || rel.Assets[0].File != agentAssetBase || rel.Assets[0].Checksum == "" {
				t.Fatalf("assets = %+v", rel.Assets)
			}
			if err := api.client(tc.arch).VerifySignatures(rel); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := api.client(testArch).LatestForOS(context.Background(), "windows", CheckInfo{}); !errors.Is(err, ErrCheck) {
		t.Fatalf("windows: err = %v, want ErrCheck", err)
	}
	api.metaBody = `{"version":"latest"}`
	if _, err := api.client(testArch).LatestForOS(context.Background(), "linux", CheckInfo{}); !errors.Is(err, ErrCheck) {
		t.Fatalf("non-semver target: err = %v, want ErrCheck", err)
	}
}

func TestUnixFloorIsAStrictRelease(t *testing.T) {
	if UnixFloor().String() != minUnixSelfUpdateVersion {
		t.Fatalf("floor = %s", UnixFloor())
	}
}
