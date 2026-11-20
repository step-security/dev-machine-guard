//go:build !windows

package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
	"golang.org/x/sys/unix"
)

// The macOS/Linux self-update. Binary-scheduled installs (the loader
// registers launchd/systemd to run the binary directly and writes
// auto_update: true) have no loader tick to converge the binary, so the
// binary does it itself at the start of every scheduled run: ask
// latest-binary for the tenant's target, verify the SSHSIG over its checksum
// before downloading, download next to the running binary, verify the
// sha256, run the staged binary's self-check, then replace the binary with
// one rename. The running process keeps executing its own image; the new
// version takes effect on the next scheduled run (no re-exec). The replaced
// binary stays linked as <binary>.prev until the new version runs a tick.
// Everything is best-effort: a failure is logged and reported as an update
// event, never returned, so a scan is never blocked by an update problem.

// EnvDisable is the per-device kill switch of the macOS/Linux self-update.
const EnvDisable = "STEPSEC_DISABLE_SELF_UPDATE"

const (
	// minUnixSelfUpdateVersion is the macOS/Linux floor: the first release
	// whose binary updates itself. A binary-scheduled install that landed an
	// older version would never update again, so a target below it is
	// refused. Set at release cut.
	minUnixSelfUpdateVersion = "1.20.0"

	// UnixStateFile is the tick's record in the install directory.
	UnixStateFile = "self-update.json"
	// VersionMarkerFile is the loaders' version marker, refreshed after a
	// switch so uninstall and diagnostics name the installed version.
	VersionMarkerFile = ".current_version"

	unixStateSchema   = 1
	unixQuarantine    = 7 * 24 * time.Hour // a version that failed its smoke test is not staged again before this
	unixTickTimeout   = 8 * time.Minute    // check + download + smoke, each bounded on its own as well
	unixSendTimeout   = 45 * time.Second   // PostUpdateEvent's three attempts fit
	unixStagingPrefix = ".stepsecurity-dev-machine-guard.update-"
	unixPrevSuffix    = ".prev"
	unixMaxSent       = 64
)

// UnixFloor returns the macOS/Linux floor.
func UnixFloor() updatestate.Version {
	v, err := updatestate.ParseVersion(minUnixSelfUpdateVersion)
	if err != nil {
		panic(err)
	}
	return v
}

// UnixState is what one tick leaves for the next (<install dir>/self-update.json).
// Missing or corrupt, it is rebuilt from the running version: nothing in it
// is load-bearing for a scan.
type UnixState struct {
	SchemaVersion int `json:"schema_version"`
	// Current is the version the last switch installed (what the scheduler
	// runs next); Previous the one it replaced, kept as <binary>.prev until
	// Current confirms by running a tick.
	Current    string `json:"current"`
	Previous   string `json:"previous,omitempty"`
	SwitchedAt int64  `json:"switched_at,omitempty"`
	Confirmed  bool   `json:"confirmed"`
	// CurrentSHA256 is the sha256 of the binary file Current names: the
	// signed checksum at a switch, else the file's hash when the state was
	// started. It tells a process still running an older image (started, or
	// queued on the update lock, before another run switched the file) from
	// a binary restored by hand: the former must leave the pending switch
	// alone, the latter restarts the state from the running version.
	CurrentSHA256 string `json:"current_sha256,omitempty"`
	// LastCheckAt and LastCheckVersion space latest-binary calls: a tick
	// checks again after the check interval, or at once when the running
	// version changed since the last check.
	LastCheckAt      int64  `json:"last_check_at,omitempty"`
	LastCheckVersion string `json:"last_check_version,omitempty"`
	// Quarantine maps a version that failed its smoke test to the unix time
	// until which it is not staged again.
	Quarantine map[string]int64 `json:"quarantine,omitempty"`
	// Sent maps an event dedupe key to the unix time it was last posted.
	Sent map[string]int64 `json:"sent,omitempty"`
}

// UnixDeps are the side effects of one macOS/Linux tick, injected so the
// flow runs unchanged in tests.
type UnixDeps struct {
	Self    updatestate.Version // version of this process
	SelfExe string              // the running binary: the file a switch replaces
	GOOS    string              // darwin | linux: picks the release asset
	// StateDir holds self-update.json and .current_version; "" keeps no
	// state (every tick checks, events are not deduplicated).
	StateDir string
	Client   *Client
	// Smoke runs `<exe> self-check` and checks it reports version want.
	Smoke func(ctx context.Context, exe string, want updatestate.Version) error
	// Send posts one update event (install_channel loader).
	Send func(ctx context.Context, ev updatestate.OutboxEvent) error
	// FreeBytes reports free space on the volume holding path; nil skips
	// the space check.
	FreeBytes func(path string) (uint64, error)
	Now       func() time.Time
	Log       *progress.Logger
}

type unixTick struct {
	d    *UnixDeps
	st   *UnixState
	now  time.Time
	path string // state file; "" when stateless
	log  *progress.Logger
}

// RunUnix performs one macOS/Linux self-update tick: confirm the last
// switch, ask latest-binary for the tenant's target, verify, stage, smoke
// test and switch. It reports whether a new version was installed; that
// version takes effect on the next scheduled run.
func RunUnix(ctx context.Context, d *UnixDeps) (updated bool) {
	ctx, cancel := context.WithTimeout(ctx, unixTickTimeout)
	defer cancel()
	t := &unixTick{d: d, now: d.Now(), log: d.Log}
	if t.log == nil {
		t.log = progress.NewNoop()
	}
	if d.StateDir != "" {
		t.path = filepath.Join(d.StateDir, UnixStateFile)
	}
	t.st = loadUnixState(t.path)
	self := d.Self.String()
	if !t.confirm(ctx, self) {
		return false
	}
	if !t.checkDue(self) {
		return false
	}
	return t.update(ctx, self)
}

// loadUnixState reads the state file; a missing, unreadable, corrupt or
// foreign-schema file yields a fresh state.
func loadUnixState(path string) *UnixState {
	fresh := &UnixState{SchemaVersion: unixStateSchema}
	if path == "" {
		return fresh
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed name inside the install directory
	if err != nil {
		return fresh
	}
	var st UnixState
	if err := json.Unmarshal(data, &st); err != nil || st.SchemaVersion != unixStateSchema {
		return fresh
	}
	return &st
}

// save writes the state atomically (temp file + rename). Best-effort: a
// state that cannot be written only costs an earlier re-check next tick.
func (t *unixTick) save() {
	if t.path == "" {
		return
	}
	t.prune()
	data, err := json.MarshalIndent(t.st, "", "  ")
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(t.path), ".self-update-*.tmp")
	if err != nil {
		t.log.Debug("self-update: state not written: %v", err)
		return
	}
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		t.log.Debug("self-update: state not written: %v", errors.Join(werr, serr, cerr))
		return
	}
	if err := os.Rename(tmp.Name(), t.path); err != nil {
		_ = os.Remove(tmp.Name())
		t.log.Debug("self-update: state not written: %v", err)
	}
}

// prune drops expired quarantines and stale dedupe entries so the state
// file stays small.
func (t *unixTick) prune() {
	for v, until := range t.st.Quarantine {
		if !t.now.Before(time.Unix(until, 0)) {
			delete(t.st.Quarantine, v)
		}
	}
	window := duration(knobDedupeWindow)
	for k, at := range t.st.Sent {
		if t.now.Sub(time.Unix(at, 0)) >= window || len(t.st.Sent) > unixMaxSent {
			delete(t.st.Sent, k)
		}
	}
}

// confirm closes the previous switch once the version it installed runs a
// tick: the kept copy of the replaced binary goes and update_confirmed is
// posted. A tick by any other version than the one installed last is one of
// two things. While the file on disk is still the installed version, this
// process runs an older image (it started, or waited on the update lock,
// before another run switched the file): it reports false so the tick ends
// here and the pending switch, its backup and its confirmation stay for the
// installed version's first run. Otherwise the file was restored by hand, or
// the state belongs to another binary, and the state restarts from the
// running version.
func (t *unixTick) confirm(ctx context.Context, self string) bool {
	st := t.st
	switch {
	case st.Current == "":
		st.Current = self
		st.CurrentSHA256 = t.hashSelf()
	case st.Current == self && !st.Confirmed && st.Previous != "":
		st.Confirmed = true
		t.removePrev()
		t.send(ctx, EventConfirmed, st.Previous, self, "first_run", "")
		t.save()
	case st.Current != self:
		if onDisk := t.hashSelf(); onDisk != "" && onDisk == st.CurrentSHA256 {
			t.log.Debug("self-update: running %s while %s is installed; this tick is left to the installed version", self, st.Current)
			return false
		}
		t.log.Debug("self-update: running %s while the state names %s; continuing from the running version", self, st.Current)
		st.Current, st.Previous, st.SwitchedAt, st.Confirmed = self, "", 0, true
		st.CurrentSHA256 = t.hashSelf()
		t.removePrev()
		t.save()
		t.writeVersionMarker(self)
	}
	return true
}

// hashSelf is the sha256 of the binary file as it is on disk now (the file
// the scheduler runs next, which is not always this process's image); ""
// when it cannot be read.
func (t *unixTick) hashSelf() string {
	sum, err := updatestate.FileSHA256(t.d.SelfExe)
	if err != nil {
		t.log.Debug("self-update: cannot hash %s: %v", t.d.SelfExe, err)
		return ""
	}
	return sum
}

func (t *unixTick) removePrev() {
	if err := os.Remove(t.d.SelfExe + unixPrevSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.log.Debug("self-update: %s not removed: %v", t.d.SelfExe+unixPrevSuffix, err)
	}
}

// checkDue spaces latest-binary calls by the check interval. A changed
// running version (after a switch, or a loader re-push) checks at once.
func (t *unixTick) checkDue(self string) bool {
	st := t.st
	if st.LastCheckAt == 0 || st.LastCheckVersion != self {
		return true
	}
	last := time.Unix(st.LastCheckAt, 0)
	if t.now.Before(last) { // clock went back: check again rather than wait it out
		return true
	}
	if since := t.now.Sub(last); since < duration(knobCheckInterval) {
		t.log.Debug("self-update: checked %s ago; next check after %s", since.Round(time.Second), duration(knobCheckInterval))
		return false
	}
	return true
}

// update is the check, stage, smoke and switch of one tick.
func (t *unixTick) update(ctx context.Context, self string) bool {
	d, st := t.d, t.st
	dir := filepath.Dir(d.SelfExe)
	// A binary this process cannot replace (a system-wide install owned by
	// another account) is not updated from here; say so without a round trip.
	if err := unix.Access(dir, unix.W_OK); err != nil {
		t.log.Debug("self-update: %s is not writable (%v); the install owner updates this binary", dir, err)
		return false
	}
	reason := CheckInterval
	if st.LastCheckAt == 0 {
		reason = CheckFirst
	}
	rel, err := d.Client.LatestForOS(ctx, d.GOOS, CheckInfo{Current: self, Reason: reason})
	st.LastCheckAt, st.LastCheckVersion = t.now.Unix(), self
	if err != nil {
		t.log.Warn("self-update: check failed (%v); continuing on %s", err, self)
		t.send(ctx, EventCheckFailed, self, "", err.Error(), EventCheckFailed)
		t.save()
		return false
	}
	target := rel.Version.String()
	if updatestate.Compare(rel.Version, UnixFloor()) < 0 {
		msg := fmt.Sprintf("target %s is below the self-update floor %s", target, UnixFloor())
		t.log.Warn("self-update: %s; staying on %s", msg, self)
		t.send(ctx, EventRefusedFloor, self, target, msg, EventRefusedFloor+":"+target)
		t.save()
		return false
	}
	if until, ok := st.Quarantine[target]; ok && t.now.Before(time.Unix(until, 0)) {
		t.log.Debug("self-update: %s failed its smoke test recently; not staged again before %s", target, time.Unix(until, 0).UTC().Format(time.RFC3339))
		t.save()
		return false
	}
	if err := d.Client.VerifySignatures(rel); err != nil {
		t.log.Warn("self-update: %v; staying on %s", err, self)
		t.send(ctx, EventVerifyFailed, self, target, err.Error(), EventVerifyFailed+":"+target)
		t.save()
		return false
	}
	asset := rel.Assets[0]
	own, err := updatestate.FileSHA256(d.SelfExe)
	if err != nil {
		t.log.Warn("self-update: cannot hash the running binary: %v", err)
		t.send(ctx, EventStageFailed, self, target, err.Error(), EventStageFailed+":hash")
		t.save()
		return false
	}
	if own == asset.Checksum {
		t.log.Debug("self-update: %s is current", self)
		t.save()
		return false
	}
	if err := t.room(dir); err != nil {
		t.log.Warn("self-update: %v; staying on %s", err, self)
		t.send(ctx, EventStageFailed, self, target, err.Error(), EventStageFailed+":space")
		t.save()
		return false
	}

	t.log.Progress("Self-update: %s is available (running %s); downloading...", target, self)
	// Staged next to the binary: same file system, so the final rename is
	// atomic and a crash leaves either the old or the new binary, never a
	// partial one.
	staging, err := os.MkdirTemp(dir, unixStagingPrefix)
	if err != nil {
		t.log.Warn("self-update: staging directory: %v", err)
		t.send(ctx, EventStageFailed, self, target, err.Error(), EventStageFailed+":staging")
		t.save()
		return false
	}
	defer os.RemoveAll(staging)
	if err := d.Client.Download(ctx, rel.Version, asset, staging); err != nil {
		ev := EventStageFailed
		switch {
		case errors.Is(err, ErrDownload):
			ev = EventDownloadFailed
		case errors.Is(err, ErrVerify):
			ev = EventVerifyFailed
		}
		t.log.Warn("self-update: %v; staying on %s", err, self)
		t.send(ctx, ev, self, target, err.Error(), ev+":"+target)
		t.save()
		return false
	}
	staged := filepath.Join(staging, asset.File)
	// #nosec G302 -- this is the agent executable being installed; the loaders set the same mode.
	if err := os.Chmod(staged, 0o755); err != nil {
		t.log.Warn("self-update: chmod: %v", err)
		t.send(ctx, EventStageFailed, self, target, err.Error(), EventStageFailed+":chmod")
		t.save()
		return false
	}
	// The smoke runs on its own budget (its timeout), not the tick's. A
	// timeout is retried at the next check; any other failure quarantines
	// the version so it is not downloaded again every check.
	if err := d.Smoke(context.WithoutCancel(ctx), staged, rel.Version); err != nil {
		if errors.Is(err, ErrSmokeTimeout) {
			t.log.Warn("self-update: smoke test of %s %v; retried at the next check", target, err)
		} else {
			t.log.Warn("self-update: %s failed its smoke test (%v); not staged again for %s", target, err, unixQuarantine)
			if st.Quarantine == nil {
				st.Quarantine = map[string]int64{}
			}
			st.Quarantine[target] = t.now.Add(unixQuarantine).Unix()
		}
		t.send(ctx, EventHealthFailed, self, target, ReasonSmokeFailed+": "+err.Error(), EventHealthFailed+":"+target)
		t.save()
		return false
	}
	if err := switchBinary(staged, d.SelfExe); err != nil {
		t.log.Warn("self-update: install of %s failed: %v", target, err)
		t.send(ctx, EventSwitchFailed, self, target, err.Error(), EventSwitchFailed+":"+target)
		t.save()
		return false
	}
	st.Previous, st.Current, st.SwitchedAt, st.Confirmed = self, target, t.now.Unix(), false
	st.CurrentSHA256 = asset.Checksum
	delete(st.Quarantine, target)
	t.save()
	t.writeVersionMarker(target)
	t.send(ctx, EventOK, self, target, "", "")
	t.log.Progress("Self-update: installed %s (replacing %s); it takes effect on the next scheduled run", target, self)
	return true
}

// room checks the binary's volume has space for the download plus margin.
func (t *unixTick) room(dir string) error {
	if t.d.FreeBytes == nil {
		return nil
	}
	free, err := t.d.FreeBytes(dir)
	if err != nil {
		return nil // unknown: try, and let the write fail if it must
	}
	if need := uint64(maxAssetBytes + freeSpaceMargin); free < need {
		return fmt.Errorf("%d MiB free in %s, %d MiB needed", free>>20, dir, need>>20)
	}
	return nil
}

// switchBinary installs staged over exe. The old file stays reachable as
// <exe>.prev (a hard link, or a copy on a file system without links) until
// the new version confirms; then one rename replaces the name. The running
// process keeps its own image.
func switchBinary(staged, exe string) error {
	prev := exe + unixPrevSuffix
	_ = os.Remove(prev)
	if err := os.Link(exe, prev); err != nil {
		if err := copyFile(exe, prev); err != nil {
			return fmt.Errorf("keeping the running binary: %w", err)
		}
	}
	if err := os.Rename(staged, exe); err != nil {
		_ = os.Remove(prev)
		return err
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- the running binary
	if err != nil {
		return err
	}
	defer in.Close()
	// #nosec G302 G304 -- an executable copy next to the running binary.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

// writeVersionMarker refreshes the loaders' .current_version. Diagnostic
// only (uninstall and scheduler_info read it), never load-bearing.
func (t *unixTick) writeVersionMarker(version string) {
	if t.d.StateDir == "" {
		return
	}
	// #nosec G306 -- the loaders write the marker world-readable as well.
	if err := os.WriteFile(filepath.Join(t.d.StateDir, VersionMarkerFile), []byte(version+"\n"), 0o644); err != nil {
		t.log.Debug("self-update: version marker not written: %v", err)
	}
}

// send posts one update event, at most once per dedupe window for a
// non-empty key. Failures are logged; nothing is retried across ticks.
func (t *unixTick) send(ctx context.Context, event, from, to, msg, key string) {
	if key != "" {
		if at, ok := t.st.Sent[key]; ok {
			last := time.Unix(at, 0)
			if !t.now.Before(last) && t.now.Sub(last) < duration(knobDedupeWindow) {
				return
			}
		}
	}
	if t.d.Send == nil {
		return
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unixSendTimeout)
	defer cancel()
	ev := updatestate.OutboxEvent{ExecutionID: uuid.NewString(), Event: event, From: from, To: to, Error: msg, At: t.now.UTC()}
	if err := t.d.Send(sctx, ev); err != nil {
		t.log.Debug("self-update: event %s not posted: %v", event, err)
		return
	}
	if key != "" {
		if t.st.Sent == nil {
			t.st.Sent = map[string]int64{}
		}
		t.st.Sent[key] = t.now.Unix()
	}
}
