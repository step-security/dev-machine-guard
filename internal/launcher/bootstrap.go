package launcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/step-security/dev-machine-guard/internal/authenticode"
	"github.com/step-security/dev-machine-guard/internal/winproc"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/step-security/dev-machine-guard/internal/faultinject"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// Bootstrap mode (spec §2, D2). The MSI installs this launcher a second time
// as BootstrapBinary in the install root; under that name it resolves the
// state.json pointer and launches the versioned binaries. It must stay tiny
// and frozen-safe: no network and no crypto, never crash, and read
// state.json only through the frozen pointer contract.
const (
	BootstrapBinary = "stepsecurity-dev-machine-guard-bootstrap.exe"

	// ExitCannotStart is returned when no child could be started (D5). It is
	// outside {0, 1}, so a run record carrying it classifies as bad.
	ExitCannotStart = 70
	// ExitKilled is the exit status given to a child tree the bootstrap
	// terminated at its deadline.
	ExitKilled = 124
	// exitUsage is returned for a malformed bootstrap command line.
	exitUsage = 64

	EnvRunRecord         = "STEPSEC_RUN_RECORD"
	EnvRunID             = "STEPSEC_RUN_ID"
	EnvBootstrapVersion  = "STEPSEC_BOOTSTRAP_VERSION"
	EnvBootstrapFallback = "STEPSEC_BOOTSTRAP_FALLBACK"

	// envMaxExecution mirrors telemetry.EnvMaxExecutionDuration; the
	// bootstrap reads it (and config.json) to bound a scan it launched.
	envMaxExecution = "STEPSEC_MAX_EXECUTION_DURATION"

	// UpdaterFailureThreshold consecutive failures of one updater version
	// make `update` fall back to the seed's updater.
	UpdaterFailureThreshold = 3
)

// Fallback reasons passed in EnvBootstrapFallback. Reasons about a named
// version carry it after a colon (current_missing:1.20.0) so the agent can
// report update_pointer_invalid with update_from = that version.
const (
	ReasonStateMissing      = updatestate.FallbackStateMissing
	ReasonStateCorrupt      = updatestate.FallbackStateCorrupt
	ReasonStateUnreadable   = updatestate.FallbackStateUnreadable
	ReasonCurrentMissing    = updatestate.FallbackCurrentMissing
	ReasonCurrentIncomplete = updatestate.FallbackCurrentIncomplete
	ReasonStartFailed       = updatestate.FallbackStartFailed
	ReasonUpdaterFailed     = updatestate.FallbackUpdaterFailed
	ReasonNoUpdater         = updatestate.FallbackNoUpdater
)

const (
	defaultExecutionDeadline = 4 * time.Hour
	// runDeadlineSlack lets the agent's own watchdog fire first; the scan
	// task's ExecutionTimeLimit is the watchdog + 30 min.
	runDeadlineSlack = 10 * time.Minute
	// defaultUpdateDeadline stays under the update task's 30 min
	// ExecutionTimeLimit so a hung updater is recorded as a failure.
	defaultUpdateDeadline = 25 * time.Minute
	// defaultRunLockWait bounds the wait for a run-record lock; past it the
	// bookkeeping is skipped and the scan still runs.
	defaultRunLockWait = 5 * time.Second
	maxConfigSize      = 1 << 20
	maxLogSize         = 1 << 20
)

// IsBootstrapBinary reports whether exePath is the bootstrap's file name.
func IsBootstrapBinary(exePath string) bool {
	base := exePath
	if i := strings.LastIndexAny(base, `\/`); i >= 0 {
		base = base[i+1:]
	}
	return strings.EqualFold(base, BootstrapBinary)
}

// Bootstrap runs the bootstrap verbs. All fields are injectable for tests;
// NewBootstrap fills production values.
type Bootstrap struct {
	Layout   updatestate.Layout
	Spawn    Spawner
	IsSystem func() bool
	Now      func() time.Time
	Sleep    func(time.Duration)
	Getenv   func(string) string
	Environ  func() []string
	Out      io.Writer
	NewRunID func() string
	// SetRunningVersion records the version adopt-seed made current
	// (HKLM RunningVersion on Windows); nil skips it.
	SetRunningVersion func(string) error
	// SelfExe is this bootstrap's own image; adopt-seed copies it to
	// Layout.MSIHelperFile for the MSI's stop-for-msi action. "" skips it.
	SelfExe string
	// VerifySeed checks a seed's executables before adopt-seed copies them
	// (authenticode.SameSeedPublisher in production); nil skips it.
	VerifySeed func(path string) error

	AdoptLockWait  time.Duration // adopt-seed: bounded wait for the update lock
	RecordLockWait time.Duration // update: wait to record the updater result
	LockPoll       time.Duration
	RunLockWait    time.Duration // run-record lock; 0 means defaultRunLockWait
	UpdateDeadline time.Duration

	log io.Writer
}

// NewBootstrap returns a production bootstrap rooted at the directory of
// exePath, with runs under the ProgramData data root.
func NewBootstrap(exePath string, isSystem func() bool) *Bootstrap {
	return &Bootstrap{
		Layout:            updatestate.Layout{InstallRoot: filepath.Dir(exePath), DataRoot: updatestate.DataRoot()},
		Spawn:             SpawnHidden,
		IsSystem:          isSystem,
		Now:               time.Now,
		Sleep:             time.Sleep,
		Getenv:            os.Getenv,
		Environ:           os.Environ,
		Out:               os.Stdout,
		NewRunID:          uuid.NewString,
		SetRunningVersion: SetRunningVersion,
		VerifySeed:        func(p string) error { return authenticode.SameSeedPublisher(p, exePath) },
		SelfExe:           exePath,
		AdoptLockWait:     60 * time.Second,
		RecordLockWait:    30 * time.Second,
		LockPoll:          500 * time.Millisecond,
		UpdateDeadline:    defaultUpdateDeadline,
	}
}

// Main dispatches a bootstrap command line (argv without the program name).
func (b *Bootstrap) Main(argv []string) int {
	if len(argv) == 0 {
		b.logf("usage: %s run <args...> | update | adopt-seed --seed-dir <dir>", BootstrapBinary)
		return exitUsage
	}
	switch argv[0] {
	case "run":
		return b.Run(argv[1:])
	case "update":
		return b.Update()
	case "adopt-seed":
		return b.AdoptSeed(argv[1:])
	case "stop-for-msi":
		return b.StopForMSI(argv[1:])
	default:
		b.logf("unknown bootstrap verb %q", argv[0])
		return exitUsage
	}
}

func (b *Bootstrap) logf(format string, args ...any) {
	line := b.Now().UTC().Format(time.RFC3339) + " bootstrap: " + fmt.Sprintf(format, args...) + "\n"
	if b.Out != nil {
		_, _ = io.WriteString(b.Out, line)
	}
	if b.log != nil {
		_, _ = io.WriteString(b.log, line)
	}
}

// openUpdateLog appends SYSTEM-verb logs to state\update.log (best effort,
// restarted when it grows past maxLogSize).
func (b *Bootstrap) openUpdateLog() func() {
	path := b.Layout.LogFile()
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogSize {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600) // #nosec G304 -- fixed path in the protected state dir
	if err != nil {
		return func() {}
	}
	b.log = f
	return func() { b.log = nil; _ = f.Close() }
}

// installDirArg returns the --install-dir value in args, if any.
func installDirArg(args []string) string {
	for i, a := range args {
		switch {
		case strings.HasPrefix(a, "--install-dir="):
			return strings.Trim(strings.TrimPrefix(a, "--install-dir="), `"`)
		case a == "--install-dir" && i+1 < len(args):
			return strings.Trim(args[i+1], `"`)
		}
	}
	return ""
}

// childEnv is the bootstrap's environment with our variables replaced.
func (b *Bootstrap) childEnv(set map[string]string) []string {
	ours := []string{EnvRunRecord, EnvRunID, EnvBootstrapVersion, EnvBootstrapFallback}
	var env []string
	for _, kv := range b.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, o := range ours {
			if strings.EqualFold(k, o) {
				drop = true
			}
		}
		if !drop {
			env = append(env, kv)
		}
	}
	for _, k := range ours {
		if v, ok := set[k]; ok && v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func parseDeadline(v string) (time.Duration, bool) {
	switch v {
	case "":
		return 0, false
	case "0", "off":
		return 0, true
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

// runDeadline mirrors the agent's execution watchdog (env > config.json >
// 4 h) plus slack. It catches a scan that hangs before the agent arms its
// own watchdog. 0 disables it, as for the agent.
func (b *Bootstrap) runDeadline(dataRoot string) time.Duration {
	d, ok := parseDeadline(b.Getenv(envMaxExecution))
	if !ok {
		var cfg struct {
			MaxExecutionDuration string `json:"max_execution_duration"`
		}
		if data, err := readSmall(filepath.Join(dataRoot, "config.json"), maxConfigSize); err == nil && json.Unmarshal(data, &cfg) == nil {
			d, ok = parseDeadline(cfg.MaxExecutionDuration)
		}
	}
	if !ok {
		d = defaultExecutionDeadline
	}
	if d == 0 {
		return 0
	}
	return d + runDeadlineSlack
}

func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the agent's own config path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("too large")
	}
	return data, nil
}

func checkpointLogged(b *Bootstrap, name string) {
	if err := faultinject.Point(name); err != nil {
		b.logf("checkpoint %s: %v (continuing)", name, err)
	}
}

// Run is `run <agent args...>`: launch versions\<v>\task.exe with args from
// the first usable of current → previous → seed, record the run, and return
// the child's exit code.
func (b *Bootstrap) Run(args []string) int {
	layout := b.Layout
	if d := installDirArg(args); d != "" {
		layout.DataRoot = d
	}
	p, corrupt, err := updatestate.LoadPointers(layout.StateFile())
	if err != nil {
		b.logf("reading state: %v", err)
	}
	cands := updatestate.ResolveRunChain(layout, p, updatestate.LoadReason(p != nil, corrupt, err))
	checkpointLogged(b, "boot.resolved")
	if len(cands) == 0 {
		b.logf("no launchable version (state, previous and seed all unusable)")
		return ExitCannotStart
	}
	deadline := b.runDeadline(layout.DataRoot)
	startReason := ""
	for _, c := range cands {
		reason := c.Reason
		if startReason != "" {
			reason = startReason
		}
		runFile := layout.RunFile(c.Version)
		runID := b.NewRunID()
		runLock := layout.RunLockFile(c.Version)
		if err := b.withRunLock(runLock, func() error {
			return updatestate.AppendRun(runFile, updatestate.RunRecord{RunID: runID, Version: c.Version.String()})
		}); err != nil {
			// Never block a scan on bookkeeping: launch without a run id,
			// so the agent skips the started marker.
			b.logf("run record %s: %v; launching without one", runFile, err)
			runID = ""
		}
		env := b.childEnv(map[string]string{
			EnvRunRecord:         runFile,
			EnvRunID:             runID,
			EnvBootstrapVersion:  c.Version.String(),
			EnvBootstrapFallback: reason,
		})
		res := b.Spawn(filepath.Join(c.Dir, updatestate.LauncherFile), args, env, deadline, func() {
			checkpointLogged(b, "boot.launched")
		})
		if !res.Started {
			b.logf("starting %s: %v", c.Dir, res.Err)
			b.finalize(runLock, runFile, runID, ExitCannotStart, false)
			startReason = ReasonStartFailed + ":" + c.Version.String()
			continue
		}
		code, killed := runOutcome(res)
		b.finalize(runLock, runFile, runID, code, killed)
		return code
	}
	return ExitCannotStart
}

// runOutcome is the exit code and watchdog flag a scan launch records. The
// deadline counts awake time only (sleep excluded), so a deadline kill is a
// real hang: a watchdog kill.
func runOutcome(res SpawnResult) (code int, watchdogKilled bool) {
	if res.Killed {
		return ExitKilled, true
	}
	return res.ExitCode, false
}

func (b *Bootstrap) finalize(runLock, runFile, runID string, code int, killed bool) {
	if runID == "" {
		return
	}
	if err := b.withRunLock(runLock, func() error {
		return updatestate.FinalizeRun(runFile, runID, code, killed, b.Now())
	}); err != nil {
		b.logf("finalizing run record %s: %v", runFile, err)
	}
}

// withRunLock runs fn holding the run-record lock (R-B-2), waiting at most
// RunLockWait. It returns an error, without running fn, when the lock can't
// be taken; callers skip the bookkeeping and never block the scan.
func (b *Bootstrap) withRunLock(path string, fn func() error) error {
	wait := b.RunLockWait
	if wait <= 0 {
		wait = defaultRunLockWait
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	deadline := b.Now().Add(wait)
	for {
		l, err := updatestate.AcquireLock(path)
		if err == nil {
			defer l.Release()
			return fn()
		}
		if !errors.Is(err, updatestate.ErrLocked) || !b.Now().Before(deadline) {
			return fmt.Errorf("run-record lock %s: %w", path, err)
		}
		b.Sleep(b.LockPoll)
	}
}

// lockWithWait polls for the update lock for up to wait.
func (b *Bootstrap) lockWithWait(wait time.Duration) (*updatestate.Lock, error) {
	deadline := b.Now().Add(wait)
	for {
		l, err := updatestate.AcquireLock(b.Layout.LockFile())
		if err == nil {
			return l, nil
		}
		if !errors.Is(err, updatestate.ErrLocked) || !b.Now().Before(deadline) {
			return nil, err
		}
		b.Sleep(b.LockPoll)
	}
}

// Update is `update` (SYSTEM): pick the updater binary, run
// `agent.exe self-update --system`, and record its result in state.updater.
func (b *Bootstrap) Update() int {
	if !b.IsSystem() {
		b.logf("update must run as SYSTEM")
		return 1
	}
	defer b.openUpdateLog()()

	p, corrupt, err := updatestate.LoadPointers(b.Layout.StateFile())
	if err != nil {
		b.logf("reading state: %v", err)
	}
	var primary *updatestate.RunChoice
	reason := updatestate.LoadReason(p != nil, corrupt, err)
	if p != nil {
		pick := p.Current
		if p.Probation != "" && p.Probation == p.Current {
			pick = p.Previous
		}
		if pick == "" {
			reason = ReasonNoUpdater
		} else if v, why := b.Layout.CheckVersionDir(pick); why != "" {
			reason = why
		} else if p.UpdaterVersion == pick && p.UpdaterFailures >= UpdaterFailureThreshold {
			reason = ReasonUpdaterFailed + ":" + pick
		} else {
			primary = &updatestate.RunChoice{Version: v, Dir: b.Layout.VersionDir(v)}
		}
	}
	var cands []updatestate.RunChoice
	if primary != nil {
		cands = append(cands, *primary)
	}
	if v, ok := b.Layout.FindSeed(); ok {
		cands = append(cands, updatestate.RunChoice{Version: v, Dir: b.Layout.SeedDir(v), Reason: reason})
	}
	checkpointLogged(b, "boot.resolved")
	if len(cands) == 0 {
		b.logf("no updater binary available")
		return ExitCannotStart
	}
	for i, c := range cands {
		isPrimary := primary != nil && i == 0
		if !isPrimary {
			b.logf("updater fallback to seed %s (%s)", c.Version, c.Reason)
		}
		agent := filepath.Join(c.Dir, updatestate.AgentFile)
		res := b.Spawn(agent, []string{"self-update", "--system"}, b.childEnv(nil), b.UpdateDeadline, func() {
			checkpointLogged(b, "boot.launched")
		})
		code := res.ExitCode
		switch {
		case !res.Started:
			b.logf("starting updater %s: %v", agent, res.Err)
			code = ExitCannotStart
		case res.Killed:
			b.logf("updater %s killed after %s", c.Version, b.UpdateDeadline)
			code = ExitKilled
		}
		b.logf("updater %s exited %d", c.Version, code)
		if isPrimary {
			b.recordUpdater(c.Version.String(), code)
		}
		if res.Started {
			return code
		}
	}
	return ExitCannotStart
}

// recordUpdater stores the updater result for the next tick's selection.
func (b *Bootstrap) recordUpdater(version string, code int) {
	l, err := b.lockWithWait(b.RecordLockWait)
	if err != nil {
		b.logf("not recording updater result (lock: %v)", err)
		return
	}
	defer l.Release()
	// D18: the same tolerant read as the run path, so values this build's
	// Load rejects can't stop the failure count (and the seed fallback).
	err = updatestate.SaveUpdaterRecord(b.Layout.StateFile(), "boot", func(v string, failures int) (string, int) {
		switch {
		case code == 0:
			return version, 0
		case v == version:
			return version, failures + 1
		default:
			return version, 1
		}
	})
	if err != nil {
		b.logf("not recording updater result: %v", err)
	}
}

// AdoptSeed is `adopt-seed --seed-dir <dir>` (SYSTEM, MSI custom action):
// protect versions\ and state\, copy the seed into versions\<seed> if
// absent, and point current at it when current is unusable or older. It
// always exits 0: it must never fail the MSI.
func (b *Bootstrap) AdoptSeed(args []string) int {
	seedDir := ""
	for i, a := range args {
		switch {
		case strings.HasPrefix(a, "--seed-dir="):
			seedDir = strings.TrimPrefix(a, "--seed-dir=")
		case a == "--seed-dir" && i+1 < len(args):
			seedDir = args[i+1]
		}
	}
	for _, a := range args {
		switch a {
		case "--rollback":
			return b.adoptRollback()
		case "--commit":
			return b.adoptCommit()
		}
	}
	if seedDir == "" {
		b.logf("adopt-seed: --seed-dir is required")
		return 0
	}
	if !b.IsSystem() {
		b.logf("adopt-seed must run as SYSTEM")
		return 0
	}
	seedDir = filepath.Clean(strings.Trim(seedDir, `"`))
	v, err := updatestate.ParseVersion(filepath.Base(seedDir))
	if err != nil {
		b.logf("adopt-seed: seed dir %q is not seed\\<x.y.z>: %v", seedDir, err)
		return 0
	}
	if !samePath(seedDir, b.Layout.SeedDir(v)) {
		b.logf("adopt-seed: seed dir %q is not %q", seedDir, b.Layout.SeedDir(v))
		return 0
	}
	if !seedComplete(seedDir) {
		b.logf("adopt-seed: seed %s is incomplete", seedDir)
		return 0
	}
	for _, d := range []string{b.Layout.VersionsDir(), b.Layout.StateDir()} {
		fixed, err := updatestate.EnsureProtectedDir(d)
		if err != nil {
			b.logf("adopt-seed: protecting %s: %v", d, err)
			return 0
		}
		if fixed {
			b.logf("adopt-seed: re-asserted owner/DACL on %s", d)
		}
	}
	defer b.openUpdateLog()()

	l, err := b.lockWithWait(b.AdoptLockWait)
	if err != nil {
		b.logf("adopt-seed: update lock not taken (%v); the updater converges on its next tick", err)
		return 0
	}
	defer l.Release()

	b.refreshMSIHelper()

	// Snapshot before changing anything, for the MSI's rollback action.
	snapPath := b.Layout.AdoptSnapshotFile()
	updatestate.SweepStaleAdoptSnapshot(snapPath)
	snap := b.adoptSnapshot(v)
	if err := updatestate.WriteAdoptSnapshot(snapPath, snap); err != nil {
		b.logf("adopt-seed: writing rollback snapshot: %v; not adopting", err)
		return 0
	}

	if note, err := b.Layout.CopySeedVersion(v, b.Now(), b.VerifySeed); err != nil {
		b.logf("adopt-seed: copying seed %s: %v", v, err)
	} else if note != "" {
		b.logf("adopt-seed: %s", note)
	}
	if err := updatestate.VerifyVersionDir(b.Layout.VersionDir(v), v); err != nil {
		b.logf("adopt-seed: versions\\%s unusable (%v); state left unchanged", v, err)
		return 0
	}
	if b.adoptState(v) {
		if gen, ok := updatestate.StateGeneration(b.Layout.StateFile()); ok {
			snap.AfterGeneration = &gen
			if err := updatestate.WriteAdoptSnapshot(snapPath, snap); err != nil {
				b.logf("adopt-seed: updating rollback snapshot: %v", err)
			}
		}
	}
	return 0
}

// refreshMSIHelper copies this bootstrap to Layout.MSIHelperFile, which the
// next MSI's stop-for-msi action runs (D29). Best effort.
func (b *Bootstrap) refreshMSIHelper() {
	if b.SelfExe == "" {
		return
	}
	dst := b.Layout.MSIHelperFile()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { // #nosec G301 -- inside the protected state dir
		b.logf("adopt-seed: MSI helper: %v", err)
		return
	}
	tmp := dst + ".new"
	if err := copyExecutable(b.SelfExe, tmp); err != nil {
		b.logf("adopt-seed: MSI helper: %v", err)
		_ = os.Remove(tmp)
		return
	}
	// Keep the previous install's helper until the MSI commits, so a
	// failed upgrade's rollback can put it back.
	prev := dst + msiHelperPrevSuffix
	if _, err := os.Lstat(dst); err == nil {
		_ = os.Remove(prev)
		if err := os.Rename(dst, prev); err != nil {
			b.logf("adopt-seed: MSI helper: keeping the previous copy: %v", err)
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		b.logf("adopt-seed: MSI helper: %v", err)
		_ = os.Remove(tmp)
		_ = os.Rename(prev, dst) // keep a helper in place
	}
}

// msiHelperPrevSuffix names the previous install's MSI helper, kept from
// adopt-seed until the MSI commits or rolls back.
const msiHelperPrevSuffix = ".prev"

// restoreMSIHelper is the rollback of refreshMSIHelper: the previous
// install's helper replaces the failed build's.
func (b *Bootstrap) restoreMSIHelper() {
	dst := b.Layout.MSIHelperFile()
	prev := dst + msiHelperPrevSuffix
	if _, err := os.Lstat(prev); err != nil {
		return
	}
	if err := os.Rename(prev, dst); err != nil {
		b.logf("adopt-seed --rollback: restoring the MSI helper: %v", err)
		return
	}
	b.logf("adopt-seed --rollback: restored the previous MSI helper")
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- this bootstrap's own image
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // #nosec G302 G304 -- protected state dir
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// StopForMSI is `stop-for-msi --install-dir <root>`, the MSI's first
// deferred action (D29): it stops every DMG process under root and waits,
// bounded, until no process holds any MSI-owned file, so Windows Installer
// never finds one in use (which needs a reboot). It runs from the helper
// copy in state\msi\, so its own image is not an MSI file. Always exits 0.
func (b *Bootstrap) StopForMSI(args []string) int {
	root := ""
	for i, a := range args {
		switch {
		case strings.HasPrefix(a, "--install-dir="):
			root = strings.TrimPrefix(a, "--install-dir=")
		case a == "--install-dir" && i+1 < len(args):
			root = args[i+1]
		}
	}
	if root == "" {
		b.logf("stop-for-msi: --install-dir is required")
		return 0
	}
	root = filepath.Clean(strings.Trim(root, `"`))
	stopped, err := winproc.StopUnder(root)
	for _, img := range stopped {
		b.logf("stop-for-msi: stopped %s", img)
	}
	if err != nil {
		b.logf("stop-for-msi: %v", err)
	}
	files := updatestate.Layout{InstallRoot: root}.MSIOwnedFiles()
	if held := winproc.WaitReleased(files, msiReleaseWait, 50*time.Millisecond); len(held) > 0 {
		b.logf("stop-for-msi: still held after %s: %s", msiReleaseWait, strings.Join(held, ", "))
		return 0
	}
	b.logf("stop-for-msi: %d MSI-owned files free", len(files))
	return 0
}

// msiReleaseWait bounds stop-for-msi's wait for MSI-owned files.
const msiReleaseWait = 30 * time.Second

// adoptSnapshot records state.json and whether versions\<v> exists, before
// adopt-seed touches either.
func (b *Bootstrap) adoptSnapshot(v updatestate.Version) *updatestate.AdoptSnapshot {
	snap := &updatestate.AdoptSnapshot{Seed: v.String()}
	if data, err := os.ReadFile(b.Layout.StateFile()); err == nil { // #nosec G304 -- protected state dir
		snap.StatePresent, snap.State = true, data
	}
	snap.CreatedDir = updatestate.VerifyVersionDir(b.Layout.VersionDir(v), v) != nil
	return snap
}

// renameDir and stopUnder are os.Rename and winproc.StopUnder; tests
// replace them.
var (
	renameDir = os.Rename
	stopUnder = winproc.StopUnder
)

// rollbackRemoveWait bounds the rollback's retries to remove the version
// dir adopt-seed created; rollbackRemovePoll spaces them.
const (
	rollbackRemoveWait = 30 * time.Second
	rollbackRemovePoll = 250 * time.Millisecond
)

// removeAdoptedDir moves dir to trash and deletes it. A scan the failed
// install started may still run from dir, so it stops what runs from there
// and retries until the rename succeeds or rollbackRemoveWait passes.
func (b *Bootstrap) removeAdoptedDir(dir, trash string) error {
	var err error
	for waited := time.Duration(0); ; waited += rollbackRemovePoll {
		if stopped, serr := stopUnder(dir); serr != nil {
			b.logf("adopt-seed --rollback: stopping processes under %s: %v", dir, serr)
		} else if len(stopped) > 0 {
			b.logf("adopt-seed --rollback: stopped %s", strings.Join(stopped, ", "))
		}
		if err = renameDir(dir, trash); err == nil {
			_ = os.RemoveAll(trash)
			return nil
		}
		if waited >= rollbackRemoveWait {
			return err
		}
		b.Sleep(rollbackRemovePoll)
	}
}

// adoptRollback is `adopt-seed --rollback`, the MSI's rollback action for
// adopt-seed (DMG-I5-2): when the transaction fails after adopt-seed ran,
// restore the state.json it changed (only if nobody wrote it since) and
// remove the versions\<seed> it created unless the restored state points at
// it. Always exits 0 (Return=ignore).
func (b *Bootstrap) adoptRollback() int {
	if !b.IsSystem() {
		b.logf("adopt-seed --rollback must run as SYSTEM")
		return 0
	}
	defer b.openUpdateLog()()
	l, err := b.lockWithWait(b.AdoptLockWait)
	if err != nil {
		b.logf("adopt-seed --rollback: update lock not taken (%v)", err)
		return 0
	}
	defer l.Release()
	b.restoreMSIHelper()
	snapPath := b.Layout.AdoptSnapshotFile()
	snap, age, err := updatestate.ReadAdoptSnapshot(snapPath)
	switch {
	case err != nil:
		b.logf("adopt-seed --rollback: unreadable snapshot (%v); removed", err)
		_ = os.Remove(snapPath)
		return 0
	case snap == nil:
		b.logf("adopt-seed --rollback: nothing to roll back")
		return 0
	case age > updatestate.AdoptSnapshotMaxAge:
		b.logf("adopt-seed --rollback: snapshot is %s old (not this MSI's); removed", age.Round(time.Second))
		_ = os.Remove(snapPath)
		return 0
	}
	defer func() { _ = os.Remove(snapPath) }()
	path := b.Layout.StateFile()
	if snap.AfterGeneration != nil {
		if gen, ok := updatestate.StateGeneration(path); !ok || gen != *snap.AfterGeneration {
			b.logf("adopt-seed --rollback: state.json changed since adopt-seed; left as is")
		} else {
			b.restoreState(path, snap, gen)
		}
	}
	if snap.CreatedDir {
		v, err := updatestate.ParseVersion(snap.Seed)
		p, _, _ := updatestate.LoadPointers(path)
		if err == nil && (p == nil || (p.Current != snap.Seed && p.Previous != snap.Seed)) {
			dir := b.Layout.VersionDir(v)
			trash := filepath.Join(b.Layout.VersionsDir(), fmt.Sprintf("%s%s-rollback", updatestate.TrashPrefix, snap.Seed))
			if err := b.removeAdoptedDir(dir, trash); err != nil {
				b.logf("adopt-seed --rollback: could not remove %s: %v; left in place", dir, err)
			} else {
				b.logf("adopt-seed --rollback: removed %s", dir)
			}
		}
	}
	return 0
}

// restoreState puts back the pre-adopt state.json: through the preserving
// Save (generation continues upward) when it parses, else byte-for-byte;
// removed if there was none.
func (b *Bootstrap) restoreState(path string, snap *updatestate.AdoptSnapshot, gen uint64) {
	if !snap.StatePresent {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			b.logf("adopt-seed --rollback: removing state.json: %v", err)
			return
		}
		b.logf("adopt-seed --rollback: removed the state.json adopt-seed created")
		return
	}
	tmp := path + ".rollback"
	if err := os.WriteFile(tmp, snap.State, 0o600); err != nil {
		b.logf("adopt-seed --rollback: %v", err)
		return
	}
	defer os.Remove(tmp)
	st, corrupt, err := updatestate.Load(tmp)
	if err != nil || corrupt || st == nil {
		b.logf("adopt-seed --rollback: pre-adopt state not loadable; left as is")
		return
	}
	st.Generation = gen
	if err := updatestate.SaveCheckpointed(path, st, "adopt"); err != nil {
		b.logf("adopt-seed --rollback: writing state: %v", err)
		return
	}
	b.logf("adopt-seed --rollback: restored current %s", st.Current)
	b.recordRunningVersion(st.Current)
}

// adoptCommit is `adopt-seed --commit`, the MSI's commit action: the
// transaction succeeded, so the rollback snapshot is no longer needed.
func (b *Bootstrap) adoptCommit() int {
	if !b.IsSystem() {
		return 0
	}
	l, err := b.lockWithWait(b.AdoptLockWait)
	if err != nil {
		return 0 // swept later (AdoptSnapshotMaxAge)
	}
	defer l.Release()
	_ = os.Remove(b.Layout.AdoptSnapshotFile())
	_ = os.Remove(b.Layout.MSIHelperFile() + msiHelperPrevSuffix)
	return 0
}

func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if filepath.Separator == '\\' {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// seedComplete reports whether dir holds every updatestate.VersionFiles entry.
func seedComplete(dir string) bool {
	for _, name := range updatestate.VersionFiles {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !fi.Mode().IsRegular() {
			return false
		}
	}
	return true
}

// adoptState sets current = seed when there is no state yet, when current
// is unusable, or when the seed is newer than current (and not quarantined).
// An existing state is never replaced (R-B-1): only current/previous (and
// probation, which belonged to the old current) change, through the
// unknown-field-preserving Save; a state this build can't round-trip
// (unreadable pointers, fields Load rejects, a newer schema) is left
// byte-for-byte alone for the updater to handle. An MSI never downgrades a
// self-updated device. Called with the update lock held.
func (b *Bootstrap) adoptState(seed updatestate.Version) (changed bool) {
	path := b.Layout.StateFile()
	s := seed.String()
	p, corrupt, err := updatestate.LoadPointers(path)
	switch {
	case err != nil:
		b.logf("adopt-seed: reading state: %v; left unchanged", err)
		return false
	case corrupt:
		b.logf("adopt-seed: state pointers unreadable; left unchanged for the updater")
		return false
	case p == nil:
		st := &updatestate.State{Schema: updatestate.SchemaVersion, Current: s}
		if err := updatestate.SaveCheckpointed(path, st, "adopt"); err != nil {
			b.logf("adopt-seed: writing state: %v", err)
			return false
		}
		b.logf("adopt-seed: no state; current = seed %s", s)
		b.recordRunningVersion(s)
		return true
	case p.Schema > updatestate.SchemaVersion:
		b.logf("adopt-seed: state schema %d is newer than this bootstrap; left unchanged", p.Schema)
		return false
	}
	st, corrupt, err := updatestate.Load(path)
	if err != nil || corrupt || st == nil {
		b.logf("adopt-seed: state has fields this build can't round-trip (%v); left unchanged", err)
		return false
	}
	changed, why := b.Layout.AdoptSeedRule(st, seed, b.Now())
	if why != "" {
		b.logf("adopt-seed: %s", why)
	}
	if !changed {
		return false
	}
	if err := updatestate.SaveCheckpointed(path, st, "adopt"); err != nil {
		b.logf("adopt-seed: writing state: %v", err)
		return false
	}
	b.recordRunningVersion(s)
	return true
}

// recordRunningVersion sets RunningVersion after adopt-seed set current
// (R-B-4). Best effort: inventory only.
func (b *Bootstrap) recordRunningVersion(v string) {
	if b.SetRunningVersion == nil {
		return
	}
	if err := b.SetRunningVersion(v); err != nil {
		b.logf("adopt-seed: setting RunningVersion: %v", err)
	}
}
