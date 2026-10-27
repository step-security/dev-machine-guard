package updatestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// A launch can't outlive the agent's execution deadline (4 h default), plus
// the scan task's ExecutionTimeLimit margin over it (30 min, which covers
// the bootstrap's own watchdog slack), plus abandonSlack. An open record
// older than that belongs to a bootstrap that died (logoff, shutdown, the
// task time limit) and will never be finalized.
const (
	runAgentDeadline = 4 * time.Hour
	runTaskMargin    = 30 * time.Minute
	abandonSlack     = 2 * time.Hour
	abandonAfter     = runAgentDeadline + runTaskMargin + abandonSlack
)

// MaxRunRecords is how many run records a runs\<v>.json keeps.
const MaxRunRecords = 10

// maxRunsSize bounds what ReadRuns reads from the user-writable file.
const maxRunsSize = 64 << 10

// RunRecord is one bootstrap launch of a version. The bootstrap generates
// RunID, appends the record and passes STEPSEC_RUN_ID to the agent; the
// agent sets Started right after a successful run-status "started", and the
// bootstrap finalizes ExitCode, WatchdogKilled and At. Both updates match by
// RunID, so overlapping launches never touch each other's record. A nil
// ExitCode means not finalized yet.
type RunRecord struct {
	RunID string `json:"run_id,omitempty"`
	// Seq is the per-file launch sequence number (max+1 at append).
	Seq     int    `json:"seq,omitempty"`
	Version string `json:"version"`
	// StartedAt is when the record was appended (the launch began).
	StartedAt time.Time `json:"start,omitzero"`
	// Abandoned marks an open record whose launch outlived any possible
	// scan (its bootstrap died); it is Neutral and evicted first.
	Abandoned bool `json:"abandoned,omitempty"`
	// OwnerPID/OwnerStart identify the bootstrap process that owns an open
	// record (its creation time guards against PID reuse); FirstSeen is
	// when a writer first saw a record whose start time it couldn't trust.
	OwnerPID       int       `json:"owner_pid,omitempty"`
	OwnerStart     time.Time `json:"owner_start,omitzero"`
	FirstSeen      time.Time `json:"first_seen,omitzero"`
	ExecutionID    string    `json:"execution_id,omitempty"`
	Started        bool      `json:"started"`
	ExitCode       *int      `json:"exit_code,omitempty"`
	WatchdogKilled bool      `json:"watchdog_killed,omitempty"`
	At             time.Time `json:"at,omitzero"`
}

type runFile struct {
	Records []RunRecord `json:"records"`
	// MaxSeq is the highest Seq ever assigned in this file, kept across
	// trimming so sequence numbers never repeat.
	MaxSeq int `json:"max_seq,omitempty"`
}

// ErrNoOpenRun means the run file has no unfinalized record with that run_id.
var ErrNoOpenRun = errors.New("updatestate: no open run record")

// ReadRuns returns every record in the file, oldest first; trimming
// happens only when writing. The file
// is user-writable, so anything unreadable or malformed reads as no records
// and records with an invalid version are dropped; it never fails.
func ReadRuns(path string) []RunRecord {
	recs, _ := readRunFile(path)
	return recs
}

// MaxRunSeq is the highest sequence number assigned in a run file (0 when
// none). The updater records it at a switch as the probation's start.
func MaxRunSeq(path string) int {
	_, maxSeq := readRunFile(path)
	return maxSeq
}

func readRunFile(path string) ([]RunRecord, int) {
	data, err := readBounded(path, maxRunsSize)
	if err != nil {
		return nil, 0
	}
	return decodeRunFile(data)
}

func decodeRuns(data []byte) []RunRecord {
	recs, _ := decodeRunFile(data)
	return recs
}

// decodeRunFile returns the valid records and the file's highest seq.
func decodeRunFile(data []byte) ([]RunRecord, int) {
	var f runFile
	if json.Unmarshal(data, &f) != nil {
		return nil, 0
	}
	maxSeq := max(f.MaxSeq, 0)
	for _, r := range f.Records {
		maxSeq = max(maxSeq, r.Seq)
	}
	out := f.Records[:0]
	for _, r := range f.Records {
		if validVersion(r.Version) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, maxSeq
	}
	return out, maxSeq
}

// trimRuns keeps at most MaxRunRecords plus any fresh open records,
// evicting the oldest closed or abandoned records first. A fresh open
// record (its launch still running) and the record named protect (the one
// this write finalizes or marks) are never evicted. Order is kept.
func trimRuns(recs []RunRecord, protect string) []RunRecord {
	excess := len(recs) - MaxRunRecords
	if excess <= 0 {
		return recs
	}
	out := make([]RunRecord, 0, len(recs))
	for _, r := range recs {
		if excess > 0 && ClassifyRun(r) != RunOpen && (protect == "" || r.RunID != protect) {
			excess--
			continue
		}
		out = append(out, r)
	}
	return out
}

// abandonStale marks open records whose bootstrap is gone as abandoned:
// they will never be finalized. Liveness comes from the owning process
// (PID + creation time). Only when it can't be determined does wall-clock
// age decide, from the start time, or from FirstSeen when the start time
// is missing or in the future (clock moved).
func abandonStale(recs []RunRecord, now time.Time, protect string) {
	for i := range recs {
		r := &recs[i]
		if r.Abandoned || ClassifyRun(*r) != RunOpen || (protect != "" && r.RunID == protect) {
			continue // the record this write touches is its own live evidence
		}
		switch ownerOf(*r) {
		case ownerDead:
			r.Abandoned = true
		case ownerAlive:
		default:
			switch {
			case !r.StartedAt.IsZero() && !r.StartedAt.After(now):
				r.Abandoned = now.Sub(r.StartedAt) > abandonAfter
			case r.FirstSeen.IsZero():
				r.FirstSeen = now.UTC()
			default:
				r.Abandoned = now.Sub(r.FirstSeen) > abandonAfter
			}
		}
	}
}

// writeRuns abandons stale open records, trims (never evicting protect)
// and writes. Callers hold the run-record lock.
func writeRuns(path string, recs []RunRecord, protect string, maxSeq int) error {
	abandonStale(recs, time.Now(), protect)
	recs = trimRuns(recs, protect)
	data, err := json.Marshal(runFile{Records: recs, MaxSeq: maxSeq})
	if err != nil {
		return err
	}
	// #nosec G301 -- runs\ is shared by the user scan and the SYSTEM updater.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeAtomic(path, data, nil, nil)
}

// ErrRunID means AppendRun got an empty run_id or one already in the file;
// such a record could never be finalized by its own launch.
var ErrRunID = errors.New("updatestate: run record needs a unique run_id")

// AppendRun appends r, keeping the newest MaxRunRecords.
func AppendRun(path string, r RunRecord) error {
	if !validVersion(r.Version) {
		return errors.New("updatestate: run record needs a strict x.y.z version")
	}
	if r.RunID == "" {
		return ErrRunID
	}
	recs, maxSeq := readRunFile(path)
	for _, existing := range recs {
		if existing.RunID == r.RunID {
			return ErrRunID
		}
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = time.Now().UTC()
	}
	stampOwner(&r)
	maxSeq++
	r.Seq = maxSeq
	return writeRuns(path, append(recs, r), r.RunID, maxSeq)
}

// MarkRunStarted sets the started marker on the open record runID.
func MarkRunStarted(path, runID string) error {
	return updateOpenRun(path, runID, func(r *RunRecord) { r.Started = true })
}

// RunLockPath is the lock beside a run file (runs\<v>.json.lock) that every
// read-modify-write of it takes: the bootstrap's AppendRun/FinalizeRun (via
// Layout.RunLockFile) and the agent's MarkRunStartedLocked.
func RunLockPath(runFile string) string { return runFile + ".lock" }

// MarkRunStartedLocked is the agent's MarkRunStarted under the run-record
// lock the bootstrap takes for AppendRun/FinalizeRun (RunLockPath), waiting
// at most wait. On timeout it
// returns an error without writing; callers skip the marker and never fail
// the scan.
func MarkRunStartedLocked(path, runID string, wait time.Duration) error {
	lockPath := RunLockPath(path)
	deadline := time.Now().Add(wait)
	for {
		l, err := AcquireLock(lockPath)
		if err == nil {
			defer l.Release()
			return MarkRunStarted(path, runID)
		}
		if !errors.Is(err, ErrLocked) || !time.Now().Before(deadline) {
			return fmt.Errorf("run-record lock %s: %w", lockPath, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// FinalizeRun closes the open record runID.
func FinalizeRun(path, runID string, exitCode int, watchdogKilled bool, at time.Time) error {
	return updateOpenRun(path, runID, func(r *RunRecord) {
		r.ExitCode = &exitCode
		r.WatchdogKilled = watchdogKilled
		r.At = at.UTC()
	})
}

func updateOpenRun(path, runID string, fn func(*RunRecord)) error {
	if runID == "" {
		return ErrNoOpenRun
	}
	recs, maxSeq := readRunFile(path)
	for i := range recs {
		// An abandoned record is revivable by its own run: its late
		// finalize or marker records the real outcome.
		if r := recs[i]; r.RunID == runID && r.ExitCode == nil && !r.WatchdogKilled {
			recs[i].Abandoned = false
			fn(&recs[i])
			return writeRuns(path, recs, runID, maxSeq)
		}
	}
	return ErrNoOpenRun
}

// RunVerdict is the health reading of one run record (spec §4).
type RunVerdict int

const (
	// RunOpen: not finalized (still running, or the bootstrap died).
	RunOpen RunVerdict = iota
	// RunHealthy: the started marker is set, no panic exit, no watchdog kill.
	RunHealthy
	// RunBad: a watchdog kill, exit code 2 (Go panic), or an exit before the
	// started marker with a crash-like code (anything but 0 or 1).
	RunBad
	// RunNeutral: exited 0 or 1 without the started marker. That is how the
	// agent ends when the backend is unreachable or another scan holds the
	// instance lock; spec §4 says environmental failures are not bad runs.
	RunNeutral
)

// cannotStartExitCode is the launcher's "couldn't start the agent" (D5).
const cannotStartExitCode = 70

// sessionEnd reports exits caused by the user's session ending, not by the
// version: 130 (the agent's SIGTERM path, which Go maps CTRL_CLOSE /
// CTRL_LOGOFF / CTRL_SHUTDOWN events to), STATUS_CONTROL_C_EXIT 0xC000013A
// and DBG_TERMINATE_PROCESS 0x40010004 (a process terminated at logoff or
// shutdown). Compared as uint32, so the int32 and uint32 forms both match.
func sessionEnd(code int) bool {
	switch uint32(code) { // #nosec G115 -- Windows exit codes are 32-bit
	case 130, 0xC000013A, 0x40010004:
		return true
	}
	return false
}

// panicExitCode is the exit status of an unrecovered Go panic (and of the
// agent's watchdog hard-out).
const panicExitCode = 2

// ClassifyRun applies the bad-run rule to one record.
func ClassifyRun(r RunRecord) RunVerdict {
	switch {
	case r.Abandoned:
		// Its launch died unrecorded: neither a crash nor a scan.
		return RunNeutral
	case r.WatchdogKilled:
		return RunBad
	case r.ExitCode == nil:
		return RunOpen
	case *r.ExitCode == panicExitCode || *r.ExitCode == cannotStartExitCode:
		// Kills and crashes are judged before the started marker: a version
		// that crashes or hangs after posting started is still bad.
		return RunBad
	case r.Started:
		return RunHealthy
	case *r.ExitCode == 0 || *r.ExitCode == 1 || sessionEnd(*r.ExitCode):
		return RunNeutral
	default:
		return RunBad
	}
}
