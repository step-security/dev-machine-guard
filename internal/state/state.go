package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// SchemaVersion is the on-disk format version. Bump when the JSON shape changes
// in a way Load can't transparently migrate. Older versions are treated as
// empty state — a corrupt or unmigratable file must never break a scan.
const SchemaVersion = 1

// Ecosystem identifiers used for routing in Reconcile / Partition / Commit.
const (
	EcosystemNPM    = "npm"
	EcosystemPython = "python"
)

// DefaultFullSyncHorizon is the maximum gap between successful uploads before
// the next run is forced to treat every discovered project as `changed`.
// Counters push-only drift: agent cannot detect backend data loss, so it
// re-asserts the full picture periodically.
const DefaultFullSyncHorizon = 7 * 24 * time.Hour

// ProjectEntry is one project's last-successfully-uploaded record. Used for
// both npm and Python project maps in State.
type ProjectEntry struct {
	ScanOutputHash          string    `json:"scan_output_hash"`
	LastUploadedExecutionID string    `json:"last_uploaded_execution_id"`
	LastUploadedAt          time.Time `json:"last_uploaded_at"`
	LastVerifiedAt          time.Time `json:"last_verified_at"`
	FirstSeenAt             time.Time `json:"first_seen_at"`
	PackageManager          string    `json:"pm"`
	PMVersion               string    `json:"pm_version,omitempty"`
}

// GlobalEntry is one PM's last-successfully-uploaded global-packages record.
// Keyed by PM name in State.NPMGlobal / State.PythonGlobal.
type GlobalEntry struct {
	ScanOutputHash          string    `json:"scan_output_hash"`
	LastUploadedExecutionID string    `json:"last_uploaded_execution_id"`
	LastUploadedAt          time.Time `json:"last_uploaded_at"`
	LastVerifiedAt          time.Time `json:"last_verified_at"`
}

// PendingRemoval is a project that has disappeared from disk but whose
// corresponding `removed` payload entry has not yet been confirmed by the
// backend. Survives across runs until AckRemovals drops it.
type PendingRemoval struct {
	Path      string    `json:"path"`
	Ecosystem string    `json:"ecosystem"`
	RemovedAt time.Time `json:"removed_at"`
}

// State is the on-disk envelope. Marshaled as scan-state.json.
type State struct {
	SchemaVersion             int                     `json:"schema_version"`
	AgentVersion              string                  `json:"agent_version"`
	LastFullSyncAt            time.Time               `json:"last_full_sync_at"`
	LastSuccessfulExecutionID string                  `json:"last_successful_execution_id,omitempty"`
	NPMProjects               map[string]ProjectEntry `json:"npm_projects"`
	PythonProjects            map[string]ProjectEntry `json:"python_projects"`
	NPMGlobal                 map[string]GlobalEntry  `json:"npm_global"`
	PythonGlobal              map[string]GlobalEntry  `json:"python_global"`
	RemovedPendingAck         []PendingRemoval        `json:"removed_pending_ack"`
}

// New returns a zero-value state stamped with the running agent version. Used
// when Load finds no file or refuses to migrate from a foreign schema.
func New(agentVersion string) *State {
	return &State{
		SchemaVersion:     SchemaVersion,
		AgentVersion:      agentVersion,
		NPMProjects:       map[string]ProjectEntry{},
		PythonProjects:    map[string]ProjectEntry{},
		NPMGlobal:         map[string]GlobalEntry{},
		PythonGlobal:      map[string]GlobalEntry{},
		RemovedPendingAck: []PendingRemoval{},
	}
}

// Load reads scan-state.json. Missing file, parse error, or schema mismatch
// returns a fresh empty state — the next run becomes a full sync naturally.
// The returned error is non-nil only for read or parse failures (to surface
// the cause for logging); missing file and schema mismatch return a nil error
// because those are expected fall-throughs.
func Load(path, agentVersion string) (*State, error) {
	cleanedPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanedPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return New(agentVersion), nil
		}
		return New(agentVersion), err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return New(agentVersion), err
	}
	if s.SchemaVersion != SchemaVersion {
		return New(agentVersion), nil
	}
	// Nil maps after unmarshal of `null` or missing fields — normalize so
	// callers never have to nil-check.
	if s.NPMProjects == nil {
		s.NPMProjects = map[string]ProjectEntry{}
	}
	if s.PythonProjects == nil {
		s.PythonProjects = map[string]ProjectEntry{}
	}
	if s.NPMGlobal == nil {
		s.NPMGlobal = map[string]GlobalEntry{}
	}
	if s.PythonGlobal == nil {
		s.PythonGlobal = map[string]GlobalEntry{}
	}
	return &s, nil
}

// Save writes scan-state.json atomically: write tmp sibling, fsync, rename.
// On any error before the rename the original file is untouched.
func (s *State) Save(path string) error {
	cleanedPath := filepath.Clean(path)
	dir := filepath.Dir(cleanedPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".scan-state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	// Windows os.Rename fails when the destination already exists, so the
	// second save would silently stop overwriting. POSIX rename atomically
	// replaces, making this Remove a no-op there. Same pattern as
	// internal/progress/filelog/filelog.go RotateIfOverCap.
	_ = os.Remove(cleanedPath)
	if err := os.Rename(tmpPath, cleanedPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// IsFullSyncDue returns true when the next upload must include every
// discovered project regardless of hash match. Triggered by:
//   - LastFullSyncAt older than `horizon`
//   - AgentVersion in state differs from the running binary (payload-format
//     drift insurance after agent upgrades).
func (s *State) IsFullSyncDue(now time.Time, runningAgentVersion string, horizon time.Duration) bool {
	if s.AgentVersion != runningAgentVersion {
		return true
	}
	if s.LastFullSyncAt.IsZero() {
		return true
	}
	return now.Sub(s.LastFullSyncAt) >= horizon
}

// Reconcile splits the discovered project set against per-ecosystem state.
//
//	unknown — discovered AND not in state; caller orders by mtime desc.
//	known   — discovered AND in state; returned sorted by LastVerifiedAt
//	          ascending so the planner re-verifies the staleest first.
//	removed — in state AND not in discovered.
//
// Returned slices are independent; the caller may sort/cap them freely.
func (s *State) Reconcile(ecosystem string, discovered []string) (unknown, known, removed []string) {
	entries := s.projectMap(ecosystem)
	discoveredSet := make(map[string]struct{}, len(discovered))
	for _, p := range discovered {
		discoveredSet[p] = struct{}{}
		if _, ok := entries[p]; ok {
			known = append(known, p)
		} else {
			unknown = append(unknown, p)
		}
	}
	for p := range entries {
		if _, ok := discoveredSet[p]; !ok {
			removed = append(removed, p)
		}
	}
	sort.Slice(known, func(i, j int) bool {
		return entries[known[i]].LastVerifiedAt.Before(entries[known[j]].LastVerifiedAt)
	})
	sort.Strings(removed)
	return unknown, known, removed
}

// ScanRecord is the caller's per-project result fed into Partition and Commit.
// ExitCode == 0 means the PM CLI succeeded; failed scans are never cached so
// the next run retries them.
type ScanRecord struct {
	Path           string
	Hash           string
	PackageManager string
	PMVersion      string
	ExitCode       int
}

// Partition classifies scanned project records against the stored hash.
// A record is `changed` when no prior entry exists OR the stored hash differs.
// A record is `unchanged` when stored hash matches the scanned hash. Failed
// scans (ExitCode != 0) always count as `changed` — we can't claim the prior
// snapshot is still accurate. `fullSync` forces every record into `changed`.
func (s *State) Partition(ecosystem string, scanned []ScanRecord, fullSync bool) (changed, unchanged []string) {
	entries := s.projectMap(ecosystem)
	for _, r := range scanned {
		if fullSync || r.ExitCode != 0 {
			changed = append(changed, r.Path)
			continue
		}
		prev, ok := entries[r.Path]
		if !ok || prev.ScanOutputHash != r.Hash {
			changed = append(changed, r.Path)
			continue
		}
		unchanged = append(unchanged, r.Path)
	}
	return changed, unchanged
}

// GlobalRecord is the caller's per-PM globals result for npm/Python globals.
type GlobalRecord struct {
	PM       string
	Hash     string
	ExitCode int
}

// PartitionGlobals classifies global-scan records by PM. Same rules as
// Partition — failed scans always `changed`, fullSync forces `changed`.
func (s *State) PartitionGlobals(ecosystem string, scanned []GlobalRecord, fullSync bool) (changed, unchanged []string) {
	entries := s.globalMap(ecosystem)
	for _, r := range scanned {
		if fullSync || r.ExitCode != 0 {
			changed = append(changed, r.PM)
			continue
		}
		prev, ok := entries[r.PM]
		if !ok || prev.ScanOutputHash != r.Hash {
			changed = append(changed, r.PM)
			continue
		}
		unchanged = append(unchanged, r.PM)
	}
	return changed, unchanged
}

// MarkRemovedPending appends paths to RemovedPendingAck (dedup by path +
// ecosystem). Called once per run, before payload assembly, so the upload's
// `removed` list is built from the pending-ack tail rather than this run's
// fresh diff alone — that's what survives the commit-after-confirm ordering.
func (s *State) MarkRemovedPending(ecosystem string, paths []string, now time.Time) {
	existing := make(map[string]struct{}, len(s.RemovedPendingAck))
	for _, e := range s.RemovedPendingAck {
		existing[e.Ecosystem+"|"+e.Path] = struct{}{}
	}
	for _, p := range paths {
		key := ecosystem + "|" + p
		if _, ok := existing[key]; ok {
			continue
		}
		s.RemovedPendingAck = append(s.RemovedPendingAck, PendingRemoval{
			Path:      p,
			Ecosystem: ecosystem,
			RemovedAt: now,
		})
		existing[key] = struct{}{}
	}
}

// PendingRemovalsFor returns the current pending-ack entries for an ecosystem.
// Callers use the returned slice to build the payload's `removed` list and
// then pass it back to AckRemovals after confirm-upload succeeds.
func (s *State) PendingRemovalsFor(ecosystem string) []PendingRemoval {
	out := make([]PendingRemoval, 0, len(s.RemovedPendingAck))
	for _, e := range s.RemovedPendingAck {
		if e.Ecosystem == ecosystem {
			out = append(out, e)
		}
	}
	return out
}

// AckRemovals drops the given (ecosystem, path) pairs from RemovedPendingAck.
// Called only after confirm-upload returns 200 for an upload that included
// those removals.
func (s *State) AckRemovals(acked []PendingRemoval) {
	if len(acked) == 0 {
		return
	}
	drop := make(map[string]struct{}, len(acked))
	for _, e := range acked {
		drop[e.Ecosystem+"|"+e.Path] = struct{}{}
	}
	kept := s.RemovedPendingAck[:0]
	for _, e := range s.RemovedPendingAck {
		if _, ok := drop[e.Ecosystem+"|"+e.Path]; ok {
			continue
		}
		kept = append(kept, e)
	}
	s.RemovedPendingAck = kept
}

// CommitAfterUpload applies a successful upload's effects to the in-memory
// state. The caller must call Save afterward to persist. Effects:
//
//   - For every scanned record with ExitCode == 0: upsert the project entry
//     with this run's hash, execution_id, and timestamps. FirstSeenAt is
//     preserved when present; LastVerifiedAt is always bumped.
//   - LastSuccessfulExecutionID and AgentVersion are stamped.
//   - If fullSync: refresh LastFullSyncAt.
//
// Failed scans are intentionally not touched — next run retries them and the
// previous successful hash (if any) stays valid for the unchanged-skip path.
func (s *State) CommitAfterUpload(
	now time.Time,
	executionID, runningAgentVersion string,
	npmScanned, pythonScanned []ScanRecord,
	npmGlobals, pythonGlobals []GlobalRecord,
	fullSync bool,
) {
	s.commitProjects(EcosystemNPM, npmScanned, now, executionID)
	s.commitProjects(EcosystemPython, pythonScanned, now, executionID)
	s.commitGlobals(EcosystemNPM, npmGlobals, now, executionID)
	s.commitGlobals(EcosystemPython, pythonGlobals, now, executionID)
	s.LastSuccessfulExecutionID = executionID
	s.AgentVersion = runningAgentVersion
	if fullSync {
		s.LastFullSyncAt = now
	}
}

func (s *State) commitProjects(ecosystem string, scanned []ScanRecord, now time.Time, executionID string) {
	entries := s.projectMap(ecosystem)
	for _, r := range scanned {
		if r.ExitCode != 0 {
			continue
		}
		prev, existed := entries[r.Path]
		next := ProjectEntry{
			ScanOutputHash:          r.Hash,
			LastUploadedExecutionID: executionID,
			LastUploadedAt:          now,
			LastVerifiedAt:          now,
			PackageManager:          r.PackageManager,
			PMVersion:               r.PMVersion,
		}
		if existed && !prev.FirstSeenAt.IsZero() {
			next.FirstSeenAt = prev.FirstSeenAt
		} else {
			next.FirstSeenAt = now
		}
		entries[r.Path] = next
	}
}

func (s *State) commitGlobals(ecosystem string, scanned []GlobalRecord, now time.Time, executionID string) {
	entries := s.globalMap(ecosystem)
	for _, r := range scanned {
		if r.ExitCode != 0 {
			continue
		}
		entries[r.PM] = GlobalEntry{
			ScanOutputHash:          r.Hash,
			LastUploadedExecutionID: executionID,
			LastUploadedAt:          now,
			LastVerifiedAt:          now,
		}
	}
}

// BumpVerified updates LastVerifiedAt on entries whose hash matched (the
// `unchanged` bucket from Partition) without otherwise touching them. Lets the
// planner pick the staleest-verified known project next run.
func (s *State) BumpVerified(ecosystem string, paths []string, now time.Time) {
	entries := s.projectMap(ecosystem)
	for _, p := range paths {
		if e, ok := entries[p]; ok {
			e.LastVerifiedAt = now
			entries[p] = e
		}
	}
}

// BumpVerifiedGlobals updates LastVerifiedAt on global entries whose hash
// matched.
func (s *State) BumpVerifiedGlobals(ecosystem string, pms []string, now time.Time) {
	entries := s.globalMap(ecosystem)
	for _, pm := range pms {
		if e, ok := entries[pm]; ok {
			e.LastVerifiedAt = now
			entries[pm] = e
		}
	}
}

// DropRemovedFromProjects removes acknowledged-removed paths from the project
// map after AckRemovals drops them from pending. Callers running the full
// commit-after-confirm sequence should invoke this once per ecosystem with
// the paths that the backend just acked.
func (s *State) DropRemovedFromProjects(ecosystem string, paths []string) {
	entries := s.projectMap(ecosystem)
	for _, p := range paths {
		delete(entries, p)
	}
}

func (s *State) projectMap(ecosystem string) map[string]ProjectEntry {
	switch ecosystem {
	case EcosystemNPM:
		return s.NPMProjects
	case EcosystemPython:
		return s.PythonProjects
	}
	panic("state: unknown ecosystem " + ecosystem)
}

func (s *State) globalMap(ecosystem string) map[string]GlobalEntry {
	switch ecosystem {
	case EcosystemNPM:
		return s.NPMGlobal
	case EcosystemPython:
		return s.PythonGlobal
	}
	panic("state: unknown ecosystem " + ecosystem)
}
