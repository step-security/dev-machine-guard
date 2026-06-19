package telemetry

import (
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/state"
)

// deltaSnapshot is the partitioned view of one run's scan output. Built after
// scanning but before payload assembly so the payload can route each project
// to its correct slot (full body for changed, ref for unchanged or removed).
// Carries both the wire-ready slices and the state.ScanRecord lists needed
// for the post-upload commit.
type deltaSnapshot struct {
	fullSync bool

	npmRecords          []state.ScanRecord
	npmChanged          []model.NodeScanResult
	npmUnchanged        []model.UnchangedProjectRef
	npmRemoved          []model.RemovedProjectRef
	npmGlobalRecords    []state.GlobalRecord
	npmGlobalsChanged   []model.NodeScanResult
	npmGlobalsUnchanged []model.UnchangedGlobalRef

	pyRecords          []state.ScanRecord
	pyChanged          []model.ProjectInfo
	pyUnchanged        []model.UnchangedProjectRef
	pyRemoved          []model.RemovedProjectRef
	pyGlobalRecords    []state.GlobalRecord
	pyGlobalsChanged   []model.PythonScanResult
	pyGlobalsUnchanged []model.UnchangedGlobalRef
}

// buildDeltaSnapshot runs the partition / reconcile / pending-removal
// pipeline against the freshly-scanned outputs. It mutates the in-memory
// state (appends to RemovedPendingAck) but does NOT persist — only
// commitDeltaSnapshot, called after a successful upload, calls state.Save.
// A nil scan state means delta is disabled and the caller should use the
// legacy payload shape.
func buildDeltaSnapshot(
	s *state.State, fullSync bool,
	npmResults []model.NodeScanResult, npmDiscovered []string,
	pythonResults []model.ProjectInfo, pythonDiscovered []string,
	npmGlobals []model.NodeScanResult, pythonGlobals []model.PythonScanResult,
) *deltaSnapshot {
	if s == nil {
		return nil
	}
	snap := &deltaSnapshot{fullSync: fullSync}

	snap.npmRecords = npmRecordsFromResults(npmResults)
	snap.pyRecords = pythonRecordsFromResults(pythonResults)
	snap.npmGlobalRecords = globalRecordsFromNode(npmGlobals)
	snap.pyGlobalRecords = globalRecordsFromPython(pythonGlobals)

	npmChangedPaths, npmUnchangedPaths := s.Partition(state.EcosystemNPM, snap.npmRecords, fullSync)
	pyChangedPaths, pyUnchangedPaths := s.Partition(state.EcosystemPython, snap.pyRecords, fullSync)
	npmGChanged, npmGUnchanged := s.PartitionGlobals(state.EcosystemNPM, snap.npmGlobalRecords, fullSync)
	pyGChanged, pyGUnchanged := s.PartitionGlobals(state.EcosystemPython, snap.pyGlobalRecords, fullSync)

	snap.npmChanged, snap.npmUnchanged = splitNodeProjects(s.NPMProjects, npmResults, snap.npmRecords, npmChangedPaths, npmUnchangedPaths)
	snap.pyChanged, snap.pyUnchanged = splitPythonProjects(s.PythonProjects, pythonResults, snap.pyRecords, pyChangedPaths, pyUnchangedPaths)
	snap.npmGlobalsChanged, snap.npmGlobalsUnchanged = splitNodeGlobals(s.NPMGlobal, npmGlobals, snap.npmGlobalRecords, npmGChanged, npmGUnchanged)
	snap.pyGlobalsChanged, snap.pyGlobalsUnchanged = splitPythonGlobals(s.PythonGlobal, pythonGlobals, snap.pyGlobalRecords, pyGChanged, pyGUnchanged)

	now := time.Now()
	_, _, npmRemovedPaths := s.Reconcile(state.EcosystemNPM, npmDiscovered)
	_, _, pyRemovedPaths := s.Reconcile(state.EcosystemPython, pythonDiscovered)
	s.MarkRemovedPending(state.EcosystemNPM, npmRemovedPaths, now)
	s.MarkRemovedPending(state.EcosystemPython, pyRemovedPaths, now)

	snap.npmRemoved = removedRefsFor(s, state.EcosystemNPM, npmDiscovered)
	snap.pyRemoved = removedRefsFor(s, state.EcosystemPython, pythonDiscovered)
	return snap
}

func npmRecordsFromResults(results []model.NodeScanResult) []state.ScanRecord {
	out := make([]state.ScanRecord, 0, len(results))
	for _, r := range results {
		if r.ProjectPath == "" {
			continue
		}
		out = append(out, state.ScanRecordFromBase64(
			r.ProjectPath, r.PackageManager, r.PMVersion, r.RawStdoutBase64, r.ExitCode,
		))
	}
	return out
}

func pythonRecordsFromResults(results []model.ProjectInfo) []state.ScanRecord {
	out := make([]state.ScanRecord, 0, len(results))
	for _, r := range results {
		if r.Path == "" {
			continue
		}
		exitCode := 0
		if r.Packages == nil {
			exitCode = 1
		}
		out = append(out, state.ScanRecordFromValue(
			r.Path, r.PackageManager, "", r.Packages, exitCode,
		))
	}
	return out
}

func globalRecordsFromNode(results []model.NodeScanResult) []state.GlobalRecord {
	out := make([]state.GlobalRecord, 0, len(results))
	for _, r := range results {
		if r.PackageManager == "" {
			continue
		}
		hash, _ := state.CanonicalHashJSON(decodeBase64OrRaw(r.RawStdoutBase64))
		out = append(out, state.GlobalRecord{PM: r.PackageManager, Hash: hash, ExitCode: r.ExitCode})
	}
	return out
}

func globalRecordsFromPython(results []model.PythonScanResult) []state.GlobalRecord {
	out := make([]state.GlobalRecord, 0, len(results))
	for _, r := range results {
		if r.PackageManager == "" {
			continue
		}
		hash, _ := state.CanonicalHashJSON(decodeBase64OrRaw(r.RawStdoutBase64))
		out = append(out, state.GlobalRecord{PM: r.PackageManager, Hash: hash, ExitCode: r.ExitCode})
	}
	return out
}

func splitNodeProjects(
	prior map[string]state.ProjectEntry,
	results []model.NodeScanResult,
	records []state.ScanRecord,
	changedPaths, unchangedPaths []string,
) ([]model.NodeScanResult, []model.UnchangedProjectRef) {
	changedSet := setFromStrings(changedPaths)
	unchangedSet := setFromStrings(unchangedPaths)
	hashByPath := hashesByPath(records)

	changed := make([]model.NodeScanResult, 0, len(changedPaths))
	unchanged := make([]model.UnchangedProjectRef, 0, len(unchangedPaths))
	for _, r := range results {
		if _, ok := changedSet[r.ProjectPath]; ok {
			changed = append(changed, r)
			continue
		}
		if _, ok := unchangedSet[r.ProjectPath]; ok {
			unchanged = append(unchanged, model.UnchangedProjectRef{
				Path:                    r.ProjectPath,
				ScanOutputHash:          hashByPath[r.ProjectPath],
				LastUploadedExecutionID: prior[r.ProjectPath].LastUploadedExecutionID,
			})
		}
	}
	return changed, unchanged
}

func splitPythonProjects(
	prior map[string]state.ProjectEntry,
	results []model.ProjectInfo,
	records []state.ScanRecord,
	changedPaths, unchangedPaths []string,
) ([]model.ProjectInfo, []model.UnchangedProjectRef) {
	changedSet := setFromStrings(changedPaths)
	unchangedSet := setFromStrings(unchangedPaths)
	hashByPath := hashesByPath(records)

	changed := make([]model.ProjectInfo, 0, len(changedPaths))
	unchanged := make([]model.UnchangedProjectRef, 0, len(unchangedPaths))
	for _, r := range results {
		if _, ok := changedSet[r.Path]; ok {
			changed = append(changed, r)
			continue
		}
		if _, ok := unchangedSet[r.Path]; ok {
			unchanged = append(unchanged, model.UnchangedProjectRef{
				Path:                    r.Path,
				ScanOutputHash:          hashByPath[r.Path],
				LastUploadedExecutionID: prior[r.Path].LastUploadedExecutionID,
			})
		}
	}
	return changed, unchanged
}

func splitNodeGlobals(
	prior map[string]state.GlobalEntry,
	results []model.NodeScanResult,
	records []state.GlobalRecord,
	changedPMs, unchangedPMs []string,
) ([]model.NodeScanResult, []model.UnchangedGlobalRef) {
	changedSet := setFromStrings(changedPMs)
	unchangedSet := setFromStrings(unchangedPMs)
	hashByPM := hashesByPM(records)

	changed := make([]model.NodeScanResult, 0, len(changedPMs))
	unchanged := make([]model.UnchangedGlobalRef, 0, len(unchangedPMs))
	for _, r := range results {
		if _, ok := changedSet[r.PackageManager]; ok {
			changed = append(changed, r)
			continue
		}
		if _, ok := unchangedSet[r.PackageManager]; ok {
			unchanged = append(unchanged, model.UnchangedGlobalRef{
				PackageManager:          r.PackageManager,
				ScanOutputHash:          hashByPM[r.PackageManager],
				LastUploadedExecutionID: prior[r.PackageManager].LastUploadedExecutionID,
			})
		}
	}
	return changed, unchanged
}

func splitPythonGlobals(
	prior map[string]state.GlobalEntry,
	results []model.PythonScanResult,
	records []state.GlobalRecord,
	changedPMs, unchangedPMs []string,
) ([]model.PythonScanResult, []model.UnchangedGlobalRef) {
	changedSet := setFromStrings(changedPMs)
	unchangedSet := setFromStrings(unchangedPMs)
	hashByPM := hashesByPM(records)

	changed := make([]model.PythonScanResult, 0, len(changedPMs))
	unchanged := make([]model.UnchangedGlobalRef, 0, len(unchangedPMs))
	for _, r := range results {
		if _, ok := changedSet[r.PackageManager]; ok {
			changed = append(changed, r)
			continue
		}
		if _, ok := unchangedSet[r.PackageManager]; ok {
			unchanged = append(unchanged, model.UnchangedGlobalRef{
				PackageManager:          r.PackageManager,
				ScanOutputHash:          hashByPM[r.PackageManager],
				LastUploadedExecutionID: prior[r.PackageManager].LastUploadedExecutionID,
			})
		}
	}
	return changed, unchanged
}

// removedRefsFor returns refs for every pending-ack entry in the ecosystem,
// EXCLUDING paths that are present in `discovered`. A project that reappears
// before its prior removal was confirmed by the backend should not be
// reported as removed on this run.
func removedRefsFor(s *state.State, ecosystem string, discovered []string) []model.RemovedProjectRef {
	discoveredSet := setFromStrings(discovered)
	pending := s.PendingRemovalsFor(ecosystem)
	out := make([]model.RemovedProjectRef, 0, len(pending))
	for _, p := range pending {
		if _, ok := discoveredSet[p.Path]; ok {
			continue
		}
		var lastExec string
		switch ecosystem {
		case state.EcosystemNPM:
			lastExec = s.NPMProjects[p.Path].LastUploadedExecutionID
		case state.EcosystemPython:
			lastExec = s.PythonProjects[p.Path].LastUploadedExecutionID
		}
		out = append(out, model.RemovedProjectRef{Path: p.Path, LastUploadedExecutionID: lastExec})
	}
	return out
}

// commitDeltaSnapshot persists the run's outcome after a successful upload:
// upserts state entries for successful scans, acks the removals the wire
// reported (drops them from pending_ack and from the main maps), and
// atomically saves the file.
func commitDeltaSnapshot(s *state.State, snap *deltaSnapshot, path, executionID, agentVersion string) error {
	now := time.Now()
	s.CommitAfterUpload(now, executionID, agentVersion,
		snap.npmRecords, snap.pyRecords,
		snap.npmGlobalRecords, snap.pyGlobalRecords,
		snap.fullSync,
	)
	ackNPM := pendingFromRefs(state.EcosystemNPM, snap.npmRemoved)
	ackPy := pendingFromRefs(state.EcosystemPython, snap.pyRemoved)
	s.AckRemovals(append(ackNPM, ackPy...))
	s.DropRemovedFromProjects(state.EcosystemNPM, pathsFromRemovedRefs(snap.npmRemoved))
	s.DropRemovedFromProjects(state.EcosystemPython, pathsFromRemovedRefs(snap.pyRemoved))
	return s.Save(path)
}

func pendingFromRefs(ecosystem string, refs []model.RemovedProjectRef) []state.PendingRemoval {
	out := make([]state.PendingRemoval, 0, len(refs))
	for _, r := range refs {
		out = append(out, state.PendingRemoval{Path: r.Path, Ecosystem: ecosystem})
	}
	return out
}

func pathsFromRemovedRefs(refs []model.RemovedProjectRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Path)
	}
	return out
}

func setFromStrings(xs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		out[x] = struct{}{}
	}
	return out
}

func hashesByPath(records []state.ScanRecord) map[string]string {
	out := make(map[string]string, len(records))
	for _, r := range records {
		out[r.Path] = r.Hash
	}
	return out
}

func hashesByPM(records []state.GlobalRecord) map[string]string {
	out := make(map[string]string, len(records))
	for _, r := range records {
		out[r.PM] = r.Hash
	}
	return out
}
