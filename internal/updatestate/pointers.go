package updatestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Pointers is the frozen bootstrap read contract of state.json: the fields
// every bootstrap, including the first one ever shipped, must keep reading.
// Probation and Updater are only filled for schema 1; a higher schema is read
// as current/previous only and never as corrupt.
type Pointers struct {
	Schema    int
	Current   string
	Previous  string
	Probation string // probation version, "" when none (schema 1 only)
	// Updater bookkeeping (schema 1 only).
	UpdaterVersion  string
	UpdaterFailures int
}

// LoadPointers reads state.json for the bootstrap through the frozen read
// contract (R-B-1): only schema (an integer >= 1), current (strict x.y.z) and
// previous (strict x.y.z, else dropped) decide whether the state is usable;
// no other field is validated, for any schema, so a future writer can change
// everything else without stranding first-generation bootstraps on the seed.
// Probation and updater are read best-effort, for any schema, for the update
// verb's selection: anything malformed there reads as absent, never corrupt.
// The (p, corrupt, err) contract matches Load.
func LoadPointers(path string) (p *Pointers, corrupt bool, err error) {
	data, err := readBounded(path, maxStateSize)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	case errors.Is(err, errUnreadable):
		return nil, true, nil
	case err != nil:
		return nil, false, err
	}
	p, derr := decodePointers(data)
	if derr != nil {
		return nil, true, nil
	}
	return p, false, nil
}

func decodePointers(data []byte) (*Pointers, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var p Pointers
	if err := json.Unmarshal(raw["schema"], &p.Schema); err != nil || p.Schema < SchemaVersion {
		return nil, fmt.Errorf("unsupported schema %s", raw["schema"])
	}
	if err := json.Unmarshal(raw["current"], &p.Current); err != nil || !validVersion(p.Current) {
		return nil, fmt.Errorf("invalid current %s", raw["current"])
	}
	if json.Unmarshal(raw["previous"], &p.Previous) != nil || !validVersion(p.Previous) {
		p.Previous = ""
	}
	// Existing fields keep their meaning in every schema (additive-only
	// contract), so probation/updater are read for any schema, best-effort.
	var prob struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw["probation"], &prob) == nil {
		p.Probation = prob.Version
	}
	var upd struct {
		Version             string `json:"version"`
		ConsecutiveFailures int    `json:"consecutive_failures"`
	}
	if json.Unmarshal(raw["updater"], &upd) == nil {
		p.UpdaterVersion, p.UpdaterFailures = upd.Version, upd.ConsecutiveFailures
	}
	return &p, nil
}

// Fallback reasons for the bootstrap's EnvBootstrapFallback. Reasons about a
// named version carry it after a colon (current_missing:1.20.0) so the agent
// can report update_pointer_invalid with update_from = that version.
const (
	FallbackStateMissing      = "state_missing"
	FallbackStateCorrupt      = "state_corrupt"
	FallbackStateUnreadable   = "state_unreadable"
	FallbackCurrentMissing    = "current_missing"
	FallbackCurrentIncomplete = "current_incomplete"
	FallbackStartFailed       = "start_failed"
	FallbackUpdaterFailed     = "updater_failed"
	FallbackNoUpdater         = "no_confirmed_updater"
	FallbackNothingRunnable   = "no_runnable_version"
)

// VersionDirUsable reports whether dir holds LauncherFile and AgentFile as
// non-empty regular files: what the bootstrap needs to launch a version.
// It is file presence only; integrity is the updater's manifest check
// (VerifyVersionDir), not the bootstrap's.
func VersionDirUsable(dir string) bool {
	for _, name := range []string{LauncherFile, AgentFile} {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
			return false
		}
	}
	return true
}

// FindSeed returns the newest usable seed\<v>\ version.
func (l Layout) FindSeed() (Version, bool) {
	entries, err := os.ReadDir(filepath.Join(l.InstallRoot, "seed"))
	if err != nil {
		return Version{}, false
	}
	var best Version
	found := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		v, err := ParseVersion(e.Name())
		if err != nil || !VersionDirUsable(l.SeedDir(v)) {
			continue
		}
		if !found || Compare(v, best) > 0 {
			best, found = v, true
		}
	}
	return best, found
}

// RunChoice is one launchable directory in the bootstrap's run order.
type RunChoice struct {
	Version Version
	Dir     string
	Reason  string // why this is not the state's current; "" when it is
}

// LoadReason maps a LoadPointers/Load result to a fallback reason, "" when
// a state was read.
func LoadReason(found bool, corrupt bool, err error) string {
	switch {
	case err != nil:
		return FallbackStateUnreadable
	case corrupt:
		return FallbackStateCorrupt
	case !found:
		return FallbackStateMissing
	}
	return ""
}

// CheckVersionDir validates versions\<s>\ and returns its version, or the
// fallback reason (current_missing / current_incomplete) it is unusable.
func (l Layout) CheckVersionDir(s string) (Version, string) {
	v, err := ParseVersion(s)
	if err != nil {
		return Version{}, FallbackCurrentMissing + ":" + s
	}
	dir := l.VersionDir(v)
	if _, err := os.Lstat(dir); err != nil {
		return Version{}, FallbackCurrentMissing + ":" + s
	}
	if !VersionDirUsable(dir) {
		return Version{}, FallbackCurrentIncomplete + ":" + s
	}
	return v, ""
}

// ResolveRunChain orders current → previous → seed, skipping unusable
// directories. p is the LoadPointers result (nil when missing or corrupt);
// stateReason is LoadReason of that load. Every choice after the state's
// current carries the reason current was not used.
func ResolveRunChain(l Layout, p *Pointers, stateReason string) []RunChoice {
	var out []RunChoice
	seen := map[Version]bool{}
	reason := stateReason
	if p != nil {
		if v, why := l.CheckVersionDir(p.Current); why == "" {
			out = append(out, RunChoice{Version: v, Dir: l.VersionDir(v)})
			seen[v] = true
		} else {
			reason = why
		}
		if p.Previous != "" && p.Previous != p.Current {
			if v, why := l.CheckVersionDir(p.Previous); why == "" && !seen[v] {
				out = append(out, RunChoice{Version: v, Dir: l.VersionDir(v), Reason: reason})
				seen[v] = true
			}
		}
	}
	if v, ok := l.FindSeed(); ok {
		out = append(out, RunChoice{Version: v, Dir: l.SeedDir(v), Reason: reason})
	}
	return out
}

// ResolveRunVersion is the version a scan launched now would run for st
// (nil = missing or corrupt state), with the fallback reason ("" when it is
// st.Current). With nothing runnable it returns the zero Version and
// FallbackNothingRunnable.
func ResolveRunVersion(l Layout, st *State) (Version, string) {
	var p *Pointers
	if st != nil {
		p = &Pointers{Schema: st.Schema, Current: st.Current, Previous: st.Previous}
	}
	chain := ResolveRunChain(l, p, LoadReason(st != nil, false, nil))
	if len(chain) == 0 {
		return Version{}, FallbackNothingRunnable
	}
	return chain[0].Version, chain[0].Reason
}

// RunLockFile is the lock beside runs\<v>.json that every read-modify-write
// of that file takes (R-B-2): the bootstrap's AppendRun/FinalizeRun and the
// agent's MarkRunStarted, so overlapping scan tasks never lose a record.
func (l Layout) RunLockFile(v Version) string { return RunLockPath(l.RunFile(v)) }

// ErrNotRecordable means SaveUpdaterRecord found no state it may patch: the
// file is missing or its pointers (schema/current/previous) are unreadable.
var ErrNotRecordable = errors.New("updatestate: state not recordable by this build")

// SaveUpdaterRecord rewrites only state.updater.{version,consecutive_failures}
// via fn, through the same tolerant read as LoadPointers (D18): every other
// byte of the file, including values this build's Load would reject and
// unknown keys inside updater, is kept. Written atomically with checkpoints
// <prefix>.state-temp / <prefix>.state-renamed. Call it with the update lock
// held.
func SaveUpdaterRecord(path, prefix string, fn func(version string, failures int) (string, int)) error {
	data, err := readBounded(path, maxStateSize)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errUnreadable) {
			return ErrNotRecordable
		}
		return err
	}
	// Any schema >= 1: updater.version/consecutive_failures keep their meaning
	// in every schema, and the rest of the file (schema included) is kept.
	p, err := decodePointers(data)
	if err != nil {
		return ErrNotRecordable
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return ErrNotRecordable
	}
	upd := map[string]json.RawMessage{}
	if json.Unmarshal(raw["updater"], &upd) != nil || upd == nil {
		upd = map[string]json.RawMessage{}
	}
	version, failures := fn(p.UpdaterVersion, p.UpdaterFailures)
	if failures < 0 {
		failures = 0
	}
	if upd["version"], err = json.Marshal(version); err != nil {
		return err
	}
	if upd["consecutive_failures"], err = json.Marshal(failures); err != nil {
		return err
	}
	if raw["updater"], err = json.Marshal(upd); err != nil {
		return err
	}
	// Bump generation like every state writer (the updater decides whether
	// its own write landed by generation).
	var gen uint64
	_ = json.Unmarshal(raw["generation"], &gen)
	if raw["generation"], err = json.Marshal(gen + 1); err != nil {
		return err
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	var afterTemp, afterRename func() error
	if prefix != "" {
		afterTemp = func() error { return checkpoint(prefix + ".state-temp") }
		afterRename = func() error { return checkpoint(prefix + ".state-renamed") }
	}
	return writeAtomic(path, append(out, '\n'), afterTemp, afterRename)
}
