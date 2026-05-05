package detector

import (
	"fmt"
	"sort"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// DiffNPMRC produces an NPMRCDiff describing how a fresh audit differs from
// the previous snapshot.
//
//   - prev == nil → FirstRun=true; everything else empty.
//   - per-file: appeared / disappeared / sha256 differs / metadata differs / entry list differs
//   - per env var: set transitions, value-sha rotation
//
// The diff never references plaintext: it operates only on
// already-redacted display values (in NPMRCFile.Entries) and SHA-256
// fingerprints. That guarantee is a property of NPMRCSnapshot's schema —
// see the comment on NPMRCEntryDigest.
func DiffNPMRC(prev *model.NPMRCSnapshot, current *model.NPMRCAudit, currentTakenAtUnix int64) *model.NPMRCDiff {
	if current == nil {
		return nil
	}
	diff := &model.NPMRCDiff{
		CurrentAt: currentTakenAtUnix,
	}
	if prev == nil {
		diff.FirstRun = true
		return diff
	}
	diff.PreviousAt = prev.TakenAt

	// Index previous-state files by path for O(1) lookup. Same for current
	// audit's entries, which we'll need by-path-then-by-key.
	prevByPath := make(map[string]model.NPMRCFileSnapshot, len(prev.Files))
	for _, f := range prev.Files {
		prevByPath[f.Path] = f
	}
	currentByPath := make(map[string]model.NPMRCFile, len(current.Files))
	for _, f := range current.Files {
		currentByPath[f.Path] = f
	}

	// Walk current files: anything new is "added"; anything also in prev is
	// either unchanged or modified.
	for _, cur := range current.Files {
		ps, hadBefore := prevByPath[cur.Path]
		if !hadBefore {
			// Surface the file as added if we actually see content for it.
			// A file we resolved a path for but that doesn't exist on disk
			// would have Exists=false; treating that as "added" is noisy.
			if cur.Exists {
				diff.AddedFiles = append(diff.AddedFiles, model.NPMRCFileChange{Path: cur.Path, Scope: cur.Scope})
			}
			continue
		}
		// Was-existing-now-existing: full modification check.
		// Was-existing-now-missing or vice versa is captured by the existence
		// flag — surface it as a removal/addition instead of a modification.
		if ps.Exists && !cur.Exists {
			diff.RemovedFiles = append(diff.RemovedFiles, model.NPMRCFileChange{Path: cur.Path, Scope: cur.Scope})
			continue
		}
		if !ps.Exists && cur.Exists {
			diff.AddedFiles = append(diff.AddedFiles, model.NPMRCFileChange{Path: cur.Path, Scope: cur.Scope})
			continue
		}
		if !cur.Exists && !ps.Exists {
			continue // both missing; nothing to say
		}
		mod, changed := diffFile(ps, cur)
		if changed {
			diff.ModifiedFiles = append(diff.ModifiedFiles, mod)
		}
	}

	// Walk previous files: paths that are no longer in the current audit
	// at all → file disappeared (e.g. a project was deleted).
	for _, ps := range prev.Files {
		if _, stillThere := currentByPath[ps.Path]; stillThere {
			continue
		}
		if ps.Exists {
			diff.RemovedFiles = append(diff.RemovedFiles, model.NPMRCFileChange{Path: ps.Path, Scope: ps.Scope})
		}
	}

	// Stable order so the JSON is reproducible.
	sort.SliceStable(diff.AddedFiles, func(i, j int) bool { return diff.AddedFiles[i].Path < diff.AddedFiles[j].Path })
	sort.SliceStable(diff.RemovedFiles, func(i, j int) bool { return diff.RemovedFiles[i].Path < diff.RemovedFiles[j].Path })
	sort.SliceStable(diff.ModifiedFiles, func(i, j int) bool { return diff.ModifiedFiles[i].Path < diff.ModifiedFiles[j].Path })

	curEnvSnap := envToSnapshot(current.Env)
	diff.EnvChanges = diffEnv(prev.Env, curEnvSnap)

	return diff
}

// envToSnapshot converts the live env-var slice on an audit to the digest
// form used for diffing. The display value is dropped — only Set + SHA
// matter across runs.
func envToSnapshot(env []model.NPMRCEnvVar) []model.NPMRCEnvVarSnapshot {
	out := make([]model.NPMRCEnvVarSnapshot, len(env))
	for i, e := range env {
		out[i] = model.NPMRCEnvVarSnapshot{Name: e.Name, Set: e.Set, ValueSHA256: e.ValueSHA256}
	}
	return out
}

// diffFile compares one file's previous snapshot to its current state and
// returns the modification record. The bool indicates whether anything
// actually changed — false means we should drop the record (an
// unchanged-but-existing file is not interesting).
func diffFile(prev model.NPMRCFileSnapshot, cur model.NPMRCFile) (model.NPMRCFileModification, bool) {
	mod := model.NPMRCFileModification{Path: cur.Path, Scope: cur.Scope}
	changed := false

	if prev.SHA256 != cur.SHA256 {
		mod.ContentChanged = true
		changed = true
	}
	if prev.OwnerName != cur.OwnerName {
		mod.OwnerChanged = &model.NPMRCStringChange{From: prev.OwnerName, To: cur.OwnerName}
		changed = true
	}
	if prev.GroupName != cur.GroupName {
		mod.GroupChanged = &model.NPMRCStringChange{From: prev.GroupName, To: cur.GroupName}
		changed = true
	}
	if prev.Mode != cur.Mode {
		mod.ModeChanged = &model.NPMRCStringChange{From: prev.Mode, To: cur.Mode}
		changed = true
	}
	if prev.SizeBytes != cur.SizeBytes {
		mod.SizeChanged = &model.NPMRCInt64Change{From: prev.SizeBytes, To: cur.SizeBytes}
		changed = true
	}

	// Entry-level diff. Use compound keys (key + array-suffix) so two
	// `key[]=` lines don't collide. Within an array, we identify each
	// distinct entry by its position-stable signature: key + value SHA.
	// This means an array entry with a rotated value reads as
	// removed-then-added, which is fine — surfaced clearly enough.
	prevEntries := indexEntries(prev.Entries)
	curEntries := indexEntries(toDigests(cur.Entries))

	addedKeys := []string{}
	removedKeys := []string{}
	for sig, e := range curEntries {
		if _, ok := prevEntries[sig]; !ok {
			addedKeys = append(addedKeys, sig)
			mod.AddedEntries = append(mod.AddedEntries, e)
			changed = true
		}
	}
	for sig, e := range prevEntries {
		if _, ok := curEntries[sig]; !ok {
			removedKeys = append(removedKeys, sig)
			mod.RemovedEntries = append(mod.RemovedEntries, e)
			changed = true
		}
	}

	// Value-changed: same key, distinct sha. Walk each entry by name and
	// match where the value SHA differs.
	prevByKey := groupByKey(prev.Entries)
	curByKey := groupByKey(toDigests(cur.Entries))
	for key, curList := range curByKey {
		prevList := prevByKey[key]
		// Single-value keys: compare directly.
		if len(curList) == 1 && len(prevList) == 1 {
			if prevList[0].ValueSHA256 != curList[0].ValueSHA256 {
				mod.ChangedEntries = append(mod.ChangedEntries, model.NPMRCEntryValueDiff{
					Key:            key,
					IsAuth:         curList[0].IsAuth,
					PreviousSHA256: prevList[0].ValueSHA256,
					CurrentSHA256:  curList[0].ValueSHA256,
				})
				changed = true
				// Don't double-count this as added/removed.
				removeFromList(&mod.AddedEntries, key, curList[0].ValueSHA256)
				removeFromList(&mod.RemovedEntries, key, prevList[0].ValueSHA256)
			}
		}
		// Multi-value keys (array form): the added/removed lists already
		// describe the change at the SHA-pair granularity, which is
		// sufficient. Fancier matching isn't worth the complexity for now.
	}

	if mod.AddedEntries == nil {
		mod.AddedEntries = nil // keep nil-vs-[] consistent for JSON
	}

	sort.SliceStable(mod.AddedEntries, func(i, j int) bool { return mod.AddedEntries[i].Key < mod.AddedEntries[j].Key })
	sort.SliceStable(mod.RemovedEntries, func(i, j int) bool { return mod.RemovedEntries[i].Key < mod.RemovedEntries[j].Key })
	sort.SliceStable(mod.ChangedEntries, func(i, j int) bool {
		// Auth changes float to the top — they're the most actionable.
		if mod.ChangedEntries[i].IsAuth != mod.ChangedEntries[j].IsAuth {
			return mod.ChangedEntries[i].IsAuth
		}
		return mod.ChangedEntries[i].Key < mod.ChangedEntries[j].Key
	})

	return mod, changed
}

// removeFromList drops the entry matching (key, valueSHA256) from a slice
// of NPMRCEntryDigest. Used to suppress double-counting an entry as both
// "value changed" and "added/removed". Stable; preserves order of the rest.
func removeFromList(list *[]model.NPMRCEntryDigest, key, valueSHA string) {
	if list == nil || *list == nil {
		return
	}
	out := (*list)[:0]
	for _, e := range *list {
		if e.Key == key && e.ValueSHA256 == valueSHA {
			continue
		}
		out = append(out, e)
	}
	*list = out
}

// indexEntries keys each entry by a stable signature (key + value SHA) so
// two "same key, same value" entries collapse and two "same key, different
// value" entries don't.
func indexEntries(entries []model.NPMRCEntryDigest) map[string]model.NPMRCEntryDigest {
	out := make(map[string]model.NPMRCEntryDigest, len(entries))
	for _, e := range entries {
		sig := fmt.Sprintf("%s|%s", e.Key, e.ValueSHA256)
		out[sig] = e
	}
	return out
}

// groupByKey groups entry digests by their key — used for the
// value-changed pass that matches same-key pairs across snapshots.
func groupByKey(entries []model.NPMRCEntryDigest) map[string][]model.NPMRCEntryDigest {
	out := make(map[string][]model.NPMRCEntryDigest, len(entries))
	for _, e := range entries {
		out[e.Key] = append(out[e.Key], e)
	}
	return out
}

// toDigests converts a slice of full entries (from a fresh audit) to the
// digest form (which is what diffing operates on).
func toDigests(entries []model.NPMRCEntry) []model.NPMRCEntryDigest {
	out := make([]model.NPMRCEntryDigest, len(entries))
	for i, e := range entries {
		out[i] = model.NPMRCEntryDigest{
			Key:         e.Key,
			ValueSHA256: e.ValueSHA256,
			IsAuth:      e.IsAuth,
			IsArray:     e.IsArray,
		}
	}
	return out
}

// diffEnv compares two slices of env-var snapshots by Name and emits one
// change record per transition. Names absent from both sides are skipped.
func diffEnv(prev, current []model.NPMRCEnvVarSnapshot) []model.NPMRCEnvChange {
	prevByName := make(map[string]model.NPMRCEnvVarSnapshot, len(prev))
	for _, e := range prev {
		prevByName[e.Name] = e
	}
	currentByName := make(map[string]model.NPMRCEnvVarSnapshot, len(current))
	for _, e := range current {
		currentByName[e.Name] = e
	}

	var out []model.NPMRCEnvChange
	for _, ce := range current {
		pe, hadBefore := prevByName[ce.Name]
		switch {
		case !hadBefore:
			// New name in our watch list (e.g. we expanded the list).
			// Treat as a transition only if it became set.
			if ce.Set {
				out = append(out, model.NPMRCEnvChange{Name: ce.Name, Type: "appeared", CurrentSHA256: ce.ValueSHA256})
			}
		case !pe.Set && ce.Set:
			out = append(out, model.NPMRCEnvChange{Name: ce.Name, Type: "appeared", CurrentSHA256: ce.ValueSHA256})
		case pe.Set && !ce.Set:
			out = append(out, model.NPMRCEnvChange{Name: ce.Name, Type: "disappeared", PreviousSHA256: pe.ValueSHA256})
		case pe.Set && ce.Set && pe.ValueSHA256 != ce.ValueSHA256:
			out = append(out, model.NPMRCEnvChange{Name: ce.Name, Type: "value_changed", PreviousSHA256: pe.ValueSHA256, CurrentSHA256: ce.ValueSHA256})
		}
	}
	// Names removed from the watch list aren't a "change" — they're a
	// schema change. Skip.

	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
