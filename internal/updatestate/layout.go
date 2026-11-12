// Package updatestate owns the on-disk self-update layout: version
// directories, state.json, the updater lock and the bootstrap's run records.
//
//	<install root>\versions\<v>\              immutable once renamed in
//	<install root>\versions\.staging-<v>-*\   never executed
//	<install root>\seed\<msi-ver>\            MSI-owned fallback payload
//	<install root>\state\{state.json,update.lock,update.log}
//	<data root>\runs\<v>.<owner>.json         each user's own, advisory only
//	<data root>\runs\<v>.json                 shared (bootstraps before per-user files)
package updatestate

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	// ManifestName is the per-version manifest written before the rename in.
	ManifestName = "manifest.json"
	// StagingPrefix and TrashPrefix name entries of VersionsDir that S1 sweeps.
	StagingPrefix = ".staging-"
	TrashPrefix   = ".trash-"
)

// Layout resolves every self-update path from an install root (versions,
// seed, state) and a data root (runs). Production code derives it from the
// running binary (ResolveLayout); nothing hard-codes the MSI's folders.
type Layout struct {
	InstallRoot string
	DataRoot    string
}

func (l Layout) VersionsDir() string { return filepath.Join(l.InstallRoot, "versions") }

func (l Layout) VersionDir(v Version) string { return filepath.Join(l.VersionsDir(), v.String()) }

func (l Layout) SeedDir(v Version) string {
	return filepath.Join(l.InstallRoot, "seed", v.String())
}

func (l Layout) StateDir() string  { return filepath.Join(l.InstallRoot, "state") }
func (l Layout) StateFile() string { return filepath.Join(l.StateDir(), "state.json") }
func (l Layout) LockFile() string  { return filepath.Join(l.StateDir(), "update.lock") }
func (l Layout) LogFile() string   { return filepath.Join(l.StateDir(), "update.log") }

func (l Layout) RunsDir() string { return filepath.Join(l.DataRoot, "runs") }

// RunFile is the shared run file (runs\<v>.json) written before run files
// were per user. Users can't write it under the hardened state-dir ACLs;
// the updater still reads it, and it is the fallback when the user can't
// be identified.
func (l Layout) RunFile(v Version) string {
	return filepath.Join(l.RunsDir(), v.String()+".json")
}

// RunFileFor is owner's own run file, runs\<v>.<owner>.json: each user
// creates and owns theirs, so no user writes another's (RunOwner). An
// invalid owner falls back to RunFile.
func (l Layout) RunFileFor(v Version, owner string) string {
	if !validRunOwner(owner) {
		return l.RunFile(v)
	}
	return filepath.Join(l.RunsDir(), v.String()+"."+owner+".json")
}

// maxRunFiles bounds how many run files of one version RunFiles returns:
// the directory is user-writable.
const maxRunFiles = 256

// RunFiles lists every run file of v, the shared one and each user's, in
// name order. The updater judges a probation from all of them.
func (l Layout) RunFiles(v Version) []string {
	entries, err := os.ReadDir(l.RunsDir())
	if err != nil {
		return nil
	}
	shared, prefix := v.String()+".json", v.String()+"."
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() {
			continue
		}
		if name != shared {
			owner, ok := strings.CutPrefix(name, prefix)
			if owner, ok = strings.CutSuffix(owner, ".json"); !ok || !validRunOwner(owner) {
				continue // a lock, a temp file, another version's file
			}
		}
		out = append(out, filepath.Join(l.RunsDir(), name))
		if len(out) == maxRunFiles {
			break
		}
	}
	return out
}

// StagingDir creates a fresh versions\.staging-<v>-<rand> directory. It sits
// in VersionsDir (which must exist) so the final rename stays on one volume.
func (l Layout) StagingDir(v Version) (string, error) {
	return os.MkdirTemp(l.VersionsDir(), StagingPrefix+v.String()+"-")
}

// IsSweepable reports whether a VersionsDir entry is staging or trash.
func IsSweepable(name string) bool {
	return strings.HasPrefix(name, StagingPrefix) || strings.HasPrefix(name, TrashPrefix)
}
