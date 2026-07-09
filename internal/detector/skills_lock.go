package detector

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// lockEntry is one normalized skills.sh lock record joined to its expected
// on-disk install directory.
type lockEntry struct {
	localName       string // the "skills" map key = canonical install folder name
	source          string // owner/repo (github) or an on-disk path (local — never serialized)
	sourceType      string // "github" | "mintlify" | "huggingface" | "local" | "well-known"
	sourceURL       string
	ref             string
	skillPath       string
	skillFolderHash string // GitHub tree SHA — recorded verbatim, never compared to our sha256
	installedAt     string
	updatedAt       string
	pluginName      string
	lockFilePath    string
	expectedDir     string // canonical install dir (installBase/localName)
}

// lockSkillRaw mirrors the per-skill lock envelope. Unknown top-level and
// per-entry fields are tolerated (lenient parse) so a future schema version
// never breaks inventory.
type lockSkillRaw struct {
	Source          string `json:"source"`
	SourceType      string `json:"sourceType"`
	SourceURL       string `json:"sourceUrl"`
	Ref             string `json:"ref"`
	SkillPath       string `json:"skillPath"`
	SkillFolderHash string `json:"skillFolderHash"`
	InstalledAt     string `json:"installedAt"`
	UpdatedAt       string `json:"updatedAt"`
	PluginName      string `json:"pluginName"`
}

// applyLocks parses the global and per-project skills.sh lock files and joins
// them to the discovered on-disk records: a record whose symlink-resolved skill
// dir matches a lock entry's expected install dir is enriched with provenance
// (both sides compared as resolved paths, which is what makes the symlink layout
// join correctly). A lock entry with no folder on disk is not an install and is
// dropped — the inventory is on-disk skills only.
func (d *SkillsDetector) applyLocks(discovered []discoveredSkill, projects []string, info *model.AgentSkillScanInfo) []discoveredSkill {
	home := getHomeDir(d.exec)
	var entries []lockEntry

	// Global: ~/.agents/.skill-lock.json always; the XDG_STATE_HOME variant
	// additionally when the env var is visible. Install base is ~/.agents/skills.
	agentsBase := filepath.Join(home, ".agents", "skills")
	globalLocks := []string{filepath.Join(home, ".agents", ".skill-lock.json")}
	if xdg := d.exec.Getenv("XDG_STATE_HOME"); xdg != "" {
		globalLocks = append(globalLocks, filepath.Join(xdg, "skills", ".skill-lock.json"))
	}
	for _, lp := range globalLocks {
		entries = append(entries, d.loadLock(lp, agentsBase, info)...)
	}

	// Per-project: <project>/skills-lock.json; install base <project>/.agents/skills.
	for _, proj := range projects {
		lp := filepath.Join(proj, "skills-lock.json")
		entries = append(entries, d.loadLock(lp, filepath.Join(proj, ".agents", "skills"), info)...)
	}

	// Join each lock entry onto every on-disk record whose resolved dir matches
	// the entry's expected install dir. resolvedDir was computed at emit time, so
	// this reuses it rather than re-resolving per entry.
	for _, le := range entries {
		want := d.resolvePath(le.expectedDir)
		for i := range discovered {
			if discovered[i].rec.SkillDirPath == "" {
				continue
			}
			if discovered[i].resolvedDir == want {
				enrichWithLock(&discovered[i].rec, le)
			}
		}
	}
	return discovered
}

// loadLock reads and leniently parses one lock file. A missing file yields no
// entries and no error; a malformed file records a scan error and yields none.
// Successfully parsed files (even with an empty skills map) count toward
// LockFilesParsed.
func (d *SkillsDetector) loadLock(lockPath, installBase string, info *model.AgentSkillScanInfo) []lockEntry {
	// Bound the read: a project lock lives in any of up to 200 repos the dev has
	// opened, so its size is attacker-influenced. Stat-gate before slurping so a
	// hostile multi-GB skills-lock.json cannot balloon RSS (the sibling node/python
	// dist scanners cap their lockfile reads the same way). Stat errors fall
	// through to ReadFile, which treats a missing file as "absent, not an error".
	if fi, err := d.exec.Stat(lockPath); err == nil && fi.Size() > maxJSONConfigBytes {
		d.addError(info, fmt.Sprintf("lock %s exceeds %d bytes — skipped", lockPath, maxJSONConfigBytes))
		return nil
	}
	content, err := d.exec.ReadFile(lockPath)
	if err != nil || len(content) == 0 {
		return nil // absent — not an error
	}
	entries, perr := parseLock(content, lockPath, installBase)
	if perr != nil {
		d.addError(info, fmt.Sprintf("parse lock %s: %v", lockPath, perr))
		return nil
	}
	info.LockFilesParsed++
	return entries
}

// parseLock decodes a lock envelope, keying only off the "skills" map and
// iterating its keys sorted for deterministic output.
func parseLock(content []byte, lockPath, installBase string) ([]lockEntry, error) {
	var env struct {
		Skills map[string]lockSkillRaw `json:"skills"`
	}
	if err := json.Unmarshal(content, &env); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(env.Skills))
	for n := range env.Skills {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]lockEntry, 0, len(names))
	for _, n := range names {
		r := env.Skills[n]
		out = append(out, lockEntry{
			localName:       n,
			source:          r.Source,
			sourceType:      r.SourceType,
			sourceURL:       r.SourceURL,
			ref:             r.Ref,
			skillPath:       r.SkillPath,
			skillFolderHash: r.SkillFolderHash,
			installedAt:     r.InstalledAt,
			updatedAt:       r.UpdatedAt,
			pluginName:      r.PluginName,
			lockFilePath:    lockPath,
			expectedDir:     filepath.Join(installBase, n),
		})
	}
	return out, nil
}

// enrichWithLock stamps skills.sh provenance onto a matched folder record. It
// no-ops if the record was already enriched by an earlier lock entry.
func enrichWithLock(rec *model.AgentSkill, le lockEntry) {
	if rec.ManagedBy != "" {
		return
	}
	rec.ManagedBy = "skills.sh"
	applyProvenance(rec, le)
	if le.pluginName != "" {
		rec.PluginName = le.pluginName
	}
	rec.LockFilePath = le.lockFilePath
}

// applyProvenance copies the lock's provenance fields onto a record, applying
// the privacy carve-out for local sources: for sourceType=local the lock's
// `source` (and sourceUrl) are on-disk paths that must never leave the machine,
// so only the alias (the lock key) is recorded in source_slug.
func applyProvenance(rec *model.AgentSkill, le lockEntry) {
	rec.SourceType = le.sourceType
	rec.Ref = le.ref
	rec.SkillPath = le.skillPath
	rec.UpstreamFolderHash = le.skillFolderHash
	rec.InstalledAt = le.installedAt
	rec.UpdatedAt = le.updatedAt
	if le.sourceType == "local" {
		rec.SourceSlug = le.localName // alias only — never the path from the lock
		return
	}
	rec.SourceSlug = le.source
	rec.SourceURL = le.sourceURL
}
