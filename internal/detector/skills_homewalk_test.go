package detector

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// The home walk (walkForProjectRoots) discovers project-convention marker dirs
// anywhere under the search dirs, so a project the user never registered in
// ~/.claude.json and that no node/python scanner surfaced is still inventoried.
// These tests drive it through Detect with an explicit searchDirs and a nil
// skipper (TCC interaction lives in skills_tcc_darwin_test.go).

// TestDetect_HomeWalkDiscoversUnregisteredProject is the headline case: a deep
// repo with a committed .claude/skills tree, no claude.json entry and no
// package.json, is found purely by the walk.
func TestDetect_HomeWalkDiscoversUnregisteredProject(t *testing.T) {
	m, fs := newSkillsMock()
	repo := testHome + "/work/a/b/repo"
	fs.addSkill(filepath.Join(repo, ".claude", "skills", "x"), "SKILL.md", validFrontmatter("x", "d"), nil)
	fs.commit()

	records, info := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
	rec := findSkill(records, "claude_project", "x")
	if rec == nil {
		t.Fatalf("unregistered project not discovered by the home walk; records=%+v", records)
	}
	if rec.ProjectPath != repo {
		t.Errorf("project_path = %q, want %q", rec.ProjectPath, repo)
	}
	if info.WalkRootsFound < 1 {
		t.Errorf("WalkRootsFound = %d, want >= 1", info.WalkRootsFound)
	}
}

// TestDetect_HomeWalkMarkerConventions covers every marker/child pair in
// projectMarkerDirs, including the Cursor-only-Go-repo scenario (no
// extraProjectRoots, no claude.json), and pins the source/agent labels — new
// sources (gemini/aider) included.
func TestDetect_HomeWalkMarkerConventions(t *testing.T) {
	cases := []struct {
		markerDir, child, source, agent string
	}{
		{".claude", "skills", "claude_project", "claude-code"},
		{".agents", "skills", "agents_project", "shared"},
		{".opencode", "skills", "opencode_project", "opencode"},
		{".opencode", "skill", "opencode_project", "opencode"}, // singular spelling
		{".cursor", "skills", "cursor_project", "cursor"},      // Cursor-only non-node repo
		{".pi", "skills", "pi_project", "pi"},
		{".factory", "skills", "factory_project", "factory"},
		{".agent", "skills", "factory_agent_project", "factory"}, // singular .agent
		{".github", "skills", "github_project", "copilot"},
		{".gemini", "skills", "gemini_project", "gemini-cli"},
		{".aider", "skills", "aider_project", "aider"},
		{".grok", "skills", "grok_project", "grok-build"},
		{".kimi-code", "skills", "kimi_project", "kimi-code"},
		{".hermes", "skills", "hermes_project", "hermes-agent"},
		{".omp", "skills", "omp_project", "oh-my-pi"},
	}
	for _, c := range cases {
		t.Run(c.markerDir+"/"+c.child, func(t *testing.T) {
			m, fs := newSkillsMock()
			proj := testHome + "/repos/proj"
			fs.addSkill(filepath.Join(proj, c.markerDir, c.child, "s"), "SKILL.md", validFrontmatter("s", "d"), nil)
			fs.commit()

			records, _ := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
			rec := findSkill(records, c.source, "s")
			if rec == nil {
				t.Fatalf("marker %s/%s not discovered; records=%+v", c.markerDir, c.child, records)
			}
			if rec.Agent != c.agent || rec.ProjectPath != proj {
				t.Errorf("agent=%q project=%q, want %q/%q", rec.Agent, rec.ProjectPath, c.agent, proj)
			}
		})
	}
}

// TestDetect_HomeWalkGeminiUserGlobalRoot pins the new global root: ~/.gemini/
// skills is a global (not walk-discovered) source with the gemini-cli label.
func TestDetect_HomeWalkGeminiUserGlobalRoot(t *testing.T) {
	m, fs := newSkillsMock()
	fs.addSkill(testHome+"/.gemini/skills/g", "SKILL.md", validFrontmatter("g", "d"), nil)
	fs.commit()

	records, _ := NewSkillsDetector(m).Detect(context.Background(), nil, nil)
	rec := findSkill(records, "gemini_user", "g")
	if rec == nil || rec.Agent != "gemini-cli" || rec.Scope != "global" {
		t.Fatalf("gemini_user global skill wrong; rec=%+v", rec)
	}
}

// TestDetect_HomeWalkMarkerWithoutChild: a marker dot-dir lacking its skills
// child (only settings.json) does not mark a project.
func TestDetect_HomeWalkMarkerWithoutChild(t *testing.T) {
	m, fs := newSkillsMock()
	proj := testHome + "/repos/proj"
	fs.addFile(filepath.Join(proj, ".claude", "settings.json"), "{}")
	fs.commit()

	records, info := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
	if len(records) != 0 {
		t.Errorf(".claude without a skills child must not mark a project; records=%+v", records)
	}
	if info.WalkRootsFound != 0 {
		t.Errorf("WalkRootsFound = %d, want 0", info.WalkRootsFound)
	}
}

// TestDetect_HomeWalkMarkerChildFileOrSymlink: the marker child must be a real
// directory. A file named "skills", and a symlink named "skills", are both
// rejected (the walk never resolves a link — see hasMarkerChild).
func TestDetect_HomeWalkMarkerChildFileOrSymlink(t *testing.T) {
	// (a) skills is a FILE.
	m, fs := newSkillsMock()
	fs.addFile(filepath.Join(testHome, "repos", "pf", ".claude", "skills"), "not a dir")
	fs.commit()
	records, _ := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
	if len(records) != 0 {
		t.Errorf("a FILE named skills must not mark a project; records=%+v", records)
	}

	// (b) skills is a SYMLINK into a real skill tree elsewhere.
	m2, fs2 := newSkillsMock()
	fs2.addSymlink(filepath.Join(testHome, "repos", "ps", ".claude", "skills"), testHome+"/elsewhere")
	fs2.addSkill(testHome+"/elsewhere/s", "SKILL.md", validFrontmatter("s", "d"), nil)
	fs2.commit()
	records2, _ := NewSkillsDetector(m2).Detect(context.Background(), nil, []string{testHome})
	if findSkill(records2, "claude_project", "s") != nil {
		t.Error("a symlinked marker child must not mark a project (walk never resolves links)")
	}
}

// TestDetect_HomeWalkPrunesNoiseTrees: skills buried under node_modules, .git,
// or any non-marker dot-dir are never reached.
func TestDetect_HomeWalkPrunesNoiseTrees(t *testing.T) {
	m, fs := newSkillsMock()
	fs.addSkill(testHome+"/proj/node_modules/pkg/.claude/skills/a", "SKILL.md", validFrontmatter("a", "d"), nil)
	fs.addSkill(testHome+"/proj/.git/x/.claude/skills/b", "SKILL.md", validFrontmatter("b", "d"), nil)
	fs.addSkill(testHome+"/proj/.venv/y/.claude/skills/c", "SKILL.md", validFrontmatter("c", "d"), nil)
	fs.commit()

	records, _ := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
	for _, slug := range []string{"a", "b", "c"} {
		if findSkill(records, "claude_project", slug) != nil {
			t.Errorf("skill %q under a pruned tree must not be discovered", slug)
		}
	}
}

// TestDetect_HomeWalkPrunesWindowsAppData: on Windows the AppData tree is pruned
// by name (cost), so skills under it are never reached.
func TestDetect_HomeWalkPrunesWindowsAppData(t *testing.T) {
	m, fs := newSkillsMock()
	m.SetGOOS(model.PlatformWindows)
	fs.addSkill(testHome+"/AppData/Roaming/app/.claude/skills/a", "SKILL.md", validFrontmatter("a", "d"), nil)
	fs.commit()

	records, _ := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
	if findSkill(records, "claude_project", "a") != nil {
		t.Error("the AppData subtree must be pruned on Windows")
	}
}

// TestDetect_HomeWalkDepthLimit: a project whose marker sits at exactly
// maxHomeWalkDepth is found; one level deeper is not.
func TestDetect_HomeWalkDepthLimit(t *testing.T) {
	build := func(depth int) []model.AgentSkill {
		m, fs := newSkillsMock()
		dir := testHome
		for i := range depth {
			dir = filepath.Join(dir, fmt.Sprintf("d%d", i))
		}
		fs.addSkill(filepath.Join(dir, ".claude", "skills", "s"), "SKILL.md", validFrontmatter("s", "d"), nil)
		fs.commit()
		records, _ := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
		return records
	}
	if findSkill(build(maxHomeWalkDepth), "claude_project", "s") == nil {
		t.Errorf("a project at depth %d must be found", maxHomeWalkDepth)
	}
	if findSkill(build(maxHomeWalkDepth+1), "claude_project", "s") != nil {
		t.Errorf("a project at depth %d must NOT be found (beyond the depth cap)", maxHomeWalkDepth+1)
	}
}

// TestDetect_HomeWalkDirBudgetTruncates: exceeding maxHomeWalkDirs flags
// Truncated with a bounded error and still returns the deterministic prefix.
func TestDetect_HomeWalkDirBudgetTruncates(t *testing.T) {
	orig := maxHomeWalkDirs
	defer func() { maxHomeWalkDirs = orig }()
	maxHomeWalkDirs = 3

	m, fs := newSkillsMock()
	for i := range 10 {
		proj := filepath.Join(testHome, fmt.Sprintf("p%02d", i))
		fs.addSkill(filepath.Join(proj, ".claude", "skills", "s"), "SKILL.md", validFrontmatter(fmt.Sprintf("n%02d", i), "d"), nil)
	}
	fs.commit()

	_, info := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
	if !info.Truncated {
		t.Error("exceeding maxHomeWalkDirs must set Truncated")
	}
	if !hasErrorContaining(info.Errors, "home walk truncated") {
		t.Errorf("expected a 'home walk truncated' error, got %v", info.Errors)
	}
	// WalkDirsVisited counts ReadDir calls actually made and stops exactly at the
	// cap — never cap+1 (the pre-charge off-by-one).
	if info.WalkDirsVisited != maxHomeWalkDirs {
		t.Errorf("WalkDirsVisited = %d, want %d (must not overshoot the cap)", info.WalkDirsVisited, maxHomeWalkDirs)
	}
}

// TestDetect_HomeWalkNormalizesAndDedupesRoots pins root hygiene: search roots
// are canonicalized to absolute lexical paths, so a non-clean duplicate of a root
// collapses onto it and is walked once (not double-charged), and a relative "."
// root is never admitted as the literal project "." (which would duplicate every
// global skill as a project-scoped record).
func TestDetect_HomeWalkNormalizesAndDedupesRoots(t *testing.T) {
	m, fs := newSkillsMock()
	proj := testHome + "/work/proj"
	fs.addSkill(filepath.Join(proj, ".claude", "skills", "s"), "SKILL.md", validFrontmatter("s", "d"), nil)
	fs.commit()

	// testHome, a non-clean spelling of it (Clean -> testHome), and "." (absolutized
	// to the test CWD, absent from the mock -> not a real dir, skipped).
	dup := testHome + "/x/.."
	records, info := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome, dup, "."})

	if info.WalkRootsFound != 1 {
		t.Errorf("WalkRootsFound = %d, want 1 (duplicate roots collapse; '.' finds nothing here)", info.WalkRootsFound)
	}
	sFound := 0
	for _, r := range records {
		if r.SkillSlug == "s" {
			sFound++
		}
		if r.ProjectPath == "." {
			t.Errorf("a relative '.' root must never be admitted as the literal project %q", r.ProjectPath)
		}
	}
	if sFound != 1 {
		t.Errorf("skill s found %d times, want 1 (deduped roots must not re-emit it)", sFound)
	}
}

// TestDetect_HomeWalkCandidateCapTruncates: exceeding maxHomeWalkCandidates
// flags Truncated and stops at the cap.
func TestDetect_HomeWalkCandidateCapTruncates(t *testing.T) {
	orig := maxHomeWalkCandidates
	defer func() { maxHomeWalkCandidates = orig }()
	maxHomeWalkCandidates = 2

	m, fs := newSkillsMock()
	for i := range 5 {
		proj := filepath.Join(testHome, fmt.Sprintf("p%02d", i))
		fs.addSkill(filepath.Join(proj, ".claude", "skills", "s"), "SKILL.md", validFrontmatter(fmt.Sprintf("n%02d", i), "d"), nil)
	}
	fs.commit()

	_, info := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
	if info.WalkRootsFound != 2 {
		t.Errorf("WalkRootsFound = %d, want 2 (candidate cap)", info.WalkRootsFound)
	}
	if !info.Truncated || !hasErrorContaining(info.Errors, "candidates truncated") {
		t.Errorf("candidate cap must set Truncated + a bounded error; truncated=%v errs=%v", info.Truncated, info.Errors)
	}
}

// TestDetect_HomeWalkDoesNotEmitHomeAsProject pins the §4.3 edge: ~/.claude/
// skills makes the walk emit $HOME itself, but discoverProjects drops home, so
// the skill surfaces once as the global claude_user root, never as a duplicate
// claude_project record.
func TestDetect_HomeWalkDoesNotEmitHomeAsProject(t *testing.T) {
	m, fs := newSkillsMock()
	fs.addSkill(testHome+"/.claude/skills/foo", "SKILL.md", validFrontmatter("foo", "d"), nil)
	fs.commit()

	records, _ := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
	if findSkill(records, "claude_user", "foo") == nil {
		t.Error("global ~/.claude/skills skill must be found as claude_user")
	}
	if findSkill(records, "claude_project", "foo") != nil {
		t.Error("home must not be emitted as a project (no duplicate claude_project record)")
	}
}

// TestDetect_HomeWalkUnionDedupesWithRegistry: the same repo present in
// claude.json AND found by the walk yields exactly the registry-only record set
// (byte-equal after sort) — the walk complements, never duplicates.
func TestDetect_HomeWalkUnionDedupesWithRegistry(t *testing.T) {
	build := func(withWalk bool) []model.AgentSkill {
		m, fs := newSkillsMock()
		proj := testHome + "/work/proj"
		fs.addSkill(filepath.Join(proj, ".claude", "skills", "s"), "SKILL.md", validFrontmatter("s", "d"), nil)
		fs.addFile(testHome+"/.claude.json", `{"projects":{"`+proj+`":{}}}`)
		fs.commit()
		var sd []string
		if withWalk {
			sd = []string{testHome}
		}
		records, _ := NewSkillsDetector(m).Detect(context.Background(), nil, sd)
		return records
	}
	base := build(false) // claude.json only
	both := build(true)  // claude.json + walk, same project
	if !reflect.DeepEqual(base, both) {
		t.Errorf("registry + walk union must equal registry-only for the same project\nbase=%+v\nboth=%+v", base, both)
	}
}

// TestDetect_HomeWalkSkipsSymlinkedDirs: a directory symlink on the walk path is
// never followed, so the skill under the real path is found exactly once, never
// shadowed via the link.
func TestDetect_HomeWalkSkipsSymlinkedDirs(t *testing.T) {
	m, fs := newSkillsMock()
	real := testHome + "/real"
	fs.addSkill(filepath.Join(real, "proj", ".claude", "skills", "s"), "SKILL.md", validFrontmatter("s", "d"), nil)
	fs.addSymlink(testHome+"/link", real)
	fs.commit()

	records, _ := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
	var found []model.AgentSkill
	for _, r := range records {
		if r.SkillSlug == "s" {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly 1 record via the real path, got %d: %+v", len(found), found)
	}
	if !strings.HasPrefix(found[0].ProjectPath, real) {
		t.Errorf("project must be discovered via the real path, got %q", found[0].ProjectPath)
	}
}

// TestDetect_HomeWalkDeterministic: two runs over the same fakeFS produce
// identical records and identical walk counters.
func TestDetect_HomeWalkDeterministic(t *testing.T) {
	build := func() ([]model.AgentSkill, *model.AgentSkillScanInfo) {
		m, fs := newSkillsMock()
		for i := range 6 {
			proj := filepath.Join(testHome, fmt.Sprintf("r%d", i), "proj")
			fs.addSkill(filepath.Join(proj, ".cursor", "skills", "s"), "SKILL.md", validFrontmatter(fmt.Sprintf("s%d", i), "d"), nil)
		}
		fs.commit()
		return NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})
	}
	r1, i1 := build()
	r2, i2 := build()
	if !reflect.DeepEqual(r1, r2) {
		t.Error("two runs over the same fakeFS must yield identical records")
	}
	if i1.WalkRootsFound != i2.WalkRootsFound || i1.WalkDirsVisited != i2.WalkDirsVisited || i1.Truncated != i2.Truncated {
		t.Errorf("scan info not deterministic: %+v vs %+v", i1, i2)
	}
}

// TestDetect_HomeWalkTieringKeepsRegisteredProject pins registry-first tiering:
// with more discovered projects than the maxProjects cap, a Claude-registered
// project is never evicted by home-walk discoveries. maxProjects walk-only
// projects sort lexically BEFORE the one registered project, so a flat
// sort-then-cap would drop the registered project — but the registry tier is
// admitted first and the walk fills only the remaining capacity.
func TestDetect_HomeWalkTieringKeepsRegisteredProject(t *testing.T) {
	m, fs := newSkillsMock()
	// One registered project at a lexically LATE path (sorts after the a### walk
	// roots), with a distinctively named skill.
	reg := testHome + "/zzz-registered"
	fs.addSkill(filepath.Join(reg, ".claude", "skills", "reg"), "SKILL.md", validFrontmatter("reg", "d"), nil)
	fs.addFile(testHome+"/.claude.json", `{"projects":{"`+reg+`":{}}}`)
	// maxProjects walk-only projects at lexically EARLY paths, so with the
	// registered one the total exceeds the cap by exactly one.
	for i := range maxProjects {
		p := filepath.Join(testHome, fmt.Sprintf("a%03d", i))
		fs.addSkill(filepath.Join(p, ".claude", "skills", "s"), "SKILL.md", validFrontmatter("w", "d"), nil)
	}
	fs.commit()

	records, info := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome})

	if findSkill(records, "claude_project", "reg") == nil {
		t.Error("the registered project must survive the cap — the walk tier must not evict it")
	}
	if !info.Truncated {
		t.Error("exceeding maxProjects must set Truncated")
	}
	if info.ProjectsScanned != maxProjects {
		t.Errorf("ProjectsScanned = %d, want %d (cap)", info.ProjectsScanned, maxProjects)
	}
}

// TestDetect_HomeWalkPrunesOverlappingRoots pins the overlap skip: passing both
// $HOME and a subdirectory of it walks the tree once — the nested root is covered
// by the ancestor and skipped, so a skill under it is found exactly once and the
// same subtree isn't re-charged.
func TestDetect_HomeWalkPrunesOverlappingRoots(t *testing.T) {
	m, fs := newSkillsMock()
	proj := testHome + "/work/proj"
	fs.addSkill(filepath.Join(proj, ".claude", "skills", "s"), "SKILL.md", validFrontmatter("s", "d"), nil)
	fs.commit()

	records, info := NewSkillsDetector(m).Detect(context.Background(), nil, []string{testHome, testHome + "/work"})

	if info.WalkRootsFound != 1 {
		t.Errorf("WalkRootsFound = %d, want 1 (overlapping roots walk the tree once)", info.WalkRootsFound)
	}
	sFound := 0
	for _, r := range records {
		if r.SkillSlug == "s" {
			sFound++
		}
	}
	if sFound != 1 {
		t.Errorf("skill s found %d times, want 1", sFound)
	}
}
