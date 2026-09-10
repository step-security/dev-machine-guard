//go:build darwin

package detector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// ancestorTraversalRecorder uses real filesystem resolution in a temporary
// fake home; its Documents directory is not a user's TCC-protected directory.
type ancestorTraversalRecorder struct {
	*executor.Real
	protected string
	traversed []string
	guarded   []string
}

func (r *ancestorTraversalRecorder) GuardedFiles(roots []string, guard func(string) string, maxReadBytes int64) executor.Executor {
	return r.Real.GuardedFiles(roots, func(p string) string {
		if p == r.protected {
			r.guarded = append(r.guarded, p)
		}
		return guard(p)
	}, maxReadBytes)
}

func (r *ancestorTraversalRecorder) EvalSymlinks(p string) (string, error) {
	resolved, err := r.Real.EvalSymlinks(p)
	if err == nil && (resolved == r.protected || strings.HasPrefix(resolved, r.protected+"/")) {
		r.traversed = append(r.traversed, p)
	}
	return resolved, err
}

func TestSkillsAncestorLinkRejectedBeforeResolution(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(home, "Documents")
	root := filepath.Join(home, ".kiro", "skills")
	for _, dir := range []string{root, filepath.Join(protected, "skill")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(home, "ordinary-alias")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(alias, "skill"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	rec := &ancestorTraversalRecorder{Real: executor.NewReal(), protected: protected}
	d := NewSkillsDetector(rec).WithSkipper(tcc.New(home))
	d.enumerateRoot(context.Background(), skillsRoot{path: root, source: "kiro_project", agent: "kiro", scope: "project", projectPath: home}, &model.AgentSkillScanInfo{}, map[string]*skillScan{})
	if len(rec.traversed) != 0 {
		t.Fatalf("protected ancestor was already traversed by EvalSymlinks before rejection: %v", rec.traversed)
	}
	if len(rec.guarded) == 0 {
		t.Fatal("protected link destination was not checked by the guard")
	}
}

// tccAccessRecorder wraps the mock executor and records every path handed to a
// filesystem call that stats/reads on a real machine — the calls that fire a
// macOS TCC prompt. Tests assert none of them touched a protected tree, which
// proves the guard runs BEFORE any access: an outcome-only check (skill absent)
// would still pass if a guard were moved AFTER the stat, but the prompt would
// already have fired. Embeds *executor.Mock so all other methods pass through.
// (Distinct from skills_test.go's recordingExec, which records only ReadFile.)
type tccAccessRecorder struct {
	*executor.Mock
	mu       sync.Mutex
	accessed []string
}

func (r *tccAccessRecorder) note(path string) {
	r.mu.Lock()
	r.accessed = append(r.accessed, path)
	r.mu.Unlock()
}

func (r *tccAccessRecorder) Stat(p string) (os.FileInfo, error) { r.note(p); return r.Mock.Stat(p) }
func (r *tccAccessRecorder) DirExists(p string) bool            { r.note(p); return r.Mock.DirExists(p) }
func (r *tccAccessRecorder) ReadDir(p string) ([]os.DirEntry, error) {
	r.note(p)
	return r.Mock.ReadDir(p)
}
func (r *tccAccessRecorder) EvalSymlinks(p string) (string, error) {
	r.note(p)
	return r.Mock.EvalSymlinks(p)
}
func (r *tccAccessRecorder) ReadFile(p string) ([]byte, error) { r.note(p); return r.Mock.ReadFile(p) }

// accessedUnder returns the recorded paths that equal prefix or are nested
// under it at a "/" boundary.
func (r *tccAccessRecorder) accessedUnder(prefix string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var hits []string
	for _, p := range r.accessed {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			hits = append(hits, p)
		}
	}
	return hits
}

// runSkillsUnderProtected seeds a fully-discoverable skill inside ~/Documents (a
// TCC-protected tree) and registers its project in ~/.claude.json, then runs
// Detect with the given skipper through an access recorder. Because the whole
// tree is seeded, the skill is reachable if — and only if — the detector stats
// into ~/Documents; the recorder then lets tests assert directly on access.
// Darwin-tagged because tcc.New only builds home-anchored protected paths on
// macOS.
func runSkillsUnderProtected(t *testing.T, skipper *tcc.Skipper) ([]model.AgentSkill, *model.AgentSkillScanInfo, *tccAccessRecorder) {
	t.Helper()
	m, fs := newSkillsMock() // mock home defaults to testHome
	fs.addSkill(testHome+"/Documents/proj/.claude/skills/demo", "SKILL.md", validFrontmatter("demo", "d"), nil)
	fs.addFile(testHome+"/.claude.json", `{"projects":{"`+testHome+`/Documents/proj":{}}}`)
	fs.commit()
	rec := &tccAccessRecorder{Mock: m}
	records, info := NewSkillsDetector(rec).WithSkipper(skipper).Detect(context.Background(), nil, nil)
	return records, info, rec
}

// TestDetect_SkipsProjectUnderProtectedDir is the primary-fix regression: a
// ~/.claude.json project inside ~/Documents must be dropped before any stat, so
// the skill is never discovered and no prompt fires.
func TestDetect_SkipsProjectUnderProtectedDir(t *testing.T) {
	records, info, rec := runSkillsUnderProtected(t, tcc.New(testHome))

	if s := findSkill(records, "claude_project", "demo"); s != nil {
		t.Errorf("skill under ~/Documents must not be discovered (statting it would fire a TCC prompt), got %+v", s)
	}
	if info.ProjectsScanned != 0 {
		t.Errorf("project under ~/Documents must be dropped before probing, ProjectsScanned = %d, want 0", info.ProjectsScanned)
	}
	protected := testHome + "/Documents"
	for _, r := range info.RootsScanned {
		if r == protected || strings.HasPrefix(r, protected+"/") {
			t.Errorf("no root under a protected dir may be scanned, got %q in RootsScanned", r)
		}
	}
	// The core guarantee: the guard runs BEFORE any filesystem access, so nothing
	// under ~/Documents is ever statted or read (that stat is what pops the
	// dialog). This is what the outcome assertions above cannot prove on their own.
	if hits := rec.accessedUnder(protected); len(hits) > 0 {
		t.Errorf("no filesystem access may occur under %q (would fire a TCC prompt), got: %v", protected, hits)
	}
}

// TestDetect_ScansProtectedDirWhenSkipperNil is the opt-in counterpart: with
// --include-tcc-protected the caller passes a nil skipper, WithinProtected is a
// no-op, and the same ~/Documents skill IS scanned (FDA is assumed granted, so
// no prompt). This also proves the skill is genuinely reachable, so the skip
// assertions above are meaningful rather than vacuously true.
func TestDetect_ScansProtectedDirWhenSkipperNil(t *testing.T) {
	records, _, _ := runSkillsUnderProtected(t, nil)

	if findSkill(records, "claude_project", "demo") == nil {
		t.Error("with a nil skipper (--include-tcc-protected) the ~/Documents skill must be scanned")
	}
}

// TestApplyLocks_SkipsXDGLockUnderProtectedDir covers the lock-path vector: when
// XDG_STATE_HOME points under a protected tree (e.g. ~/Library), the global
// skills.sh lock resolves there and loadLock's Stat would fire a prompt. With a
// skipper the lock must be skipped before any access; with a nil skipper it is
// read and parsed.
func TestApplyLocks_SkipsXDGLockUnderProtectedDir(t *testing.T) {
	xdgState := testHome + "/Library/state"
	lockPath := xdgState + "/skills/.skill-lock.json"

	run := func(skipper *tcc.Skipper) (*model.AgentSkillScanInfo, *tccAccessRecorder) {
		m, fs := newSkillsMock()
		m.SetEnv("XDG_STATE_HOME", xdgState)
		fs.addFileBytes(lockPath, []byte(`{"skills":{}}`))
		fs.commit()
		rec := &tccAccessRecorder{Mock: m}
		info := &model.AgentSkillScanInfo{}
		NewSkillsDetector(rec).WithSkipper(skipper).applyLocks(nil, nil, info)
		return info, rec
	}

	// Skipper ON: the XDG lock under ~/Library is never parsed or even accessed.
	info, rec := run(tcc.New(testHome))
	if info.LockFilesParsed != 0 {
		t.Errorf("XDG lock under ~/Library must not be parsed, LockFilesParsed = %d, want 0", info.LockFilesParsed)
	}
	if hits := rec.accessedUnder(testHome + "/Library"); len(hits) > 0 {
		t.Errorf("no filesystem access may occur under ~/Library (would fire a TCC prompt), got: %v", hits)
	}

	// Skipper nil (--include-tcc-protected): the same lock IS read and parsed.
	info, _ = run(nil)
	if info.LockFilesParsed != 1 {
		t.Errorf("with a nil skipper the XDG lock must be parsed, LockFilesParsed = %d, want 1", info.LockFilesParsed)
	}
}

// TestDetect_HomeWalkSkipsProtectedTree: the home walk sweeping $HOME must prune
// ~/Documents (ShouldSkip runs before the ReadDir) while still discovering the
// project under ~/code. The recorder proves zero filesystem access under
// ~/Documents — the walk's ReadDir is what would fire a TCC prompt, so an
// outcome-only "skill absent" check is too weak.
func TestDetect_HomeWalkSkipsProtectedTree(t *testing.T) {
	m, fs := newSkillsMock()
	fs.addSkill(testHome+"/Documents/proj/.claude/skills/x", "SKILL.md", validFrontmatter("x", "d"), nil)
	fs.addSkill(testHome+"/code/proj/.claude/skills/y", "SKILL.md", validFrontmatter("y", "d"), nil)
	fs.commit()
	rec := &tccAccessRecorder{Mock: m}

	records, _ := NewSkillsDetector(rec).WithSkipper(tcc.New(testHome)).Detect(context.Background(), nil, []string{testHome})

	if findSkill(records, "claude_project", "y") == nil {
		t.Error("skill under ~/code must be discovered by the walk")
	}
	if findSkill(records, "claude_project", "x") != nil {
		t.Error("skill under ~/Documents must NOT be discovered (protected tree)")
	}
	protected := testHome + "/Documents"
	if hits := rec.accessedUnder(protected); len(hits) > 0 {
		t.Errorf("no filesystem access may occur under %q (would fire a TCC prompt), got: %v", protected, hits)
	}
}

// TestDetect_HomeWalkSymlinkDecoyIntoProtected: a directory symlink pointing into
// ~/Documents must not pull the walk inside the protected tree — symlinks are
// recognized from the parent listing and never followed, so no access occurs
// under ~/Documents and the protected skill never surfaces.
func TestDetect_HomeWalkSymlinkDecoyIntoProtected(t *testing.T) {
	m, fs := newSkillsMock()
	fs.addSkill(testHome+"/Documents/proj/.claude/skills/x", "SKILL.md", validFrontmatter("x", "d"), nil)
	fs.addSymlink(testHome+"/code/link", testHome+"/Documents/proj")
	fs.commit()
	rec := &tccAccessRecorder{Mock: m}

	records, _ := NewSkillsDetector(rec).WithSkipper(tcc.New(testHome)).Detect(context.Background(), nil, []string{testHome})

	if findSkill(records, "claude_project", "x") != nil {
		t.Error("a symlink into ~/Documents must not surface the protected skill")
	}
	if hits := rec.accessedUnder(testHome + "/Documents"); len(hits) > 0 {
		t.Errorf("a symlink decoy must not cause access under ~/Documents, got: %v", hits)
	}
}

// TestDetect_HomeWalkNilSkipperEntersProtected is the opt-in counterpart: with
// --include-tcc-protected (nil skipper) the walk enters ~/Documents and finds
// both skills — the guard genuinely opts in, so the skip cases above are not
// vacuously true.
func TestDetect_HomeWalkNilSkipperEntersProtected(t *testing.T) {
	m, fs := newSkillsMock()
	fs.addSkill(testHome+"/Documents/proj/.claude/skills/x", "SKILL.md", validFrontmatter("x", "d"), nil)
	fs.addSkill(testHome+"/code/proj/.claude/skills/y", "SKILL.md", validFrontmatter("y", "d"), nil)
	fs.commit()

	records, _ := NewSkillsDetector(m).WithSkipper(nil).Detect(context.Background(), nil, []string{testHome})

	if findSkill(records, "claude_project", "x") == nil || findSkill(records, "claude_project", "y") == nil {
		t.Error("with a nil skipper (--include-tcc-protected) the walk must enter ~/Documents and find both")
	}
}

// TestDetect_HomeWalkRejectsProtectedSearchRoot: a protected dir passed
// explicitly as a search root under the default skipper-ON posture is rejected
// BEFORE any ReadDir — the walk never enters it, so no TCC prompt fires and
// nothing is emitted. The recorder proves zero access under ~/Documents;
// surfacing a protected tree requires --include-tcc-protected (the nil-skipper
// cases above).
func TestDetect_HomeWalkRejectsProtectedSearchRoot(t *testing.T) {
	m, fs := newSkillsMock()
	fs.addSkill(testHome+"/Documents/proj/.claude/skills/x", "SKILL.md", validFrontmatter("x", "d"), nil)
	fs.commit()
	rec := &tccAccessRecorder{Mock: m}

	records, info := NewSkillsDetector(rec).WithSkipper(tcc.New(testHome)).Detect(context.Background(), nil, []string{testHome + "/Documents"})

	if info.WalkRootsFound != 0 {
		t.Errorf("WalkRootsFound = %d, want 0 (a protected search root is rejected before any ReadDir)", info.WalkRootsFound)
	}
	if findSkill(records, "claude_project", "x") != nil {
		t.Error("a protected search root must not be inventoried under the default skipper")
	}
	if hits := rec.accessedUnder(testHome + "/Documents"); len(hits) > 0 {
		t.Errorf("no filesystem access may occur under ~/Documents (would fire a TCC prompt), got: %v", hits)
	}
}

// TestDetect_HomeWalkRejectsSymlinkedSearchRoot: a search root that is itself a
// symlink into a protected tree (~/scan -> ~/Documents/proj) must not be
// followed. The root is classified from its parent listing without resolving it,
// so ReadDir never dereferences the link into ~/Documents — no prompt fires and
// the protected skill stays uninventoried. This is the root-level counterpart to
// the child-symlink decoy test above.
func TestDetect_HomeWalkRejectsSymlinkedSearchRoot(t *testing.T) {
	m, fs := newSkillsMock()
	fs.addSkill(testHome+"/Documents/proj/.claude/skills/x", "SKILL.md", validFrontmatter("x", "d"), nil)
	fs.addSymlink(testHome+"/scan", testHome+"/Documents/proj")
	fs.commit()
	rec := &tccAccessRecorder{Mock: m}

	records, info := NewSkillsDetector(rec).WithSkipper(tcc.New(testHome)).Detect(context.Background(), nil, []string{testHome + "/scan"})

	if info.WalkRootsFound != 0 {
		t.Errorf("WalkRootsFound = %d, want 0 (a symlinked search root is not followed)", info.WalkRootsFound)
	}
	if findSkill(records, "claude_project", "x") != nil {
		t.Error("a symlinked search root must not surface the protected skill it points at")
	}
	if hits := rec.accessedUnder(testHome + "/Documents"); len(hits) > 0 {
		t.Errorf("resolving a symlinked root must not access ~/Documents (would fire a TCC prompt), got: %v", hits)
	}
}

// TestDetect_HomeWalkRejectsSymlinkedAncestorRoot: a root whose ANCESTOR (not its
// final component) is a symlink into a protected tree — ~/proj -> ~/Documents/real,
// root ~/proj/sub — must not be followed. rootIsRealDir lists each ancestor
// top-down and rejects at the symlinked component (~/proj) without ever listing
// it, so no ReadDir dereferences into ~/Documents and no prompt fires. This is the
// case a parent-only check missed.
func TestDetect_HomeWalkRejectsSymlinkedAncestorRoot(t *testing.T) {
	m, fs := newSkillsMock()
	fs.addSkill(testHome+"/Documents/real/sub/.claude/skills/x", "SKILL.md", validFrontmatter("x", "d"), nil)
	fs.addSymlink(testHome+"/proj", testHome+"/Documents/real")
	fs.commit()
	rec := &tccAccessRecorder{Mock: m}

	records, info := NewSkillsDetector(rec).WithSkipper(tcc.New(testHome)).Detect(context.Background(), nil, []string{testHome + "/proj/sub"})

	if info.WalkRootsFound != 0 {
		t.Errorf("WalkRootsFound = %d, want 0 (a symlinked ancestor is not followed)", info.WalkRootsFound)
	}
	if findSkill(records, "claude_project", "x") != nil {
		t.Error("a root reached through a symlinked ancestor must not surface the protected skill")
	}
	// The decisive check: the symlinked ancestor is never listed. A real os.ReadDir
	// of ~/proj would follow the link into ~/Documents and prompt; the ancestor scan
	// rejects at ~/proj (seen as a symlink in ~'s listing) before touching it.
	if hits := rec.accessedUnder(testHome + "/proj"); len(hits) > 0 {
		t.Errorf("the symlinked ancestor ~/proj must never be listed (real ReadDir would follow it into ~/Documents), got: %v", hits)
	}
	if hits := rec.accessedUnder(testHome + "/Documents"); len(hits) > 0 {
		t.Errorf("no filesystem access may occur under ~/Documents, got: %v", hits)
	}
}

// TestDetect_LinkIntoProtectedNeverFollowed closes the residual the old
// handleSymlinkEntry documented: a symlink from a safe skill root into
// ~/Documents used to be EvalSymlink'd (statting inside the protected tree)
// before its target was guarded. The target is now read with Readlink and
// guarded lexically first, so nothing under ~/Documents is touched — for an
// absolute target and for a relative one that only resolves there once joined.
func TestDetect_LinkIntoProtectedNeverFollowed(t *testing.T) {
	protected := testHome + "/Documents"
	for name, raw := range map[string]string{
		"absolute target": protected + "/secret/skill",
		"relative target": "../../Documents/secret/skill",
	} {
		t.Run(name, func(t *testing.T) {
			m, fs := newSkillsMock()
			fs.addSkill(protected+"/secret/skill", "SKILL.md", validFrontmatter("secret", "d"), nil)
			link := testHome + "/.claude/skills/decoy"
			fs.addSymlink(link, protected+"/secret/skill")
			m.SetReadlink(link, raw)
			fs.commit()

			rec := &tccAccessRecorder{Mock: m}
			records, info := NewSkillsDetector(rec).WithSkipper(tcc.New(testHome)).Detect(context.Background(), nil, nil)
			if len(records) != 0 {
				t.Errorf("a link into ~/Documents must not surface the protected skill, got %+v", records)
			}
			if len(info.Errors) != 0 {
				t.Errorf("skipping a protected target is not an error: %v", info.Errors)
			}
			if hits := rec.accessedUnder(protected); len(hits) > 0 {
				t.Errorf("no filesystem access may occur under %q (would fire a TCC prompt), got: %v", protected, hits)
			}
		})
	}
}
