//go:build windows

package detector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// TestReal_SkillsJunctionFolds drives the skills detector's root enumeration
// and shadow folding over real directory junctions with the real executor —
// the mocked TestDetect_WindowsJunctionFolds proves the logic, this proves the
// primitives it rests on (ReadDir type bits, Readlink's NT spelling,
// EvalSymlinks through a junction) compose on Windows. Roots are temp dirs,
// not the scanning user's home, so the test is hermetic.
func TestReal_SkillsJunctionFolds(t *testing.T) {
	// Match the real user-home spelling even when CI's TEMP uses an 8.3 alias.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mkskill := func(dir string) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: pptx\ndescription: d\n---\nbody\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	junction := func(link, target string) {
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J %s: %v: %s", link, err, out)
		}
	}

	real := filepath.Join(home, ".agents", "skills", "pptx")
	mkskill(real)
	junction(filepath.Join(home, ".claude", "skills", "pptx"), real)                             // shared skill linked from Claude
	junction(filepath.Join(home, ".kiro", "skills", "pptx"), real)                               // and from Kiro
	mkskill(filepath.Join(home, ".claude", "skills", "copied"))                                  // a plain copy stays its own record
	junction(filepath.Join(home, ".kiro", "skills", "notskill"), filepath.Join(home, ".agents")) // junction to a non-skill dir
	junction(filepath.Join(home, ".kiro", "skills", "broken"), filepath.Join(home, "gone"))
	_ = os.Remove(filepath.Join(home, "gone")) // never existed; mklink /J does not require the target

	d := NewSkillsDetector(executor.NewReal())
	info := &model.AgentSkillScanInfo{}
	memo := map[string]*skillScan{}
	var discovered []discoveredSkill
	for _, r := range []skillsRoot{
		{path: filepath.Join(home, ".agents", "skills"), source: "agents_user", agent: "shared", scope: "global"},
		{path: filepath.Join(home, ".claude", "skills"), source: "claude_user", agent: "claude", scope: "global"},
		{path: filepath.Join(home, ".kiro", "skills"), source: "kiro_user", agent: "kiro", scope: "global"},
	} {
		discovered = append(discovered, d.enumerateRoot(context.Background(), r, info, memo)...)
	}
	skills := collapseSymlinkShadows(discovered)

	var pptx, copied *model.AgentSkill
	for i := range skills {
		switch {
		case skills[i].Source == "agents_user" && skills[i].SkillSlug == "pptx":
			pptx = &skills[i]
		case skills[i].Source == "claude_user" && skills[i].SkillSlug == "copied":
			copied = &skills[i]
		}
	}
	if len(skills) != 2 || pptx == nil || copied == nil {
		t.Fatalf("want exactly the folded pptx and the copied skill, got %+v", skills)
	}
	if !equalStrings(pptx.SymlinkSources, []string{"claude_user", "kiro_user"}) {
		t.Errorf("symlink_sources = %v, want [claude_user kiro_user]", pptx.SymlinkSources)
	}
	for _, e := range info.Errors {
		if !strings.Contains(e, "broken") {
			t.Errorf("unexpected error: %s", e)
		}
	}
}
