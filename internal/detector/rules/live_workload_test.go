package rules

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestMandatoryScreenPreservesEvidence(t *testing.T) {
	// Cover every mandatory/negated combination, with a failing group before a
	// satisfying group. All evidence must survive if ANY group is satisfied.
	for mask := 0; mask < 256; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			r := Rule{ID: "rule", FileGlobs: []string{"**/package.json"}}
			for g := 0; g < 2; g++ {
				group := ConditionGroup{ID: fmt.Sprint(g)}
				for c := 0; c < 2; c++ {
					i := 2*g + c
					pattern := "present"
					if c == 1 {
						pattern = "absent"
					}
					group.Conditions = append(group.Conditions, Condition{ID: fmt.Sprint(c), Kind: condKindRegex, Pattern: pattern, Mandatory: mask&(1<<i) != 0, Negate: mask&(1<<(i+4)) != 0})
				}
				r.Groups = append(r.Groups, group)
			}
			rs := prep(t, RuleSet{Rules: []Rule{r}})
			data := []byte("present")
			wantReported := false
			var wantGroups []model.GroupResult
			for _, g := range rs.Rules[0].Groups {
				gr, ok := evalGroup(g, data, "")
				wantGroups = append(wantGroups, gr)
				wantReported = wantReported || ok
			}
			root := t.TempDir()
			writeFile(t, root, "package.json", string(data))
			got := newTestEngine(t, DefaultCaps()).Scan(context.Background(), rs, []string{root})
			if (len(got.Results) > 0) != wantReported {
				t.Fatalf("reported=%v want=%v", got.Results, wantReported)
			}
			if wantReported && !reflect.DeepEqual(got.Results[0].Files[0].Groups, wantGroups) {
				t.Fatalf("evidence=%+v want=%+v", got.Results[0].Files[0].Groups, wantGroups)
			}
		})
	}
}

func TestCandidateWalkMatchesWalkDirOrder(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b/target.js", "b/z/target.js", "c/ignored.txt", "d.js", ".hidden/target.js", "node_modules/pkg/target.js"} {
		writeFile(t, root, name, "data")
	}
	for _, globs := range [][]string{{"**/target.js"}, {"**/target.js", "**/*.js"}} {
		rs := prep(t, RuleSet{Rules: []Rule{{ID: "rule", FileGlobs: globs}}})
		idx := newRelativeIndex([]*ruleState{{rule: &rs.Rules[0]}})
		var want, got []string
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || (d.Type().IsRegular() && (len(idx.wildcards) > 0 || len(idx.byName[d.Name()]) > 0)) {
				want = append(want, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		err = newTestEngine(t, DefaultCaps()).walkCandidates(context.Background(), root, idx, func(p string, _ fs.DirEntry, _ error) error { got = append(got, p); return nil })
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("walk=%v err=%v want=%v", got, err, want)
		}
	}
}

func TestScanSymlinkRootIsNotFollowed(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "target.js", "data")
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip(err)
	}
	rs := prep(t, RuleSet{Rules: []Rule{{ID: "rule", FileGlobs: []string{"**/target.js"}}}})
	got := newTestEngine(t, DefaultCaps()).Scan(context.Background(), rs, []string{link})
	if !got.ScanComplete || len(got.Results) != 0 {
		t.Fatalf("followed symlink root: %+v", got)
	}
}

type partialDirectoryExecutor struct{ executor.Executor }

func (e partialDirectoryExecutor) ReadDir(name string) ([]os.DirEntry, error) {
	entries, _ := e.Executor.ReadDir(name)
	return entries, errors.New("partial directory read")
}

func TestScanPartialDirectoryReadKeepsEntries(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "target.js", "data")
	rs := prep(t, RuleSet{Rules: []Rule{{ID: "rule", FileGlobs: []string{"**/target.js"}}}})
	e := NewEngine(partialDirectoryExecutor{executor.NewReal()}, nil, DefaultCaps(), nil)
	got := e.Scan(context.Background(), rs, []string{root})
	if len(got.Results) != 1 || len(got.Results[0].Files) != 1 {
		t.Fatalf("lost entries returned with a read error: %+v", got)
	}
}
