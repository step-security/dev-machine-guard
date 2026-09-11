package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

type countingFileExecutor struct {
	executor.Executor
	reads, stats int
}

func (e *countingFileExecutor) ReadFile(path string) ([]byte, error) {
	e.reads++
	return e.Executor.ReadFile(path)
}

func (e *countingFileExecutor) Stat(path string) (os.FileInfo, error) {
	e.stats++
	return e.Executor.Stat(path)
}

func TestScan_MixedFilenameOrder(t *testing.T) {
	for _, globs := range [][]string{{"**/*.js", "**/target.js"}, {"**/target.js", "**/*.js"}} {
		t.Run(globs[0], func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "target.js", "example")
			rs := prep(t, RuleSet{Rules: []Rule{
				{ID: "first", FileGlobs: globs},
				{ID: "second", FileGlobs: []string{"**/target.js"}},
			}})
			caps := DefaultCaps()
			caps.MaxFiles = 1
			got := newTestEngine(t, caps).Scan(context.Background(), rs, []string{root})
			if got.ScanComplete || len(got.Results) != 1 || got.Results[0].RuleID != "first" {
				t.Fatalf("scan = %+v, want only first rule and incomplete global scan", got)
			}
			if got.Results[0].Files[0].MatchedGlob != globs[0] {
				t.Errorf("matched glob = %q, want %q", got.Results[0].Files[0].MatchedGlob, globs[0])
			}
		})
	}
}

func TestScan_PrefixCoverage(t *testing.T) {
	root := t.TempDir()
	files := []string{"target.js", ".hidden/target.js", "a/target.js", "a/deep/target.js", "ab/target.js", "node_modules/pkg/target.js"}
	for _, name := range files {
		writeFile(t, root, name, "example")
	}
	tests := []struct {
		name, glob string
		want       []string
	}{
		{"literal", "a/target.js", []string{"a/target.js"}},
		{"anchored recursive", "a/**/target.js", []string{"a/deep/target.js", "a/target.js"}},
		{"wildcard directory", "a*/target.js", []string{"a/target.js", "ab/target.js"}},
		{"wildcard filename", "a/*.js", []string{"a/target.js"}},
		{"hidden", ".hidden/target.js", []string{".hidden/target.js"}},
		{"unrestricted", "**/target.js", []string{".hidden/target.js", "a/deep/target.js", "a/target.js", "ab/target.js", "node_modules/pkg/target.js", "target.js"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rs := prep(t, RuleSet{Rules: []Rule{{ID: "rule", FileGlobs: []string{tc.glob}}}})
			// Repeated roots must neither duplicate findings nor change glob precedence.
			got := newTestEngine(t, DefaultCaps()).Scan(context.Background(), rs, []string{root, root})
			if !got.ScanComplete || len(got.Results) != 1 {
				t.Fatalf("scan = %+v", got)
			}
			var names []string
			for _, f := range got.Results[0].Files {
				rel, err := filepath.Rel(root, f.Path)
				if err != nil {
					t.Fatal(err)
				}
				names = append(names, filepath.ToSlash(rel))
			}
			if !reflect.DeepEqual(names, tc.want) {
				t.Errorf("paths = %v, want %v", names, tc.want)
			}
		})
	}
}

func TestRelativeIndex_Pruning(t *testing.T) {
	rs := prep(t, RuleSet{Rules: []Rule{{ID: "rule", FileGlobs: []string{"src/config/target.js"}}}})
	state := &ruleState{rule: &rs.Rules[0]}
	idx := newRelativeIndex([]*ruleState{state})
	tests := []struct {
		name string
		want bool
	}{
		{"src", true}, {"src/config", true}, {"src/config/deeper", true},
		{"src/configuration", false}, {"src/other", false}, {"node_modules", false},
	}
	for _, tc := range tests {
		if got := idx.canDescend(tc.name); got != tc.want {
			t.Errorf("canDescend(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
	state.truncated = true
	if idx.canDescend("src") {
		t.Error("truncated rule still requires descending src")
	}
}

func TestScan_PrefixDoesNotFollowSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	target := writeFile(t, outside, "target.js", "example")
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, "target.js")); err != nil {
		t.Fatal(err)
	}
	rs := prep(t, RuleSet{Rules: []Rule{{ID: "rule", FileGlobs: []string{"linked/target.js", "target.js"}}}})
	got := newTestEngine(t, DefaultCaps()).Scan(context.Background(), rs, []string{root})
	if !got.ScanComplete || len(got.Results) != 0 {
		t.Errorf("scan = %+v, want complete with no symlink matches", got)
	}
}

func TestScan_SharedFilesReadAndStatOnce(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		t.Run(fmt.Sprintf("absolute=%v", absolute), func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"a.js", "b.js"} {
				writeFile(t, root, name, "example")
			}
			glob := "**/*.js"
			if absolute {
				glob = filepath.ToSlash(filepath.Join(root, "*.js"))
			}
			rs := RuleSet{}
			for i := 0; i < 10; i++ {
				rs.Rules = append(rs.Rules, Rule{ID: fmt.Sprint(i), FileGlobs: []string{glob}})
			}
			rs = prep(t, rs)
			exec := &countingFileExecutor{Executor: executor.NewReal()}
			got := NewEngine(exec, nil, DefaultCaps(), nil).Scan(context.Background(), rs, []string{root})
			if !got.ScanComplete || len(got.Results) != 10 {
				t.Fatalf("scan = %+v", got)
			}
			wantStats := 2
			if !absolute {
				wantStats++ // the relative walk also stats its root
			}
			if exec.reads != 2 || exec.stats != wantStats {
				t.Errorf("reads=%d stats=%d, want 2 reads and %d stats", exec.reads, exec.stats, wantStats)
			}
		})
	}
}

func TestScan_AbsoluteBudgetOrder(t *testing.T) {
	root := t.TempDir()
	first := writeFile(t, root, "a.js", "a")
	writeFile(t, root, "b.js", "b")
	glob := filepath.ToSlash(filepath.Join(root, "*.js"))
	rs := prep(t, RuleSet{Rules: []Rule{{ID: "first", FileGlobs: []string{glob}}, {ID: "second", FileGlobs: []string{glob}}}})
	caps := DefaultCaps()
	caps.MaxFiles = 3
	got := newTestEngine(t, caps).Scan(context.Background(), rs, nil)
	if got.ScanComplete || len(got.Results) != 2 || len(got.Results[0].Files) != 2 || len(got.Results[1].Files) != 1 {
		t.Fatalf("scan = %+v, want two files for first rule and one for second", got)
	}
	if got.Results[1].Files[0].Path != first {
		t.Errorf("second rule file = %q, want %q", got.Results[1].Files[0].Path, first)
	}
}

func TestScan_CachedFilesRespectEachRuleSizeLimit(t *testing.T) {
	for _, smallFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("smallFirst=%v", smallFirst), func(t *testing.T) {
			root := t.TempDir()
			target := writeFile(t, root, "a.js", "example")
			glob := filepath.ToSlash(target)
			rules := []Rule{{ID: "large", FileGlobs: []string{glob}}, {ID: "small", MaxFileSize: 1, FileGlobs: []string{glob}}}
			if smallFirst {
				rules[0], rules[1] = rules[1], rules[0]
			}
			got := newTestEngine(t, DefaultCaps()).Scan(context.Background(), prep(t, RuleSet{Rules: rules}), nil)
			small, large := fileResult(t, got, "small"), fileResult(t, got, "large")
			if !small.SizeExceeded || small.FileSHA256 != "" || large.SizeExceeded || large.FileSHA256 == "" {
				t.Errorf("small=%+v large=%+v", small, large)
			}
		})
	}
}

func TestScan_TruncationRetiresOnlyOverflowedRules(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.js", "b.js", "z.txt"} {
		writeFile(t, root, name, "example")
	}
	rs := prep(t, RuleSet{Rules: []Rule{
		{ID: "broad", FileGlobs: []string{"**/*.js", "**/a.js"}},
		{ID: "late", FileGlobs: []string{"**/z.txt"}},
	}})
	caps := DefaultCaps()
	caps.MaxMatchesPerRule = 1
	e := newTestEngine(t, caps)
	st := &scanState{cache: newFileCache()}
	for i := range rs.Rules {
		st.states = append(st.states, &ruleState{rule: &rs.Rules[i], seen: make(map[string]bool)})
	}
	e.walkRoots(context.Background(), st, []string{root, root})
	if st.globalStop || !st.states[0].truncated || st.states[0].seen != nil {
		t.Errorf("overflowed rule not retired: %+v", st.states[0])
	}
	if st.states[1].truncated || len(st.states[1].matches) != 1 {
		t.Errorf("exact-cap rule = %+v, want one complete match", st.states[1])
	}
}

func TestFileCache_BoundedAndEvicts(t *testing.T) {
	for _, size := range []int{0, 64} {
		t.Run(fmt.Sprintf("bytes=%d", size), func(t *testing.T) {
			mock := executor.NewMock()
			exec := &countingFileExecutor{Executor: mock}
			cache := newAbsoluteFileCache(256)
			for i := 0; i < 200; i++ {
				name := fmt.Sprint(i)
				mock.SetFile(name, []byte(strings.Repeat("x", size)))
				if _, _, ok := cache.read(exec, name); !ok {
					t.Fatal("read failed")
				}
				var retained int64
				for _, entry := range cache.entries {
					retained += int64(cap(entry.data))
				}
				if retained > 256 || retained != cache.bytes || len(cache.entries) > maxAbsoluteCacheEntries {
					t.Fatalf("retained=%d accounting=%d entries=%d", retained, cache.bytes, len(cache.entries))
				}
			}
			before := exec.reads
			cache.read(exec, "199")
			if exec.reads != before {
				t.Error("current file was reread")
			}
			cache.read(exec, "0")
			if exec.reads != before+1 {
				t.Error("oldest file was not evicted")
			}
		})
	}
}

func TestFileCache_ReadFailureMemoized(t *testing.T) {
	exec := &countingFileExecutor{Executor: executor.NewMock()}
	cache := newAbsoluteFileCache(256)
	for _, name := range []string{"missing", "another", "missing"} {
		if _, _, ok := cache.read(exec, name); ok {
			t.Fatal("missing file read succeeded")
		}
	}
	if exec.reads != 2 {
		t.Errorf("reads=%d, want 2", exec.reads)
	}
}
