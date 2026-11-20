package rules

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

type observedGlobExecutor struct {
	executor.Executor
	t        *testing.T
	syncRoot string
}

func (e observedGlobExecutor) ReadDir(dir string) ([]os.DirEntry, error) {
	if dir == e.syncRoot || strings.HasPrefix(dir, e.syncRoot+string(filepath.Separator)) {
		e.t.Errorf("enumerated excluded directory %q", dir)
	}
	return e.Executor.ReadDir(dir)
}

func (e observedGlobExecutor) Glob(pattern string) ([]string, error) {
	if strings.ContainsAny(filepath.Dir(pattern), "*?[") || strings.HasPrefix(pattern, e.syncRoot+string(filepath.Separator)) {
		e.t.Errorf("submitted a glob that can enumerate the excluded subtree: %q", pattern)
	}
	return e.Executor.Glob(pattern)
}

func TestAbsoluteGlobGuardsDirectories(t *testing.T) {
	root := t.TempDir()
	syncRoot := filepath.Join(root, "sync")
	writeFile(t, syncRoot, "project/payload.js", "sync file")
	local := writeFile(t, root, "local[1]/project/payload.js", "local file")
	skip := func(p string) bool { return p == syncRoot }
	for _, tc := range []struct {
		pattern string
		want    []string
	}{
		{"sync/*/payload.js", nil},
		{"sync/project/*.js", nil},
		{"*/project/payload.js", []string{local}},
		{"*/*/[ps]ayload.??", []string{local}},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			e := NewEngine(observedGlobExecutor{executor.NewReal(), t, syncRoot}, nil, DefaultCaps(), nil)
			got, err := e.absoluteMatches(context.Background(), filepath.Join(root, filepath.FromSlash(tc.pattern)), skip)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Errorf("matches = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	t.Run("Windows scan", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("OneDrive discovery is Windows-specific")
		}
		t.Setenv("OneDriveCommercial", syncRoot)
		e := NewEngine(observedGlobExecutor{executor.NewReal(), t, syncRoot}, tcc.ForRun(root, nil, nil), DefaultCaps(), nil)
		glob := filepath.ToSlash(filepath.Join(root, "*", "project", "payload.js"))
		rs := prep(t, RuleSet{Rules: []Rule{{ID: "absolute", FileGlobs: []string{glob}}}})
		got := e.Scan(context.Background(), rs, nil)
		if match := fileResult(t, got, "absolute"); match.Path != local {
			t.Errorf("match path = %q, want %q", match.Path, local)
		}
	})
}
