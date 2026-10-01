//go:build darwin

package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

func TestProtectedAbsoluteRule(t *testing.T) {
	home := t.TempDir()
	target := writeFile(t, home, "Library/Containers/test-app/marker.txt", "fixture")
	link := filepath.Join(home, "redirect")
	if err := os.Symlink(filepath.Dir(target), link); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{target, filepath.Join(link, "*.txt")} {
		rs := prep(t, RuleSet{Rules: []Rule{{ID: "test-rule", Revision: "1", FileGlobs: []string{pattern}}}})
		got := NewEngine(executor.NewReal(), tcc.New(home), DefaultCaps(), nil).Scan(context.Background(), rs, nil)
		if got.ScanComplete || len(got.Results) != 0 || len(got.EvaluatedRules) != 1 || got.EvaluatedRules[0].Complete {
			t.Fatalf("protected rule result=%+v", got)
		}
	}
}
