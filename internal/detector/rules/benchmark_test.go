package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Keep fixtures and Prepare outside the timer so before/after comparisons
// measure only the scan. These benchmarks need no backend or user-home access.
func benchmarkScan(b *testing.B, rs RuleSet, root string, caps Caps) {
	b.Helper()
	if err := rs.Prepare(); err != nil {
		b.Fatal(err)
	}
	e := NewEngine(executor.NewReal(), nil, caps, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := e.Scan(context.Background(), rs, []string{root}); !got.ScanComplete {
			b.Fatal("global scan budget exceeded")
		}
	}
}

func benchmarkFile(b *testing.B, root, name string, data []byte) {
	b.Helper()
	target := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkScanMixedFilenames(b *testing.B) {
	root := b.TempDir()
	for i := 0; i < 10000; i++ {
		benchmarkFile(b, root, fmt.Sprintf("ordinary-%05d.txt", i), nil)
	}
	rs := RuleSet{}
	for i := 0; i < 100; i++ {
		rs.Rules = append(rs.Rules, Rule{ID: fmt.Sprint(i), FileGlobs: []string{fmt.Sprintf("**/indicator-%d.js", i)}})
	}
	rs.Rules = append(rs.Rules, Rule{ID: "wildcard", FileGlobs: []string{"**/*.suspicious"}})
	benchmarkScan(b, rs, root, DefaultCaps())
}

func BenchmarkScanLiteralPrefix(b *testing.B) {
	root := b.TempDir()
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			benchmarkFile(b, root, fmt.Sprintf("unrelated-%03d/file-%03d.txt", i, j), nil)
		}
	}
	benchmarkFile(b, root, "config/target.js", []byte("example"))
	benchmarkScan(b, RuleSet{Rules: []Rule{{ID: "literal", FileGlobs: []string{"config/target.js"}}}}, root, DefaultCaps())
}

func BenchmarkScanAbsoluteSharedFiles(b *testing.B) {
	root := b.TempDir()
	data := make([]byte, 64<<10)
	for i := 0; i < 20; i++ {
		benchmarkFile(b, root, fmt.Sprintf("file-%03d.js", i), data)
	}
	rs := RuleSet{}
	for i := 0; i < 10; i++ {
		rs.Rules = append(rs.Rules, Rule{ID: fmt.Sprint(i), FileGlobs: []string{filepath.ToSlash(filepath.Join(root, "*.js"))}})
	}
	benchmarkScan(b, rs, root, DefaultCaps())
}

func BenchmarkScanTruncatedRule(b *testing.B) {
	root := b.TempDir()
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			benchmarkFile(b, root, fmt.Sprintf("dir-%03d/file-%03d.js", i, j), nil)
		}
	}
	caps := DefaultCaps()
	caps.MaxMatchesPerRule = 5
	benchmarkScan(b, RuleSet{Rules: []Rule{{ID: "broad", FileGlobs: []string{"**/*.js"}}}}, root, caps)
}

// Mirrors the backend's package.json rule: ordinary dependency metadata should
// fail the mandatory condition without paying for optional shell-pipe evidence.
func BenchmarkScanPackageJSON(b *testing.B) {
	root := b.TempDir()
	data := []byte(`{"name":"ordinary-package","description":"` + strings.Repeat("ordinary package metadata ", 100) + `","scripts":{"test":"node test.js"}}`)
	for i := 0; i < 100; i++ {
		benchmarkFile(b, root, fmt.Sprintf("node_modules/pkg-%03d/package.json", i), data)
		for j := 0; j < 20; j++ {
			benchmarkFile(b, root, fmt.Sprintf("node_modules/pkg-%03d/file-%03d.js", i, j), nil)
		}
	}
	rs := RuleSet{Rules: []Rule{{ID: "test-script", FileGlobs: []string{"**/package.json"}, Groups: []ConditionGroup{{ID: "test-hijack", Conditions: []Condition{
		{ID: "test-runs-setup", Kind: condKindRegex, Mandatory: true, Pattern: `"test"\s*:\s*"[^"]*setup\.(c?js|mjs)`},
		{ID: "pipe-to-shell", Kind: condKindRegex, Pattern: `(?i)(curl|wget)[^"]*\|\s*(ba)?sh`},
	}}}}}}
	benchmarkScan(b, rs, root, DefaultCaps())
}
