package devcli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestDeclaredCommandsSupportJSON(t *testing.T) {
	for _, cmd := range commands {
		var b bytes.Buffer
		if err := Run(context.Background(), cmd, Options{Help: true, JSON: true}, nil, nil, &b, View{}); err != nil {
			t.Fatal(err)
		}
		var d struct {
			Descriptor
			Formats []string `json:"formats"`
		}
		if err := json.Unmarshal(b.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		if d.Name == "" || len(d.Sections) == 0 || strings.Join(d.Formats, ",") != "text,json" {
			t.Fatalf("incomplete descriptor: %+v", d)
		}
		for _, s := range d.Sections {
			if _, err := Parse(d.Descriptor, []string{s, "--json"}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestParseFindings(t *testing.T) {
	d := Findings{}.Describe()
	opts, err := Parse(d, []string{"--json", "search", "lodash@4", "--refresh"})
	if err != nil || opts.Search != "lodash@4" || !opts.JSON || !opts.Refresh || opts.Overview() {
		t.Fatalf("%+v, %v", opts, err)
	}
	if opts, err = Parse(d, nil); err != nil || !opts.Overview() {
		t.Fatalf("%+v, %v", opts, err)
	}
	for _, args := range [][]string{{"install"}, {"--fix"}, {"--override-gate"}, {"send-telemetry"}, {"search"}, {"search", "--json"}, {"mcp", "skills"}, {"mcp", "search", "x"}} {
		if _, err := Parse(d, args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func fixture(packages int) findingsResult {
	rep := &model.DeveloperReport{
		SchemaVersion: model.DeveloperReportSchemaVersion,
		ScannedAt:     time.Now().Add(-3 * time.Minute).UTC().Format(time.RFC3339),
		Cached:        true,
		Scope:         &model.ReportScope{Home: "/Users/sam", ProtectedPaths: []string{"/Users/sam/Documents"}},
		Attention: []model.AttentionItem{{Severity: model.AttentionHigh, Area: "credentials", Title: "1 plaintext credential file is tracked in git",
			Detail: "aws_credentials. A push publishes them.", Action: "dmg findings credentials"}},
		Areas: []model.ReportArea{
			{ID: "mcp", Title: "MCP servers", Status: model.AreaComplete, Items: []model.ReportItem{
				{Name: "gh", Kind: "claude_code", Detail: "npx -y @scope/server-github", Location: "/Users/sam/.claude.json"}}},
			{ID: "credentials", Title: "Credential locations", Status: model.AreaComplete, Items: []model.ReportItem{
				{Name: "aws_credentials\x1b[2J", Kind: "cloud", Location: "$HOME/.aws/credentials", Flags: []string{"plaintext", "git-tracked"}}}},
			{ID: "packages", Title: "Packages", Status: model.AreaComplete, Items: []model.ReportItem{}},
			{ID: "alerts", Title: "Threat alerts", Status: model.AreaUnavailable, StatusNote: "no local feed", Items: []model.ReportItem{}},
		},
	}
	for i := range packages {
		rep.Areas[2].Items = append(rep.Areas[2].Items, model.ReportItem{Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0", Kind: "npm",
			Count: 2, Locations: []string{"/Users/sam/app", "/Users/samantha/app"}})
	}
	return findingsResult{report: rep}
}

func render(t *testing.T, r findingsResult, view View) string {
	t.Helper()
	var b bytes.Buffer
	if err := r.RenderText(&b, view); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestOverviewFitsAScreen(t *testing.T) {
	out := render(t, fixture(20000), View{})
	if n := strings.Count(out, "\n"); n > 50 {
		t.Fatalf("overview is %d lines", n)
	}
	for _, want := range []string{"NEEDS ATTENTION (1)", "HIGH", "dmg findings credentials", "20,000", "Scanned 3m ago", "not checked: no local feed", "~/Documents"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") || strings.Contains(out, "pkg-1") {
		t.Fatalf("piped overview has control characters or package rows:\n%s", out)
	}
	for _, cols := range []int{80, 120} {
		colored := render(t, fixture(3), View{Color: true, Width: cols})
		if !strings.Contains(colored, "\x1b[") {
			t.Fatal("terminal overview has no colour")
		}
		for _, line := range strings.Split(stripColor(colored), "\n") {
			if width(line) > cols {
				t.Errorf("%d columns: line is %d wide: %q", cols, width(line), line)
			}
		}
	}
}

func stripColor(s string) string {
	for {
		i := strings.Index(s, "\x1b[")
		if i < 0 {
			return s
		}
		s = s[:i] + s[i+strings.Index(s[i:], "m")+1:]
	}
}

func TestAreaAndSearchViews(t *testing.T) {
	r := fixture(2)
	r.section = "credentials"
	out := render(t, r, View{})
	// Collected text is data: an escape sequence in it must not reach the terminal.
	if strings.Contains(out, "\x1b") || !strings.Contains(out, "~/.aws/credentials") || !strings.Contains(out, "git-tracked") || !strings.Contains(out, "1 plaintext credential file") {
		t.Fatalf("credentials view:\n%q", out)
	}
	var scoped model.DeveloperReport
	data, err := json.Marshal(r)
	if err != nil || json.Unmarshal(data, &scoped) != nil || len(scoped.Areas) != 1 || len(scoped.Attention) != 1 {
		t.Fatalf("scoped json: %s, %v", data, err)
	}

	r.section, r.search = "", "pkg-1@1.0"
	out = render(t, r, View{Width: 60})
	if !strings.Contains(out, "1 match") || !strings.Contains(out, "~/app") || !strings.Contains(out, "/Users/samantha/app") || strings.Contains(out, "pkg-0") {
		t.Fatalf("search view:\n%s", out)
	}
	r.search = "SERVER-GITHUB"
	if m := r.matches(); len(m) != 1 || m[0].Area != "mcp" {
		t.Fatalf("detail search: %+v", m)
	}
	r.search = "pkg-1@2"
	if m := r.matches(); len(m) != 0 {
		t.Fatalf("version mismatch matched: %+v", m)
	}
}

func TestNarrowTableKeepsRowsReadable(t *testing.T) {
	r := fixture(0)
	r.section = "mcp"
	out := render(t, r, View{Width: 60})
	if !strings.Contains(out, "npx -y @scope/server-github") || !strings.Contains(out, "~/.claude.json") {
		t.Fatalf("narrow table cut the evidence:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if width(line) > 60 {
			t.Errorf("line is %d wide: %q", width(line), line)
		}
	}
}

func TestCacheReuse(t *testing.T) {
	dir := t.TempDir()
	original := cacheDir
	cacheDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { cacheDir = original })

	on := true
	cfg := &cli.Config{SearchDirs: []string{"/home/u"}, EnableNPMScan: &on}
	key := cacheKey(cfg)
	now := time.Now()
	saveCache(key, &model.DeveloperReport{SchemaVersion: 2, ScannedAt: now.UTC().Format(time.RFC3339)}, 42*time.Second)
	if lastScanDuration() != 42*time.Second {
		t.Errorf("last scan duration: %v", lastScanDuration())
	}

	if got := loadCache(key, now.Add(5*time.Minute)); got == nil || !got.Cached {
		t.Fatalf("recent scan not reused: %+v", got)
	}
	if loadCache(key, now.Add(cacheMaxAge+time.Minute)) != nil {
		t.Error("stale scan reused")
	}
	if loadCache(key, now.Add(-time.Hour)) != nil {
		t.Error("scan from the future reused")
	}
	cfg.SearchDirs = []string{"/home/u", "/srv"}
	if other := cacheKey(cfg); other == key || loadCache(other, now) != nil {
		t.Error("changed settings reused the scan")
	}
}
