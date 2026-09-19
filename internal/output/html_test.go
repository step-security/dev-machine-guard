package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestPluginOutputStatesAndEscaping(t *testing.T) {
	disabled := false
	zero := int64(0)
	result := &model.ScanResult{
		AgentPluginScan: &model.AgentPluginScan{Contexts: []model.AgentPluginContext{{
			Agent: model.AgentClaudeCode, MarketplaceStatus: "complete", InstallationStatus: "partial",
			Plugins: []model.PluginObservation{{Name: "<script>example</script>", ConfiguredEnabled: &disabled, ComponentStatus: "partial", Components: []model.PluginComponent{{Kind: "mcp", Name: "declared-server", Status: "complete"}}}},
		}}},
		AgentSkills: []model.AgentSkill{{SkillName: "example:check", Usage: &model.SkillUsage{Availability: "available", RecordedUses: &zero}}},
	}
	var pretty bytes.Buffer
	if err := Pretty(&pretty, result, "never"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"configured enabled: no; effective enabled: unknown", "declared components: 1; coverage: partial", "example:check: 0 recorded uses"} {
		if !strings.Contains(pretty.String(), want) {
			t.Errorf("pretty missing %q", want)
		}
	}
	output := filepath.Join(t.TempDir(), "report.html")
	if err := HTML(output, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, want := range []string{"&lt;script&gt;example&lt;/script&gt;", "no / unknown", "Coverage: partial", "example:check</td><td>0"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(html, "<script>example</script>") {
		t.Fatal("unescaped plugin name")
	}
}

func TestPluginOnlyCommunityComponents(t *testing.T) {
	result := &model.ScanResult{
		AgentSkillScan: &model.AgentSkillScanInfo{},
		AgentPluginScan: &model.AgentPluginScan{Contexts: []model.AgentPluginContext{{
			Agent: model.AgentClaudeCode,
			Plugins: []model.PluginObservation{{Name: "test-plugin", Components: []model.PluginComponent{
				{Kind: model.PluginComponentSkill, Name: "test-skill", Skill: &model.AgentSkill{SkillName: "test-skill", Agent: model.AgentClaudeCode}},
				{Kind: model.PluginComponentMCP, Name: "test-mcp", MCPConfig: &model.MCPConfigEnterprise{ConfigSource: "test-mcp", Vendor: "test-vendor"}},
			}}},
		}}},
	}
	var out bytes.Buffer
	if err := Pretty(&out, result, "never"); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, bounds := range [][2]string{{"MCP SERVERS", "AGENT SKILLS"}, {"AGENT SKILLS", "IDE EXTENSIONS"}} {
		start := strings.Index(text, bounds[0])
		end := strings.Index(text, bounds[1])
		if start < 0 || end <= start {
			t.Fatalf("missing section %v", bounds)
		}
		if strings.Contains(text[start:end], "None detected") {
			t.Errorf("pretty %s reports None detected for a present nested component", bounds[0])
		}
	}
	file := filepath.Join(t.TempDir(), "report.html")
	if err := HTML(file, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	text = string(data)
	for _, bounds := range [][2]string{{"<h2>MCP Servers", "<h2>Agent Skills"}, {"<h2>Agent Skills", "<h2>Agent Plugins"}} {
		start := strings.Index(text, bounds[0])
		end := strings.Index(text, bounds[1])
		if start < 0 || end <= start {
			t.Fatalf("missing section %v", bounds)
		}
		if strings.Contains(text[start:end], "None detected") {
			t.Errorf("HTML %s reports None detected for a present nested component", bounds[0])
		}
	}
}

func TestHTML_GeneratesFile(t *testing.T) {
	tmpFile := os.TempDir() + "/test-dmg-report.html"
	defer func() { _ = os.Remove(tmpFile) }()

	result := &model.ScanResult{
		AgentVersion:     "1.9.1",
		ScanTimestamp:    1700000000,
		ScanTimestampISO: "2023-11-14T22:13:20Z",
		Device: model.Device{
			Hostname:     "test-host",
			SerialNumber: "ABC123",
			OSVersion:    "14.1",
			Platform:     "darwin",
			UserIdentity: "testuser",
		},
		AIAgentsAndTools: []model.AITool{},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
		NodePkgManagers:  []model.PkgManager{},
		NodePackages:     []any{},
		Summary:          model.Summary{},
	}

	if err := HTML(tmpFile, result); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	html := string(content)
	if !strings.Contains(html, "<html") {
		t.Error("missing <html tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("missing </html> tag")
	}
	if !strings.Contains(html, "StepSecurity") {
		t.Error("missing StepSecurity title")
	}
}

func TestHTML_PlatformLabels(t *testing.T) {
	tests := []struct {
		platform  string
		wantLabel string
	}{
		{"darwin", "macOS"},
		{"windows", "Windows"},
		{"linux", "Linux"},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			tmpFile := os.TempDir() + "/test-dmg-platform-" + tt.platform + ".html"
			defer func() { _ = os.Remove(tmpFile) }()

			result := &model.ScanResult{
				ScanTimestamp: 1700000000,
				Device: model.Device{
					Hostname:  "test",
					OSVersion: "1.0",
					Platform:  tt.platform,
				},
			}

			if err := HTML(tmpFile, result); err != nil {
				t.Fatal(err)
			}

			content, _ := os.ReadFile(tmpFile)
			html := string(content)

			if !strings.Contains(html, tt.wantLabel) {
				t.Errorf("platform %q: HTML missing label %q", tt.platform, tt.wantLabel)
			}
		})
	}
}

// htmlAgentSkillsSection slices the Agent Skills table out of the report so
// assertions cannot false-match the "None detected" cells of other tables.
// "Agent Skills <span" anchors on the section <h2>, not the summary card label.
func htmlAgentSkillsSection(t *testing.T, html string) string {
	t.Helper()
	start := strings.Index(html, "Agent Skills <span")
	if start < 0 {
		t.Fatal("HTML missing Agent Skills section header")
	}
	rest := html[start:]
	end := strings.Index(rest, "</table>")
	if end < 0 {
		t.Fatal("HTML missing Agent Skills table close")
	}
	return rest[:end]
}

func TestHTML_AgentSkillsStates(t *testing.T) {
	cases := []struct {
		name       string
		scan       *model.AgentSkillScanInfo
		skills     []model.AgentSkill
		want       string
		wantAbsent []string
	}{
		// Nil scan info = scan never ran (feature gate off), distinct from a
		// completed scan that found nothing.
		{"not scanned", nil, nil, "Not scanned", []string{"None detected"}},
		{"none detected", &model.AgentSkillScanInfo{}, nil, "None detected", []string{"Not scanned"}},
		{"populated", &model.AgentSkillScanInfo{SkillsFound: 1},
			[]model.AgentSkill{{SkillName: "pdf-tools", Agent: "claude-code", Source: "claude_user", Scope: "global"}},
			"pdf-tools", []string{"Not scanned", "None detected"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpFile := os.TempDir() + "/test-dmg-skills-" + strings.ReplaceAll(tc.name, " ", "-") + ".html"
			defer func() { _ = os.Remove(tmpFile) }()

			result := &model.ScanResult{
				ScanTimestamp:  1700000000,
				Device:         model.Device{Hostname: "test"},
				AgentSkills:    tc.skills,
				AgentSkillScan: tc.scan,
			}
			if err := HTML(tmpFile, result); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(tmpFile)
			if err != nil {
				t.Fatal(err)
			}
			section := htmlAgentSkillsSection(t, string(content))
			if !strings.Contains(section, tc.want) {
				t.Errorf("skills section missing %q: %q", tc.want, section)
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(section, absent) {
					t.Errorf("skills section must not contain %q: %q", absent, section)
				}
			}
		})
	}
}

func TestHTML_ContainsData(t *testing.T) {
	tmpFile := os.TempDir() + "/test-dmg-data.html"
	defer func() { _ = os.Remove(tmpFile) }()

	result := &model.ScanResult{
		ScanTimestamp: 1700000000,
		Device: model.Device{
			Hostname: "my-host",
		},
		AIAgentsAndTools: []model.AITool{
			{Name: "claude-code", Vendor: "Anthropic", Type: "cli_tool", Version: "1.0"},
		},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
		NodePkgManagers:  []model.PkgManager{},
		NodePackages:     []any{},
		Summary:          model.Summary{AIAgentsAndToolsCount: 1},
	}

	_ = HTML(tmpFile, result)
	content, _ := os.ReadFile(tmpFile)
	html := string(content)

	if !strings.Contains(html, "claude-code") {
		t.Error("missing AI tool name")
	}
	if !strings.Contains(html, "my-host") {
		t.Error("missing hostname")
	}
}
