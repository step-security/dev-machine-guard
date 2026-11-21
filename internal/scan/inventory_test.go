package scan

import (
	"encoding/base64"
	"slices"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func areaByID(t *testing.T, rep *model.DeveloperReport, id string) model.ReportArea {
	t.Helper()
	for _, a := range rep.Areas {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no area %q", id)
	return model.ReportArea{}
}

func TestDeveloperViewRowsAndCoverage(t *testing.T) {
	on := true
	packages := []model.PackageDetail{{Name: "demo", Version: "1.2.3"}, {Name: "declared", Version: "https://user:token@example.test/repo"}}
	r := model.ScanResult{
		IDEExtensions: []model.Extension{
			{ID: "example.demo", Version: "1.9.0", InstallPath: "/ext/demo-1.9.0", IDEType: "code"},
			{ID: "example.demo", Version: "1.10.0", InstallPath: "/ext/demo-1.10.0", IDEType: "code"},
		},
		NodeProjects: []model.ProjectInfo{
			{Path: "/work/app", PackageManager: "npm", Packages: packages},
			{Path: "/work/app-worktrees/fix", PackageManager: "npm", Packages: packages},
			{Path: "/work/empty-a", PackageManager: "npm"},
			{Path: "/work/empty-b", PackageManager: "npm"},
		},
		RuntimeScan: &model.RuntimeScanResult{Truncated: true},
	}
	rep := developerView(&r, nil, &cli.Config{EnableNPMScan: &on, EnableBrewScan: &on}, model.PlatformDarwin, &model.ReportScope{})

	ext := areaByID(t, rep, "extensions").Items
	if len(ext) != 1 || ext[0].Version != "1.10.0" || ext[0].Location != "/ext/demo-1.10.0" || ext[0].Detail == "" {
		t.Fatalf("extensions: %+v", ext)
	}
	projects := areaByID(t, rep, "projects")
	if len(projects.Items) != 3 || projects.Status != model.AreaPartial {
		t.Fatalf("projects: %+v", projects)
	}
	i := slices.IndexFunc(projects.Items, func(it model.ReportItem) bool { return it.Name == "/work/app" })
	if i < 0 || projects.Items[i].Count != 2 || len(projects.Items[i].Locations) != 2 {
		t.Fatalf("identical projects did not share a row: %+v", projects.Items)
	}
	pkgs := areaByID(t, rep, "packages").Items
	if len(pkgs) != 2 || pkgs[0].Name != "declared" || pkgs[0].Version != "" || pkgs[1].Version != "1.2.3" || pkgs[1].Count != 2 || len(pkgs[1].Locations) != 2 {
		t.Fatalf("packages: %+v", pkgs)
	}
	for id, status := range map[string]string{
		"runtimes": model.AreaComplete, "credentials": model.AreaUnavailable, "browser": model.AreaUnavailable,
		"alerts": model.AreaUnavailable, "mcp": model.AreaComplete,
	} {
		if got := areaByID(t, rep, id).Status; got != status {
			t.Errorf("%s: %s, want %s", id, got, status)
		}
	}
}

func TestAttentionComesFromEvidence(t *testing.T) {
	on := true
	cfg := &cli.Config{EnableNPMScan: &on, EnablePythonScan: &on, EnableBrewScan: &on}
	config := func(body string) []model.MCPConfigEnterprise {
		return []model.MCPConfigEnterprise{{ConfigSource: "claude_code", ConfigPath: "/home/u/.claude.json", ConfigContentBase64: base64.StdEncoding.EncodeToString([]byte(body))}}
	}
	clean := model.ScanResult{
		CredentialScan:       &model.CredentialScanInfo{ScanComplete: true, Findings: []model.CredentialFinding{{SourceID: "ssh_private_keys", Protection: model.CredentialProtectionProtected, Mode: "0600", Count: 1}}},
		BrowserExtensionScan: &model.BrowserExtensionScanInfo{ScanComplete: true},
	}
	rep := developerView(&clean, config(`{"mcpServers":{"pinned":{"command":"npx","args":["-y","@scope/server@1.2.3"]}}}`), cfg, model.PlatformDarwin, &model.ReportScope{})
	if len(rep.Attention) != 0 {
		t.Fatalf("clean machine raised: %+v", rep.Attention)
	}

	risky := clean
	risky.CredentialScan = &model.CredentialScanInfo{ScanComplete: true, Findings: []model.CredentialFinding{
		{SourceID: "aws_credentials", Protection: model.CredentialProtectionPlaintext, Mode: "0600", GitTracked: true, Count: 1},
		{SourceID: "netrc", Protection: model.CredentialProtectionPlaintext, Mode: "0644", Count: 1},
	}}
	risky.BrowserExtensionScan = &model.BrowserExtensionScanInfo{ScanComplete: true, Findings: []model.BrowserExtensionFinding{
		{BrowserID: "chrome", Name: "gone", EnabledState: model.BrowserExtEnabled, StoreListing: model.BrowserExtStoreListingDelisted},
		{BrowserID: "chrome", Name: "off", EnabledState: model.BrowserExtDisabled, StoreListing: model.BrowserExtStoreListingDelisted},
	}}
	risky.AgentSkills = []model.AgentSkill{{SkillName: "deploy", Agent: "claude-code", HasShellInjection: true}}
	rep = developerView(&risky, config(`{"mcpServers":{"gh":{"command":"npx","args":["-y","@scope/server"]},"far":{"url":"http://mcp.example.test/sse"}},
		"projects":{"/work/app":{"mcpServers":{"local":{"url":"http://localhost:3000"}}}}}`), cfg, model.PlatformDarwin, &model.ReportScope{})
	got := map[string]string{}
	for _, a := range rep.Attention {
		got[a.Title] = a.Severity
	}
	want := map[string]string{
		"1 plaintext credential file is tracked in git":                    model.AttentionHigh,
		"1 enabled browser extension was delisted or flagged by its store": model.AttentionHigh,
		"1 agent skill runs shell commands when it loads":                  model.AttentionMedium,
		"1 location holds credentials in plaintext":                        model.AttentionMedium,
	}
	if len(got) != len(want) {
		t.Fatalf("attention: %+v", rep.Attention)
	}
	for title, severity := range want {
		if got[title] != severity {
			t.Errorf("%q: %q, want %q", title, got[title], severity)
		}
	}
	mcp := areaByID(t, rep, "mcp")
	if len(mcp.Items) != 3 {
		t.Fatalf("mcp servers: %+v", mcp.Items)
	}
	// The dashboard lists MCP servers without judging how they are launched.
	for _, it := range mcp.Items {
		if slices.ContainsFunc(it.Flags, func(f string) bool { return f != flagRemote }) {
			t.Errorf("mcp row carries a finding: %+v", it)
		}
	}
}

func TestCodexTOMLServers(t *testing.T) {
	got := mcpServers([]byte("[mcp_servers.docs]\ncommand = \"uvx\"\nargs = [\"docs-server\"]\n"), true)
	if len(got) != 1 || got[0].name != "docs" || got[0].command != "uvx" || !slices.Equal(got[0].args, []string{"docs-server"}) {
		t.Fatalf("%+v", got)
	}
}
