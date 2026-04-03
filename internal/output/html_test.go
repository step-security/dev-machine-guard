package output

import (
	"os"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestHTML_GeneratesFile(t *testing.T) {
	tmpFile := os.TempDir() + "/test-dmg-report.html"
	defer os.Remove(tmpFile)

	result := &model.ScanResult{
		AgentVersion:     "1.9.0",
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

func TestHTML_ContainsData(t *testing.T) {
	tmpFile := os.TempDir() + "/test-dmg-data.html"
	defer os.Remove(tmpFile)

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
