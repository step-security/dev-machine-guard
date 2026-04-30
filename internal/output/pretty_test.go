package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestPretty_ContainsHeaders(t *testing.T) {
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
		Summary:          model.Summary{},
	}

	var buf bytes.Buffer
	_ = Pretty(&buf, result, "never")

	output := buf.String()
	for _, header := range []string{"DEVICE", "SUMMARY", "AI AGENTS", "IDE & AI DESKTOP APPS", "MCP SERVERS", "IDE EXTENSIONS"} {
		if !strings.Contains(output, header) {
			t.Errorf("output missing header: %s", header)
		}
	}
}

func TestPretty_ContainsBanner(t *testing.T) {
	result := &model.ScanResult{
		AgentVersion:     "1.9.1",
		ScanTimestamp:    1700000000,
		Device:           model.Device{Hostname: "test"},
		AIAgentsAndTools: []model.AITool{},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
	}

	var buf bytes.Buffer
	_ = Pretty(&buf, result, "never")
	output := buf.String()

	if !strings.Contains(output, "StepSecurity Dev Machine Guard") {
		t.Error("output missing banner title")
	}
}

func TestPretty_ShowsDeviceInfo(t *testing.T) {
	result := &model.ScanResult{
		ScanTimestamp: 1700000000,
		Device: model.Device{
			Hostname:     "my-host",
			SerialNumber: "SN123",
			OSVersion:    "14.1",
			UserIdentity: "dev-user",
		},
		AIAgentsAndTools: []model.AITool{},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
	}

	var buf bytes.Buffer
	_ = Pretty(&buf, result, "never")
	output := buf.String()

	for _, expected := range []string{"my-host", "SN123", "14.1", "dev-user"} {
		if !strings.Contains(output, expected) {
			t.Errorf("output missing device info: %s", expected)
		}
	}
}

func TestPretty_PlatformLabels(t *testing.T) {
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
			result := &model.ScanResult{
				ScanTimestamp: 1700000000,
				Device: model.Device{
					Hostname:  "test",
					OSVersion: "1.0",
					Platform:  tt.platform,
				},
			}

			var buf bytes.Buffer
			_ = Pretty(&buf, result, "never")
			output := buf.String()

			if !strings.Contains(output, tt.wantLabel) {
				t.Errorf("platform %q: output missing label %q", tt.platform, tt.wantLabel)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"short", 10, "short"},
		{"a very long string", 10, "a very ..."},
		{"exactly10!", 10, "exactly10!"},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}

func TestIdeDisplayName(t *testing.T) {
	tests := map[string]string{
		"vscode":                    "Visual Studio Code",
		"cursor":                    "Cursor",
		"claude_desktop":            "Claude",
		"microsoft_copilot_desktop": "Microsoft Copilot",
		"intellij_idea":             "IntelliJ IDEA",
		"intellij_idea_ce":          "IntelliJ IDEA CE",
		"pycharm":                   "PyCharm",
		"pycharm_ce":                "PyCharm CE",
		"webstorm":                  "WebStorm",
		"goland":                    "GoLand",
		"rider":                     "Rider",
		"phpstorm":                  "PhpStorm",
		"rubymine":                  "RubyMine",
		"clion":                     "CLion",
		"datagrip":                  "DataGrip",
		"fleet":                     "Fleet",
		"android_studio":            "Android Studio",
		"eclipse":                   "Eclipse",
		"xcode":                     "Xcode",
		"unknown":                   "unknown",
	}
	for input, expected := range tests {
		got := ideDisplayName(input)
		if got != expected {
			t.Errorf("ideDisplayName(%q) = %q, want %q", input, got, expected)
		}
	}
}
