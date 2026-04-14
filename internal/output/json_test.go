package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestJSON_ValidOutput(t *testing.T) {
	result := &model.ScanResult{
		AgentVersion:     "1.9.1",
		AgentURL:         "https://github.com/step-security/dev-machine-guard",
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

	var buf bytes.Buffer
	if err := JSON(&buf, result); err != nil {
		t.Fatal(err)
	}

	// Validate it's valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check required top-level keys
	requiredKeys := []string{
		"agent_version", "agent_url", "scan_timestamp", "scan_timestamp_iso",
		"device", "ai_agents_and_tools", "ide_installations",
		"ide_extensions", "mcp_configs", "summary",
	}
	for _, key := range requiredKeys {
		if _, ok := parsed[key]; !ok {
			t.Errorf("missing required key: %s", key)
		}
	}
}

func TestJSON_DeviceFields(t *testing.T) {
	result := &model.ScanResult{
		Device: model.Device{
			Hostname:     "my-host",
			SerialNumber: "SN123",
			OSVersion:    "15.0",
			Platform:     "darwin",
			UserIdentity: "dev",
		},
		AIAgentsAndTools: []model.AITool{},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
		NodePkgManagers:  []model.PkgManager{},
		NodePackages:     []any{},
	}

	var buf bytes.Buffer
	if err := JSON(&buf, result); err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}

	device, ok := parsed["device"].(map[string]any)
	if !ok {
		t.Fatal("device is not an object")
	}

	for _, key := range []string{"hostname", "os_version", "serial_number", "platform", "user_identity"} {
		if _, ok := device[key]; !ok {
			t.Errorf("missing device field: %s", key)
		}
	}
}

func TestJSON_SummaryFields(t *testing.T) {
	result := &model.ScanResult{
		AIAgentsAndTools: []model.AITool{},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
		NodePkgManagers:  []model.PkgManager{},
		NodePackages:     []any{},
		Summary: model.Summary{
			AIAgentsAndToolsCount: 5,
			IDEInstallationsCount: 3,
			IDEExtensionsCount:    10,
			MCPConfigsCount:       2,
			NodeProjectsCount:     0,
		},
	}

	var buf bytes.Buffer
	if err := JSON(&buf, result); err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}

	summary, ok := parsed["summary"].(map[string]any)
	if !ok {
		t.Fatal("summary is not an object")
	}

	for _, key := range []string{
		"ai_agents_and_tools_count", "ide_installations_count",
		"ide_extensions_count", "mcp_configs_count", "node_projects_count",
	} {
		v, ok := summary[key]
		if !ok {
			t.Errorf("missing summary field: %s", key)
			continue
		}
		if _, ok := v.(float64); !ok {
			t.Errorf("summary.%s is not numeric", key)
		}
	}
}

func TestJSON_AIToolSchema(t *testing.T) {
	running := true
	result := &model.ScanResult{
		AIAgentsAndTools: []model.AITool{
			{Name: "test-tool", Vendor: "TestVendor", Type: "cli_tool", Version: "1.0"},
			{Name: "test-fw", Vendor: "Unknown", Type: "framework", Version: "2.0", IsRunning: &running},
		},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
		NodePkgManagers:  []model.PkgManager{},
		NodePackages:     []any{},
		Summary:          model.Summary{AIAgentsAndToolsCount: 2},
	}

	var buf bytes.Buffer
	_ = JSON(&buf, result)

	var parsed map[string]any
	_ = json.Unmarshal(buf.Bytes(), &parsed)

	items, ok := parsed["ai_agents_and_tools"].([]any)
	if !ok {
		t.Fatal("ai_agents_and_tools is not an array")
	}
	for i, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("item %d is not an object", i)
		}
		if _, ok := obj["name"]; !ok {
			t.Errorf("item %d missing name", i)
		}
		if _, ok := obj["type"]; !ok {
			t.Errorf("item %d missing type", i)
		}
	}
}
