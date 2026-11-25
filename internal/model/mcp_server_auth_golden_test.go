package model

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// mcpServerAuthGoldenPath holds MCP config entries and one plugin MCP
// component carrying every sign-in status and evidence code. The backend tests
// its reader against the same bytes.
const mcpServerAuthGoldenPath = "testdata/mcp_server_auth_golden.json"

// mcpAuthEvidence is the closed evidence vocabulary, by the status it belongs to.
var mcpAuthEvidence = map[string]string{
	"claude_needs_auth_cache":      MCPAuthNeedsAuth,
	"claude_token_cleared":         MCPAuthNeedsAuth,
	"codex_token_expired":          MCPAuthNeedsAuth,
	"copilot_signin_pending":       MCPAuthNeedsAuth,
	"pi_registration_only":         MCPAuthNeedsAuth,
	"opencode_registration_only":   MCPAuthNeedsAuth,
	"cursor_no_token":              MCPAuthNeedsAuth,
	"cursor_cli_registration_only": MCPAuthNeedsAuth,
	"vscode_signed_out":            MCPAuthNeedsAuth,
	"vscode_no_token":              MCPAuthNeedsAuth,
	"mcp_remote_signin_pending":    MCPAuthNeedsAuth,
	"gemini_token_expired":         MCPAuthNeedsAuth,
	"devin_token_expired":          MCPAuthNeedsAuth,
	"claude_token_file":            MCPAuthCredentialSaved,
	"codex_token_file":             MCPAuthCredentialSaved,
	"copilot_signin_complete":      MCPAuthCredentialSaved,
	"pi_token_file":                MCPAuthCredentialSaved,
	"opencode_token_file":          MCPAuthCredentialSaved,
	"cursor_token_key":             MCPAuthCredentialSaved,
	"cursor_cli_token_file":        MCPAuthCredentialSaved,
	"vscode_token_key":             MCPAuthCredentialSaved,
	"mcp_remote_token_file":        MCPAuthCredentialSaved,
	"gemini_token_file":            MCPAuthCredentialSaved,
	"devin_token_file":             MCPAuthCredentialSaved,
	"config_header":                MCPAuthStaticCredential,
	"config_header_helper":         MCPAuthStaticCredential,
	"config_bearer_env":            MCPAuthStaticCredential,
	"config_env_key":               MCPAuthStaticCredential,
	"local_stdio":                  MCPAuthNotApplicable,
	"no_record":                    MCPAuthUnknown,
	"encrypted_store":              MCPAuthUnknown,
	"store_unavailable":            MCPAuthUnknown,
	"join_failed":                  MCPAuthUnknown,
	"client_not_supported":         MCPAuthUnknown,
}

type mcpServerAuthGolden struct {
	MCPConfigs      []MCPConfigEnterprise `json:"mcp_configs"`
	PluginComponent PluginComponent       `json:"plugin_component"`
}

func readMCPServerAuthGolden(t *testing.T) ([]byte, mcpServerAuthGolden) {
	t.Helper()
	raw, err := os.ReadFile(mcpServerAuthGoldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var golden mcpServerAuthGolden
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&golden); err != nil {
		t.Fatalf("golden payload does not fit the model: %v", err)
	}
	return raw, golden
}

func TestMCPServerAuthGolden_RoundTripsWithNoDroppedField(t *testing.T) {
	raw, golden := readMCPServerAuthGolden(t)
	encoded, err := json.Marshal(&golden)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := decodeGeneric(t, encoded), decodeGeneric(t, raw); !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the payload\n got: %s\nwant: %s", encoded, raw)
	}
}

func TestMCPServerAuthGolden_CoversTheWholeVocabulary(t *testing.T) {
	_, golden := readMCPServerAuthGolden(t)
	var entries []MCPServerAuth
	for _, c := range golden.MCPConfigs {
		entries = append(entries, c.ServerAuth...)
	}
	if golden.PluginComponent.MCPConfig == nil || len(golden.PluginComponent.MCPConfig.ServerAuth) == 0 {
		t.Fatal("plugin component carries no server_auth")
	}
	entries = append(entries, golden.PluginComponent.MCPConfig.ServerAuth...)

	seen := map[string]bool{}
	for _, e := range entries {
		status, ok := mcpAuthEvidence[e.Evidence]
		if !ok {
			t.Errorf("%s: evidence %q is not in the vocabulary", e.ServerName, e.Evidence)
		} else if status != e.Status {
			t.Errorf("%s: evidence %q under status %q, want %q", e.ServerName, e.Evidence, e.Status, status)
		}
		seen[e.Evidence] = true
	}
	for evidence := range mcpAuthEvidence {
		if !seen[evidence] {
			t.Errorf("golden does not exercise evidence %q", evidence)
		}
	}
}

// A config entry without sign-in status keeps its wire bytes.
func TestMCPConfigEnterprise_NoServerAuthKeepsWireShape(t *testing.T) {
	c := MCPConfigEnterprise{ConfigSource: "cursor", ConfigPath: "/home/testuser/.cursor/mcp.json", Vendor: "Cursor", ConfigContentBase64: "e30="}
	got, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"config_source":"cursor","config_path":"/home/testuser/.cursor/mcp.json","vendor":"Cursor","config_content_base64":"e30="}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
