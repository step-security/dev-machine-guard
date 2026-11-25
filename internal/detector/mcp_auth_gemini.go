package detector

import (
	"context"
	"encoding/json"
	"path/filepath"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// geminiMCPAuth answers from Gemini CLI's mcp-oauth-tokens.json. Gemini writes
// the file at the first sign-in and keeps an expired token until a refresh
// fails, so a missing entry is no record, not a pending sign-in.
func geminiMCPAuth(_ context.Context, r *MCPAuthResolver, _ string, s mcpAuthServer) (string, string) {
	entries, err := r.geminiTokenEntries()
	if err != nil {
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	}
	var named, sameServer []geminiTokenEntry
	for _, e := range entries {
		if e.serverName != s.name {
			continue
		}
		named = append(named, e)
		if sameURL(e.serverURL, s.url) {
			sameServer = append(sameServer, e)
		}
	}
	if len(named) > 1 && len(sameServer) > 0 {
		named = sameServer
	}
	if len(named) == 0 {
		return model.MCPAuthUnknown, mcpAuthNoRecord
	}
	for _, e := range named {
		if e.usable {
			return model.MCPAuthCredentialSaved, "gemini_token_file"
		}
	}
	return model.MCPAuthNeedsAuth, "gemini_token_expired"
}

// geminiTokenEntry is what is kept of one stored Gemini CLI sign-in.
type geminiTokenEntry struct {
	serverName string
	serverURL  string
	usable     bool
}

// geminiTokenEntries reads ~/.gemini/mcp-oauth-tokens.json once.
func (r *MCPAuthResolver) geminiTokenEntries() ([]geminiTokenEntry, error) {
	path := filepath.Join(r.home, ".gemini", "mcp-oauth-tokens.json")
	return loadStore(r, "gemini:"+path, func() ([]geminiTokenEntry, error) {
		var doc []json.RawMessage
		if _, err := r.readJSONStore(path, maxJSONConfigBytes, &doc); err != nil {
			return nil, err
		}
		type storedEntry struct {
			ServerName   string `json:"serverName"`
			MCPServerURL string `json:"mcpServerUrl"`
			Token        struct {
				AccessToken  string   `json:"accessToken"`
				RefreshToken string   `json:"refreshToken"`
				ExpiresAt    *float64 `json:"expiresAt"` // milliseconds
			} `json:"token"`
		}
		now := float64(r.now().UnixMilli())
		entries := make([]geminiTokenEntry, 0, len(doc))
		for _, raw := range doc {
			var e *storedEntry
			if json.Unmarshal(raw, &e) != nil || e == nil {
				continue
			}
			t := e.Token
			entries = append(entries, geminiTokenEntry{serverName: e.ServerName, serverURL: e.MCPServerURL, usable: usableToken(t.AccessToken != "", t.RefreshToken != "", t.ExpiresAt, now)})
		}
		return entries, nil
	})
}

// antigravityMCPAuth answers for Antigravity, which keeps MCP sign-ins in the
// OS credential store or in an encrypted secrets file.
func antigravityMCPAuth(context.Context, *MCPAuthResolver, string, mcpAuthServer) (string, string) {
	return model.MCPAuthUnknown, mcpAuthEncryptedStore
}
