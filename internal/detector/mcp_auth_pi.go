package detector

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// piMCPAuth answers from Pi's mcp-auth.json. Pi 1.0 keys an entry by the
// server name and its normalized URL, Pi 0.99 by the normalized URL alone.
// The entry's own expiry is not read: an expired access token with a refresh
// token still refreshes.
func piMCPAuth(_ context.Context, r *MCPAuthResolver, _ string, s mcpAuthServer) (string, string) {
	entries, err := r.piOAuthEntries()
	if err != nil {
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	}
	u, ok := webURL(s.url)
	if !ok {
		return model.MCPAuthUnknown, mcpAuthNoRecord
	}
	norm := u.String()
	for _, key := range []string{"mcp__" + strings.ReplaceAll(s.name, "-", "_") + "|" + norm, norm} {
		hasToken, ok := entries[key]
		if !ok {
			continue
		}
		if hasToken {
			return model.MCPAuthCredentialSaved, "pi_token_file"
		}
		return model.MCPAuthNeedsAuth, "pi_registration_only"
	}
	return model.MCPAuthUnknown, mcpAuthNoRecord
}

// piOAuthEntries maps each mcp-auth.json key to whether its entry holds a
// token.
func (r *MCPAuthResolver) piOAuthEntries() (map[string]bool, error) {
	root, _ := piAgentRoot(r.env, r.home)
	path := filepath.Join(root, "mcp-auth.json")
	return loadStore(r, "pi:"+path, func() (map[string]bool, error) {
		var doc map[string]json.RawMessage
		if _, err := r.readJSONStore(path, maxJSONConfigBytes, &doc); err != nil {
			return nil, err
		}
		type storedEntry struct {
			Tokens struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			} `json:"tokens"`
		}
		stored := decodeEntries[storedEntry](doc)
		entries := make(map[string]bool, len(stored))
		for key, e := range stored {
			entries[key] = e.Tokens.AccessToken != "" || e.Tokens.RefreshToken != ""
		}
		return entries, nil
	})
}
