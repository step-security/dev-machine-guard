package detector

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// isClaudeMCPSource reports whether a config source is one Claude Code reads.
func isClaudeMCPSource(source string) bool {
	switch source {
	case "claude_code", "project_mcp", "claude_plugin":
		return true
	}
	return false
}

// claudeMCPAuth answers from Claude Code's needs-auth cache and, off macOS,
// its credentials file. On macOS Claude keeps sign-ins in the Keychain, and a
// credentials file there is an optional fallback that can be stale.
func claudeMCPAuth(_ context.Context, r *MCPAuthResolver, _ string, s mcpAuthServer) (string, string) {
	if s.runtimeName == "" {
		return model.MCPAuthUnknown, mcpAuthNoRecord
	}
	root := claudeConfigDir(r.exec, r.home)
	cache, err := r.claudeNeedsAuthCache(root)
	if err != nil {
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	}
	if cache[s.runtimeName] {
		return model.MCPAuthNeedsAuth, "claude_needs_auth_cache"
	}
	if r.exec.GOOS() == model.PlatformDarwin {
		return model.MCPAuthUnknown, mcpAuthEncryptedStore
	}
	records, err := r.claudeOAuthRecords(root)
	if err != nil {
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	}
	var byName, byURL []claudeOAuthRecord
	for _, record := range records {
		if record.serverName != s.runtimeName {
			continue
		}
		byName = append(byName, record)
		if record.serverURL == s.url {
			byURL = append(byURL, record)
		}
	}
	// Claude keys a record by the URL after expanding variables, so a URL
	// written with one cannot be compared; only then does the one record under
	// the name stand in. Otherwise a record at another URL is left over from
	// before the URL changed, and Claude holds no token for the new one.
	candidates := byURL
	if len(candidates) == 0 && len(byName) == 1 && strings.Contains(s.url, "${") {
		candidates = byName
	}
	if len(candidates) == 0 {
		return model.MCPAuthUnknown, mcpAuthNoRecord
	}
	for _, record := range candidates {
		if record.usable {
			return model.MCPAuthCredentialSaved, "claude_token_file"
		}
	}
	return model.MCPAuthNeedsAuth, "claude_token_cleared"
}

// claudeNeedsAuth reports whether Claude Code's needs-auth cache names a
// server. An unreadable cache names nothing.
func (r *MCPAuthResolver) claudeNeedsAuth(runtimeName string) bool {
	cache, _ := r.claudeNeedsAuthCache(claudeConfigDir(r.exec, r.home))
	return cache[runtimeName]
}

// claudeNeedsAuthCache is the set of server names in Claude Code's needs-auth
// cache. Claude removes an entry only when a later connect succeeds and leaves
// expired ones in place, so an entry of any age still means the last attempt
// needed sign-in; the entry's own TTL only paces retries.
func (r *MCPAuthResolver) claudeNeedsAuthCache(root string) (map[string]bool, error) {
	path := filepath.Join(root, "mcp-needs-auth-cache.json")
	return loadStore(r, "claude-cache:"+path, func() (map[string]bool, error) {
		var entries map[string]json.RawMessage
		if _, err := r.readJSONStore(path, maxJSONConfigBytes, &entries); err != nil {
			return nil, err
		}
		names := make(map[string]bool, len(entries))
		for name := range entries {
			names[name] = true
		}
		return names, nil
	})
}

// claudeOAuthRecord is what is kept of one stored Claude Code sign-in.
type claudeOAuthRecord struct {
	serverName string
	serverURL  string
	usable     bool
}

// claudeOAuthRecords reads the mcpOAuth records of Claude Code's credentials
// file, joined by their plaintext name and URL rather than Claude's hashed key.
func (r *MCPAuthResolver) claudeOAuthRecords(root string) ([]claudeOAuthRecord, error) {
	path := filepath.Join(root, ".credentials.json")
	return loadStore(r, "claude-credentials:"+path, func() ([]claudeOAuthRecord, error) {
		var doc struct {
			MCPOAuth map[string]json.RawMessage `json:"mcpOAuth"`
		}
		if _, err := r.readJSONStore(path, maxJSONConfigBytes, &doc); err != nil {
			return nil, err
		}
		type storedToken struct {
			ServerName   string   `json:"serverName"`
			ServerURL    string   `json:"serverUrl"`
			AccessToken  string   `json:"accessToken"`
			RefreshToken string   `json:"refreshToken"`
			ExpiresAt    *float64 `json:"expiresAt"` // milliseconds
		}
		stored := decodeEntries[storedToken](doc.MCPOAuth)
		now := float64(r.now().UnixMilli())
		records := make([]claudeOAuthRecord, 0, len(stored))
		for _, key := range sortedMapKeys(stored) {
			e := stored[key]
			records = append(records, claudeOAuthRecord{serverName: e.ServerName, serverURL: e.ServerURL, usable: usableToken(e.AccessToken != "", e.RefreshToken != "", e.ExpiresAt, now)})
		}
		return records, nil
	})
}
