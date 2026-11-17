package detector

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// codexMCPAuth answers from Codex's plaintext credentials file. Codex writes
// it only when the OS credential store (or, on Windows, its encrypted file)
// cannot be used, so a server with no entry has its sign-in, if any, where a
// passive scan does not look.
func codexMCPAuth(_ context.Context, r *MCPAuthResolver, _ string, s mcpAuthServer) (string, string) {
	root := filepath.Join(r.home, ".codex")
	if home := r.exec.Getenv("CODEX_HOME"); filepath.IsAbs(home) {
		root = home
	}
	return r.codexStoreAuth(root, s)
}

// openInterpreterMCPAuth answers for Open Interpreter, a Codex fork that keeps
// the same credentials file under its own root.
func openInterpreterMCPAuth(_ context.Context, r *MCPAuthResolver, _ string, s mcpAuthServer) (string, string) {
	return r.codexStoreAuth(openInterpreterHome(r.exec, r.home), s)
}

// codexStoreAuth answers from the credentials file under a Codex root.
func (r *MCPAuthResolver) codexStoreAuth(root string, s mcpAuthServer) (string, string) {
	entries, err := r.codexOAuthEntries(root)
	if err != nil {
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	}
	name := strings.TrimPrefix(s.name, "local:")
	for _, entry := range entries {
		if entry.serverName != name || entry.serverURL != s.url {
			continue
		}
		if entry.usable {
			return model.MCPAuthCredentialSaved, "codex_token_file"
		}
		return model.MCPAuthNeedsAuth, "codex_token_expired"
	}
	return model.MCPAuthUnknown, mcpAuthEncryptedStore
}

// codexOAuthEntry is what is kept of one stored Codex sign-in.
type codexOAuthEntry struct {
	serverName string
	serverURL  string
	usable     bool
}

// codexOAuthEntries reads <root>/.credentials.json, joined by the plaintext
// server name and URL that Codex itself also accepts as a match.
func (r *MCPAuthResolver) codexOAuthEntries(root string) ([]codexOAuthEntry, error) {
	path := filepath.Join(root, ".credentials.json")
	return loadStore(r, "codex:"+path, func() ([]codexOAuthEntry, error) {
		var doc map[string]json.RawMessage
		if _, err := r.readJSONStore(path, maxJSONConfigBytes, &doc); err != nil {
			return nil, err
		}
		stored := decodeEntries[codexStoredToken](doc)
		now := float64(r.now().UnixMilli())
		entries := make([]codexOAuthEntry, 0, len(stored))
		for _, key := range sortedMapKeys(stored) {
			e := stored[key]
			entries = append(entries, codexOAuthEntry{serverName: e.ServerName, serverURL: e.ServerURL, usable: e.usable(now)})
		}
		return entries, nil
	})
}

// codexStoredToken is one entry of Codex's credentials file.
type codexStoredToken struct {
	ServerName   string   `json:"server_name"`
	ServerURL    string   `json:"server_url"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresAt    *float64 `json:"expires_at"` // milliseconds
}

// codexRefreshMarginMs is how long before its expiry Codex stops using an
// access token as it is.
const codexRefreshMarginMs = 30_000

// usable is Codex's own test. Codex refreshes a token that is expired or about
// to expire only when the refresh token is bound to the issuer that granted
// it, so without an issuer an expired token means signing in again.
func (e codexStoredToken) usable(nowMs float64) bool {
	if strings.TrimSpace(e.ClientID) == "" {
		return false
	}
	if e.ExpiresAt != nil && nowMs+codexRefreshMarginMs >= *e.ExpiresAt {
		return strings.TrimSpace(e.Issuer) != "" && strings.TrimSpace(e.RefreshToken) != ""
	}
	return strings.TrimSpace(e.AccessToken) != ""
}
