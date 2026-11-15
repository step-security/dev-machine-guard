package detector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// devinMCPAuth answers from the one token file Devin keeps per server. Devin
// deletes the file at logout, and a server that needs no sign-in has none, so
// a missing file is no record.
func devinMCPAuth(_ context.Context, r *MCPAuthResolver, _ string, s mcpAuthServer) (string, string) {
	data, err := r.readStore(filepath.Join(r.devinOAuthDir(), devinTokenFile(s.name, s.url)), maxMCPAuthFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return model.MCPAuthUnknown, mcpAuthNoRecord
	}
	var token *struct {
		AccessToken  string   `json:"access_token"`
		RefreshToken string   `json:"refresh_token"`
		ExpiresAt    *float64 `json:"expires_at"` // seconds
	}
	if err != nil || json.Unmarshal(data, &token) != nil || token == nil {
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	}
	if usableToken(token.AccessToken != "", token.RefreshToken != "", token.ExpiresAt, float64(r.now().Unix())) {
		return model.MCPAuthCredentialSaved, "devin_token_file"
	}
	return model.MCPAuthNeedsAuth, "devin_token_expired"
}

// devinTokenFile is the name Devin gives a server's token file: the first 16
// hex characters of the SHA-256 of the name and URL as the config writes them.
func devinTokenFile(name, url string) string {
	sum := sha256.Sum256([]byte(name + url))
	return hex.EncodeToString(sum[:])[:16] + ".json"
}

// devinOAuthDir is where Devin keeps MCP token files.
func (r *MCPAuthResolver) devinOAuthDir() string {
	if r.exec.GOOS() == model.PlatformWindows {
		return filepath.Join(resolveEnvPath(r.exec, "%APPDATA%"), "devin", "mcp", "oauth")
	}
	return filepath.Join(r.home, ".local", "share", "devin", "mcp", "oauth")
}
