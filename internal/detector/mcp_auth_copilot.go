package detector

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// copilotOAuthKey is the name Copilot gives one server registration's files.
var copilotOAuthKey = regexp.MustCompile(`^[0-9a-f]{64}$`)

// copilotUserMCPAuth answers for a server in Copilot's own config from the
// store beside it, so the store and the config the scan read share one root.
func copilotUserMCPAuth(_ context.Context, r *MCPAuthResolver, configPath string, s mcpAuthServer) (string, string) {
	return r.copilotAuth(filepath.Dir(configPath), s)
}

// copilotMCPAuth answers for a server in a project or plugin config from the
// store under the user's Copilot root.
func copilotMCPAuth(_ context.Context, r *MCPAuthResolver, _ string, s mcpAuthServer) (string, string) {
	return r.copilotAuth(copilotConfigRoot(r.env, r.home), s)
}

// copilotAuth answers from the mcp-oauth-config directory under a Copilot
// root, joined by each registration's plaintext server URL. One URL can have
// several registrations, one per OAuth client; a saved one wins.
func (r *MCPAuthResolver) copilotAuth(root string, s mcpAuthServer) (string, string) {
	registrations, err := r.copilotRegistrations(root)
	if err != nil {
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	}
	found := false
	for _, reg := range registrations {
		if !sameURL(reg.serverURL, s.url) {
			continue
		}
		if reg.saved {
			return model.MCPAuthCredentialSaved, "copilot_signin_complete"
		}
		found = true
	}
	if found {
		return model.MCPAuthNeedsAuth, "copilot_signin_pending"
	}
	return model.MCPAuthUnknown, mcpAuthNoRecord
}

// copilotRegistration is what is kept of one Copilot server registration.
type copilotRegistration struct {
	serverURL string
	saved     bool
}

// copilotRegistrations lists mcp-oauth-config once. <key>.json is written at
// registration and its <key>.verifier is deleted when sign-in completes, so a
// registration is saved unless a verifier remains or its tokens are no longer
// usable. A registration whose files do not decode is skipped on its own.
func (r *MCPAuthResolver) copilotRegistrations(root string) ([]copilotRegistration, error) {
	dir := filepath.Join(root, "mcp-oauth-config")
	return loadStore(r, "copilot:"+dir, func() ([]copilotRegistration, error) {
		files := r.files(maxMCPAuthFileBytes)
		entries, more, err := files.ReadDirLimit(dir, maxCopilotOAuthKeys)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if more {
			return nil, errors.New("too many registrations")
		}
		names := make(map[string]bool, len(entries))
		for _, entry := range entries {
			names[entry.Name()] = true
		}
		now := float64(r.now().Unix())
		var out []copilotRegistration
		for _, name := range sortedMapKeys(names) {
			key, ok := strings.CutSuffix(name, ".json")
			if !ok || !copilotOAuthKey.MatchString(key) {
				continue
			}
			var registration struct {
				ServerURL string `json:"serverUrl"`
			}
			found, err := r.readJSONStore(filepath.Join(dir, name), maxMCPAuthFileBytes, &registration)
			switch {
			case errors.Is(err, errMCPAuthMalformed):
				continue
			case err != nil:
				return nil, err
			case !found:
				continue
			}
			saved := !names[key+".verifier"]
			if saved && names[key+".tokens.json"] {
				var tokens struct {
					AccessToken  string   `json:"accessToken"`
					RefreshToken string   `json:"refreshToken"`
					ExpiresAt    *float64 `json:"expiresAt"` // seconds
				}
				found, err := r.readJSONStore(filepath.Join(dir, key+".tokens.json"), maxMCPAuthFileBytes, &tokens)
				if errors.Is(err, errMCPAuthMalformed) {
					continue
				}
				if err != nil {
					return nil, err
				}
				saved = !found || usableToken(tokens.AccessToken != "", tokens.RefreshToken != "", tokens.ExpiresAt, now)
			}
			out = append(out, copilotRegistration{serverURL: registration.ServerURL, saved: saved})
		}
		return out, nil
	})
}
