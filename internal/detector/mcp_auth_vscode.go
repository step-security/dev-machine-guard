package detector

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/detector/credentials"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Fixed queries against a VS Code family editor database. The provider list
// and the grant rows are plaintext and hold no secret; the token rows are
// ciphertext, so only their key names are read.
const (
	vscodeItemQuery  = `SELECT key, CAST(value AS TEXT) FROM ItemTable WHERE key = ? LIMIT 10001`
	vscodeRangeQuery = `SELECT key, CAST(value AS TEXT) FROM ItemTable WHERE key >= ? AND key < ? LIMIT 10001`
	vscodeTokenKey   = `secret://{"isDynamicAuthProvider":true` //#nosec G101 -- a key-name prefix, not a credential
)

// vscodeMCPAuth answers from the editor database beside the user mcp.json. A
// server's grant rows name the dynamic auth provider it signed in through,
// and a token key for that provider is a saved sign-in. Sign Out keeps the
// token key and sets the grant to allowed:false, so the grant is read first.
func vscodeMCPAuth(ctx context.Context, r *MCPAuthResolver, configPath string, s mcpAuthServer) (string, string) {
	store, err := r.vscodeAuthStore(ctx, filepath.Join(filepath.Dir(configPath), "globalStorage", "state.vscdb"))
	if err != nil {
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	}
	id := "mcp.config.usrlocal." + s.name
	var providers []string
	for _, grant := range store.grants {
		if grant.serverID != id {
			continue
		}
		if grant.signedOut {
			return model.MCPAuthNeedsAuth, "vscode_signed_out"
		}
		providers = append(providers, grant.provider)
	}
	if len(providers) == 0 {
		// A dynamic provider id is "<authorization server> <resource>".
		for _, provider := range store.providers {
			if _, resource, ok := strings.Cut(provider, " "); ok && sameURL(resource, s.url) {
				providers = append(providers, provider)
			}
		}
	}
	if len(providers) == 0 {
		return model.MCPAuthUnknown, mcpAuthNoRecord
	}
	for _, provider := range providers {
		if store.tokens[provider] {
			return model.MCPAuthCredentialSaved, "vscode_token_key"
		}
	}
	return model.MCPAuthNeedsAuth, "vscode_no_token"
}

// vscodeStore is what the sign-in status needs from one editor database.
type vscodeStore struct {
	providers []string        // dynamic auth provider ids
	grants    []vscodeGrant   // per-server grants under a known provider
	tokens    map[string]bool // provider ids with a stored token
}

// vscodeGrant is one server's entry in an mcpserver-<provider>-<account> row.
type vscodeGrant struct {
	provider  string
	serverID  string
	signedOut bool
}

// vscodeAuthStore runs the three queries once per database. A missing
// database is an empty store.
func (r *MCPAuthResolver) vscodeAuthStore(ctx context.Context, db string) (vscodeStore, error) {
	return loadStore(r, "vscode:"+db, func() (vscodeStore, error) {
		var store vscodeStore
		providerRows, err := credentials.ReadEditorItems(ctx, r.skipper, r.home, db, vscodeItemQuery, "dynamicAuthProviders")
		if errors.Is(err, fs.ErrNotExist) {
			return store, nil
		}
		if err != nil {
			return store, err
		}
		for _, row := range providerRows {
			var list []struct {
				ProviderID string `json:"providerId"`
			}
			if json.Unmarshal([]byte(row.Value), &list) != nil {
				return store, errMCPAuthMalformed
			}
			for _, p := range list {
				store.providers = append(store.providers, p.ProviderID)
			}
		}

		grantRows, err := credentials.ReadEditorItems(ctx, r.skipper, r.home, db, vscodeRangeQuery, "mcpserver-", "mcpserver.")
		if err != nil {
			return store, err
		}
		for _, row := range grantRows {
			provider := vscodeGrantProvider(strings.TrimPrefix(row.Key, "mcpserver-"), store.providers)
			if provider == "" {
				continue
			}
			var entries []struct {
				ID      string `json:"id"`
				Allowed *bool  `json:"allowed"`
			}
			if json.Unmarshal([]byte(row.Value), &entries) != nil {
				return store, errMCPAuthMalformed
			}
			for _, e := range entries {
				store.grants = append(store.grants, vscodeGrant{provider: provider, serverID: e.ID, signedOut: e.Allowed != nil && !*e.Allowed})
			}
		}

		tokenRows, err := credentials.ReadEditorItems(ctx, r.skipper, r.home, db, editorKeyNames, vscodeTokenKey, vscodeTokenKey+"~")
		if err != nil {
			return store, err
		}
		store.tokens = map[string]bool{}
		for _, row := range tokenRows {
			var key struct {
				AuthProviderID string `json:"authProviderId"`
			}
			if json.Unmarshal([]byte(strings.TrimPrefix(row.Key, "secret://")), &key) == nil && key.AuthProviderID != "" {
				store.tokens[key.AuthProviderID] = true
			}
		}
		return store, nil
	})
}

// vscodeGrantProvider finds the provider a grant row is for: the longest
// dynamic provider id that, followed by "-", starts the row key after
// "mcpserver-". The account name follows it. A row for any other provider
// is not a dynamic sign-in.
func vscodeGrantProvider(rest string, providers []string) string {
	best := ""
	for _, p := range providers {
		if len(p) > len(best) && strings.HasPrefix(rest, p+"-") {
			best = p
		}
	}
	return best
}
