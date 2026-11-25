package detector

import (
	"context"
	"crypto/sha1" // #nosec G505 -- OpenCode names its integrations by this digest
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/detector/credentials"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// openCodeMCPAuth answers from OpenCode's mcp-auth.json, keyed by server
// name, and its credential database, keyed by integration. A saved sign-in in
// either wins.
func openCodeMCPAuth(ctx context.Context, r *MCPAuthResolver, _ string, s mcpAuthServer) (string, string) {
	// OpenCode makes no OAuth client for a server with OAuth turned off, so it
	// uses no stored sign-in.
	if s.fields["oauth"] == false {
		return model.MCPAuthUnknown, mcpAuthNoRecord
	}
	store, err := r.openCodeDBStore(ctx)
	// A failed read leaves OpenCode's version unknown, and OpenCode 2 never
	// reads the 1.x file, so the file cannot stand in for the database.
	if err != nil {
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	}
	matches := openCodeURLMatcher(s.url)

	status, evidence := model.MCPAuthUnknown, mcpAuthNoRecord
	// OpenCode 2 keeps MCP sign-ins only in its database.
	if !store.Version2 {
		if entries, err := r.openCodeFileEntries(); err != nil {
			evidence = mcpAuthStoreUnavailable
		} else if entry, ok := entries[s.name]; ok && matches(entry.serverURL) {
			status, evidence = openCodeAuth(entry.usable)
		}
	}

	id := openCodeIntegrationID(s.name, s.url)
	now := float64(r.now().UnixMilli())
	for _, row := range store.Credentials {
		if row.IntegrationID == id || matches(row.ServerURL) && row.IntegrationID == openCodeIntegrationID(s.name, row.ServerURL) {
			rowStatus, rowEvidence := openCodeAuth(usableToken(row.HasAccess, row.HasRefresh, row.ExpiresAt, now))
			status, evidence = strongerAuth(status, evidence, rowStatus, rowEvidence)
		}
	}
	return status, evidence
}

// openCodePlaceholder is a substitution OpenCode makes in its config text
// before it compares or hashes a URL.
var openCodePlaceholder = regexp.MustCompile(`\{(?:env|file):[^}]+\}`)

// openCodeURLMatcher reports which stored URLs a configured URL names. A plain
// URL names only itself. A URL with placeholders cannot be substituted here, so
// it names any URL that keeps its text before the first placeholder and after
// the last.
func openCodeURLMatcher(url string) func(stored string) bool {
	found := openCodePlaceholder.FindAllStringIndex(url, -1)
	if found == nil {
		return func(stored string) bool { return stored != "" && stored == url }
	}
	prefix, suffix := url[:found[0][0]], url[found[len(found)-1][1]:]
	return func(stored string) bool {
		return stored != "" && len(stored) >= len(prefix)+len(suffix) && strings.HasPrefix(stored, prefix) && strings.HasSuffix(stored, suffix)
	}
}

// openCodeIntegrationID is the integration OpenCode registers a remote server
// as, and connects it with only that integration's credentials. Two names at
// one URL are separate integrations.
func openCodeIntegrationID(name, url string) string {
	sum := sha1.Sum([]byte(name + "\x00" + url)) // #nosec G401 -- OpenCode's identifier, reproduced; nothing is protected by it
	return "mcp_" + hex.EncodeToString(sum[:])[:16]
}

// openCodeAuth maps whether an OpenCode record holds a usable token. A record
// without one still holds the client registration.
func openCodeAuth(usable bool) (string, string) {
	if usable {
		return model.MCPAuthCredentialSaved, "opencode_token_file"
	}
	return model.MCPAuthNeedsAuth, "opencode_registration_only"
}

// openCodeDataRoot is OpenCode's data directory: an absolute XDG_DATA_HOME,
// else ~/.local/share, on every platform.
func (r *MCPAuthResolver) openCodeDataRoot() string {
	if dir := r.exec.Getenv("XDG_DATA_HOME"); filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(r.home, ".local", "share")
}

// openCodeFileEntry is what is kept of one mcp-auth.json entry.
type openCodeFileEntry struct {
	serverURL string
	usable    bool
}

// openCodeFileEntries reads mcp-auth.json once, keyed by server name.
func (r *MCPAuthResolver) openCodeFileEntries() (map[string]openCodeFileEntry, error) {
	path := filepath.Join(r.openCodeDataRoot(), "opencode", "mcp-auth.json")
	return loadStore(r, "opencode:"+path, func() (map[string]openCodeFileEntry, error) {
		var doc map[string]json.RawMessage
		if _, err := r.readJSONStore(path, maxJSONConfigBytes, &doc); err != nil {
			return nil, err
		}
		type storedEntry struct {
			ServerURL string `json:"serverUrl"`
			Tokens    struct {
				AccessToken  string   `json:"accessToken"`
				RefreshToken string   `json:"refreshToken"`
				ExpiresAt    *float64 `json:"expiresAt"` // seconds
			} `json:"tokens"`
		}
		now := float64(r.now().Unix())
		stored := decodeEntries[storedEntry](doc)
		entries := make(map[string]openCodeFileEntry, len(stored))
		for name, e := range stored {
			t := e.Tokens
			entries[name] = openCodeFileEntry{serverURL: e.ServerURL, usable: usableToken(t.AccessToken != "", t.RefreshToken != "", t.ExpiresAt, now)}
		}
		return entries, nil
	})
}

// openCodeDBStore reads the MCP credential rows of OpenCode's databases and
// whether OpenCode 2 has opened one. Only each row's integration, server URL,
// expiry and which tokens it holds come back.
func (r *MCPAuthResolver) openCodeDBStore(ctx context.Context) (credentials.OpenCodeMCPStore, error) {
	xdg, db := r.openCodeDataRoot(), r.exec.Getenv("OPENCODE_DB")
	return loadStore(r, "opencode-db:"+xdg+"\x00"+db, func() (credentials.OpenCodeMCPStore, error) {
		return credentials.ReadOpenCodeMCPCredentials(ctx, r.skipper, r.home, xdg, db)
	})
}
