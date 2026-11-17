package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/detector/credentials"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// cursorMCPAuth answers from the key names of Cursor's editor database and
// from the Cursor CLI's per-project files. A saved sign-in in either wins.
func cursorMCPAuth(ctx context.Context, r *MCPAuthResolver, _ string, s mcpAuthServer) (string, string) {
	status, evidence := model.MCPAuthUnknown, mcpAuthNoRecord
	if keys, err := r.cursorKeys(ctx); err != nil {
		evidence = mcpAuthStoreUnavailable
	} else {
		canon := cursorCanonicalURL(s.url)
		for _, key := range keys {
			if key.url != "" && key.url != canon || key.url == "" && key.name != s.name {
				continue
			}
			switch key.field {
			case "mcp_tokens":
				status, evidence = strongerAuth(status, evidence, model.MCPAuthCredentialSaved, "cursor_token_key")
			case "mcp_client_information", "mcp_code_verifier", "mcp_oauth_retention":
				status, evidence = strongerAuth(status, evidence, model.MCPAuthNeedsAuth, "cursor_no_token")
			}
		}
	}

	cli, err := r.cursorCLIEntries()
	if err != nil {
		return strongerAuth(status, evidence, model.MCPAuthUnknown, mcpAuthStoreUnavailable)
	}
	for _, hasToken := range cli[s.name] {
		if hasToken {
			status, evidence = strongerAuth(status, evidence, model.MCPAuthCredentialSaved, "cursor_cli_token_file")
		} else {
			status, evidence = strongerAuth(status, evidence, model.MCPAuthNeedsAuth, "cursor_cli_registration_only")
		}
	}
	return status, evidence
}

// cursorKey is one decoded store key: the server it is for, by canonical URL
// or by name, and what it holds.
type cursorKey struct {
	url   string
	name  string
	field string
}

// cursorKeys reads and decodes the store's key names once.
func (r *MCPAuthResolver) cursorKeys(ctx context.Context) ([]cursorKey, error) {
	var db string
	switch r.exec.GOOS() {
	case model.PlatformDarwin:
		db = filepath.Join(r.home, "Library", "Application Support", "Cursor", "User", "globalStorage", "state.vscdb")
	case model.PlatformWindows:
		db = resolveEnvPath(r.exec, "%APPDATA%/Cursor/User/globalStorage/state.vscdb")
	default:
		db = filepath.Join(r.home, ".config", "Cursor", "User", "globalStorage", "state.vscdb")
	}
	return loadStore(r, "cursor:"+db, func() ([]cursorKey, error) {
		items, err := credentials.ReadEditorItems(ctx, r.skipper, r.home, db, editorKeyNames, "mcpOAuth.", "mcpOAuth/")
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var keys []cursorKey
		for _, item := range items {
			if key, ok := parseCursorKey(item.Key); ok {
				keys = append(keys, key)
			}
		}
		return keys, nil
	})
}

// parseCursorKey decodes mcpOAuth.secret.<b64url(inner)> and
// mcpOAuth.global.<b64url(inner)>, where inner is "[scope] field" after an
// optional "[profile:<b64url>] " prefix. A scope is the server's canonical URL
// or an identifier; only identifiers for servers in ~/.cursor/mcp.json name a
// server this source declares.
func parseCursorKey(key string) (cursorKey, bool) {
	suffix, ok := strings.CutPrefix(key, "mcpOAuth.secret.")
	if !ok {
		if suffix, ok = strings.CutPrefix(key, "mcpOAuth.global."); !ok {
			return cursorKey{}, false
		}
	}
	inner, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(suffix, "="))
	if err != nil {
		return cursorKey{}, false
	}
	s := string(inner)
	if strings.HasPrefix(s, "[profile:") {
		_, s, _ = strings.Cut(s, "] ")
	}
	end := strings.LastIndex(s, "] ")
	if !strings.HasPrefix(s, "[") || end < 0 {
		return cursorKey{}, false
	}
	scope, field := s[1:end], s[end+2:]
	if encoded, ok := strings.CutPrefix(scope, "url:"); ok {
		u, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
		return cursorKey{url: string(u), field: field}, err == nil && len(u) > 0
	}
	if encoded, ok := strings.CutPrefix(scope, "identifier:v1:"); ok {
		id, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
		if err != nil {
			return cursorKey{}, false
		}
		scope = string(id)
	}
	name, ok := strings.CutPrefix(scope, "user-")
	name, _, _ = strings.Cut(name, "::")
	return cursorKey{name: name, field: field}, ok && name != ""
}

// cursorCanonicalURL is Cursor's key for a server URL: the origin and the path
// with one trailing slash removed when the path is longer than one character,
// then the query; the fragment is dropped. A URL that does not parse is
// trimmed and lowercased.
func cursorCanonicalURL(raw string) string {
	u, ok := webURL(raw)
	if !ok {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	path := u.EscapedPath()
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	out := u.Scheme + "://" + u.Host + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// cursorCLIEntries reads ~/.cursor/projects/*/mcp-auth.json once and maps each
// server name to whether each of its entries holds an access token. The SDK
// shape the CLI writes has no absolute expiry. A projects directory over the
// cap is not read at all, leaving the editor's answer.
func (r *MCPAuthResolver) cursorCLIEntries() (map[string][]bool, error) {
	dir := filepath.Join(r.home, ".cursor", "projects")
	return loadStore(r, "cursor-cli:"+dir, func() (map[string][]bool, error) {
		entries, more, err := r.files(maxJSONConfigBytes).ReadDirLimit(dir, maxCursorProjects)
		if errors.Is(err, fs.ErrNotExist) || more {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		type storedEntry struct {
			Tokens struct {
				AccessToken string `json:"access_token"`
			} `json:"tokens"`
		}
		out := map[string][]bool{}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			var doc map[string]json.RawMessage
			if _, err := r.readJSONStore(filepath.Join(dir, entry.Name(), "mcp-auth.json"), maxJSONConfigBytes, &doc); err != nil {
				return nil, err
			}
			for name, e := range decodeEntries[storedEntry](doc) {
				out[name] = append(out[name], e.Tokens.AccessToken != "")
			}
		}
		return out, nil
	})
}
