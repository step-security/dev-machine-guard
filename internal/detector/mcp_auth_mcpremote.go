package detector

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- mcp-remote names its store files by this digest; nothing is protected by it
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// mcpRemoteHeader is mcp-remote's own pattern for a --header value.
var mcpRemoteHeader = regexp.MustCompile(`^([A-Za-z0-9_-]+):\s*(.*)$`)

// mcpRemoteCall is what an mcp-remote command line says about its store key.
type mcpRemoteCall struct {
	url        string
	resource   string
	headers    map[string]string
	joinFailed bool // an argument feeds the key in a way not reproduced here
}

// parseMCPRemote reads an mcp-remote wrapper's arguments: everything after
// the mcp-remote token, whether it is run directly or through npx, bunx or
// pnpm dlx.
func parseMCPRemote(s mcpAuthServer) (mcpRemoteCall, bool) {
	line := append([]string{s.command}, s.args...)
	start := -1
	for i, token := range line {
		base := token[strings.LastIndexAny(token, `/\`)+1:]
		if base == "mcp-remote" || strings.HasPrefix(base, "mcp-remote@") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return mcpRemoteCall{}, false
	}
	call := mcpRemoteCall{headers: map[string]string{}}
	disableResource, resourceSeen := false, false
	rest := line[start:]
	for i := 0; i < len(rest); i++ {
		switch arg := rest[i]; arg {
		case "--header":
			if i+1 < len(rest) {
				i++
				if m := mcpRemoteHeader.FindStringSubmatch(rest[i]); m != nil {
					call.headers[m[1]] = m[2]
				}
			}
		case "--resource":
			// mcp-remote reads the first --resource only.
			if i+1 < len(rest) {
				i++
				if !resourceSeen {
					call.resource, resourceSeen = strings.TrimSpace(rest[i]), true
				}
			}
		case "--disable-resource-parameter":
			disableResource = true
		case "--header-file", "--authorize-param", "--client-metadata-url", "--token-endpoint":
			call.joinFailed = true
			i++
		default:
			if call.url == "" && (strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://")) {
				call.url = arg
			}
		}
	}
	if disableResource {
		call.resource = ""
	}
	return call, true
}

// storeKey is mcp-remote's file name for a server: the md5 of the URL, the
// resource and the headers as sorted-key JSON, joined with "|". Header values
// go in as written, before mcp-remote expands variables in them.
func (c mcpRemoteCall) storeKey() string {
	parts := []string{c.url}
	if c.resource != "" {
		parts = append(parts, c.resource)
	}
	if len(c.headers) > 0 {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(c.headers) // a map of strings always encodes
		parts = append(parts, strings.TrimSuffix(buf.String(), "\n"))
	}
	sum := md5.Sum([]byte(strings.Join(parts, "|"))) // #nosec G401 -- a file name, as above
	return hex.EncodeToString(sum[:])
}

// mcpRemoteAuth answers from mcp-remote's store directory. A pending or
// revoked sign-in keeps the client registration file, so the verifier files,
// which would need a listing, are not read.
func (r *MCPAuthResolver) mcpRemoteAuth(s mcpAuthServer, call mcpRemoteCall) (string, string) {
	if call.joinFailed || call.url == "" {
		return model.MCPAuthUnknown, mcpAuthJoinFailed
	}
	dir, ok := r.mcpRemoteDir(s)
	if !ok {
		return model.MCPAuthUnknown, mcpAuthJoinFailed
	}
	key := filepath.Join(dir, "mcp-remote-v1", call.storeKey())
	state, err := loadStore(r, "mcp-remote:"+key, func() (string, error) {
		var tokens struct {
			AccessToken  string   `json:"access_token"`
			RefreshToken string   `json:"refresh_token"`
			ExpiresAt    *float64 `json:"expires_at"` // milliseconds
		}
		found, err := r.readJSONStore(key+"_tokens.json", maxMCPAuthFileBytes, &tokens)
		switch {
		case err != nil:
			return "", err
		case found && usableToken(tokens.AccessToken != "", tokens.RefreshToken != "", tokens.ExpiresAt, float64(r.now().UnixMilli())):
			return model.MCPAuthCredentialSaved, nil
		case found:
			return model.MCPAuthNeedsAuth, nil
		}
		_, err = r.files(maxMCPAuthFileBytes).Stat(key + "_client_info.json")
		switch {
		case err == nil:
			return model.MCPAuthNeedsAuth, nil
		case errors.Is(err, fs.ErrNotExist):
			return "", nil
		}
		return "", err
	})
	switch {
	case err != nil:
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	case state == model.MCPAuthCredentialSaved:
		return state, "mcp_remote_token_file"
	case state == model.MCPAuthNeedsAuth:
		return state, "mcp_remote_signin_pending"
	}
	return model.MCPAuthUnknown, mcpAuthNoRecord
}

// mcpRemoteDir is the directory mcp-remote keeps its store under:
// MCP_REMOTE_CONFIG_DIR from the server's own environment, else from the
// user's, else ~/.mcp-auth. A relative or unexpanded override resolves
// against a working directory or a variable this scan cannot see.
func (r *MCPAuthResolver) mcpRemoteDir(s mcpAuthServer) (string, bool) {
	dir := ""
	for _, key := range []string{"env", "environment"} {
		if env, ok := s.fields[key].(map[string]any); ok {
			if v, ok := env["MCP_REMOTE_CONFIG_DIR"].(string); ok && v != "" {
				dir = v
				break
			}
		}
	}
	if dir == "" {
		dir = r.env.Getenv("MCP_REMOTE_CONFIG_DIR")
	}
	if dir == "" {
		return filepath.Join(r.home, ".mcp-auth"), true
	}
	return dir, filepath.IsAbs(dir)
}
