package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/pelletier/go-toml/v2"
	"github.com/tailscale/hujson"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// MCPAuthResolver reports, for each configured MCP server, what its client
// stores about signing in. It reads files only, holds each store for one scan,
// and never carries a stored value out of the function that tested it.
type MCPAuthResolver struct {
	exec    executor.Executor // reads, and the variables the config scan reads the same way
	env     executor.Executor // the scanned user's environment
	skipper *tcc.Skipper
	home    string
	now     func() time.Time
	cache   map[string]any // store path -> loaded store, for this scan only
}

// NewMCPAuthResolver builds a resolver that reads through exec below home, the
// home the caller already resolved, and takes the scanned user's variables
// from env. A nil env falls back to exec. With no home every store would be
// out of bounds, so it returns nil, which resolves nothing.
func NewMCPAuthResolver(exec, env executor.Executor, home string) *MCPAuthResolver {
	if home == "" {
		return nil
	}
	if env == nil {
		env = exec
	}
	return &MCPAuthResolver{exec: exec, env: env, home: home, now: time.Now, cache: map[string]any{}}
}

// WithSkipper refuses every store below a macOS-protected directory. A nil
// skipper is a no-op.
func (r *MCPAuthResolver) WithSkipper(s *tcc.Skipper) *MCPAuthResolver {
	if r != nil {
		r.skipper = s
	}
	return r
}

// mcpAuthServer is the part of one declaration the resolvers read. fields is
// the raw declaration, credentials included, and never leaves this package.
type mcpAuthServer struct {
	name        string // the server's key in the config file
	runtimeName string // the name the client keys its stores by; empty when unknown
	url         string
	remote      bool
	command     string
	args        []string
	fields      map[string]any
}

// mcpAuthClient answers for one remote server from its client's own stores.
type mcpAuthClient func(ctx context.Context, r *MCPAuthResolver, configPath string, s mcpAuthServer) (status, evidence string)

// mcpAuthClients maps a config source to its client's resolver. A source
// missing here still gets the static, stdio and mcp-remote rules; its remote
// servers are reported as not supported.
var mcpAuthClients = map[string]mcpAuthClient{
	"claude_code": claudeMCPAuth, "project_mcp": claudeMCPAuth, "claude_plugin": claudeMCPAuth,
	"codex": codexMCPAuth, "open_interpreter": openInterpreterMCPAuth,
	"copilot": copilotUserMCPAuth, "copilot_project": copilotMCPAuth, "copilot_plugin": copilotMCPAuth,
	"pi": piMCPAuth, "pi_project": piMCPAuth,
	"opencode": openCodeMCPAuth,
	"cursor":   cursorMCPAuth,
	"vscode":   vscodeMCPAuth, "vscode_insiders": vscodeMCPAuth, "vscodium": vscodeMCPAuth,
	"gemini": geminiMCPAuth, "antigravity": antigravityMCPAuth,
	"devin": devinMCPAuth,
}

// Reasons an unknown status carries.
const (
	mcpAuthNoRecord          = "no_record"
	mcpAuthEncryptedStore    = "encrypted_store"
	mcpAuthStoreUnavailable  = "store_unavailable"
	mcpAuthJoinFailed        = "join_failed"
	mcpAuthClientUnsupported = "client_not_supported"
)

// Read caps for store files a client writes per server.
const (
	maxMCPAuthFileBytes = 64 << 10
	maxCopilotOAuthKeys = 2000
	maxCursorProjects   = 500
)

// editorKeyNames selects the key names in one range of an editor database's
// key-value table, through its key index. The values are never read: those
// rows hold ciphertext, and the names already say what is stored for which
// server.
const editorKeyNames = `SELECT key, '' FROM ItemTable WHERE key >= ? AND key < ? LIMIT 10001`

// errMCPAuthMalformed stands for a store that does not decode. The decoder's
// own message can quote the token it choked on, so it is never kept.
var errMCPAuthMalformed = errors.New("malformed store")

// mcpAuthRank orders statuses for a server name declared more than once in one
// file: a config credential is sent whatever a store holds, and a pending
// sign-in is what the developer has to act on.
var mcpAuthRank = map[string]int{
	model.MCPAuthStaticCredential: 0,
	model.MCPAuthNeedsAuth:        1,
	model.MCPAuthCredentialSaved:  2,
	model.MCPAuthNotApplicable:    3,
	model.MCPAuthUnknown:          4,
}

// resolveConfig resolves every server declared in one config file's raw
// content, one entry per name, sorted by name.
func (r *MCPAuthResolver) resolveConfig(ctx context.Context, source, configPath string, content []byte) []model.MCPServerAuth {
	if r == nil {
		return nil
	}
	byName := map[string]model.MCPServerAuth{}
	for _, decl := range mcpDeclarations(source, configPath, content) {
		// A plugin config walked as a plain file has lost its plugin name, so
		// its plain server name could match another server's store entry.
		runtimeName := decl.name
		if source == "claude_plugin" {
			runtimeName = ""
		}
		status, evidence := r.resolveDecl(ctx, source, configPath, newMCPAuthServer(decl.name, runtimeName, decl.fields))
		if prev, ok := byName[decl.name]; ok && mcpAuthRank[prev.Status] <= mcpAuthRank[status] {
			continue
		}
		byName[decl.name] = model.MCPServerAuth{ServerName: decl.name, Status: status, Evidence: evidence}
	}
	if len(byName) == 0 {
		return nil
	}
	out := make([]model.MCPServerAuth, 0, len(byName))
	for _, name := range sortedMapKeys(byName) {
		out = append(out, byName[name])
	}
	return out
}

// resolveServer resolves one declaration. Plugin scans call it per component.
func (r *MCPAuthResolver) resolveServer(ctx context.Context, source, configPath, name, runtimeName string, decl json.RawMessage) model.MCPServerAuth {
	var fields map[string]any
	if json.Unmarshal(decl, &fields) != nil {
		fields = nil
	}
	status, evidence := r.resolveDecl(ctx, source, configPath, newMCPAuthServer(name, runtimeName, fields))
	return model.MCPServerAuth{ServerName: name, Status: status, Evidence: evidence}
}

// resolveDecl applies the resolution order to one server: a credential the
// config supplies, then a local server's own rules, then the client's stores.
func (r *MCPAuthResolver) resolveDecl(ctx context.Context, source, configPath string, s mcpAuthServer) (status, evidence string) {
	if ctx.Err() != nil {
		return model.MCPAuthUnknown, mcpAuthStoreUnavailable
	}
	if evidence := staticCredential(s); evidence != "" {
		return model.MCPAuthStaticCredential, evidence
	}
	switch {
	case s.remote:
		client := mcpAuthClients[source]
		if client == nil {
			return model.MCPAuthUnknown, mcpAuthClientUnsupported
		}
		return client(ctx, r, configPath, s)
	case s.command != "":
		if call, ok := parseMCPRemote(s); ok {
			return r.mcpRemoteAuth(s, call)
		}
		if isClaudeMCPSource(source) && s.runtimeName != "" && r.claudeNeedsAuth(s.runtimeName) {
			return model.MCPAuthNeedsAuth, "claude_needs_auth_cache"
		}
		return model.MCPAuthNotApplicable, "local_stdio"
	}
	return model.MCPAuthUnknown, mcpAuthNoRecord
}

// mcpDecl is one server declaration as written in a config file.
type mcpDecl struct {
	name   string
	fields map[string]any
}

// mcpDeclarations reads the raw server declarations from the content the
// config scan already read, under the same keys its filter keeps, because the
// filtered copy has dropped the headers and env the static rule reads. Only
// the server keys are decoded: ~/.claude.json can hold many megabytes of
// project history beside them.
func mcpDeclarations(source, configPath string, content []byte) []mcpDecl {
	if isCodexTOML(source, configPath) {
		var config struct {
			Servers map[string]any `toml:"mcp_servers"`
		}
		if toml.Unmarshal(bytes.TrimPrefix(content, utf8BOM), &config) != nil {
			return nil
		}
		var out []mcpDecl
		for _, name := range sortedMapKeys(config.Servers) {
			if fields, ok := config.Servers[name].(map[string]any); ok {
				out = append(out, mcpDecl{name: name, fields: fields})
			}
		}
		return out
	}
	if !strings.HasSuffix(configPath, ".json") && !strings.HasSuffix(configPath, ".jsonc") {
		return nil
	}
	// Relax the syntax only where the config filter does, so both read the
	// same servers.
	data := bytes.TrimPrefix(content, utf8BOM)
	if source == "zed" || source == "gemini" {
		data = stripJSONCComments(data)
	}
	bare := source == "copilot_project" || isCopilotProjectMCP(configPath)
	if bare || source == model.AgentCopilot || isOpenCodeConfigPath(configPath) {
		standard, err := hujson.Standardize(data)
		if err != nil {
			return nil
		}
		data = standard
	}
	var doc struct {
		MCPServers     json.RawMessage `json:"mcpServers"`
		Servers        json.RawMessage `json:"servers"`
		ContextServers json.RawMessage `json:"context_servers"`
		MCP            json.RawMessage `json:"mcp"`
		Projects       json.RawMessage `json:"projects"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []mcpDecl
	for _, servers := range []json.RawMessage{doc.MCPServers, doc.Servers, doc.ContextServers, openCodeServers(doc.MCP)} {
		out = append(out, serverDecls(servers)...)
	}
	var projects map[string]struct {
		MCPServers json.RawMessage `json:"mcpServers"`
	}
	if json.Unmarshal(doc.Projects, &projects) == nil {
		for _, project := range sortedMapKeys(projects) {
			out = append(out, serverDecls(projects[project].MCPServers)...)
		}
	}
	if bare && doc.MCPServers == nil && doc.Servers == nil && doc.ContextServers == nil && doc.MCP == nil {
		out = append(out, serverDecls(data)...)
	}
	return out
}

// serverDecls lists the object entries of one server map in name order.
func serverDecls(servers json.RawMessage) []mcpDecl {
	var entries map[string]json.RawMessage
	if json.Unmarshal(servers, &entries) != nil {
		return nil
	}
	var out []mcpDecl
	for _, name := range sortedMapKeys(entries) {
		var fields map[string]any
		if json.Unmarshal(entries[name], &fields) == nil && fields != nil {
			out = append(out, mcpDecl{name: name, fields: fields})
		}
	}
	return out
}

// newMCPAuthServer reads the fields every resolver needs. OpenCode declares a
// local command as one array, the command first.
func newMCPAuthServer(name, runtimeName string, fields map[string]any) mcpAuthServer {
	s := mcpAuthServer{name: name, runtimeName: runtimeName, fields: fields}
	s.url, _ = fields["url"].(string)
	if s.url == "" {
		s.url, _ = fields["serverUrl"].(string)
	}
	_, hasURL := fields["url"]
	_, hasServerURL := fields["serverUrl"]
	if u, ok := liftedServerURL(fields); ok && !hasURL && !hasServerURL {
		s.url, _ = u.(string)
	}
	s.remote = s.url != "" || fields["type"] == "remote"
	switch command := fields["command"].(type) {
	case string:
		s.command, s.args = command, anyStrings(fields["args"])
	case []any:
		if parts := anyStrings(command); len(parts) > 0 {
			s.command, s.args = parts[0], parts[1:]
		}
	}
	return s
}

// anyStrings keeps the string elements of a decoded array.
func anyStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// staticCredential returns the evidence for a credential the config itself
// supplies, or "" when there is none. Only the names and the emptiness of the
// values are tested.
func staticCredential(s mcpAuthServer) string {
	transport, _ := s.fields["transport"].(map[string]any)
	for _, headers := range []any{s.fields["headers"], s.fields["http_headers"], s.fields["env_http_headers"], transport["headers"]} {
		if credentialEntry(headers) {
			return "config_header"
		}
	}
	if call, ok := parseMCPRemote(s); ok && credentialEntry(call.headers) {
		return "config_header"
	}
	if nonEmptyValue(s.fields["headersHelper"]) || nonEmptyValue(s.fields["http_headers_helper"]) {
		return "config_header_helper"
	}
	if nonEmptyValue(s.fields["bearer_token_env_var"]) {
		return "config_bearer_env"
	}
	if !s.remote && (credentialEntry(s.fields["env"]) || credentialEntry(s.fields["environment"])) {
		return "config_env_key"
	}
	return ""
}

// credentialEntry reports whether a name-to-value map has a credential name
// with a value. A variable reference is a value: the client sends what it
// expands to.
func credentialEntry(v any) bool {
	switch entries := v.(type) {
	case map[string]any:
		for name, value := range entries {
			if isCredentialName(name) && nonEmptyValue(value) {
				return true
			}
		}
	case map[string]string:
		for name, value := range entries {
			if isCredentialName(name) && strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return false
}

// nonEmptyValue reports whether a decoded value holds anything: a string with
// more than white space, or any value of another type.
func nonEmptyValue(v any) bool {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s) != ""
	}
	return v != nil
}

// credentialWords are the words that make a header or variable name a
// credential name on their own. "headers" covers variables that carry whole
// HTTP headers, such as OPENAPI_MCP_HEADERS, which usually hold Authorization.
var credentialWords = map[string]bool{
	"token": true, "key": true, "apikey": true, "secret": true, "password": true, "passwd": true,
	"pat": true, "auth": true, "authorization": true, "bearer": true, "credential": true, "credentials": true,
	"headers": true,
}

// isCredentialName matches whole words, so PATH and AUTHOR are not taken for
// PAT and AUTH, and MAX_TOKENS is not taken for a token.
func isCredentialName(name string) bool {
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, word := range words {
		if credentialWords[word] {
			return true
		}
		for _, suffix := range []string{"token", "key", "secret", "password"} {
			if strings.HasSuffix(word, suffix) {
				return true
			}
		}
	}
	return false
}

// usableToken reports whether a stored token can still be used: an access
// token with a refresh token beside it, with no expiry, or with an expiry
// still ahead. Every client but Codex refreshes an expired token silently.
// now is in the unit the store writes its expiry in.
func usableToken(hasAccess, hasRefresh bool, expiresAt *float64, now float64) bool {
	return hasAccess && (hasRefresh || expiresAt == nil || *expiresAt > now)
}

// sameURL compares two server URLs as the clients write them, ignoring one
// trailing slash.
func sameURL(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

// webURL parses an absolute URL with its scheme and host lowercased and a
// default port dropped, as a browser's URL parser serializes them.
func webURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if port := u.Port(); u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
		u.Host = strings.TrimSuffix(u.Host, ":"+port)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, true
}

// readStore reads one store file through the guard. A refused path fails like
// an unreadable one; only a missing file reports fs.ErrNotExist.
func (r *MCPAuthResolver) readStore(path string, limit int64) ([]byte, error) {
	return r.files(limit).ReadFile(path)
}

// files is the executor every store read goes through: confined to the home
// and refusing macOS-protected paths.
func (r *MCPAuthResolver) files(limit int64) executor.Executor {
	return r.exec.GuardedFiles([]string{r.home}, func(path string) string {
		if r.skipper.WithinProtected(path) {
			return "tcc_protected"
		}
		return ""
	}, limit)
}

// readJSONStore decodes one store file into v and reports whether it existed.
// A missing file is an empty store, not a failure.
func (r *MCPAuthResolver) readJSONStore(path string, limit int64, v any) (bool, error) {
	data, err := r.readStore(path, limit)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if json.Unmarshal(bytes.TrimPrefix(data, utf8BOM), v) != nil {
		return false, errMCPAuthMalformed
	}
	return true, nil
}

// decodeEntries decodes each entry of a store keyed by server on its own, so
// an entry of another shape, such as a version number beside the servers,
// drops only itself.
func decodeEntries[T any](raw map[string]json.RawMessage) map[string]T {
	out := make(map[string]T, len(raw))
	for key, data := range raw {
		var entry *T
		if json.Unmarshal(data, &entry) == nil && entry != nil {
			out[key] = *entry
		}
	}
	return out
}

// mcpAuthStore is one loaded store and the error loading it gave.
type mcpAuthStore[T any] struct {
	value T
	err   error
}

// loadStore loads a store once per scan. A failure is kept too, so a broken
// store is read once however many servers point at it.
func loadStore[T any](r *MCPAuthResolver, key string, load func() (T, error)) (T, error) {
	if s, ok := r.cache[key].(mcpAuthStore[T]); ok {
		return s.value, s.err
	}
	value, err := load()
	r.cache[key] = mcpAuthStore[T]{value: value, err: err}
	return value, err
}

// strongerAuth picks between two stores' answers for one server of one
// client: a saved sign-in wins, because one of the stores can use the server,
// then a pending sign-in, then a store that could not be read over no record.
func strongerAuth(status, evidence, otherStatus, otherEvidence string) (string, string) {
	weight := func(status, evidence string) int {
		switch {
		case status == model.MCPAuthCredentialSaved:
			return 0
		case status == model.MCPAuthNeedsAuth:
			return 1
		case evidence == mcpAuthStoreUnavailable:
			return 2
		}
		return 3
	}
	if weight(otherStatus, otherEvidence) < weight(status, evidence) {
		return otherStatus, otherEvidence
	}
	return status, evidence
}
