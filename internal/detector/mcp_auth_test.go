package detector

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- reproduces OpenCode's integration id
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// authNow is the clock every sign-in status test runs at.
var authNow = time.UnixMilli(1_800_000_000_000)

// authExec gives the mock the guarded reader's contract: a missing file or
// directory is fs.ErrNotExist, a refused or oversized read fails, and every
// file read is recorded.
type authExec struct {
	*executor.Mock
	guard func(string) string
	limit int64
	reads *[]string
}

func (e authExec) GuardedFiles(_ []string, guard func(string) string, limit int64) executor.Executor {
	return authExec{Mock: e.Mock, guard: guard, limit: limit, reads: e.reads}
}

func (e authExec) refused(path string) bool { return e.guard != nil && e.guard(path) != "" }

func (e authExec) ReadFile(path string) ([]byte, error) {
	if e.refused(path) {
		return nil, errors.New("refused")
	}
	*e.reads = append(*e.reads, path)
	if !e.FileExists(path) {
		return nil, fs.ErrNotExist
	}
	data, err := e.Mock.ReadFile(path)
	if err == nil && e.limit > 0 && int64(len(data)) > e.limit {
		return nil, errors.New("over the read cap")
	}
	return data, err
}

func (e authExec) ReadDirLimit(path string, max int) ([]os.DirEntry, bool, error) {
	if e.refused(path) {
		return nil, false, errors.New("refused")
	}
	if !e.DirExists(path) {
		return nil, false, fs.ErrNotExist
	}
	return e.Mock.ReadDirLimit(path, max)
}

func (e authExec) Stat(path string) (os.FileInfo, error) {
	if e.refused(path) {
		return nil, errors.New("refused")
	}
	if !e.FileExists(path) {
		return nil, fs.ErrNotExist
	}
	return e.Mock.Stat(path)
}

// newAuthMock is a Linux mock whose home is a real, resolved temporary
// directory, so editor databases written below it are read from disk.
func newAuthMock(t *testing.T) (*executor.Mock, string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := executor.NewMock()
	m.SetHomeDir(home)
	m.SetGOOS(model.PlatformLinux)
	return m, home
}

// newAuthResolver builds a resolver over the mock and returns the list its
// file reads are recorded in.
func newAuthResolver(m *executor.Mock) (*MCPAuthResolver, *[]string) {
	reads := &[]string{}
	e := authExec{Mock: m, reads: reads}
	r := NewMCPAuthResolver(e, e, executor.ResolveHome(m))
	r.now = func() time.Time { return authNow }
	return r, reads
}

// authOf resolves one declaration for a source.
func authOf(r *MCPAuthResolver, source, configPath, name, decl string) model.MCPServerAuth {
	return r.resolveServer(context.Background(), source, configPath, name, name, json.RawMessage(decl))
}

// checkAuth fails the test when a result is not the wanted status and evidence.
func checkAuth(t *testing.T, got model.MCPServerAuth, status, evidence string) {
	t.Helper()
	if got.Status != status || got.Evidence != evidence {
		t.Errorf("got %s/%s, want %s/%s", got.Status, got.Evidence, status, evidence)
	}
}

// writeItemTable creates an editor database with the given key-value rows.
func writeItemTable(t *testing.T, path string, rows map[string]string) {
	t.Helper()
	writeSQLite(t, path, `CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)`, `INSERT INTO ItemTable VALUES (?, ?)`, rows)
}

// writeSQLite creates a database with one table and its rows, and closes it
// so no journal is left beside it.
func writeSQLite(t *testing.T, path, schema, insert string, rows map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	for key, value := range rows {
		if _, err := db.Exec(insert, key, value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsCredentialName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"GITHUB_PERSONAL_ACCESS_TOKEN", true},
		{"X-API-Key", true},
		{"Authorization", true},
		{"OPENAI_API_KEY", true},
		{"DB_PASSWORD", true},
		{"apikey", true},
		{"accessToken", true},
		{"PAT", true},
		{"client-secret", true},
		{"BEARER", true},
		{"OPENAPI_MCP_HEADERS", true},
		{"PATH", false},
		{"AUTHOR", false},
		{"OAUTH_CLIENT_ID", false},
		{"MAX_TOKENS", false},
		{"HOME", false},
		{"NODE_OPTIONS", false},
		{"LOG_LEVEL", false},
		{"X-Tenant", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCredentialName(tc.name); got != tc.want {
				t.Errorf("isCredentialName(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestStaticCredential(t *testing.T) {
	tests := []struct {
		name, decl, want string
	}{
		{"credential header", `{"url":"https://a.example.com","headers":{"Authorization":"Bearer x"}}`, "config_header"},
		{"variable header value", `{"url":"https://a.example.com","headers":{"X-API-Key":"${input:key}"}}`, "config_header"},
		{"white space header value", `{"url":"https://a.example.com","headers":{"Authorization":"  "}}`, ""},
		{"other header", `{"url":"https://a.example.com","headers":{"X-Tenant":"acme"}}`, ""},
		{"codex header", `{"url":"https://a.example.com","http_headers":{"Authorization":"Bearer x"}}`, "config_header"},
		{"codex env header names a variable", `{"url":"https://a.example.com","env_http_headers":{"Authorization":"LAB_TOKEN"}}`, "config_header"},
		{"claude header helper", `{"url":"https://a.example.com","headersHelper":"/usr/local/bin/lab-headers"}`, "config_header_helper"},
		{"codex header helper", `{"url":"https://a.example.com","http_headers_helper":"lab-headers"}`, "config_header_helper"},
		{"empty header helper", `{"url":"https://a.example.com","headersHelper":""}`, ""},
		{"codex bearer variable", `{"url":"https://a.example.com","bearer_token_env_var":"LAB_TOKEN"}`, "config_bearer_env"},
		{"stdio credential env", `{"command":"lab","env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"${GH_TOKEN}"}}`, "config_env_key"},
		{"stdio header env", `{"command":"npx","env":{"OPENAPI_MCP_HEADERS":"{\"Authorization\":\"Bearer x\"}"}}`, "config_env_key"},
		{"stdio plain env", `{"command":"lab","env":{"PATH":"/usr/bin","HOME":"/home/dev","MAX_TOKENS":"100"}}`, ""},
		{"stdio empty credential env", `{"command":"lab","env":{"API_KEY":""}}`, ""},
		{"remote env is not sent", `{"url":"https://a.example.com","env":{"API_KEY":"x"}}`, ""},
		{"opencode environment", `{"type":"local","command":["lab"],"environment":{"OPENAI_API_KEY":"{env:KEY}"}}`, "config_env_key"},
		{"mcp-remote credential header", `{"command":"npx","args":["-y","mcp-remote@latest","https://a.example.com/mcp","--header","Authorization: Bearer ${T}"]}`, "config_header"},
		{"mcp-remote empty header", `{"command":"npx","args":["mcp-remote","https://a.example.com/mcp","--header","Authorization:"]}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]any
			if err := json.Unmarshal([]byte(tc.decl), &fields); err != nil {
				t.Fatal(err)
			}
			if got := staticCredential(newMCPAuthServer("lab", "lab", fields)); got != tc.want {
				t.Errorf("staticCredential(%s) = %q, want %q", tc.decl, got, tc.want)
			}
		})
	}
}

func TestUsableToken(t *testing.T) {
	past, future := 100.0, 300.0
	tests := []struct {
		name            string
		access, refresh bool
		expiresAt       *float64
		want            bool
	}{
		{"no access token", false, true, nil, false},
		{"no expiry", true, false, nil, true},
		{"expiry ahead", true, false, &future, true},
		{"expired", true, false, &past, false},
		{"expired with refresh", true, true, &past, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := usableToken(tc.access, tc.refresh, tc.expiresAt, 200); got != tc.want {
				t.Errorf("usableToken = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMCPAuthResolver_ResolutionOrder(t *testing.T) {
	m, home := newAuthMock(t)
	m.SetFile(filepath.Join(home, ".claude", "mcp-needs-auth-cache.json"), []byte(`{"plugin:lab:lab-stdio":{"timestamp":1},"lab-stdio":{"timestamp":1}}`))
	m.SetFile(filepath.Join(home, ".claude", ".credentials.json"), []byte(`{"mcpOAuth":{"lab-header|1":{"serverName":"lab-header","serverUrl":"https://a.example.com/mcp","accessToken":"a"}}}`))
	r, _ := newAuthResolver(m)
	configPath := filepath.Join(home, ".claude.json")

	t.Run("static beats a saved sign-in", func(t *testing.T) {
		checkAuth(t, authOf(r, "claude_code", configPath, "lab-header", `{"url":"https://a.example.com/mcp","headers":{"Authorization":"Bearer x"}}`), model.MCPAuthStaticCredential, "config_header")
	})
	t.Run("claude plugin stdio in the needs-auth cache", func(t *testing.T) {
		got := r.resolveServer(context.Background(), "claude_plugin", configPath, "lab-stdio", "plugin:lab:lab-stdio", json.RawMessage(`{"command":"lab"}`))
		checkAuth(t, got, model.MCPAuthNeedsAuth, "claude_needs_auth_cache")
	})
	t.Run("plain stdio", func(t *testing.T) {
		checkAuth(t, authOf(r, "cursor", configPath, "lab-local", `{"command":"lab","args":["serve"]}`), model.MCPAuthNotApplicable, "local_stdio")
	})
	t.Run("unsupported remote client", func(t *testing.T) {
		checkAuth(t, authOf(r, "windsurf", configPath, "lab-oauth", `{"serverUrl":"https://a.example.com/mcp"}`), model.MCPAuthUnknown, "client_not_supported")
	})
	t.Run("neither url nor command", func(t *testing.T) {
		checkAuth(t, authOf(r, "claude_code", configPath, "lab-empty", `{"type":"stdio"}`), model.MCPAuthUnknown, "no_record")
	})
	t.Run("walked plugin config has no plugin name", func(t *testing.T) {
		content := []byte(`{"mcpServers":{"lab-stdio":{"command":"lab"},"lab-header":{"url":"https://a.example.com/mcp"}}}`)
		got := r.resolveConfig(context.Background(), "claude_plugin", filepath.Join(home, "plugin", ".mcp.json"), content)
		want := []model.MCPServerAuth{
			{ServerName: "lab-header", Status: model.MCPAuthUnknown, Evidence: "no_record"},
			{ServerName: "lab-stdio", Status: model.MCPAuthNotApplicable, Evidence: "local_stdio"},
		}
		if !equalAuth(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})
	t.Run("cancelled scan", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got := r.resolveServer(ctx, "cursor", configPath, "lab-local", "lab-local", json.RawMessage(`{"command":"lab"}`))
		checkAuth(t, got, model.MCPAuthUnknown, "store_unavailable")
	})
}

func equalAuth(a, b []model.MCPServerAuth) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMCPAuthResolver_ResolveConfig(t *testing.T) {
	m, home := newAuthMock(t)
	r, _ := newAuthResolver(m)
	tests := []struct {
		name, source, path, content string
		want                        []model.MCPServerAuth
	}{
		{
			name: "codex toml", source: "codex", path: filepath.Join(home, ".codex", "config.toml"),
			content: "[mcp_servers.lab-header]\nurl = \"https://a.example.com/mcp\"\nbearer_token_env_var = \"LAB_TOKEN\"\n\n[mcp_servers.lab-local]\ncommand = \"lab\"\n",
			want: []model.MCPServerAuth{
				{ServerName: "lab-header", Status: model.MCPAuthStaticCredential, Evidence: "config_bearer_env"},
				{ServerName: "lab-local", Status: model.MCPAuthNotApplicable, Evidence: "local_stdio"},
			},
		},
		{
			name: "duplicate project names fold to the strongest", source: "claude_code", path: filepath.Join(home, ".claude.json"),
			content: `{"mcpServers":{"lab":{"command":"lab"}},"projects":{"/a":{"mcpServers":{"lab":{"command":"lab","env":{"API_KEY":"x"}}}},"/b":{"mcpServers":{"other":{"command":"o"}}}}}`,
			want: []model.MCPServerAuth{
				{ServerName: "lab", Status: model.MCPAuthStaticCredential, Evidence: "config_env_key"},
				{ServerName: "other", Status: model.MCPAuthNotApplicable, Evidence: "local_stdio"},
			},
		},
		{
			name: "opencode command array and scalar keys", source: "opencode", path: filepath.Join(home, ".config", "opencode", "opencode.jsonc"),
			content: "\ufeff{\n // comment\n \"mcp\": {\"lab-local\": {\"type\": \"local\", \"command\": [\"lab\", \"serve\"]},},\n}",
			want:    []model.MCPServerAuth{{ServerName: "lab-local", Status: model.MCPAuthNotApplicable, Evidence: "local_stdio"}},
		},
		{
			name: "copilot project bare map", source: "copilot_project", path: filepath.Join(home, "repo", ".mcp.json"),
			content: `{"lab-local":{"command":"lab"},"$schema":"x"}`,
			want:    []model.MCPServerAuth{{ServerName: "lab-local", Status: model.MCPAuthNotApplicable, Evidence: "local_stdio"}},
		},
		{
			name: "claude.json history beside the servers", source: "claude_code", path: filepath.Join(home, ".claude.json"),
			content: `{"numStartups":3,"projects":{"/a":{"history":[{"display":"x"}],"mcpServers":{"lab":{"command":"lab"}}},"/b":{"history":[]}},"cachedStatsig":{"k":[1,2]}}`,
			want:    []model.MCPServerAuth{{ServerName: "lab", Status: model.MCPAuthNotApplicable, Evidence: "local_stdio"}},
		},
		{
			name: "zed comments", source: "zed", path: filepath.Join(home, ".config", "zed", "settings.json"),
			content: "{\n // comment\n \"context_servers\": {\"lab\": {\"command\": \"lab\"}}\n}",
			want:    []model.MCPServerAuth{{ServerName: "lab", Status: model.MCPAuthNotApplicable, Evidence: "local_stdio"}},
		},
		{name: "trailing comma where the config filter is strict", source: "cursor", path: filepath.Join(home, ".cursor", "mcp.json"),
			content: `{"mcpServers":{"lab":{"command":"lab"},}}`},
		{name: "scalar mcp key", source: "claude_code", path: filepath.Join(home, ".claude", "settings.json"), content: `{"mcp":true}`},
		{name: "yaml", source: "open_interpreter", path: filepath.Join(home, "config.yaml"), content: "mcp: {}"},
		{name: "unparseable", source: "cursor", path: filepath.Join(home, ".cursor", "mcp.json"), content: `{"mcpServers":`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := r.resolveConfig(context.Background(), tc.source, tc.path, []byte(tc.content))
			if !equalAuth(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestMCPAuthResolver_NilResolvesNothing(t *testing.T) {
	r := NewMCPAuthResolver(executor.NewMock(), nil, "").WithSkipper(nil)
	if r != nil {
		t.Fatalf("a resolver with no home: %+v", r)
	}
	if got := r.resolveConfig(context.Background(), "cursor", "/x/mcp.json", []byte(`{"mcpServers":{"a":{"command":"a"}}}`)); got != nil {
		t.Errorf("nil resolver returned %+v", got)
	}
}

func TestMCPDetector_DetectEnterpriseServerAuth(t *testing.T) {
	m, home := newAuthMock(t)
	m.SetFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(`{"mcpServers":{"lab-local":{"command":"lab"}}}`))
	m.SetFile(filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), []byte(`{"other":{}}`))
	r, _ := newAuthResolver(m)

	for _, tc := range []struct {
		name string
		auth *MCPAuthResolver
		want map[string][]model.MCPServerAuth
	}{
		{"without a resolver", nil, map[string][]model.MCPServerAuth{"cursor": nil, "windsurf": nil}},
		{"with a resolver", r, map[string][]model.MCPServerAuth{
			"cursor":   {{ServerName: "lab-local", Status: model.MCPAuthNotApplicable, Evidence: "local_stdio"}},
			"windsurf": nil, // no servers, no content
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configs := NewMCPDetector(m).WithAuth(tc.auth).DetectEnterprise(context.Background(), nil)
			if len(configs) != len(tc.want) {
				t.Fatalf("got %d configs, want %d: %+v", len(configs), len(tc.want), configs)
			}
			for _, c := range configs {
				if !equalAuth(c.ServerAuth, tc.want[c.ConfigSource]) {
					t.Errorf("%s: got %+v, want %+v", c.ConfigSource, c.ServerAuth, tc.want[c.ConfigSource])
				}
				if c.ConfigContentBase64 == "" && c.ServerAuth != nil {
					t.Errorf("%s: server_auth without content: %+v", c.ConfigSource, c)
				}
			}
		})
	}
}

// Token expiry times either side of authNow.
const (
	futureMs  = 1_800_003_600_000
	pastMs    = 1_799_996_400_000
	futureSec = 1_800_003_600
	pastSec   = 1_799_996_400
)

// authCase is one server resolved against the stores a test writes.
type authCase struct {
	name             string
	goos             string                                            // defaults to linux
	env              map[string]string                                 // a "~/" value is under the test home
	files            map[string]string                                 // home-relative store files
	setup            func(t *testing.T, m *executor.Mock, home string) // real databases and listings
	server, decl     string                                            // "<home>" in decl is the test home
	status, evidence string
}

// runAuthCases resolves each case for a source with a fresh resolver, so no
// store is cached between cases.
func runAuthCases(t *testing.T, source, configRel string, cases []authCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, home := newAuthMock(t)
			if tc.goos != "" {
				m.SetGOOS(tc.goos)
			}
			for k, v := range tc.env {
				if rest, ok := strings.CutPrefix(v, "~/"); ok {
					v = filepath.Join(home, rest)
				}
				m.SetEnv(k, v)
			}
			setAuthFiles(m, home, tc.files)
			if tc.setup != nil {
				tc.setup(t, m, home)
			}
			r, _ := newAuthResolver(m)
			decl := strings.ReplaceAll(tc.decl, "<home>", filepath.ToSlash(home))
			checkAuth(t, authOf(r, source, filepath.Join(home, configRel), tc.server, decl), tc.status, tc.evidence)
		})
	}
}

// setAuthFiles writes home-relative files into the mock and lists each one
// in every directory above it, up to home.
func setAuthFiles(m *executor.Mock, home string, files map[string]string) {
	entries := map[string]map[string]bool{}
	for rel, content := range files {
		path := filepath.Join(home, filepath.FromSlash(rel))
		m.SetFile(path, []byte(content))
		for child, isDir := path, false; child != home; child, isDir = filepath.Dir(child), true {
			parent := filepath.Dir(child)
			if entries[parent] == nil {
				entries[parent] = map[string]bool{}
			}
			entries[parent][filepath.Base(child)] = isDir
		}
	}
	for dir, children := range entries {
		var list []os.DirEntry
		for _, name := range sortedMapKeys(children) {
			list = append(list, executor.MockDirEntry(name, children[name]))
		}
		m.SetDirEntries(dir, list)
	}
}

// overCap is a JSON document larger than any store read cap.
var overCap = `{"pad":"` + strings.Repeat("x", maxJSONConfigBytes) + `"}`

const labOAuth = `{"type":"http","url":"https://a.example.com/mcp"}`

func TestClaudeMCPAuth(t *testing.T) {
	creds := func(entries string) map[string]string {
		return map[string]string{".claude/.credentials.json": `{"mcpOAuth":{` + entries + `}}`}
	}
	cases := []authCase{
		{name: "saved", server: "lab-oauth", decl: labOAuth,
			files:  creds(`"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"https://a.example.com/mcp","accessToken":"a","expiresAt":` + strconv.Itoa(futureMs) + `}`),
			status: model.MCPAuthCredentialSaved, evidence: "claude_token_file"},
		{name: "a record whose URL differs by a trailing slash", server: "lab-oauth", decl: labOAuth,
			files:  creds(`"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"https://a.example.com/mcp/","accessToken":"a"}`),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "expired with a refresh token", server: "lab-oauth", decl: labOAuth,
			files:  creds(`"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"https://a.example.com/mcp","accessToken":"a","refreshToken":"r","expiresAt":` + strconv.Itoa(pastMs) + `}`),
			status: model.MCPAuthCredentialSaved, evidence: "claude_token_file"},
		{name: "cleared token", server: "lab-oauth", decl: labOAuth,
			files:  creds(`"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"https://a.example.com/mcp","accessToken":""}`),
			status: model.MCPAuthNeedsAuth, evidence: "claude_token_cleared"},
		{name: "a stale record left at an old URL", server: "lab-oauth", decl: labOAuth,
			files:  creds(`"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"https://a.example.com/sse","accessToken":"a"}`),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "a URL with a variable falls back to the one record by name", server: "lab-oauth", decl: `{"type":"http","url":"https://${LAB_HOST}/mcp"}`,
			files:  creds(`"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"https://a.example.com/mcp","accessToken":"a"}`),
			status: model.MCPAuthCredentialSaved, evidence: "claude_token_file"},
		{name: "two records by name, neither at the URL", server: "lab-oauth", decl: labOAuth,
			files: creds(`"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"https://b.example.com/mcp","accessToken":"a"},` +
				`"lab-oauth|2":{"serverName":"lab-oauth","serverUrl":"https://c.example.com/mcp","accessToken":"a"}`),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "needs-auth cache beats a saved token", server: "lab-oauth", decl: labOAuth,
			files: map[string]string{
				".claude/mcp-needs-auth-cache.json": `{"lab-oauth":{"timestamp":1}}`,
				".claude/.credentials.json":         `{"mcpOAuth":{"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"https://a.example.com/mcp","accessToken":"a"}}}`,
			},
			status: model.MCPAuthNeedsAuth, evidence: "claude_needs_auth_cache"},
		{name: "config dir from the environment", server: "lab-oauth", decl: labOAuth,
			env:    map[string]string{"CLAUDE_CONFIG_DIR": "~/claude-alt"},
			files:  map[string]string{"claude-alt/mcp-needs-auth-cache.json": `{"lab-oauth":{}}`},
			status: model.MCPAuthNeedsAuth, evidence: "claude_needs_auth_cache"},
		{name: "no store", server: "lab-oauth", decl: labOAuth, status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "an entry of another shape drops only itself", server: "lab-oauth", decl: labOAuth,
			files:  creds(`"version":1,"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"https://a.example.com/mcp","accessToken":"a"}`),
			status: model.MCPAuthCredentialSaved, evidence: "claude_token_file"},
		{name: "malformed credentials", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{".claude/.credentials.json": `{"mcpOAuth":[`},
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "cache over the cap", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{".claude/mcp-needs-auth-cache.json": overCap},
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "macOS keeps sign-ins in the Keychain", goos: model.PlatformDarwin, server: "lab-oauth", decl: labOAuth,
			files:  creds(`"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"https://a.example.com/mcp","accessToken":"a"}`),
			status: model.MCPAuthUnknown, evidence: "encrypted_store"},
	}
	runAuthCases(t, "claude_code", ".claude.json", cases)
}

func TestClaudeMCPAuth_DarwinNeverReadsCredentials(t *testing.T) {
	m, home := newAuthMock(t)
	m.SetGOOS(model.PlatformDarwin)
	setAuthFiles(m, home, map[string]string{".claude/.credentials.json": `{"mcpOAuth":{}}`})
	r, reads := newAuthResolver(m)
	checkAuth(t, authOf(r, "claude_code", filepath.Join(home, ".claude.json"), "lab-oauth", labOAuth), model.MCPAuthUnknown, "encrypted_store")
	for _, path := range *reads {
		if filepath.Base(path) == ".credentials.json" {
			t.Errorf("read %s on macOS", path)
		}
	}
}

func TestCodexMCPAuth(t *testing.T) {
	store := func(entry string) map[string]string {
		return map[string]string{".codex/.credentials.json": `{"k1":` + entry + `}`}
	}
	cases := []authCase{
		{name: "saved", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp","access_token":"a","expires_at":` + strconv.Itoa(futureMs) + `}`),
			status: model.MCPAuthCredentialSaved, evidence: "codex_token_file"},
		{name: "a URL that differs by a trailing slash", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp/","access_token":"a","expires_at":` + strconv.Itoa(futureMs) + `}`),
			status: model.MCPAuthUnknown, evidence: "encrypted_store"},
		{name: "expired", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp","access_token":"a","expires_at":` + strconv.Itoa(pastMs) + `}`),
			status: model.MCPAuthNeedsAuth, evidence: "codex_token_expired"},
		{name: "expired, refreshable from its issuer", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp","issuer":"https://auth.example.com","access_token":"a","refresh_token":"r","expires_at":` + strconv.Itoa(pastMs) + `}`),
			status: model.MCPAuthCredentialSaved, evidence: "codex_token_file"},
		{name: "expired with a refresh token but no issuer", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp","access_token":"a","refresh_token":"r","expires_at":` + strconv.Itoa(pastMs) + `}`),
			status: model.MCPAuthNeedsAuth, evidence: "codex_token_expired"},
		{name: "within the refresh margin", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp","access_token":"a","expires_at":` + strconv.FormatInt(authNow.UnixMilli()+10_000, 10) + `}`),
			status: model.MCPAuthNeedsAuth, evidence: "codex_token_expired"},
		{name: "no client id", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"server_name":"lab-oauth","server_url":"https://a.example.com/mcp","access_token":"a"}`),
			status: model.MCPAuthNeedsAuth, evidence: "codex_token_expired"},
		{name: "an entry of another shape drops only itself", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{".codex/.credentials.json": `{"version":1,"k1":{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp","access_token":"a"}}`},
			status: model.MCPAuthCredentialSaved, evidence: "codex_token_file"},
		{name: "local prefix", server: "local:lab-oauth", decl: labOAuth,
			files:  store(`{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp","access_token":"a"}`),
			status: model.MCPAuthCredentialSaved, evidence: "codex_token_file"},
		{name: "same name at another URL", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"server_name":"lab-oauth","client_id":"c","server_url":"https://b.example.com/mcp","access_token":"a"}`),
			status: model.MCPAuthUnknown, evidence: "encrypted_store"},
		{name: "no file", server: "lab-oauth", decl: labOAuth, status: model.MCPAuthUnknown, evidence: "encrypted_store"},
		{name: "CODEX_HOME", server: "lab-oauth", decl: labOAuth, env: map[string]string{"CODEX_HOME": "~/codex-alt"},
			files:  map[string]string{"codex-alt/.credentials.json": `{"k1":{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp","access_token":"a"}}`},
			status: model.MCPAuthCredentialSaved, evidence: "codex_token_file"},
		{name: "relative CODEX_HOME is ignored", server: "lab-oauth", decl: labOAuth, env: map[string]string{"CODEX_HOME": "codex-alt"},
			files:  store(`{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp","access_token":"a"}`),
			status: model.MCPAuthCredentialSaved, evidence: "codex_token_file"},
		{name: "malformed", server: "lab-oauth", decl: labOAuth, files: map[string]string{".codex/.credentials.json": `[]`},
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "over the cap", server: "lab-oauth", decl: labOAuth, files: map[string]string{".codex/.credentials.json": overCap},
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
	}
	runAuthCases(t, "codex", ".codex/config.toml", cases)
}

func TestCopilotMCPAuth(t *testing.T) {
	keyA, keyB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	dir := ".copilot/mcp-oauth-config/"
	reg := `{"serverUrl":"https://a.example.com/mcp/"}`
	cases := []authCase{
		{name: "sign-in complete, joined across a trailing slash", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + keyA + ".json": reg},
			status: model.MCPAuthCredentialSaved, evidence: "copilot_signin_complete"},
		{name: "usable tokens", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + keyA + ".json": reg, dir + keyA + ".tokens.json": `{"accessToken":"a","expiresAt":` + strconv.Itoa(futureSec) + `}`},
			status: model.MCPAuthCredentialSaved, evidence: "copilot_signin_complete"},
		{name: "expired tokens", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + keyA + ".json": reg, dir + keyA + ".tokens.json": `{"accessToken":"a","expiresAt":` + strconv.Itoa(pastSec) + `}`},
			status: model.MCPAuthNeedsAuth, evidence: "copilot_signin_pending"},
		{name: "verifier left", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + keyA + ".json": reg, dir + keyA + ".verifier": "v"},
			status: model.MCPAuthNeedsAuth, evidence: "copilot_signin_pending"},
		{name: "a saved registration wins", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + keyA + ".json": reg, dir + keyA + ".verifier": "v", dir + keyB + ".json": reg},
			status: model.MCPAuthCredentialSaved, evidence: "copilot_signin_complete"},
		{name: "other server", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + keyA + ".json": `{"serverUrl":"https://b.example.com/mcp"}`},
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "not a registration key", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + "config.json": reg, dir + strings.Repeat("A", 64) + ".json": reg},
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "no directory", server: "lab-oauth", decl: labOAuth, status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "COPILOT_HOME the scan did not see", server: "lab-oauth", decl: labOAuth, env: map[string]string{"COPILOT_HOME": "~/copilot-alt"},
			files:  map[string]string{dir + keyA + ".json": reg, "copilot-alt/mcp-oauth-config/" + keyA + ".json": `{"serverUrl":"https://b.example.com/mcp"}`},
			status: model.MCPAuthCredentialSaved, evidence: "copilot_signin_complete"},
		{name: "malformed registration", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + keyA + ".json": `{`},
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "a malformed registration drops only itself", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + keyA + ".json": `{`, dir + keyB + ".json": reg, dir + keyB + ".tokens.json": `{"accessToken":"a"}`},
			status: model.MCPAuthCredentialSaved, evidence: "copilot_signin_complete"},
		{name: "malformed tokens drop only their registration", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + keyA + ".json": reg, dir + keyA + ".tokens.json": `[`, dir + keyB + ".json": reg, dir + keyB + ".verifier": "v"},
			status: model.MCPAuthNeedsAuth, evidence: "copilot_signin_pending"},
		{name: "registration over the cap", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{dir + keyA + ".json": `{"pad":"` + strings.Repeat("x", maxMCPAuthFileBytes) + `"}`},
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "too many registrations", server: "lab-oauth", decl: labOAuth,
			setup: func(_ *testing.T, m *executor.Mock, home string) {
				entries := make([]os.DirEntry, maxCopilotOAuthKeys+1)
				for i := range entries {
					entries[i] = executor.MockDirEntry(fmt.Sprintf("%064x.json", i), false)
				}
				m.SetDirEntries(filepath.Join(home, ".copilot", "mcp-oauth-config"), entries)
			},
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
	}
	runAuthCases(t, "copilot", ".copilot/mcp-config.json", cases)

	// The store sits beside the user config the scan read; project servers
	// use the user's own root.
	runAuthCases(t, "copilot", "copilot-alt/mcp-config.json", []authCase{
		{name: "user config under another root", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{"copilot-alt/mcp-oauth-config/" + keyA + ".json": reg},
			status: model.MCPAuthCredentialSaved, evidence: "copilot_signin_complete"},
	})
	runAuthCases(t, "copilot_project", "repo/.mcp.json", []authCase{
		{name: "project config under COPILOT_HOME", server: "lab-oauth", decl: labOAuth, env: map[string]string{"COPILOT_HOME": "~/copilot-alt"},
			files:  map[string]string{"copilot-alt/mcp-oauth-config/" + keyA + ".json": reg},
			status: model.MCPAuthCredentialSaved, evidence: "copilot_signin_complete"},
	})
}

func TestPiMCPAuth(t *testing.T) {
	store := func(doc string) map[string]string { return map[string]string{".pi/agent/mcp-auth.json": doc} }
	cases := []authCase{
		{name: "keyed by name and URL", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"mcp__lab_oauth|https://a.example.com/mcp":{"tokens":{"access_token":"a"}}}`),
			status: model.MCPAuthCredentialSaved, evidence: "pi_token_file"},
		{name: "keyed by URL alone", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"https://a.example.com/mcp":{"tokens":{"refresh_token":"r"}}}`),
			status: model.MCPAuthCredentialSaved, evidence: "pi_token_file"},
		{name: "normalized scheme, host and default port", server: "lab-oauth", decl: `{"url":"HTTPS://A.Example.com:443"}`,
			files:  store(`{"mcp__lab_oauth|https://a.example.com/":{"tokens":{"access_token":"a"}}}`),
			status: model.MCPAuthCredentialSaved, evidence: "pi_token_file"},
		{name: "registration only", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"mcp__lab_oauth|https://a.example.com/mcp":{"client_info":{"client_id":"c"}}}`),
			status: model.MCPAuthNeedsAuth, evidence: "pi_registration_only"},
		{name: "other server", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"https://b.example.com/mcp":{"tokens":{"access_token":"a"}}}`),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "PI_CODING_AGENT_DIR", server: "lab-oauth", decl: labOAuth, env: map[string]string{"PI_CODING_AGENT_DIR": "~/pi-alt"},
			files:  map[string]string{"pi-alt/mcp-auth.json": `{"https://a.example.com/mcp":{"tokens":{"access_token":"a"}}}`},
			status: model.MCPAuthCredentialSaved, evidence: "pi_token_file"},
		{name: "no file", server: "lab-oauth", decl: labOAuth, status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "an entry of another shape drops only itself", server: "lab-oauth", decl: labOAuth,
			files:  store(`{"version":1,"https://a.example.com/mcp":{"tokens":{"access_token":"a"}}}`),
			status: model.MCPAuthCredentialSaved, evidence: "pi_token_file"},
		{name: "malformed", server: "lab-oauth", decl: labOAuth, files: store(`[1]`),
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
	}
	runAuthCases(t, "pi", ".pi/agent/mcp.json", cases)
}

// writeOpenCodeDB writes an OpenCode credential database with one MCP row,
// under the integration OpenCode registers for the server's name and URL.
func writeOpenCodeDB(t *testing.T, path, name, serverURL string, token map[string]any) {
	t.Helper()
	id := openCodeIntegrationID(name, serverURL)
	row := map[string]any{"methodID": id, "metadata": map[string]any{"serverUrl": serverURL, "tokenType": "Bearer"}}
	for k, v := range token {
		row[k] = v
	}
	value, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	writeSQLite(t, path, `CREATE TABLE credential (integration_id TEXT PRIMARY KEY, value TEXT)`,
		`INSERT INTO credential VALUES (?, ?)`, map[string]string{id: string(value)})
}

func TestOpenCodeMCPAuth(t *testing.T) {
	file := ".local/share/opencode/mcp-auth.json"
	db := func(file, name, serverURL string, token map[string]any) func(*testing.T, *executor.Mock, string) {
		return func(t *testing.T, _ *executor.Mock, home string) {
			writeOpenCodeDB(t, filepath.Join(home, ".local", "share", "opencode", file), name, serverURL, token)
		}
	}
	// migrations adds OpenCode's migration table, holding these ids, to opencode.db.
	migrations := func(ids ...string) func(*testing.T, *executor.Mock, string) {
		return func(t *testing.T, _ *executor.Mock, home string) {
			rows := map[string]string{}
			for _, id := range ids {
				rows[id] = "1"
			}
			writeSQLite(t, filepath.Join(home, ".local", "share", "opencode", "opencode.db"),
				`CREATE TABLE migration (id TEXT PRIMARY KEY, time_completed INTEGER NOT NULL)`, `INSERT INTO migration VALUES (?, ?)`, rows)
		}
	}
	both := func(first, second func(*testing.T, *executor.Mock, string)) func(*testing.T, *executor.Mock, string) {
		return func(t *testing.T, m *executor.Mock, home string) {
			first(t, m, home)
			second(t, m, home)
		}
	}
	// schemaOnly writes opencode.db with only this schema.
	schemaOnly := func(schema string) func(*testing.T, *executor.Mock, string) {
		return func(t *testing.T, _ *executor.Mock, home string) {
			writeSQLite(t, filepath.Join(home, ".local", "share", "opencode", "opencode.db"), schema, "", nil)
		}
	}
	version2 := migrations("20260622202450_simplify_session_input", "20260805200742_import_legacy_credentials")
	version1 := migrations("20260622202450_simplify_session_input")
	access := map[string]any{"access": "a"}
	// entry is an mcp-auth.json entry for lab-oauth at a server URL.
	entry := func(serverURL, tokens string) map[string]string {
		return map[string]string{file: `{"lab-oauth":{"serverUrl":"` + serverURL + `","tokens":` + tokens + `}}`}
	}
	aURL := "https://a.example.com/mcp"
	cases := []authCase{
		{name: "file token", server: "lab-oauth", decl: `{"type":"remote","url":"https://a.example.com/mcp"}`,
			files:  entry(aURL, `{"accessToken":"a"}`),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "file token for another server URL", server: "lab-oauth", decl: labOAuth,
			files:  entry("https://b.example.com/mcp", `{"accessToken":"a"}`),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "file token across a trailing slash", server: "lab-oauth", decl: labOAuth,
			files:  entry(aURL+"/", `{"accessToken":"a"}`),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "file token without a server URL", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{file: `{"lab-oauth":{"tokens":{"accessToken":"a"}}}`},
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "file token expired without a refresh token", server: "lab-oauth", decl: labOAuth,
			files:  entry(aURL, `{"accessToken":"a","expiresAt":`+strconv.Itoa(pastSec)+`}`),
			status: model.MCPAuthNeedsAuth, evidence: "opencode_registration_only"},
		{name: "file token expired with a refresh token", server: "lab-oauth", decl: labOAuth,
			files:  entry(aURL, `{"accessToken":"a","refreshToken":"r","expiresAt":`+strconv.Itoa(pastSec)+`}`),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "file token expiry ahead", server: "lab-oauth", decl: labOAuth,
			files:  entry(aURL, `{"accessToken":"a","expiresAt":`+strconv.Itoa(futureSec)+`}`),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "file registration only", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{file: `{"lab-oauth":{"serverUrl":"https://a.example.com/mcp","clientInfo":{"clientId":"c"}}}`},
			status: model.MCPAuthNeedsAuth, evidence: "opencode_registration_only"},
		{name: "database token for the server's integration", server: "lab-oauth", decl: labOAuth,
			setup:  db("opencode.db", "lab-oauth", aURL, access),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "database token for another name at the same URL", server: "lab-oauth", decl: labOAuth,
			setup:  db("opencode.db", "lab-other", aURL, access),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "database token for the URL with a trailing slash", server: "lab-oauth", decl: labOAuth,
			setup:  db("opencode.db", "lab-oauth", aURL+"/", access),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "OAuth turned off", server: "lab-oauth", decl: `{"type":"remote","url":"https://a.example.com/mcp","oauth":false}`,
			setup:  db("opencode.db", "lab-oauth", aURL, access),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "OAuth turned off, file token", server: "lab-oauth", decl: `{"type":"remote","url":"https://a.example.com/mcp","oauth":false}`,
			files:  entry(aURL, `{"accessToken":"a"}`),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "OpenCode 2 no longer reads a file token", server: "lab-oauth", decl: labOAuth,
			files:  entry(aURL, `{"accessToken":"a"}`),
			setup:  both(db("opencode.db", "lab-other", aURL, access), version2),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "OpenCode 2 database token", server: "lab-oauth", decl: labOAuth,
			setup:  both(db("opencode.db", "lab-oauth", aURL, access), version2),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "OpenCode 1 database, file token", server: "lab-oauth", decl: labOAuth,
			files:  entry(aURL, `{"accessToken":"a"}`),
			setup:  both(db("opencode.db", "lab-other", aURL, access), version1),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "database without a migration table, file token", server: "lab-oauth", decl: labOAuth,
			files:  entry(aURL, `{"accessToken":"a"}`),
			setup:  db("opencode.db", "lab-other", aURL, access),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "database from before OpenCode kept credentials", server: "lab-oauth", decl: labOAuth,
			setup:  schemaOnly(`CREATE TABLE session (id TEXT PRIMARY KEY)`),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "database without a credential table still records OpenCode 2", server: "lab-oauth", decl: labOAuth,
			files: entry(aURL, `{"accessToken":"a"}`),
			setup: schemaOnly(`CREATE TABLE migration (id TEXT PRIMARY KEY, time_completed INTEGER NOT NULL);
				INSERT INTO migration VALUES ('20260805200742_import_legacy_credentials', 1)`),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "a credential view", server: "lab-oauth", decl: labOAuth,
			setup: schemaOnly(`CREATE TABLE stored (integration_id TEXT, value TEXT);
				CREATE VIEW credential AS SELECT integration_id, value FROM stored`),
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "a credential table with a renamed column", server: "lab-oauth", decl: labOAuth,
			setup:  schemaOnly(`CREATE TABLE credential (integration TEXT, value TEXT)`),
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "a URL with a variable, file token under the name", server: "lab-oauth", decl: `{"type":"remote","url":"https://{env:LAB_HOST}/mcp"}`,
			files:  entry(aURL, `{"accessToken":"a"}`),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "a URL with a file reference, database token at the URL it signed in at", server: "lab-oauth", decl: `{"type":"remote","url":"https://lab.example.com/{file:path.txt}"}`,
			setup:  db("opencode.db", "lab-oauth", "https://lab.example.com/mcp", access),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "a URL with a variable, file token at an old URL", server: "lab-oauth", decl: `{"type":"remote","url":"https://{env:LAB_HOST}/mcp"}`,
			files:  entry("https://old.example.test/sse", `{"accessToken":"a"}`),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "a URL with a variable, database token at an old URL", server: "lab-oauth", decl: `{"type":"remote","url":"https://{env:LAB_HOST}/mcp"}`,
			setup:  db("opencode.db", "lab-oauth", "https://old.example.test/sse", access),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "a failed database read does not bring back the file", server: "lab-oauth", decl: labOAuth,
			files: entry(aURL, `{"accessToken":"a"}`),
			setup: schemaOnly(`CREATE TABLE migration (id TEXT PRIMARY KEY, time_completed INTEGER NOT NULL);
				INSERT INTO migration VALUES ('20260805200742_import_legacy_credentials', 1);
				CREATE TABLE stored (integration_id TEXT, value TEXT);
				CREATE VIEW credential AS SELECT integration_id, value FROM stored`),
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "a URL with a variable, database token under another name", server: "lab-oauth", decl: `{"type":"remote","url":"https://{env:LAB_HOST}/mcp"}`,
			setup:  db("opencode.db", "lab-other", aURL, access),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "database token expired without a refresh token", server: "lab-oauth", decl: labOAuth,
			setup:  db("opencode.db", "lab-oauth", aURL, map[string]any{"access": "a", "refresh": "", "expires": pastMs}),
			status: model.MCPAuthNeedsAuth, evidence: "opencode_registration_only"},
		{name: "database token expired with a refresh token", server: "lab-oauth", decl: labOAuth,
			setup:  db("opencode.db", "lab-oauth", aURL, map[string]any{"access": "a", "refresh": "r", "expires": pastMs}),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "database token with no lifetime", server: "lab-oauth", decl: labOAuth,
			setup:  db("opencode.db", "lab-oauth", aURL, map[string]any{"access": "a", "refresh": "", "expires": 0}),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "channel database without a token", server: "lab-oauth", decl: labOAuth,
			setup:  db("opencode-dev.db", "lab-oauth", "https://a.example.com/mcp", map[string]any{"access": ""}),
			status: model.MCPAuthNeedsAuth, evidence: "opencode_registration_only"},
		{name: "a saved database row beats a file registration", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{file: `{"lab-oauth":{}}`},
			setup:  db("opencode.db", "lab-oauth", "https://a.example.com/mcp", access),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "OPENCODE_DB", server: "lab-oauth", decl: labOAuth, env: map[string]string{"OPENCODE_DB": "~/alt/oc.db"},
			setup: func(t *testing.T, _ *executor.Mock, home string) {
				writeOpenCodeDB(t, filepath.Join(home, "alt", "oc.db"), "lab-oauth", "https://a.example.com/mcp", map[string]any{"access": "a"})
			},
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "XDG_DATA_HOME", server: "lab-oauth", decl: labOAuth, env: map[string]string{"XDG_DATA_HOME": "~/data"},
			files:  map[string]string{"data/opencode/mcp-auth.json": `{"lab-oauth":{"serverUrl":"https://a.example.com/mcp","tokens":{"accessToken":"a"}}}`},
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
		{name: "no store", server: "lab-oauth", decl: labOAuth, status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "an entry of another shape drops only itself", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{file: `{"lab-oauth":[],"other":{"tokens":{"accessToken":"a"}}}`},
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "malformed file", server: "lab-oauth", decl: labOAuth, files: map[string]string{file: `{`},
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "malformed file, saved database row", server: "lab-oauth", decl: labOAuth, files: map[string]string{file: `{`},
			setup:  db("opencode.db", "lab-oauth", "https://a.example.com/mcp", access),
			status: model.MCPAuthCredentialSaved, evidence: "opencode_token_file"},
	}
	runAuthCases(t, "opencode", ".config/opencode/opencode.json", cases)
}

func TestOpenCodeURLMatcher(t *testing.T) {
	tests := []struct {
		name, url, stored string
		want              bool
	}{
		{"plain URL, same", "https://a.example.com/mcp", "https://a.example.com/mcp", true},
		{"plain URL, trailing slash", "https://a.example.com/mcp", "https://a.example.com/mcp/", false},
		{"plain URL, nothing stored", "", "", false},
		{"variable host", "https://{env:LAB_HOST}/mcp", "https://lab.example.test/mcp", true},
		{"variable host, other path", "https://{env:LAB_HOST}/mcp", "https://old.example.test/sse", false},
		{"two placeholders", "https://{env:HOST}/{file:path.txt}/mcp", "https://lab.example.test/v1/mcp", true},
		{"prefix and suffix overlap", "https://{env:LAB_HOST}/mcp", "https://mcp", false},
		{"only a placeholder, nothing stored", "{env:MCP_URL}", "", false},
		{"only a placeholder", "{env:MCP_URL}", "https://lab.example.test/mcp", true},
		{"unclosed placeholder is literal", "https://{env:LAB_HOST/mcp", "https://lab.example.test/mcp", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := openCodeURLMatcher(tc.url)(tc.stored); got != tc.want {
				t.Errorf("openCodeURLMatcher(%q)(%q) = %v, want %v", tc.url, tc.stored, got, tc.want)
			}
		})
	}
}

func TestOpenCodeIntegrationID(t *testing.T) {
	name, url := "lab-oauth", "https://lab.example.test/mcp"
	sum := sha1.Sum([]byte(name + "\x00" + url))
	if got, want := openCodeIntegrationID(name, url), "mcp_"+hex.EncodeToString(sum[:])[:16]; got != want {
		t.Errorf("openCodeIntegrationID = %s, want %s", got, want)
	}
	if got, want := openCodeIntegrationID(name, url), "mcp_87fb00546a7d5a45"; got != want {
		t.Errorf("openCodeIntegrationID = %s, want %s", got, want)
	}
}

// cursorStoreKey builds a Cursor secret key for a scope and field.
func cursorStoreKey(scope, field string) string {
	return "mcpOAuth.secret." + base64.RawURLEncoding.EncodeToString([]byte("["+scope+"] "+field))
}

func cursorURLScope(u string) string { return "url:" + base64.RawURLEncoding.EncodeToString([]byte(u)) }

func TestParseCursorKey(t *testing.T) {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	tests := []struct {
		name, key string
		want      cursorKey
		ok        bool
	}{
		{"url scope", cursorStoreKey(cursorURLScope("https://a.example.com/mcp"), "mcp_tokens"), cursorKey{url: "https://a.example.com/mcp", field: "mcp_tokens"}, true},
		{"user scope", cursorStoreKey("user-lab-oauth", "mcp_client_information"), cursorKey{name: "lab-oauth", field: "mcp_client_information"}, true},
		{"user scope with suffix", cursorStoreKey("user-lab-oauth::abc", "mcp_tokens"), cursorKey{name: "lab-oauth", field: "mcp_tokens"}, true},
		{"identifier scope", cursorStoreKey("identifier:v1:"+b64("user-lab-oauth"), "mcp_tokens"), cursorKey{name: "lab-oauth", field: "mcp_tokens"}, true},
		{"global with profile", "mcpOAuth.global." + b64("[profile:"+b64("p")+"] [user-lab-oauth] mcp_code_verifier"), cursorKey{name: "lab-oauth", field: "mcp_code_verifier"}, true},
		{"project scope", cursorStoreKey("project-lab-oauth", "mcp_tokens"), cursorKey{}, false},
		{"not base64", "mcpOAuth.secret.%%%", cursorKey{}, false},
		{"other prefix", "mcpOAuth.other." + b64("[user-a] mcp_tokens"), cursorKey{}, false},
		{"no scope", "mcpOAuth.secret." + b64("mcp_tokens"), cursorKey{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseCursorKey(tc.key)
			if ok != tc.ok || ok && got != tc.want {
				t.Errorf("parseCursorKey = %+v, %v, want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestCursorCanonicalURL(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://A.example.com:443/mcp/", "https://a.example.com/mcp"},
		{"https://a.example.com/", "https://a.example.com/"},
		{"https://a.example.com", "https://a.example.com/"},
		{"https://a.example.com/mcp?x=1#frag", "https://a.example.com/mcp?x=1"},
		{"  Not A URL ", "not a url"},
	}
	for _, tc := range tests {
		if got := cursorCanonicalURL(tc.in); got != tc.want {
			t.Errorf("cursorCanonicalURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCursorMCPAuth(t *testing.T) {
	db := func(keys ...string) func(*testing.T, *executor.Mock, string) {
		return func(t *testing.T, _ *executor.Mock, home string) {
			rows := map[string]string{"cursorAuth/accessToken": "x"}
			for _, k := range keys {
				rows[k] = "ciphertext"
			}
			writeItemTable(t, filepath.Join(home, ".config", "Cursor", "User", "globalStorage", "state.vscdb"), rows)
		}
	}
	urlScope := cursorURLScope("https://a.example.com/mcp")
	cli := ".cursor/projects/p1/mcp-auth.json"
	cases := []authCase{
		{name: "token by URL, joined across a trailing slash", server: "lab-oauth", decl: `{"url":"https://a.example.com/mcp/"}`,
			setup:  db(cursorStoreKey(urlScope, "mcp_tokens")),
			status: model.MCPAuthCredentialSaved, evidence: "cursor_token_key"},
		{name: "token by name", server: "lab-oauth", decl: labOAuth,
			setup:  db(cursorStoreKey("user-lab-oauth", "mcp_tokens")),
			status: model.MCPAuthCredentialSaved, evidence: "cursor_token_key"},
		{name: "registration only", server: "lab-oauth", decl: labOAuth,
			setup:  db(cursorStoreKey(urlScope, "mcp_client_information"), cursorStoreKey(urlScope, "mcp_code_verifier")),
			status: model.MCPAuthNeedsAuth, evidence: "cursor_no_token"},
		{name: "token beats registration", server: "lab-oauth", decl: labOAuth,
			setup:  db(cursorStoreKey(urlScope, "mcp_client_information"), cursorStoreKey("user-lab-oauth", "mcp_tokens")),
			status: model.MCPAuthCredentialSaved, evidence: "cursor_token_key"},
		{name: "another server's keys", server: "lab-oauth", decl: labOAuth,
			setup:  db(cursorStoreKey(cursorURLScope("https://b.example.com/mcp"), "mcp_tokens"), cursorStoreKey("user-other", "mcp_tokens")),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "CLI token", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{cli: `{"lab-oauth":{"tokens":{"access_token":"a"}}}`},
			status: model.MCPAuthCredentialSaved, evidence: "cursor_cli_token_file"},
		{name: "CLI registration only", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{cli: `{"lab-oauth":{"client_information":{"client_id":"c"}}}`},
			status: model.MCPAuthNeedsAuth, evidence: "cursor_cli_registration_only"},
		{name: "CLI token beats an editor registration", server: "lab-oauth", decl: labOAuth,
			setup:  db(cursorStoreKey(urlScope, "mcp_client_information")),
			files:  map[string]string{cli: `{"lab-oauth":{"tokens":{"access_token":"a"}}}`},
			status: model.MCPAuthCredentialSaved, evidence: "cursor_cli_token_file"},
		{name: "a CLI entry of another shape drops only itself", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{cli: `{"version":1,"lab-oauth":{"tokens":{"access_token":"a"}}}`},
			status: model.MCPAuthCredentialSaved, evidence: "cursor_cli_token_file"},
		{name: "malformed CLI file", server: "lab-oauth", decl: labOAuth,
			files:  map[string]string{cli: `[`},
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "malformed CLI file, saved editor token", server: "lab-oauth", decl: labOAuth,
			setup:  db(cursorStoreKey(urlScope, "mcp_tokens")),
			files:  map[string]string{cli: `[`},
			status: model.MCPAuthCredentialSaved, evidence: "cursor_token_key"},
		{name: "too many CLI projects", server: "lab-oauth", decl: labOAuth,
			setup: func(_ *testing.T, m *executor.Mock, home string) {
				entries := make([]os.DirEntry, maxCursorProjects+1)
				for i := range entries {
					entries[i] = executor.MockDirEntry(fmt.Sprintf("p%d", i), true)
				}
				dir := filepath.Join(home, ".cursor", "projects")
				m.SetDirEntries(dir, entries)
				m.SetFile(filepath.Join(dir, "p0", "mcp-auth.json"), []byte(`{"lab-oauth":{"tokens":{"access_token":"a"}}}`))
			},
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "corrupt database", server: "lab-oauth", decl: labOAuth,
			setup: func(t *testing.T, _ *executor.Mock, home string) {
				path := filepath.Join(home, ".config", "Cursor", "User", "globalStorage", "state.vscdb")
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "no store", server: "lab-oauth", decl: labOAuth, status: model.MCPAuthUnknown, evidence: "no_record"},
	}
	runAuthCases(t, "cursor", ".cursor/mcp.json", cases)
}

func TestVSCodeMCPAuth(t *testing.T) {
	provider := "https://auth.example.com https://a.example.com/mcp"
	providers := `[{"providerId":"` + provider + `","label":"a","authorizationServer":"https://auth.example.com"}]`
	grantKey := "mcpserver-" + provider + "-dev@example.com"
	tokenKey := `secret://{"isDynamicAuthProvider":true,"authProviderId":"` + provider + `","clientId":"c"}`
	db := func(rows map[string]string) func(*testing.T, *executor.Mock, string) {
		return func(t *testing.T, _ *executor.Mock, home string) {
			writeItemTable(t, filepath.Join(home, ".config", "Code", "User", "globalStorage", "state.vscdb"), rows)
		}
	}
	cases := []authCase{
		{name: "granted with a token key", server: "lab-oauth", decl: labOAuth,
			setup: db(map[string]string{"dynamicAuthProviders": providers, tokenKey: "ciphertext",
				grantKey: `[{"id":"mcp.config.usrlocal.lab-oauth","allowed":true}]`}),
			status: model.MCPAuthCredentialSaved, evidence: "vscode_token_key"},
		{name: "signed out keeps the token key", server: "lab-oauth", decl: labOAuth,
			setup: db(map[string]string{"dynamicAuthProviders": providers, tokenKey: "ciphertext",
				grantKey: `[{"id":"mcp.config.usrlocal.lab-oauth","allowed":false}]`}),
			status: model.MCPAuthNeedsAuth, evidence: "vscode_signed_out"},
		{name: "provider without a token key", server: "lab-oauth", decl: labOAuth,
			setup:  db(map[string]string{"dynamicAuthProviders": providers}),
			status: model.MCPAuthNeedsAuth, evidence: "vscode_no_token"},
		{name: "provider by resource, joined across a trailing slash", server: "lab-oauth", decl: `{"url":"https://a.example.com/mcp/"}`,
			setup:  db(map[string]string{"dynamicAuthProviders": providers, tokenKey: "ciphertext"}),
			status: model.MCPAuthCredentialSaved, evidence: "vscode_token_key"},
		{name: "grant for another server", server: "lab-oauth", decl: `{"url":"https://b.example.com/mcp"}`,
			setup: db(map[string]string{"dynamicAuthProviders": providers, tokenKey: "ciphertext",
				grantKey: `[{"id":"mcp.config.usrlocal.other","allowed":false}]`}),
			status: model.MCPAuthUnknown, evidence: "no_record"},
		{name: "malformed provider list", server: "lab-oauth", decl: labOAuth,
			setup:  db(map[string]string{"dynamicAuthProviders": `{`}),
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "malformed grant", server: "lab-oauth", decl: labOAuth,
			setup:  db(map[string]string{"dynamicAuthProviders": providers, grantKey: `{`}),
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "no database", server: "lab-oauth", decl: labOAuth, status: model.MCPAuthUnknown, evidence: "no_record"},
	}
	runAuthCases(t, "vscode", ".config/Code/User/mcp.json", cases)
}

func TestVSCodeGrantProvider(t *testing.T) {
	providers := []string{"https://auth.example.com", "https://auth.example.com https://a.example.com/mcp"}
	tests := []struct{ rest, want string }{
		{"https://auth.example.com https://a.example.com/mcp-dev@example.com", providers[1]},
		{"https://auth.example.com-dev@example.com", providers[0]},
		{"github-dev", ""},
	}
	for _, tc := range tests {
		if got := vscodeGrantProvider(tc.rest, providers); got != tc.want {
			t.Errorf("vscodeGrantProvider(%q) = %q, want %q", tc.rest, got, tc.want)
		}
	}
}

// The store keys below were computed with mcp-remote 0.16.6's own key
// function: md5 over the URL, the resource and the sorted-key header JSON.
func TestMCPRemoteStoreKey(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"url only", []string{"-y", "mcp-remote@0.16.6", "https://mcp.example.com/mcp"}, "94baabe3c3fadb285b26c035e4e86046"},
		{"resource and credential header", []string{"mcp-remote", "https://mcp.example.com/mcp", "--resource", "https://mcp.example.com", "--header", "Authorization: Bearer lab-token"}, "52c6c95c8f0c83f7f5231e4deb5d00fd"},
		{"unexpanded variable", []string{"mcp-remote", "https://mcp.example.com/mcp", "--header", "X-Tenant:acme", "--header", "Authorization:Bearer ${AUTH_TOKEN}"}, "af96673f601566947ddefbf35f01c9d5"},
		{"first resource wins", []string{"mcp-remote", "https://mcp.example.com/mcp", "--resource", "https://mcp.example.com", "--resource", "https://other.example.com", "--header", "Authorization: Bearer lab-token"}, "52c6c95c8f0c83f7f5231e4deb5d00fd"},
		{"resource disabled", []string{"mcp-remote", "https://mcp.example.com/mcp", "--resource", "https://mcp.example.com", "--disable-resource-parameter", "--header", "X-Tenant: acme"}, "11c4bdd20ef2d233ceb7fdd45d7d2883"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			call, ok := parseMCPRemote(mcpAuthServer{command: "npx", args: tc.args})
			if !ok {
				t.Fatal("not recognized as mcp-remote")
			}
			if got := call.storeKey(); got != tc.want {
				t.Errorf("storeKey() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestMCPRemoteAuth(t *testing.T) {
	key := "94baabe3c3fadb285b26c035e4e86046"
	decl := `{"command":"npx","args":["-y","mcp-remote@latest","https://mcp.example.com/mcp"]}`
	store := ".mcp-auth/mcp-remote-v1/" + key
	cases := []authCase{
		{name: "usable tokens", server: "lab-remote", decl: decl,
			files:  map[string]string{store + "_tokens.json": `{"access_token":"a","expires_at":` + strconv.Itoa(futureMs) + `}`},
			status: model.MCPAuthCredentialSaved, evidence: "mcp_remote_token_file"},
		{name: "expired tokens", server: "lab-remote", decl: decl,
			files:  map[string]string{store + "_tokens.json": `{"access_token":"a","expires_at":` + strconv.Itoa(pastMs) + `}`},
			status: model.MCPAuthNeedsAuth, evidence: "mcp_remote_signin_pending"},
		{name: "client registration only", server: "lab-remote", decl: decl,
			files:  map[string]string{store + "_client_info.json": `{"client_id":"c"}`},
			status: model.MCPAuthNeedsAuth, evidence: "mcp_remote_signin_pending"},
		{name: "config dir from the server env", server: "lab-remote",
			decl:   `{"command":"npx","args":["mcp-remote","https://mcp.example.com/mcp"],"env":{"MCP_REMOTE_CONFIG_DIR":"<home>/auth"}}`,
			files:  map[string]string{"auth/mcp-remote-v1/" + key + "_tokens.json": `{"access_token":"a"}`},
			status: model.MCPAuthCredentialSaved, evidence: "mcp_remote_token_file"},
		{name: "config dir from the user env", server: "lab-remote", decl: decl, env: map[string]string{"MCP_REMOTE_CONFIG_DIR": "~/auth"},
			files:  map[string]string{"auth/mcp-remote-v1/" + key + "_tokens.json": `{"access_token":"a"}`},
			status: model.MCPAuthCredentialSaved, evidence: "mcp_remote_token_file"},
		{name: "relative config dir", server: "lab-remote", decl: decl, env: map[string]string{"MCP_REMOTE_CONFIG_DIR": "auth"},
			status: model.MCPAuthUnknown, evidence: "join_failed"},
		{name: "header file feeds the key", server: "lab-remote",
			decl:   `{"command":"mcp-remote","args":["https://mcp.example.com/mcp","--header-file","h.txt"]}`,
			status: model.MCPAuthUnknown, evidence: "join_failed"},
		{name: "no URL", server: "lab-remote", decl: `{"command":"mcp-remote","args":["--debug"]}`,
			status: model.MCPAuthUnknown, evidence: "join_failed"},
		{name: "a static header comes first", server: "lab-remote",
			decl:   `{"command":"mcp-remote","args":["https://mcp.example.com/mcp","--header","Authorization: Bearer ${T}"]}`,
			status: model.MCPAuthStaticCredential, evidence: "config_header"},
		{name: "malformed tokens", server: "lab-remote", decl: decl,
			files:  map[string]string{store + "_tokens.json": `[`},
			status: model.MCPAuthUnknown, evidence: "store_unavailable"},
		{name: "no store", server: "lab-remote", decl: decl, status: model.MCPAuthUnknown, evidence: "no_record"},
	}
	runAuthCases(t, "claude_code", ".claude.json", cases)
}

func TestPluginMCPServerAuth(t *testing.T) {
	for _, tc := range []struct {
		name, manifestName string
		want               []model.MCPServerAuth
	}{
		{"namespaced by the manifest name", "lab", []model.MCPServerAuth{
			{ServerName: "lab-local", Status: model.MCPAuthNotApplicable, Evidence: "local_stdio"},
			{ServerName: "lab-stdio", Status: model.MCPAuthNeedsAuth, Evidence: "claude_needs_auth_cache"},
		}},
		{"namespaced by the plugin name", "", []model.MCPServerAuth{
			{ServerName: "lab-local", Status: model.MCPAuthNeedsAuth, Evidence: "claude_needs_auth_cache"},
			{ServerName: "lab-stdio", Status: model.MCPAuthNotApplicable, Evidence: "local_stdio"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			m.SetHomeDir(testHome)
			root := filepath.Join(testHome, "plugin")
			file := filepath.Join(root, ".mcp.json")
			fs.addFile(file, `{"mcpServers":{"lab-stdio":{"command":"lab"},"lab-local":{"command":"lab-local"}}}`)
			fs.addFile(filepath.Join(testHome, ".claude", "mcp-needs-auth-cache.json"), `{"plugin:lab:lab-stdio":{},"plugin:lab-plugin:lab-local":{}}`)
			fs.commit()
			r, _ := newAuthResolver(m.Mock)
			d := NewSkillsDetector(m).WithMCPAuth(r)
			s := &pluginScan{d: d, ctx: context.Background(), evidence: newPluginEvidence()}
			p := newPlugin("lab-plugin@company", "lab-plugin", model.PluginInstallMarketplace, model.PluginScopeUser)
			p.ManifestName = tc.manifestName
			scan := pluginRootScan{s: s, gd: d, p: p, root: root, attr: nestedAttr{agent: model.AgentClaudeCode, source: "claude_plugin"}}
			scan.mcpFileComponents(file, ".mcp.json", false)
			var got []model.MCPServerAuth
			for _, c := range p.Components {
				if c.MCPConfig == nil || len(c.MCPConfig.ServerAuth) != 1 {
					t.Fatalf("component %s: server_auth = %+v", c.Name, c.MCPConfig)
				}
				got = append(got, c.MCPConfig.ServerAuth[0])
			}
			if !equalAuth(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// A scan that walks the home finds Pi's and Copilot's project files before it
// adds them by name, so they keep the discovered label; their servers still
// answer from their client's store.
func TestMCPAuthWalkedClientFiles(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		".pi/agent/mcp.json":      `{"mcpServers":{"lab-oauth":{"url":"https://a.example.com/mcp"}}}`,
		".pi/agent/mcp-auth.json": `{"https://a.example.com/mcp":{"tokens":{"access_token":"a"}}}`,
		"proj/.pi/mcp.json":       `{"mcpServers":{"lab-project":{"url":"https://a.example.com/mcp"}}}`,
		"proj/.github/mcp.json":   `{"mcpServers":{"lab-copilot":{"url":"https://b.example.com/mcp"},"lab-copilot-hdr":{"url":"https://b.example.com/mcp","headers":{"Authorization":"Bearer x"}}}}`,
		"proj/.mcp.json":          `{"mcpServers":{"lab-shared":{"url":"https://b.example.com/mcp"}}}`,
		"p2/.github/mcp.json":     `{"mcpServers":{"lab-odd-type":{"type":"weird","url":"https://b.example.com/mcp"}}}`,
		"p3/.github/mcp.json":     `{"servers":{"lab-vs-shape":{"type":"http","url":"https://b.example.com/mcp"}}}`,
		".copilot/mcp-oauth-config/" + strings.Repeat("c", 64) + ".json":     `{"serverUrl":"https://b.example.com/mcp"}`,
		".copilot/mcp-oauth-config/" + strings.Repeat("c", 64) + ".verifier": `v`,
	}
	for rel, body := range files {
		path := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exec := mcpFixtureExecutor{Executor: executor.NewReal(), home: home}
	r := NewMCPAuthResolver(exec, exec, home).WithSkipper(tcc.New(home))
	got := map[string]model.MCPServerAuth{}
	for _, config := range NewMCPDetector(exec).WithSkipper(tcc.New(home)).WithAuth(r).DetectEnterprise(context.Background(), []string{home}) {
		if config.ConfigSource != "discovered_mcp" {
			continue
		}
		for _, a := range config.ServerAuth {
			got[a.ServerName] = a
		}
	}
	for name, want := range map[string][2]string{
		"lab-oauth":   {model.MCPAuthCredentialSaved, "pi_token_file"},
		"lab-project": {model.MCPAuthCredentialSaved, "pi_token_file"},
		"lab-copilot": {model.MCPAuthNeedsAuth, "copilot_signin_pending"},
		// The header in the file decides, not the store for its URL.
		"lab-copilot-hdr": {model.MCPAuthStaticCredential, "config_header"},
		"lab-shared":      {model.MCPAuthUnknown, "client_not_supported"},
		// Copilot does not load these entries, so its store does not answer.
		"lab-odd-type": {model.MCPAuthUnknown, "client_not_supported"},
		"lab-vs-shape": {model.MCPAuthUnknown, "client_not_supported"},
	} {
		a, ok := got[name]
		if !ok {
			t.Fatalf("%s not found as a discovered config: %v", name, got)
		}
		t.Run(name, func(t *testing.T) { checkAuth(t, a, want[0], want[1]) })
	}
}

// On macOS the scan reads no store inside a protected folder, except an
// editor database admitted by its exact path.
func TestMCPAuthResolver_ProtectedFolders(t *testing.T) {
	if runtime.GOOS != model.PlatformDarwin {
		t.Skip("protected folders exist only on macOS")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	user := filepath.Join(home, "Library", "Application Support", "Code", "User")
	provider := "https://auth.example.com https://a.example.com/mcp"
	writeItemTable(t, filepath.Join(user, "globalStorage", "state.vscdb"), map[string]string{
		"dynamicAuthProviders": `[{"providerId":"` + provider + `"}]`,
		`secret://{"isDynamicAuthProvider":true,"authProviderId":"` + provider + `"}`: "ciphertext",
	})
	// A store file beside the admitted database is still refused.
	sibling := filepath.Join(user, "globalStorage", ".credentials.json")
	if err := os.WriteFile(sibling, []byte(`{"k":{"server_name":"lab-oauth","server_url":"https://a.example.com/mcp","access_token":"a"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", filepath.Dir(sibling))

	exec := executor.NewReal()
	r := NewMCPAuthResolver(exec, exec, home).WithSkipper(tcc.New(home))
	checkAuth(t, authOf(r, "vscode", filepath.Join(user, "mcp.json"), "lab-oauth", labOAuth), model.MCPAuthCredentialSaved, "vscode_token_key")
	checkAuth(t, authOf(r, "codex", filepath.Join(home, ".codex", "config.toml"), "lab-oauth", labOAuth), model.MCPAuthUnknown, "store_unavailable")
}

// No credential material from any store reaches the results or stderr.
func TestMCPAuthResolver_NoCredentialMaterial(t *testing.T) {
	const canary = "canary-7f3e9b"
	m, home := newAuthMock(t)
	setAuthFiles(m, home, map[string]string{
		".claude/.credentials.json":                                             `{"mcpOAuth":{"k":{"serverName":"lab-oauth","serverUrl":"https://a.example.com/mcp","accessToken":"` + canary + `"}}}`,
		".codex/.credentials.json":                                              `{"k":{"server_name":"lab-oauth","client_id":"c","server_url":"https://a.example.com/mcp","access_token":"` + canary + `"}}`,
		".copilot/mcp-oauth-config/" + strings.Repeat("c", 64) + ".json":        `{"serverUrl":"https://a.example.com/mcp","clientSecret":"` + canary + `"}`,
		".copilot/mcp-oauth-config/" + strings.Repeat("c", 64) + ".tokens.json": `{"accessToken":"` + canary + `"}`,
		".pi/agent/mcp-auth.json":                                               `{"https://a.example.com/mcp":{"tokens":{"access_token":"` + canary + `"}}}`,
		".local/share/opencode/mcp-auth.json":                                   `{"lab-oauth":{"serverUrl":"https://a.example.com/mcp","tokens":{"accessToken":"` + canary + `","refreshToken":"` + canary + `"}}}`,
		".cursor/projects/p/mcp-auth.json":                                      `{"lab-oauth":{"tokens":{"access_token":"` + canary + `"}}}`,
		".mcp-auth/mcp-remote-v1/94baabe3c3fadb285b26c035e4e86046_tokens.json":  `{"access_token":"` + canary + `"}`,
	})
	writeOpenCodeDB(t, filepath.Join(home, ".local", "share", "opencode", "opencode.db"), "lab-oauth", "https://a.example.com/mcp", map[string]any{"access": canary, "refresh": canary})
	writeItemTable(t, filepath.Join(home, ".config", "Cursor", "User", "globalStorage", "state.vscdb"), map[string]string{
		cursorStoreKey("user-lab-oauth", "mcp_tokens"): canary,
	})
	writeItemTable(t, filepath.Join(home, ".config", "Code", "User", "globalStorage", "state.vscdb"), map[string]string{
		"dynamicAuthProviders": `[{"providerId":"x https://a.example.com/mcp"}]`,
		`secret://{"isDynamicAuthProvider":true,"authProviderId":"x https://a.example.com/mcp"}`: canary,
	})
	r, _ := newAuthResolver(m)

	stderr := os.Stderr
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = pw
	content := `{"mcpServers":{"lab-oauth":{"url":"https://a.example.com/mcp"},` +
		`"lab-header":{"url":"https://a.example.com/mcp","headers":{"Authorization":"Bearer ` + canary + `"}},` +
		`"lab-env":{"command":"lab","env":{"API_KEY":"` + canary + `"}},` +
		`"lab-remote":{"command":"npx","args":["mcp-remote","https://mcp.example.com/mcp"]}}}`
	var results [][]model.MCPServerAuth
	for _, source := range []string{"claude_code", "codex", "copilot", "pi", "opencode", "cursor", "vscode"} {
		configPath := filepath.Join(home, ".config", "Code", "User", "mcp.json")
		results = append(results, r.resolveConfig(context.Background(), source, configPath, []byte(content)))
	}
	os.Stderr = stderr
	_ = pw.Close()
	logged, _ := io.ReadAll(pr)

	out, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "credential_saved") {
		t.Fatalf("no saved sign-in resolved, the stores were not read: %s", out)
	}
	if strings.Contains(string(out)+string(logged), canary) {
		t.Errorf("credential material leaked: %s %s", out, logged)
	}
}

// mcpServerAuthGolden is the shared sign-in status fixture: the enterprise MCP
// config entries and one plugin MCP component.
type mcpServerAuthGolden struct {
	MCPConfigs      []model.MCPConfigEnterprise `json:"mcp_configs"`
	PluginComponent model.PluginComponent       `json:"plugin_component"`
}

// TestMCPServerAuthGoldenProducer resolves every client's stores into the
// shared fixture. Regenerate with UPDATE_MCP_AUTH_GOLDEN=1.
func TestMCPServerAuthGoldenProducer(t *testing.T) {
	m, home := newAuthMock(t)
	const (
		a = "https://a.example.com/mcp"
		b = "https://b.example.com/mcp"
		c = "https://c.example.com/mcp"
		d = "https://d.example.com/mcp"
	)
	provider := func(u string) string { return "https://auth.example.com " + u }
	token := func(u string) string {
		return `secret://{"isDynamicAuthProvider":true,"authProviderId":"` + provider(u) + `","clientId":"c"}`
	}
	keyA, keyB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	usable := strconv.Itoa(futureMs)
	setAuthFiles(m, home, map[string]string{
		".claude.json": `{"mcpServers":{
			"lab-header":{"url":"` + a + `","headers":{"Authorization":"Bearer ${LAB_TOKEN}"}},
			"lab-helper":{"url":"` + a + `","headersHelper":"lab-headers"},
			"lab-env":{"command":"lab","env":{"LAB_API_KEY":"${LAB_API_KEY}"}},
			"lab-local":{"command":"lab"},
			"lab-stdio":{"command":"lab-stdio"},
			"lab-oauth":{"type":"http","url":"` + a + `"},
			"lab-cleared":{"type":"http","url":"` + b + `"},
			"lab-open":{"type":"http","url":"` + c + `"},
			"lab-remote":{"command":"npx","args":["-y","mcp-remote@0.16.6","https://mcp.example.com/mcp"]},
			"lab-remote-pending":{"command":"npx","args":["mcp-remote","https://mcp.example.com/mcp","--header","X-Tenant: acme"]},
			"lab-remote-file":{"command":"npx","args":["mcp-remote","https://mcp.example.com/mcp","--header-file","headers.txt"]}}}`,
		".claude/mcp-needs-auth-cache.json": `{"lab-stdio":{"timestamp":1},"plugin:lab:lab-plugin":{"timestamp":1}}`,
		".claude/.credentials.json": `{"mcpOAuth":{
			"lab-oauth|1":{"serverName":"lab-oauth","serverUrl":"` + a + `","accessToken":"t","expiresAt":` + usable + `},
			"lab-cleared|2":{"serverName":"lab-cleared","serverUrl":"` + b + `","accessToken":""}}}`,
		".mcp-auth/mcp-remote-v1/94baabe3c3fadb285b26c035e4e86046_tokens.json":      `{"access_token":"t"}`,
		".mcp-auth/mcp-remote-v1/11c4bdd20ef2d233ceb7fdd45d7d2883_client_info.json": `{"client_id":"c"}`,

		".codex/config.toml": "[mcp_servers.lab-bearer]\nurl = \"" + a + "\"\nbearer_token_env_var = \"LAB_TOKEN\"\n\n" +
			"[mcp_servers.lab-oauth]\nurl = \"" + a + "\"\n\n[mcp_servers.lab-expired]\nurl = \"" + b + "\"\n\n[mcp_servers.lab-open]\nurl = \"" + c + "\"\n",
		".codex/.credentials.json": `{
			"k1":{"server_name":"lab-oauth","client_id":"c","server_url":"` + a + `","access_token":"t"},
			"k2":{"server_name":"lab-expired","client_id":"c","server_url":"` + b + `","access_token":"t","expires_at":` + strconv.Itoa(pastMs) + `}}`,

		".copilot/mcp-config.json":                        `{"mcpServers":{"lab-oauth":{"type":"http","url":"` + a + `"},"lab-pending":{"type":"http","url":"` + b + `"}}}`,
		".copilot/mcp-oauth-config/" + keyA + ".json":     `{"serverUrl":"` + a + `"}`,
		".copilot/mcp-oauth-config/" + keyB + ".json":     `{"serverUrl":"` + b + `"}`,
		".copilot/mcp-oauth-config/" + keyB + ".verifier": "v",

		".pi/agent/mcp.json":      `{"mcpServers":{"lab-oauth":{"url":"` + a + `"},"lab-pending":{"url":"` + b + `"}}}`,
		".pi/agent/mcp-auth.json": `{"mcp__lab_oauth|` + a + `":{"tokens":{"access_token":"t"}},"` + b + `":{"client_info":{"client_id":"c"}}}`,

		".config/opencode/opencode.json":      `{"mcp":{"lab-oauth":{"type":"remote","url":"` + a + `"},"lab-pending":{"type":"remote","url":"` + b + `"}}}`,
		".local/share/opencode/mcp-auth.json": `{"lab-oauth":{"serverUrl":"` + a + `","tokens":{"accessToken":"t"}}}`,

		".cursor/mcp.json":                  `{"mcpServers":{"lab-oauth":{"url":"` + a + `"},"lab-pending":{"url":"` + b + `"},"lab-cli":{"url":"` + c + `"},"lab-cli-pending":{"url":"` + d + `"}}}`,
		".cursor/projects/p1/mcp-auth.json": `{"lab-cli":{"tokens":{"access_token":"t"}},"lab-cli-pending":{"client_information":{"client_id":"c"}}}`,

		".config/Code/User/mcp.json":     `{"servers":{"lab-oauth":{"type":"http","url":"` + a + `"},"lab-signed-out":{"type":"http","url":"` + b + `"},"lab-no-token":{"type":"http","url":"` + c + `"}}}`,
		".config/VSCodium/User/mcp.json": `{"servers":{"lab-oauth":{"type":"http","url":"` + a + `"}}}`,

		".codeium/windsurf/mcp_config.json": `{"mcpServers":{"lab-oauth":{"serverUrl":"` + a + `"}}}`,

		"plugins/lab/.mcp.json": `{"mcpServers":{"lab-plugin":{"command":"lab-plugin"}}}`,
	})
	writeOpenCodeDB(t, filepath.Join(home, ".local", "share", "opencode", "opencode.db"), "lab-pending", b, map[string]any{"access": ""})
	writeItemTable(t, filepath.Join(home, ".config", "Cursor", "User", "globalStorage", "state.vscdb"), map[string]string{
		cursorStoreKey(cursorURLScope(a), "mcp_tokens"):             "ciphertext",
		cursorStoreKey(cursorURLScope(b), "mcp_client_information"): "ciphertext",
	})
	providers, err := json.Marshal([]map[string]string{{"providerId": provider(a)}, {"providerId": provider(b)}, {"providerId": provider(c)}})
	if err != nil {
		t.Fatal(err)
	}
	writeItemTable(t, filepath.Join(home, ".config", "Code", "User", "globalStorage", "state.vscdb"), map[string]string{
		"dynamicAuthProviders":              string(providers),
		"mcpserver-" + provider(a) + "-dev": `[{"id":"mcp.config.usrlocal.lab-oauth","allowed":true}]`,
		"mcpserver-" + provider(b) + "-dev": `[{"id":"mcp.config.usrlocal.lab-signed-out","allowed":false}]`,
		token(a):                            "ciphertext",
		token(b):                            "ciphertext",
	})
	vscodium := filepath.Join(home, ".config", "VSCodium", "User", "globalStorage", "state.vscdb")
	if err := os.MkdirAll(filepath.Dir(vscodium), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vscodium, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}

	r, _ := newAuthResolver(m)
	var golden mcpServerAuthGolden
	golden.MCPConfigs = NewMCPDetector(m).WithAuth(r).DetectEnterprise(context.Background(), nil)

	pm := &pluginMock{m}
	sd := NewSkillsDetector(pm).WithMCPAuth(r)
	p := newPlugin("lab-plugin@example-org", "lab-plugin", model.PluginInstallMarketplace, model.PluginScopeUser)
	p.ManifestName = "lab"
	root := filepath.Join(home, "plugins", "lab")
	scan := pluginRootScan{s: &pluginScan{d: sd, ctx: context.Background(), evidence: newPluginEvidence()}, gd: sd, p: p, root: root,
		attr: nestedAttr{agent: model.AgentClaudeCode, source: "claude_plugin", vendor: "Anthropic"}}
	scan.mcpFileComponents(filepath.Join(root, ".mcp.json"), ".mcp.json", true)
	if len(p.Components) != 1 {
		t.Fatalf("plugin components = %+v", p.Components)
	}
	golden.PluginComponent = p.Components[0]

	// Paths are reported under a fixed home so the bytes match on every host.
	fixed := func(path string) string {
		if rest, ok := strings.CutPrefix(path, home); ok {
			return "/home/testuser" + filepath.ToSlash(rest)
		}
		return path
	}
	for i := range golden.MCPConfigs {
		golden.MCPConfigs[i].ConfigPath = fixed(golden.MCPConfigs[i].ConfigPath)
	}
	pc := &golden.PluginComponent
	pc.DefinitionPath, pc.ResolvedDefinitionPath, pc.MCPConfig.ConfigPath = fixed(pc.DefinitionPath), fixed(pc.ResolvedDefinitionPath), fixed(pc.MCPConfig.ConfigPath)

	raw, err := json.MarshalIndent(golden, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := "../model/testdata/mcp_server_auth_golden.json"
	if os.Getenv("UPDATE_MCP_AUTH_GOLDEN") == "1" {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatal("producer differs from the shared MCP sign-in golden; the backend copy changes with it")
	}
}
