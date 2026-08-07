package credentials

import (
	"testing"
)

// TestParseGCPADC covers the three shapes this file takes plus the one it does not
// recognise. Classification is by which fields are present: no value is read and no
// type string inspected, so an unknown shape resolves to unclassified.
func TestParseGCPADC(t *testing.T) {
	runParseCases(t, parseGCPADC, []parseCase{
		{name: "interactive login holds material", body: `{"type":"authorized_user","client_id":"id.apps.googleusercontent.com","client_secret":"value","refresh_token":"value"}`, want: obsPlain(1)},
		{name: "service account key holds material", body: `{"type":"service_account","client_email":"svc@example.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nvalue\n-----END PRIVATE KEY-----\n"}`, want: obsPlain(1)},
		{name: "external account points elsewhere", body: `{"type":"external_account","audience":"//iam.googleapis.com/x","credential_source":{"file":"/var/run/secrets/token"}}`, want: obsExt(1)},
		// Impersonation carries the credential it goes through inside itself, so
		// the material can sit one level below the fields that describe it.
		{name: "impersonation folds the nested credential", body: `{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/x","source_credentials":{"type":"authorized_user","client_secret":"value","refresh_token":"value"}}`, want: obsPlain(2)},
		// The inline test wins, so a file that names an external source and also
		// carries a secret of its own is not described by the safer half.
		{name: "material beside an external source is plaintext", body: `{"type":"external_account","credential_source":{"file":"/var/run/secrets/token"},"client_secret":"value"}`, want: obsPlain(1)},
		// This file is written by an interactive login, so its presence means a
		// credential was established even when the shape is unfamiliar.
		{name: "unrecognised shape is unclassified rather than absent", body: `{"type":"some_future_credential_family","account":"octocat"}`, want: obsUnk(1)},
		{name: "null and empty fields are not material", body: `{"type":"authorized_user","client_secret":null,"refresh_token":""}`, want: obsUnk(1)},
		{name: "malformed document", body: `{"type":"authorized_user",`, want: obsUnk(1)},
		{name: "blank file", body: "\n", want: obsNone},
	})
}

func TestParseDockerConfig(t *testing.T) {
	runParseCases(t, parseDockerConfig, []parseCase{
		// The inline field is an encoding, not a protection, so an entry that
		// carries it is material in the clear.
		{name: "inline registry auth is plaintext", body: `{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}}}`, want: obsPlain(1)},
		{name: "identity token is material", body: `{"auths":{"registry.example.com":{"identitytoken":"value"}}}`, want: obsPlain(1)},
		{name: "entry with no inline material is a reference", body: `{"auths":{"registry.example.com":{}},"credsStore":"desktop"}`, want: obsExt(1)},
		{name: "default helper alone is a reference", body: `{"credsStore":"desktop"}`, want: obsExt(1)},
		{name: "per-registry helper is a reference", body: `{"credHelpers":{"123456789012.dkr.ecr.us-east-1.amazonaws.com":"ecr-login"}}`, want: obsExt(1)},
		// A helper for a registry that already has an entry describes the same
		// registry, so counting both would double it.
		{name: "helper for an already-counted registry is not a second entry", body: `{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}},"credHelpers":{"registry.example.com":"ecr-login"}}`, want: obsPlain(1)},
		{name: "registries fold to the worst state", body: `{"auths":{"a.example.com":{},"b.example.com":{"auth":"dXNlcjpwYXNz"}}}`, want: obsPlain(2)},
		{name: "configuration with no credential statement", body: `{"currentContext":"desktop-linux"}`, want: obsNone},
		{name: "malformed document", body: `{"auths":`, want: obsUnk(1)},
		{name: "blank file", body: "\n", want: obsNone},
	})
}

func TestParseTerraformCredentials(t *testing.T) {
	runParseCases(t, parseTerraformCredentials, []parseCase{
		{name: "host token", body: `{"credentials":{"app.terraform.io":{"token":"value"}}}`, want: obsPlain(1)},
		{name: "hosts count separately", body: `{"credentials":{"app.terraform.io":{"token":"value"},"tfe.example.com":{"token":"value"}}}`, want: obsPlain(2)},
		{name: "empty token is not a credential", body: `{"credentials":{"app.terraform.io":{"token":""}}}`, want: obsNone},
		// Unlike the cloud login file, this one also holds unrelated settings, so
		// its presence alone is not evidence that a token was ever stored.
		{name: "valid document with no credentials block", body: `{"unrelated":true}`, want: obsNone},
		{name: "malformed document", body: `{"credentials":`, want: obsUnk(1)},
		{name: "blank file", body: "\n", want: obsNone},
	})
}

func TestJSONFieldSet(t *testing.T) {
	obj, ok := decodeJSONObject([]byte(`{"filled":"value","empty":"","nulled":null,"zero":0,"object":{}}`))
	if !ok {
		t.Fatal("document must decode")
	}
	tests := []struct {
		field string
		want  bool
	}{
		{"filled", true},
		// A tool writes an empty or null field to mean "no value here", so treating
		// either as material would report a credential the developer does not have.
		{"empty", false},
		{"nulled", false},
		{"missing", false},
		{"zero", true},
		{"object", true},
	}
	for _, tt := range tests {
		if got := jsonFieldSet(obj, tt.field); got != tt.want {
			t.Errorf("jsonFieldSet(%q) = %v, want %v", tt.field, got, tt.want)
		}
	}
}

func TestParseGitHubCLIHosts(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		want  observation
		hosts []githubHostConfig
	}{
		{
			name: "inline token",
			body: "github.com:\n    users:\n        octocat:\n            oauth_token: value\n    oauth_token: value\n    user: octocat\n",
			want: obsPlain(1),
			hosts: []githubHostConfig{
				{Host: "github.com", AccountCount: 1, InlineToken: true},
			},
		},
		{
			// The usual arrangement keeps the token in an OS keystore this file
			// cannot show, so no inline token is a reference, not an absence.
			name: "no inline token",
			body: "github.com:\n    users:\n        octocat:\n            git_protocol: ssh\n    user: octocat\n",
			want: obsExt(1),
			hosts: []githubHostConfig{
				{Host: "github.com", AccountCount: 1, InlineToken: false},
			},
		},
		{
			name: "token on an account rather than the host",
			body: "github.com:\n    users:\n        octocat:\n            oauth_token: value\n        hubot:\n            git_protocol: https\n    user: octocat\n",
			want: obsPlain(1),
			hosts: []githubHostConfig{
				{Host: "github.com", AccountCount: 2, InlineToken: true},
			},
		},
		{
			// Hosts come out of a map, so a stable order is what keeps two scans of an
			// unchanged machine from looking like a change.
			name: "hosts fold and sort",
			body: "github.com:\n    user: octocat\n    oauth_token: value\nghe.example.com:\n    user: octocat\n",
			want: obsPlain(2),
			hosts: []githubHostConfig{
				{Host: "ghe.example.com", AccountCount: 1, InlineToken: false},
				{Host: "github.com", AccountCount: 1, InlineToken: true},
			},
		},
		{name: "blank file", body: "\n", want: obsNone},
		{name: "valid document with no hosts", body: "{}\n", want: obsNone},
		{name: "malformed document", body: "github.com:\n  - this is a list where a map belongs\n", want: obsUnk(1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, hosts := parseGitHubCLIHosts([]byte(tt.body))
			if got != tt.want {
				t.Errorf("observation = %+v, want %+v", got, tt.want)
			}
			if len(hosts) != len(tt.hosts) {
				t.Fatalf("hosts = %+v, want %+v", hosts, tt.hosts)
			}
			for i := range hosts {
				if hosts[i] != tt.hosts[i] {
					t.Errorf("host %d = %+v, want %+v", i, hosts[i], tt.hosts[i])
				}
			}
		})
	}
}

func TestParseKubeconfig(t *testing.T) {
	runParseCases(t, parseKubeconfig, []parseCase{
		{name: "embedded token", body: "users:\n  - name: dev\n    user:\n      token: value\n", want: obsPlain(1)},
		{name: "embedded key material", body: "users:\n  - name: dev\n    user:\n      client-key-data: dmFsdWU=\n", want: obsPlain(1)},
		{name: "basic password", body: "users:\n  - name: dev\n    user:\n      username: octocat\n      password: value\n", want: obsPlain(1)},
		{name: "token file is a reference", body: "users:\n  - name: dev\n    user:\n      tokenFile: /var/run/secrets/token\n", want: obsExt(1)},
		{name: "key path is a reference", body: "users:\n  - name: dev\n    user:\n      client-certificate: /home/octocat/.kube/client.crt\n      client-key: /home/octocat/.kube/client.key\n", want: obsExt(1)},
		{name: "credential plugin is a reference", body: "users:\n  - name: dev\n    user:\n      exec:\n        command: aws\n        args: [eks, get-token]\n", want: obsExt(1)},
		{name: "identity provider is a reference", body: "users:\n  - name: dev\n    user:\n      auth-provider:\n        name: oidc\n", want: obsExt(1)},
		// The public half authenticates nothing without its key, so it is not an
		// entry at all.
		{name: "certificate alone is not a credential", body: "users:\n  - name: dev\n    user:\n      client-certificate: /home/octocat/.kube/client.crt\n", want: obsNone},
		{name: "entries fold to the worst state", body: "users:\n  - name: a\n    user:\n      tokenFile: /var/run/secrets/token\n  - name: b\n    user:\n      token: value\n", want: obsPlain(2)},
		{name: "clusters with no user entries", body: "clusters:\n  - name: dev\n    cluster:\n      server: https://cluster.example.com\n", want: obsNone},
		{name: "blank file", body: "\n", want: obsNone},
		{name: "malformed document", body: "users: [ unterminated\n", want: obsUnk(1)},
	})
}

func TestParseMCPConfig(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want observation
	}{
		{name: "inline environment secret", path: "mcp.json", body: `{"mcpServers":{"demo":{"command":"npx","env":{"GITHUB_TOKEN":"value"}}}}`, want: obsPlain(1)},
		{name: "environment reference defers the secret", path: "mcp.json", body: `{"mcpServers":{"demo":{"command":"npx","env":{"GITHUB_TOKEN":"${GH_PAT}"}}}}`, want: obsExt(1)},
		{name: "remote server header", path: "mcp.json", body: `{"mcpServers":{"remote":{"url":"https://mcp.example.com","headers":{"Authorization":"Bearer value"}}}}`, want: obsPlain(1)},
		// A configured tool handed no credential is not a credential location, so
		// counting it would inflate the inventory with entries holding nothing.
		{name: "server with no credential is not an entry", path: "mcp.json", body: `{"mcpServers":{"demo":{"command":"npx","args":["-y","server"],"env":{"LOG_LEVEL":"debug"}}}}`, want: obsNone},
		// A server is one entry however many credentials it was given, and its own
		// fold collapses to the worst of them.
		{name: "several credentials on one server are one entry", path: "mcp.json", body: `{"mcpServers":{"demo":{"env":{"API_KEY":"${FROM_ENV}","GITHUB_TOKEN":"value"}}}}`, want: obsPlain(1)},
		{name: "servers count separately", path: "mcp.json", body: `{"mcpServers":{"a":{"env":{"API_KEY":"value"}},"b":{"env":{"API_KEY":"${FROM_ENV}"}}}}`, want: obsPlain(2)},
		// The tools that write these files spell the server map differently, and
		// all the spellings are checked in every document.
		{name: "alternate map key", path: "mcp.json", body: `{"servers":{"demo":{"env":{"API_KEY":"value"}}}}`, want: obsPlain(1)},
		{name: "editor settings spelling", path: "settings.json", body: `{"context_servers":{"demo":{"env":{"API_KEY":"value"}}}}`, want: obsPlain(1)},
		// These files are documented as accepting comments and trailing commas, so a
		// strict decoder would report a fully configured machine as having none.
		{name: "comments and trailing commas", path: "mcp.json", body: "{\n  // the server we use\n  \"mcpServers\": {\n    \"demo\": {\"env\": {\"API_KEY\": \"value\"},},\n  },\n}", want: obsPlain(1)},
		{name: "toml serialisation", path: "config.toml", body: "[mcp_servers.demo]\ncommand = \"run\"\n\n[mcp_servers.demo.env]\nAPI_KEY = \"value\"\n", want: obsPlain(1)},
		{name: "yaml serialisation", path: "config.yaml", body: "mcpServers:\n  demo:\n    env:\n      API_KEY: value\n", want: obsPlain(1)},
		// One tool keeps per-directory definitions inside the user-level file.
		// Reading them reads the file already opened; no directory is visited.
		{name: "per-directory definitions inside the same file", path: "config.json", body: `{"projects":{"/home/octocat/work":{"mcpServers":{"demo":{"env":{"API_KEY":"value"}}}}}}`, want: obsPlain(1)},
		{name: "user-level and per-directory definitions both count", path: "config.json", body: `{"mcpServers":{"a":{"env":{"API_KEY":"${FROM_ENV}"}}},"projects":{"/w":{"mcpServers":{"b":{"env":{"API_KEY":"value"}}}}}}`, want: obsPlain(2)},
		{name: "valid document with no servers", path: "settings.json", body: `{"theme":"dark"}`, want: obsNone},
		{name: "blank file", path: "mcp.json", body: "\n", want: obsNone},
		{name: "malformed document", path: "mcp.json", body: `{"mcpServers":`, want: obsUnk(1)},
		// A file whose serialisation this build cannot read is reported as
		// unclassified rather than as holding nothing.
		{name: "extension with no decoder", path: "config.hcl", body: `mcp_servers { demo { env = { API_KEY = "value" } } }`, want: obsUnk(1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseMCPConfig(tt.path, []byte(tt.body)); got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestIsCredentialSettingName matches on the slot a setting occupies, never on what
// the value looks like: that would mean classifying a secret by its contents.
func TestIsCredentialSettingName(t *testing.T) {
	tests := map[string]bool{
		"GITHUB_TOKEN":      true,
		"github_token":      true,
		"API_KEY":           true,
		"APIKEY":            true,
		"api-key":           true,
		"X-Api-Key":         true,
		"Authorization":     true,
		"AWS_SECRET_KEY":    true,
		"DB_PASSWORD":       true,
		"PASSWD":            true,
		"AWS_ACCESS_KEY_ID": true,
		"PRIVATE_KEY_PATH":  true,
		"CREDENTIALS_FILE":  true,
		"LOG_LEVEL":         false,
		"HOME":              false,
		"Content-Type":      false,
		"NODE_ENV":          false,
		"":                  false,
	}
	for name, want := range tests {
		if got := isCredentialSettingName(name); got != want {
			t.Errorf("isCredentialSettingName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestClassifyMCPServer_NonStringSettingsAreSkipped(t *testing.T) {
	server := map[string]any{
		"env": map[string]any{
			"API_KEY":     nil,
			"OTHER_TOKEN": 42,
			"EMPTY_TOKEN": "",
		},
	}
	if state, found := classifyMCPServer(server); found {
		t.Errorf("classified %q, want no credential found", state)
	}
}

func TestDecodeConfigDocument_FormatByExtension(t *testing.T) {
	if _, ok := decodeConfigDocument("x.jsonc", []byte("{\n// comment\n\"a\":1}")); !ok {
		t.Error("the tolerant reader must accept comments")
	}
	if _, ok := decodeConfigDocument("x.yml", []byte("a: 1\n")); !ok {
		t.Error(".yml must decode")
	}
	if _, ok := decodeConfigDocument("x.toml", []byte("a = 1\n")); !ok {
		t.Error(".toml must decode")
	}
	if _, ok := decodeConfigDocument("x.ini", []byte("a = 1\n")); ok {
		t.Error("an extension with no decoder must not report success")
	}
}
