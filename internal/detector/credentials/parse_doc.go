package credentials

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"
)

// gcpInlineSecretFields hold usable material in the file itself. The client secret
// belongs here despite its name: the loader accepts it on the external-account
// paths too, so a file naming an external source and carrying one holds material.
var gcpInlineSecretFields = []string{"private_key", "refresh_token", "client_secret"}

// gcpExternalFields name a credential the loader fetches from elsewhere — a file,
// a URL, an executable, or another credential it impersonates through.
var gcpExternalFields = []string{"credential_source", "source_credentials", "service_account_impersonation_url"}

// parseGCPADC classifies the application default credentials by which fields are
// present. Presence is the whole test: no value is read and the type string is
// never inspected. The inline test runs first and wins, because a file can name an
// external source and still carry a secret of its own.
func parseGCPADC(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		top, ok := decodeJSONObject(data)
		if !ok {
			return false
		}
		f.add(classifyGCPFields(top))

		// One nested level, no deeper: an impersonation configuration carries
		// the credential it impersonates through inside itself. Recursing
		// further would chase a structure the loader does not define.
		if nested, ok := decodeNestedObject(top, "source_credentials"); ok {
			f.add(classifyGCPFields(nested))
		}
		return true
	})
}

// classifyGCPFields resolves one object. An unrecognised shape is unknown rather
// than absent: this file is written by an interactive login, so its presence means
// a credential was established whatever shape it took.
func classifyGCPFields(obj map[string]json.RawMessage) string {
	if jsonFieldSet(obj, gcpInlineSecretFields...) {
		return model.CredentialProtectionPlaintext
	}
	if jsonFieldSet(obj, gcpExternalFields...) {
		return model.CredentialProtectionExternal
	}
	return model.CredentialProtectionUnknown
}

// dockerConfig is the subset of the container client's configuration that says
// where registry credentials live. Registry names are read to count and
// deduplicate entries and are not reported.
type dockerConfig struct {
	Auths map[string]struct {
		Auth          string `json:"auth"`
		IdentityToken string `json:"identitytoken"`
	} `json:"auths"`
	CredsStore  string            `json:"credsStore"`
	CredHelpers map[string]string `json:"credHelpers"`
}

// parseDockerConfig counts the registry entries in the container client
// configuration and folds how each is held. The inline field is base64 rather than
// encrypted — an encoding, not a protection — so an entry carrying it is plaintext,
// and its contents are never decoded.
func parseDockerConfig(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var cfg dockerConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return false
		}
		for _, entry := range cfg.Auths {
			if entry.Auth != "" || entry.IdentityToken != "" {
				f.add(model.CredentialProtectionPlaintext)
				continue
			}
			// An entry with no inline material is the client recording that this
			// registry is logged in, with the secret held by a helper.
			f.add(model.CredentialProtectionExternal)
		}
		for registry := range cfg.CredHelpers {
			// A per-registry helper beside an entry already counted describes the same
			// registry, so counting both would double it.
			if _, counted := cfg.Auths[registry]; counted {
				continue
			}
			f.add(model.CredentialProtectionExternal)
		}
		// A configuration whose only credential statement is a default helper names no
		// registry, but it does assert that credentials for this client are held
		// outside the file.
		if f.empty() && cfg.CredsStore != "" {
			f.add(model.CredentialProtectionExternal)
		}
		return true
	})
}

// terraformCredentials is the credentials file's shape. Host keys are counted and
// never reported: a private infrastructure hostname is an internal detail of the
// customer's estate, not part of a credential inventory.
type terraformCredentials struct {
	Credentials map[string]struct {
		Token string `json:"token"`
	} `json:"credentials"`
}

// parseTerraformCredentials counts the host entries that carry a token. Unlike the
// cloud login file, a valid document with no credentials block yields no finding
// rather than an unknown: unrelated settings live here too, so the file's presence
// alone is not evidence a token was ever stored.
func parseTerraformCredentials(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var doc terraformCredentials
		if err := json.Unmarshal(data, &doc); err != nil {
			return false
		}
		for _, entry := range doc.Credentials {
			if entry.Token == "" {
				continue
			}
			f.add(model.CredentialProtectionPlaintext)
		}
		return true
	})
}

// decodeJSONObject parses a document as an object.
func decodeJSONObject(data []byte) (map[string]json.RawMessage, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, false
	}
	return obj, true
}

// decodeNestedObject reads one field as an object.
func decodeNestedObject(obj map[string]json.RawMessage, field string) (map[string]json.RawMessage, bool) {
	raw, ok := obj[field]
	if !ok {
		return nil, false
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err != nil {
		return nil, false
	}
	return nested, true
}

// jsonFieldSet reports whether any of the named fields is present with a value. A
// null or empty string is not set: tools write those to mean "no value here", and
// treating them as material would report a credential the developer does not have.
func jsonFieldSet(obj map[string]json.RawMessage, fields ...string) bool {
	for _, field := range fields {
		raw, ok := obj[field]
		if !ok {
			continue
		}
		value := bytes.TrimSpace(raw)
		if len(value) == 0 || bytes.Equal(value, []byte("null")) || bytes.Equal(value, []byte(`""`)) {
			continue
		}
		return true
	}
	return false
}

// ghHostEntry is the per-host shape of the GitHub CLI's configuration. Only the
// presence of an inline token and the number of configured accounts are read;
// account logins are counted and discarded.
type ghHostEntry struct {
	OAuthToken string `yaml:"oauth_token"`
	User       string `yaml:"user"`
	Users      map[string]struct {
		OAuthToken string `yaml:"oauth_token"`
	} `yaml:"users"`
}

// githubHostConfig is what the configuration file establishes about one host on
// its own, before the CLI is asked anything.
type githubHostConfig struct {
	// The one place this inventory names a service: the customer question
	// behind this source is which forge the machine is authenticated to.
	Host         string
	AccountCount int
	// A token sits in the file itself. Its absence is not evidence of a missing
	// credential — the usual arrangement keeps the token in an OS keystore,
	// which this file cannot show.
	InlineToken bool
}

// parseGitHubCLIHosts reads the configured hosts out of the CLI's configuration,
// returning them alongside the observation so the caller can attach the CLI's own
// report to the same finding. On-disk evidence cannot tell a live keystore
// credential from a stale entry, which is why that report is a separate step.
func parseGitHubCLIHosts(data []byte) (observation, []githubHostConfig) {
	var configs []githubHostConfig
	obs := observed(data, func(data []byte, f *fold) bool {
		var hosts map[string]ghHostEntry
		if err := yaml.Unmarshal(data, &hosts); err != nil {
			return false
		}
		configs = make([]githubHostConfig, 0, len(hosts))
		for host, entry := range hosts {
			cfg := githubHostConfig{Host: host, AccountCount: len(entry.Users)}
			if cfg.AccountCount == 0 && entry.User != "" {
				cfg.AccountCount = 1
			}
			cfg.InlineToken = entry.OAuthToken != ""
			if !cfg.InlineToken {
				for _, account := range entry.Users {
					if account.OAuthToken != "" {
						cfg.InlineToken = true
						break
					}
				}
			}
			if cfg.InlineToken {
				f.add(model.CredentialProtectionPlaintext)
			} else {
				f.add(model.CredentialProtectionExternal)
			}
			configs = append(configs, cfg)
		}
		// Sorted before they leave: out of a map, the payload would differ
		// between two scans of an unchanged machine and every run would look
		// like a change.
		slices.SortFunc(configs, func(a, b githubHostConfig) int {
			return strings.Compare(a.Host, b.Host)
		})
		return true
	})
	if obs.Count == 0 {
		// No host is configured, so there is nothing for the CLI to be asked about.
		return obs, nil
	}
	return obs, configs
}

// kubeconfigDoc is the subset of a cluster configuration that says how each user
// entry authenticates. Entry names, cluster names and server URLs are not read.
type kubeconfigDoc struct {
	Users []struct {
		User struct {
			Token     string `yaml:"token"`
			TokenFile string `yaml:"tokenFile"`
			// The password is the credential in a basic-auth entry; the account
			// name it belongs to is not read, so there is no field for it here.
			Password          string         `yaml:"password"`
			ClientKeyData     string         `yaml:"client-key-data"`
			ClientKey         string         `yaml:"client-key"`
			Exec              map[string]any `yaml:"exec"`
			AuthProvider      map[string]any `yaml:"auth-provider"`
			ClientCertificate string         `yaml:"client-certificate"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// parseKubeconfig counts the user entries that authenticate with something and
// folds how each holds it. The distinction is embedded versus referenced: a key or
// token written into the document is material in the file, while a path, a plugin
// or an identity provider block points at material fetched at run time. A client
// certificate alone is not counted — the public half authenticates nothing.
func parseKubeconfig(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var doc kubeconfigDoc
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return false
		}
		for _, entry := range doc.Users {
			u := entry.User
			switch {
			case u.Token != "", u.Password != "", u.ClientKeyData != "":
				f.add(model.CredentialProtectionPlaintext)
			case u.TokenFile != "", u.ClientKey != "", len(u.Exec) > 0, len(u.AuthProvider) > 0:
				f.add(model.CredentialProtectionExternal)
			}
		}
		return true
	})
}

// mcpServerMapKeys are the field names the various tools use for their server map.
// All three spellings coexist across the files this source reads, so every one is
// checked in every document rather than keyed to a particular tool.
var mcpServerMapKeys = []string{"mcpServers", "servers", "context_servers", "mcp_servers"}

// credentialKeyHints match the setting names that carry credentials into a server
// process. The match is on the name, never the value: what makes a setting a
// credential is the slot it occupies, not the characters of the secret in it.
var credentialKeyHints = []string{
	"TOKEN",
	"SECRET",
	"PASSWORD",
	"PASSWD",
	"API_KEY",
	"APIKEY",
	"ACCESS_KEY",
	"PRIVATE_KEY",
	"CREDENTIAL",
	"AUTH",
}

// mcpSecretHolders are the two places a server definition puts credentials: the
// environment handed to a local process, and the headers sent to a remote one.
var mcpSecretHolders = []string{"env", "headers"}

// parseMCPConfig counts the configured servers that carry a credential and folds
// whether each is written into the file or referenced from the environment. The
// path is needed because these files share one purpose across three serialisations
// distinguished by extension. Everything below the server map is read structurally:
// no command, argument, URL or value is retained, and the only thing asked of a
// value is whether it is a reference.
func parseMCPConfig(path string, data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		doc, ok := decodeConfigDocument(path, data)
		if !ok {
			return false
		}
		foldMCPServers(doc, f)

		// One tool keeps per-directory server definitions inside the same
		// user-level file. Reading them is reading the file already opened —
		// the directories themselves are never visited.
		if projects, ok := doc["projects"].(map[string]any); ok {
			for _, project := range projects {
				if fields, ok := project.(map[string]any); ok {
					foldMCPServers(fields, f)
				}
			}
		}
		return true
	})
}

// foldMCPServers folds every server map found directly under a document node.
func foldMCPServers(node map[string]any, f *fold) {
	for _, key := range mcpServerMapKeys {
		servers, ok := node[key].(map[string]any)
		if !ok {
			continue
		}
		for _, server := range servers {
			fields, ok := server.(map[string]any)
			if !ok {
				continue
			}
			if state, found := classifyMCPServer(fields); found {
				f.add(state)
			}
		}
	}
}

// classifyMCPServer resolves one server definition. A server carrying no credential
// returns false and is not counted: it is a configured tool, not a credential
// location, and counting it would inflate the inventory with empty entries.
func classifyMCPServer(server map[string]any) (string, bool) {
	var inner fold
	for _, holder := range mcpSecretHolders {
		settings, ok := server[holder].(map[string]any)
		if !ok {
			continue
		}
		for name, value := range settings {
			text, ok := value.(string)
			if !ok || text == "" || !isCredentialSettingName(name) {
				continue
			}
			if isEnvRef(text) {
				inner.add(model.CredentialProtectionExternal)
				continue
			}
			inner.add(model.CredentialProtectionPlaintext)
		}
	}
	if inner.empty() {
		return "", false
	}
	// A server is one entry however many credentials it was given, so its own
	// fold collapses to the worst of them.
	return inner.result().Protection, true
}

// isCredentialSettingName reports whether a setting name occupies a credential
// slot. Names are normalised so that the environment-variable and header
// spellings of the same thing match one list.
func isCredentialSettingName(name string) bool {
	normalized := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	return slices.ContainsFunc(credentialKeyHints, func(hint string) bool {
		return strings.Contains(normalized, hint)
	})
}

// decodeConfigDocument decodes a configuration file into a generic document,
// choosing the format from the extension. A file that fails to decode is reported
// as such rather than as holding nothing. The JSON path uses the tolerant reader
// because several of these files are documented as accepting comments and trailing
// commas, and a strict decoder would reject a fully configured machine over one.
func decodeConfigDocument(path string, data []byte) (map[string]any, bool) {
	doc := map[string]any{}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".jsonc":
		standard, err := hujson.Standardize(data)
		if err != nil {
			return nil, false
		}
		if err := json.Unmarshal(standard, &doc); err != nil {
			return nil, false
		}
	case ".toml":
		if err := toml.Unmarshal(data, &doc); err != nil {
			return nil, false
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, false
		}
	default:
		return nil, false
	}
	return doc, true
}
