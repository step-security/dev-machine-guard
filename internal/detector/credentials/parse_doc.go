package credentials

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"
)

// gcpInlineSecretFields hold usable material in the file itself. The client secret
// belongs here despite its name: the loader accepts it on the external-account
// paths too, so a file naming an external source and carrying one holds material.
//
// Every field naming a credential the loader fetches at run time — an external
// source, an impersonation URL — is deliberately absent: none of them puts
// material in this file.
var gcpInlineSecretFields = []string{"private_key", "refresh_token", "client_secret"}

// parseGCPADC reports whether the application default credentials carry material.
// One file is one credential however many of its fields are filled in, so the
// nested credential adds to the count of nothing.
func parseGCPADC(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		top, ok := decodeJSONObject(data)
		if !ok {
			return false
		}
		material, malformed := gcpInlineMaterial(top)
		// The one field holding a whole credential of its own: an impersonation
		// configuration carries the credential it goes through inside itself. One
		// nested level, no deeper — recursing further would chase a structure the
		// loader does not define. It is read whether or not the outer object held
		// material of its own, because a nested shape this build cannot account
		// for is uncertainty the outer credential does not resolve: the file could
		// be carrying a second one nothing here can see.
		if raw, present := top["source_credentials"]; present && string(raw) != "null" {
			nested, ok := decodeJSONObject(raw)
			if !ok {
				malformed = true
			} else {
				nestedMaterial, nestedMalformed := gcpInlineMaterial(nested)
				material = material || nestedMaterial
				malformed = malformed || nestedMalformed
			}
		}
		f.unrecognized = malformed
		if material {
			f.add(model.CredentialProtectionPlaintext)
		}
		return true
	})
}

// gcpInlineMaterial reports whether one object fills a material field with a
// concrete value, and whether one of those fields held something that is not a
// string at all. The loader reads every one of them as a string, so another type
// there is a document this build cannot account for — while an unrecognised key
// elsewhere in the file is just a field this build does not need.
func gcpInlineMaterial(obj map[string]json.RawMessage) (material, malformed bool) {
	for _, field := range gcpInlineSecretFields {
		raw, ok := obj[field]
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			malformed = true
			continue
		}
		// A null decodes to the empty string, which is what a tool writes to mean
		// "no value here" — not material, and not a failure either.
		if concrete(value) {
			material = true
		}
	}
	return material, malformed
}

// decodeJSONObject parses a document as an object. A root that is not a mapping
// — a null, a list, a bare scalar — is rejected rather than read as an object
// with no fields in it, which would let a document this build cannot account for
// describe the file as holding nothing.
func decodeJSONObject(data []byte) (map[string]json.RawMessage, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

// decodeJSONDocument reads a document whose root must be an object into v, for
// the formats that decode straight into a shape of their own.
func decodeJSONDocument(data []byte, v any) bool {
	if _, ok := decodeJSONObject(data); !ok {
		return false
	}
	return json.Unmarshal(data, v) == nil
}

// decodeYAMLDocument is the same guard for the formats written in YAML.
func decodeYAMLDocument(data []byte, v any) bool {
	var root map[string]yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil || root == nil {
		return false
	}
	return yaml.Unmarshal(data, v) == nil
}

// dockerConfig is the subset of the container client's configuration that can
// hold a credential. The helper settings beside these are not decoded at all:
// they name a store this file does not contain. Registry names are read to
// iterate the entries and are not reported.
type dockerConfig struct {
	Auths map[string]struct {
		Auth          string `json:"auth"`
		IdentityToken string `json:"identitytoken"`
	} `json:"auths"`
}

// parseDockerConfig counts the registry entries holding material. The inline
// field is base64 rather than encrypted — an encoding, not a protection — so an
// entry carrying it is plaintext, and its contents are never decoded.
func parseDockerConfig(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var cfg dockerConfig
		if !decodeJSONDocument(data, &cfg) {
			return false
		}
		for _, entry := range cfg.Auths {
			// One registry is one credential, whichever of the two fields holds it.
			if concrete(entry.Auth) || concrete(entry.IdentityToken) {
				f.add(model.CredentialProtectionPlaintext)
			}
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

// parseTerraformCredentials counts the host entries that carry a token. A valid
// document with no credentials block yields nothing: unrelated settings live here
// too, so the file's presence alone is not evidence a token was ever stored.
func parseTerraformCredentials(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var doc terraformCredentials
		if !decodeJSONDocument(data, &doc) {
			return false
		}
		for _, entry := range doc.Credentials {
			if concrete(entry.Token) {
				f.add(model.CredentialProtectionPlaintext)
			}
		}
		return true
	})
}

// ghHostEntry is the part of the GitHub CLI's configuration that can hold a
// token: the host itself in the older layout, and each account in the current
// one. Host and account names are read to iterate and are never reported.
type ghHostEntry struct {
	OAuthToken string `yaml:"oauth_token"`
	Users      map[string]struct {
		OAuthToken string `yaml:"oauth_token"`
	} `yaml:"users"`
}

// parseGitHubCLIHosts counts the hosts whose token is written into the file. The
// usual arrangement keeps it in an OS keystore instead, which this file cannot
// show and which is not material in any file this agent reads — so a configured
// host with no inline token is not a finding, and nothing here asks the CLI.
func parseGitHubCLIHosts(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var hosts map[string]ghHostEntry
		if !decodeYAMLDocument(data, &hosts) {
			return false
		}
		for _, entry := range hosts {
			// One host is one credential however many of its accounts carry a
			// token, since the tool authenticates to the host.
			if concrete(entry.OAuthToken) {
				f.add(model.CredentialProtectionPlaintext)
				continue
			}
			for _, account := range entry.Users {
				if concrete(account.OAuthToken) {
					f.add(model.CredentialProtectionPlaintext)
					break
				}
			}
		}
		return true
	})
}

// kubeconfigDoc is the subset of a cluster configuration that can hold material.
// The referencing fields beside these — a token path, a key path, a credential
// plugin, an identity provider, a client certificate — are not decoded: each
// names something fetched at run time, and none is a credential in this file.
// Entry names, cluster names and server URLs are not read.
type kubeconfigDoc struct {
	Users []struct {
		User struct {
			Token string `yaml:"token"`
			// The password is the credential in a basic-auth entry; the account
			// name it belongs to is not read, so there is no field for it here.
			Password      string `yaml:"password"`
			ClientKeyData string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// parseKubeconfig counts the user entries that carry material in the document
// itself. Embedded key data is decoded and structurally validated rather than
// counted on sight: this field is declared to hold a private key, so anything
// else in it is a document this build cannot account for.
func parseKubeconfig(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var doc kubeconfigDoc
		if !decodeYAMLDocument(data, &doc) {
			return false
		}
		for _, entry := range doc.Users {
			u := entry.User
			protection := ""
			if concrete(u.Token) || concrete(u.Password) {
				protection = model.CredentialProtectionPlaintext
			}
			if u.ClientKeyData != "" {
				// Read whatever else the entry carries: a token beside key data
				// that will not parse answers nothing about the key, and letting
				// it stand in would report the entry as fully understood.
				keyProtection, material, malformed := classifyEmbeddedKey(u.ClientKeyData)
				f.unrecognized = f.unrecognized || malformed
				if material && protectionRank[keyProtection] > protectionRank[protection] {
					protection = keyProtection
				}
			}
			// One user entry is one credential whichever of its fields holds it.
			if protection != "" {
				f.add(protection)
			}
		}
		return true
	})
}

// classifyEmbeddedKey reads the base64 a document embeds a private key in. The
// field is declared to hold one, so anything else in it — bytes that are not
// base64, a published half, a key that does not parse — is a document this build
// cannot account for rather than an entry holding nothing.
func classifyEmbeddedKey(field string) (protection string, material, malformed bool) {
	decoded, err := base64.StdEncoding.DecodeString(field)
	if err != nil {
		return "", false, true
	}
	protection, material, malformed = classifySSHKey(decoded)
	return protection, material, malformed || !material
}

// The API client keeps each model in a line-oriented JSON database: one object
// per line, appended on every save. Superseded revisions and deleted records
// stay in the file until it is compacted, so every line is read and a tombstone
// erases nothing.
const (
	// The most credentials one finding reports. Past it the count is a lower
	// bound and the finding says so.
	insomniaMaxCount = 10000
	// Bounds what retained request history may expand to across one file. The
	// history is gzip over JSON, so a file within the read cap can inflate to far
	// more than the cap admitted.
	insomniaMaxExpanded = 8 << 20
	// The key under which an environment mirrors its secret-typed variables.
	insomniaVaultKey = "__insomnia_vault"
)

// insomniaAuthFields names, per authentication type, the fields that hold the
// credential itself. A username, key identifier, token URL or grant type is not
// material; a type with no material field maps to nothing so it is still known.
var insomniaAuthFields = map[string][]string{
	"basic":       {"password"},
	"digest":      {"password"},
	"ntlm":        {"password"},
	"bearer":      {"token"},
	"singleToken": {"token"},
	"apikey":      {"value"},
	"oauth2":      {"clientSecret", "password", "accessToken", "refreshToken"},
	"oauth1":      {"consumerSecret", "tokenSecret", "privateKey"},
	"iam":         {"secretAccessKey", "sessionToken"},
	"hawk":        {"key"},
	"asap":        {"privateKey"},
	"netrc":       nil,
	"none":        nil,
}

// insomniaHeaderNames are the header names whose value is a credential by the
// protocol's own definition, lower-cased for the comparison. Header names are
// read only to match against this set and are never reported.
var insomniaHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"api-key":             true,
}

// insomniaEnvKeys are the environment variable names, lower-cased with hyphens
// folded to underscores, whose value the parser reads as a credential. Fixed
// names rather than a substring match so that a variable named for a token URL or
// a key identifier is not counted as material.
var insomniaEnvKeys = map[string]bool{
	"password":          true,
	"passwd":            true,
	"token":             true,
	"api_token":         true,
	"api_key":           true,
	"apikey":            true,
	"access_token":      true,
	"refresh_token":     true,
	"client_secret":     true,
	"secret_access_key": true,
	"session_token":     true,
	"private_key":       true,
}

// insomniaTemplate matches one template tag. A tag is resolved when the request
// runs, so a field holding nothing else refers to material kept elsewhere.
var insomniaTemplate = regexp.MustCompile(`(?s)\{\{.*?\}\}|\{%.*?%\}`)

// insomniaUnit is what one record contributes: how many credentials it holds and
// the worst state any of them is in.
type insomniaUnit struct {
	count int
	state string
}

// add records one credential at the given state.
func (u *insomniaUnit) add(state string) {
	u.count++
	if protectionRank[state] > protectionRank[u.state] {
		u.state = state
	}
}

// plus sums two parts of one record.
func (u insomniaUnit) plus(o insomniaUnit) insomniaUnit {
	if protectionRank[o.state] > protectionRank[u.state] {
		u.state = o.state
	}
	u.count += o.count
	return u
}

// parseInsomnia counts the credentials held across every revision in one
// database file. The revisions of one record fold to the largest count any of
// them held, not the sum: a save appends a revision, not a credential. Records
// dispatch on their type field, so one parser serves every file.
func parseInsomnia(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		budget := insomniaMaxExpanded
		records := map[string]insomniaUnit{}
		var order []string
		scanLines(data, func(line string) bool {
			line = strings.TrimSpace(line)
			if line == "" {
				return true
			}
			doc, ok := decodeJSONObject([]byte(line))
			if !ok {
				f.unrecognized = true
				return true
			}
			// The store's own bookkeeping lines describe indexes, not records.
			if _, meta := doc["$$indexCreated"]; meta {
				return true
			}
			if _, meta := doc["$$indexRemoved"]; meta {
				return true
			}
			id, bad := insomniaField(doc, "_id")
			if bad || id == "" {
				f.unrecognized = true
				return true
			}
			// A tombstone says the application stopped showing the record. The
			// revisions before it are still in the file and are counted as such.
			if string(doc["$$deleted"]) == "true" {
				return true
			}
			unit, malformed, capped := insomniaRecord(doc, &budget)
			f.unrecognized = f.unrecognized || malformed
			f.capped = f.capped || capped
			prev, seen := records[id]
			if !seen {
				order = append(order, id)
			}
			if unit.count > prev.count {
				prev.count = unit.count
			}
			if protectionRank[unit.state] > protectionRank[prev.state] {
				prev.state = unit.state
			}
			records[id] = prev
			return true
		})
		for _, id := range order {
			u := records[id]
			// Count is bounded, but protection includes every record already read.
			if protectionRank[u.state] > protectionRank[f.state] {
				f.state = u.state
			}
			for range u.count {
				if f.count >= insomniaMaxCount {
					f.capped = true
					break
				}
				f.add(u.state)
			}
		}
		return true
	})
}

// insomniaRecord reads one record by its type. A type this build does not know
// is a record it cannot account for, not one holding nothing.
func insomniaRecord(doc map[string]json.RawMessage, budget *int) (u insomniaUnit, malformed, capped bool) {
	kind, bad := insomniaField(doc, "type")
	if bad {
		return u, true, false
	}
	if u, malformed, known := insomniaRequestRecord(kind, doc); known {
		return u, malformed, false
	}
	switch kind {
	case "GitCredentials", "GitRepository", "CloudCredential":
		keys := []string{"token", "refreshToken", "password"}
		var material, bad bool
		if kind == "GitCredentials" {
			material, bad = insomniaStoredMaterial(doc, "token", "refreshToken")
		}
		if raw := doc["credentials"]; len(raw) != 0 && string(raw) != "null" {
			credentials, ok := decodeJSONObject(raw)
			if !ok {
				bad = true
			} else {
				if kind == "CloudCredential" && len(credentials) > 0 {
					provider, _ := insomniaField(doc, "provider")
					switch provider {
					case "aws":
						keys = []string{"secretAccessKey", "sessionToken"}
					case "azure":
						keys = []string{"accessToken"}
					case "hashicorp":
						keys = []string{"client_secret", "secret_id", "access_token"}
					case "gcp":
						keys = nil // The model stores only a key-file reference.
					default:
						return u, true, false
					}
				}
				nested, badNested := insomniaStoredMaterial(credentials, keys...)
				material, bad = material || nested, bad || badNested
			}
		}
		// Legacy and current representations describe one credential set.
		if material {
			u.add(model.CredentialProtectionPlaintext)
		}
		return u, bad, false
	case "RequestGroup":
		// A folder carries the same authentication and headers a request does,
		// and an environment of its own.
		u, malformed = insomniaAuth(doc)
		h, bad := insomniaHeaders(doc["headers"])
		e, badEnv := insomniaEnv(doc["environment"], doc["kvPairData"])
		return u.plus(h).plus(e), malformed || bad || badEnv, false
	case "Environment":
		u, malformed = insomniaEnv(doc["data"], doc["kvPairData"])
		return u, malformed, false
	case "OAuth2Token":
		// One token record is one credential whichever of its tokens is filled.
		material, malformed := insomniaStoredMaterial(doc, "accessToken", "refreshToken", "identityToken")
		if material {
			u.add(model.CredentialProtectionPlaintext)
		}
		return u, malformed, false
	case "ClientCertificate":
		// The certificate and key fields are paths to files this source does not
		// read; the passphrase is the material stored here.
		material, malformed := insomniaStoredMaterial(doc, "passphrase")
		if material {
			u.add(model.CredentialProtectionPlaintext)
		}
		return u, malformed, false
	case "RequestVersion":
		return insomniaVersion(doc, budget)
	case "UserSession":
		u, malformed = insomniaSession(doc)
		return u, malformed, false
	}
	return u, true, false
}

func insomniaSession(doc map[string]json.RawMessage) (u insomniaUnit, malformed bool) {
	material, malformed := insomniaStoredMaterial(doc, "id")
	if material {
		u.add(model.CredentialProtectionPlaintext)
	}
	material, bad := insomniaSymmetricKey(doc["symmetricKey"])
	malformed = malformed || bad
	if material {
		u.add(model.CredentialProtectionPlaintext)
	}
	if raw := doc["encPrivateKey"]; len(raw) != 0 && string(raw) != "null" {
		key, ok := decodeJSONObject(raw)
		switch {
		case !ok:
			malformed = true
		case len(key) == 0:
			// An uninitialized session has an empty key object.
		case insomniaHex(key, "iv", 24, 24) && insomniaHex(key, "t", 32, 32) &&
			insomniaHex(key, "ad", 0, -1) && insomniaHex(key, "d", 2, -1):
			u.add(model.CredentialProtectionProtected)
		default:
			malformed = true
		}
	}
	vault, bad := insomniaField(doc, "vaultKey")
	malformed = malformed || bad
	if vault != "" {
		// Without safeStorage, Insomnia saves the base64 JWK in the clear.
		// Opaque OS-encrypted blobs have no portable envelope; never guess or decrypt.
		decoded, err := base64.StdEncoding.DecodeString(vault)
		material, bad := insomniaSymmetricKey(decoded)
		if err == nil && material && !bad {
			u.add(model.CredentialProtectionPlaintext)
		} else {
			malformed = true
		}
	}
	return u, malformed
}

func insomniaSymmetricKey(raw json.RawMessage) (material, malformed bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return false, false
	}
	key, ok := decodeJSONObject(raw)
	if !ok {
		return false, true
	}
	if len(key) == 0 {
		return false, false
	}
	kind, badKind := insomniaField(key, "kty")
	value, badValue := insomniaField(key, "k")
	if badKind || badValue || kind != "oct" || value == "" {
		return false, true
	}
	return true, false
}

// insomniaRequestRecord reads the record kinds that carry request authentication,
// reporting whether kind is one of them. Shared by the live request databases and
// the request history, which stores whole requests of these kinds.
func insomniaRequestRecord(kind string, doc map[string]json.RawMessage) (u insomniaUnit, malformed, known bool) {
	switch kind {
	case "Request", "WebSocketRequest", "SocketIORequest", "McpRequest":
		u, malformed = insomniaAuth(doc)
		h, bad := insomniaHeaders(doc["headers"])
		return u.plus(h), malformed || bad, true
	case "GrpcRequest":
		// Metadata is this protocol's spelling of headers. The reflection
		// endpoint's key is the one other field holding material.
		u, malformed = insomniaHeaders(doc["metadata"])
		if raw, ok := doc["reflectionApi"]; ok && string(raw) != "null" {
			api, ok := decodeJSONObject(raw)
			if !ok {
				return u, true, true
			}
			material, bad := insomniaMaterial(api, "apiKey")
			malformed = malformed || bad
			if material {
				u.add(model.CredentialProtectionPlaintext)
			}
		}
		return u, malformed, true
	}
	return u, false, false
}

// insomniaAuth reads a record's authentication object. The empty object is the
// default and holds nothing; otherwise the type selects the material fields, and
// a missing or unknown type cannot be accounted for. Disabled authentication
// changes nothing: the material is stored either way.
func insomniaAuth(doc map[string]json.RawMessage) (u insomniaUnit, malformed bool) {
	raw, ok := doc["authentication"]
	if !ok || string(raw) == "null" {
		return u, false
	}
	auth, ok := decodeJSONObject(raw)
	if !ok {
		return u, true
	}
	if len(auth) == 0 {
		return u, false
	}
	kind, bad := insomniaField(auth, "type")
	if bad || kind == "" {
		return u, true
	}
	fields, known := insomniaAuthFields[kind]
	if !known {
		return u, true
	}
	// One authentication object is one credential however many of its fields
	// are filled in.
	material, malformed := insomniaMaterial(auth, fields...)
	if material {
		u.add(model.CredentialProtectionPlaintext)
	}
	return u, malformed
}

// insomniaHeaders counts the entries of a header list whose name the protocol
// defines as carrying a credential and whose value is written into the record.
func insomniaHeaders(raw json.RawMessage) (u insomniaUnit, malformed bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return u, false
	}
	var list []map[string]json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return u, true
	}
	for _, h := range list {
		name, bad := insomniaField(h, "name")
		if bad {
			malformed = true
			continue
		}
		if !insomniaHeaderNames[strings.ToLower(strings.TrimSpace(name))] {
			continue
		}
		material, bad := insomniaMaterial(h, "value")
		malformed = malformed || bad
		if material {
			u.add(model.CredentialProtectionPlaintext)
		}
	}
	return u, malformed
}

// insomniaEnv counts the credentials in an environment, stored twice: as a data
// object and as the pair list the editor shows. A name counts once. Ordinary
// variables count by name; secret-typed variables count whatever their name,
// classified by how they are stored, and are mirrored under one reserved key.
func insomniaEnv(dataRaw, pairsRaw json.RawMessage) (u insomniaUnit, malformed bool) {
	seen := map[string]bool{}
	count := func(name, state string) {
		if state == "" {
			return
		}
		// A name held in both representations is one credential, at the weaker of
		// the two storages: a vault entry mirrored in the clear is in the clear.
		if seen[name] {
			u = u.plus(insomniaUnit{state: state})
			return
		}
		seen[name] = true
		u.add(state)
	}
	if len(dataRaw) > 0 && string(dataRaw) != "null" {
		data, ok := decodeJSONObject(dataRaw)
		if !ok {
			return u, true
		}
		for key, raw := range data {
			if key == insomniaVaultKey {
				vault, ok := decodeJSONObject(raw)
				if !ok {
					malformed = true
					continue
				}
				for name := range vault {
					value, bad := insomniaField(vault, name)
					state, badEnvelope := insomniaEnvelope(value)
					malformed = malformed || bad || badEnvelope
					count(name, state)
				}
				continue
			}
			if !insomniaEnvKeys[insomniaEnvName(key)] {
				continue
			}
			value, bad := insomniaField(data, key)
			literal, mixed := insomniaLiteral(value)
			malformed = malformed || bad || mixed
			if literal {
				count(key, model.CredentialProtectionPlaintext)
			}
		}
	}
	if len(pairsRaw) > 0 && string(pairsRaw) != "null" {
		var pairs []map[string]json.RawMessage
		if json.Unmarshal(pairsRaw, &pairs) != nil {
			return u, true
		}
		for _, pair := range pairs {
			name, badName := insomniaField(pair, "name")
			kind, badKind := insomniaField(pair, "type")
			if badName || badKind {
				malformed = true
				continue
			}
			if kind == "secret" {
				value, bad := insomniaField(pair, "value")
				state, badEnvelope := insomniaEnvelope(value)
				malformed = malformed || bad || badEnvelope
				count(name, state)
				continue
			}
			if !insomniaEnvKeys[insomniaEnvName(name)] {
				continue
			}
			material, bad := insomniaMaterial(pair, "value")
			malformed = malformed || bad
			if material {
				count(name, model.CredentialProtectionPlaintext)
			}
		}
	}
	return u, malformed
}

// insomniaEnvName folds a variable name to the spelling the key set uses.
func insomniaEnvName(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "_")
}

// insomniaEnvelope classifies a secret-typed value. With a vault key the
// application writes base64 over a JSON object of hex fields: that shape is
// protected, a JSON object of another shape cannot be accounted for, and
// anything else is the value written in the clear because no key was available.
func insomniaEnvelope(value string) (state string, malformed bool) {
	literal, mixed := insomniaLiteral(value)
	if mixed {
		return "", true
	}
	if !literal {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return model.CredentialProtectionPlaintext, false
	}
	obj, ok := decodeJSONObject(decoded)
	if !ok {
		return model.CredentialProtectionPlaintext, false
	}
	shaped := insomniaHex(obj, "iv", 24, 24) &&
		insomniaHex(obj, "t", 32, 32) &&
		insomniaHex(obj, "ad", 0, -1) &&
		insomniaHex(obj, "d", 2, -1)
	if !shaped {
		return "", true
	}
	return model.CredentialProtectionProtected, false
}

// insomniaHex reports whether a field is a hex string within the given length
// bounds; a negative maximum is no maximum.
func insomniaHex(obj map[string]json.RawMessage, key string, minLen, maxLen int) bool {
	raw, ok := obj[key]
	if !ok {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || len(s) < minLen || (maxLen >= 0 && len(s) > maxLen) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// insomniaVersion reads one retained request revision, stored as base64 over
// gzip over the request's JSON. Expansion is bounded per file: past the bound the
// revision is capped and contributes nothing. Only request kinds are read inside,
// so history cannot nest history.
func insomniaVersion(doc map[string]json.RawMessage, budget *int) (u insomniaUnit, malformed, capped bool) {
	value, bad := insomniaField(doc, "compressedRequest")
	if bad {
		return u, true, false
	}
	if value == "" {
		return u, false, false
	}
	packed, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return u, true, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		return u, true, false
	}
	// Charge what the stream produced before judging it: a damaged stream can
	// hand back most of its bytes along with the error.
	expanded, err := io.ReadAll(io.LimitReader(zr, int64(*budget)+1))
	if len(expanded) > *budget {
		*budget = 0
		return u, false, true
	}
	*budget -= len(expanded)
	if err != nil {
		return u, true, false
	}
	inner, ok := decodeJSONObject(expanded)
	if !ok {
		return u, true, false
	}
	kind, bad := insomniaField(inner, "type")
	if bad {
		return u, true, false
	}
	u, malformed, known := insomniaRequestRecord(kind, inner)
	return u, malformed || !known, false
}

// insomniaMaterial reports whether any of the named fields holds a value written
// into the record, and whether one of them held something the parser cannot
// classify: a value that is not a string, or text mixed with a template tag.
func insomniaMaterial(obj map[string]json.RawMessage, keys ...string) (material, malformed bool) {
	for _, key := range keys {
		value, bad := insomniaField(obj, key)
		literal, mixed := insomniaLiteral(value)
		malformed = malformed || bad || mixed
		material = material || literal
	}
	return material, malformed
}

// Account and provider stores do not render request templates or shell values.
func insomniaStoredMaterial(obj map[string]json.RawMessage, keys ...string) (material, malformed bool) {
	for _, key := range keys {
		value, bad := insomniaField(obj, key)
		material, malformed = material || value != "", malformed || bad
	}
	return material, malformed
}

// insomniaField reads a field the application declares as a string. An absent or
// null field is the empty string; a field of another type is a document this
// build cannot account for.
func insomniaField(obj map[string]json.RawMessage, key string) (value string, malformed bool) {
	raw, ok := obj[key]
	if !ok || string(raw) == "null" {
		return "", false
	}
	if json.Unmarshal(raw, &value) != nil {
		return "", true
	}
	return value, false
}

// insomniaLiteral reports whether a field holds a value written into the record,
// and whether it mixes one with template tags. Tags alone refer to material
// resolved at run time; text beside a tag is not classified either way. Tags are
// matched, never evaluated, and a dollar-prefixed value is stored as typed.
func insomniaLiteral(value string) (literal, mixed bool) {
	if value == "" {
		return false, false
	}
	if !insomniaTemplate.MatchString(value) {
		return true, false
	}
	rest := strings.TrimSpace(insomniaTemplate.ReplaceAllString(value, ""))
	return false, rest != ""
}

// decodeDoc reads a structured document into generic values, choosing the syntax
// by the file's extension: the catalog names every one of these files, so the
// extension is the tool's own choice of format. JSON goes through the comment-
// and trailing-comma-tolerant reader, which accepts strict JSON unchanged.
func decodeDoc(data []byte, path string) (any, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		var out map[string]any
		return out, toml.Unmarshal(data, &out) == nil && out != nil
	case ".yaml", ".yml":
		var out map[string]any
		return out, yaml.Unmarshal(data, &out) == nil && out != nil
	}
	standard, err := hujson.Standardize(slices.Clone(data))
	if err != nil {
		return nil, false
	}
	var out any
	return out, json.Unmarshal(standard, &out) == nil && out != nil
}

// parseDoc decodes one document and runs a client's count over it, anchored at
// the document's own directory.
func parseDoc(in fileInput, g grammar, fill func(c counter, doc any)) parsed {
	var refs parsed
	p := observedKeys(in.Data, in.Fragments, func(data []byte, f *fold) bool {
		doc, ok := decodeDoc(data, in.Path)
		if !ok {
			return false
		}
		fill(counter{f: f, p: &refs, g: g, dir: filepath.Dir(in.Path), home: in.Home}, doc)
		return true
	})
	p.Opaque, p.Unresolved, p.Refs = refs.Opaque, refs.Unresolved, refs.Refs
	return p
}

// mcpDialect is where one client keeps a server's credential fields. Every
// client also carries a URL and an argument list in the same places.
type mcpDialect struct {
	env     string
	headers string
	// Fields holding an API key or bearer token directly, and fields holding
	// another credential directly, as paths of nested keys.
	keys    [][]string
	secrets [][]string
	// The server may name a dotenv file its environment is read from.
	envFile bool
}

var (
	portableDialect   = mcpDialect{env: "env", headers: "headers"}
	codexDialect      = mcpDialect{env: "env", headers: "http_headers", keys: [][]string{{"bearer_token"}}, secrets: [][]string{{"oauth", "client_secret"}}}
	openCodeV1Dialect = mcpDialect{env: "environment", headers: "headers", secrets: [][]string{{"oauth", "clientSecret"}}}
	openCodeV2Dialect = mcpDialect{env: "environment", headers: "headers", secrets: [][]string{{"oauth", "client_secret"}}}
	piDialect         = mcpDialect{env: "env", headers: "headers", secrets: [][]string{{"oauth", "clientSecret"}}}
	hermesDialect     = mcpDialect{env: "env", headers: "headers", secrets: [][]string{{"oauth", "client_secret"}}}
	cursorDialect     = mcpDialect{env: "env", headers: "headers", secrets: [][]string{{"auth", "CLIENT_SECRET"}}, envFile: true}
	vscodeDialect     = mcpDialect{env: "env", headers: "headers", envFile: true}
)

// servers counts every server of one declaration map. A disabled server still
// counts: switching it off does not take its secret out of the file.
func (c counter) servers(v any, d mcpDialect) {
	for _, server := range c.object(v) {
		s := c.object(server)
		if s == nil {
			continue
		}
		c.env(s[d.env], true)
		c.headers(s[d.headers])
		c.url(s["url"])
		c.args(s["args"])
		if _, ok := s["command"].([]any); ok {
			c.args(s["command"])
		}
		for _, path := range d.keys {
			c.key(c.at(s, path...))
		}
		for _, path := range d.secrets {
			c.field(s, path...)
		}
		if d.envFile {
			c.envFile(s["envFile"])
		}
	}
}

// envFile names a server's dotenv file. The editors resolve a relative path
// against their own process directory rather than the configuration, so only a
// path anchored at the home, the workspace or the root can be followed.
func (c counter) envFile(v any) {
	path, ok := v.(string)
	if !ok || strings.TrimSpace(path) == "" {
		return
	}
	switch {
	case strings.HasPrefix(path, "${userHome}"):
		path = c.home + strings.TrimPrefix(path, "${userHome}")
	case strings.HasPrefix(path, "${workspaceFolder}") && c.workspace != "":
		path = c.workspace + strings.TrimPrefix(path, "${workspaceFolder}")
	case filepath.IsAbs(path) && !strings.Contains(path, "${"):
	default:
		c.p.Unresolved = true
		return
	}
	if strings.Contains(path, "${") {
		c.p.Unresolved = true
		return
	}
	c.p.Refs = append(c.p.Refs, fileRef{Path: filepath.Clean(filepath.FromSlash(path))})
}

// literalCounter is the same counter for stored records, whose values a client
// never substitutes into.
func (c counter) literalCounter() counter {
	c.g = literalGrammar
	return c
}

// projectWorkspace is the project a file below "<project>/<dir>/" belongs to,
// or "" for the copy of that directory in the home, which has no workspace.
func projectWorkspace(path, home string) string {
	workspace := filepath.Dir(filepath.Dir(path))
	if _, ok := trimPathPrefix(home, workspace); ok {
		return ""
	}
	return workspace
}

// parseClaudeCode reads Claude Code's account, key and settings files, and the
// Anthropic profile tokens.
func parseClaudeCode(in fileInput) parsed {
	name := filepath.Base(in.Path)
	switch {
	case filepath.Base(filepath.Dir(in.Path)) == "credentials":
		return parseDoc(in, literalGrammar, func(c counter, doc any) {
			c.grant(doc, "access_token", "refresh_token")
		})
	case name == ".credentials.json":
		return parseDoc(in, literalGrammar, func(c counter, doc any) {
			root := c.object(doc)
			c.grant(root["claudeAiOauth"], "accessToken", "refreshToken")
			claudePluginSecrets(c, root)
		})
	case name == "settings.json" || name == "settings.local.json":
		return parseDoc(in, claudeGrammar, func(c counter, doc any) {
			c.env(c.object(doc)["env"], false)
		})
	}
	// The account key only. The approved-key list beside it keeps the tail of
	// every key the developer accepted and is never read.
	return parseDoc(in, literalGrammar, func(c counter, doc any) {
		c.key(c.object(doc)["primaryApiKey"])
	})
}

// claudePluginSecrets marks the plugin option store, which mixes provider and
// server secrets with no record of which is which, as uncounted for both
// sources rather than assigning its values to either.
func claudePluginSecrets(c counter, root map[string]any) {
	if len(c.object(root["pluginSecrets"])) > 0 {
		c.f.unrecognized = true
	}
}

// parseClaudeMCP reads Claude Code's MCP sign-in state and its server
// declarations, globally and per project.
func parseClaudeMCP(in fileInput) parsed {
	if filepath.Base(in.Path) == ".credentials.json" {
		return parseDoc(in, literalGrammar, func(c counter, doc any) {
			root := c.object(doc)
			for _, rec := range c.object(root["mcpOAuth"]) {
				c.grant(rec, "accessToken", "refreshToken")
				c.field(rec, "clientSecret")
			}
			for _, rec := range c.object(root["mcpOAuthClientConfig"]) {
				c.field(rec, "clientSecret")
			}
			for _, rec := range c.object(root["mcpXaaIdp"]) {
				c.field(rec, "idToken")
			}
			for _, rec := range c.object(root["mcpXaaIdpConfig"]) {
				c.field(rec, "clientSecret")
			}
			claudePluginSecrets(c, root)
		})
	}
	return parseDoc(in, claudeGrammar, func(c counter, doc any) {
		root := c.object(doc)
		c.servers(root["mcpServers"], portableDialect)
		for _, project := range c.object(root["projects"]) {
			c.servers(c.object(project)["mcpServers"], portableDialect)
		}
	})
}

// parseCodex reads Codex's account store, gateway sign-in state and provider
// configuration. The encrypted account store is attempted and reported opaque.
func parseCodex(in fileInput) parsed {
	switch filepath.Base(in.Path) {
	case "codex_auth.age":
		return parsed{Opaque: true}
	case "auth.json":
		return parseDoc(in, literalGrammar, codexAuth)
	case "gateway_oauth.json":
		return parseDoc(in, literalGrammar, func(c counter, doc any) {
			for _, rec := range c.object(doc) {
				c.grant(rec, "access_token", "refresh_token")
			}
		})
	}
	return parseDoc(in, literalGrammar, func(c counter, doc any) {
		for _, provider := range c.object(c.object(doc)["model_providers"]) {
			p := c.object(provider)
			c.key(p["experimental_bearer_token"])
			c.headers(p["http_headers"])
			for name, v := range c.object(p["query_params"]) {
				switch folded := insomniaEnvName(name); {
				case keyNames[folded]:
					c.key(v)
				case urlQueryNames[folded]:
					c.value(v)
				}
			}
		}
	})
}

// codexAuth counts the account store: an API key, the account's tokens as one
// grant, a personal access token, an agent identity, and Bedrock keys.
func codexAuth(c counter, doc any) {
	root := c.object(doc)
	c.key(root["OPENAI_API_KEY"])
	c.grant(root["tokens"], "id_token", "access_token", "refresh_token")
	c.value(root["personal_access_token"])
	switch identity := root["agent_identity"].(type) {
	case nil:
	case string:
		c.value(identity)
	case map[string]any:
		c.value(identity["agent_private_key"])
	default:
		c.f.unrecognized = true
	}
	c.field(root, "bedrock_api_key", "api_key")
	c.grant(root["bedrock_access_keys"], "secret_access_key", "session_token")
}

// parseCodexMCP reads Codex's server declarations and MCP sign-in state. The
// encrypted sign-in store is attempted and reported opaque.
func parseCodexMCP(in fileInput) parsed {
	switch filepath.Base(in.Path) {
	case "mcp_oauth.age":
		return parsed{Opaque: true}
	case ".credentials.json":
		return parseDoc(in, literalGrammar, func(c counter, doc any) {
			for _, rec := range c.object(doc) {
				c.grant(rec, "access_token", "refresh_token")
			}
		})
	}
	return parseDoc(in, literalGrammar, func(c counter, doc any) {
		root := c.object(doc)
		c.servers(root["mcp_servers"], codexDialect)
		c.field(root, "mcp_enterprise_managed_auth", "idp", "client_secret")
	})
}

// parseOpenCode reads OpenCode's account store, provider configuration and
// credential database.
func parseOpenCode(in fileInput) parsed {
	if in.SQLite {
		return openCodeRows(in, false)
	}
	if openCodeStore(in.Path, in.Config) {
		return parseDoc(in, literalGrammar, func(c counter, doc any) {
			for _, rec := range c.object(doc) {
				r := c.object(rec)
				switch r["type"] {
				case "api":
					c.key(r["key"])
				case "oauth":
					c.grant(r, "access", "refresh")
				case "wellknown":
					c.value(r["token"])
				default:
					c.f.unrecognized = true
				}
			}
		})
	}
	return parseDoc(in, openCodeGrammar, func(c counter, doc any) {
		root := c.object(doc)
		for _, provider := range c.object(root["provider"]) {
			p := c.object(provider)
			options := c.object(p["options"])
			c.key(options["apiKey"])
			c.headers(options["headers"])
			for _, model := range c.object(p["models"]) {
				c.headers(c.object(model)["headers"])
			}
		}
		for _, provider := range c.object(root["providers"]) {
			p := c.object(provider)
			openCodeSettings(c, p)
			for _, model := range c.object(p["models"]) {
				m := c.object(model)
				openCodeSettings(c, m)
				for _, variant := range c.list(m["variants"]) {
					openCodeSettings(c, c.object(variant))
				}
			}
		}
	})
}

// openCodeSettings counts the credential settings and headers of one provider,
// model or variant. The settings object is open, so only the named fields are
// read from it.
func openCodeSettings(c counter, m map[string]any) {
	settings := c.object(m["settings"])
	c.key(settings["apiKey"])
	c.value(settings["authToken"])
	c.value(settings["accessToken"])
	c.headers(m["headers"])
}

// parseOpenCodeMCP reads OpenCode's MCP sign-in state, server declarations and
// credential database.
func parseOpenCodeMCP(in fileInput) parsed {
	if in.SQLite {
		return openCodeRows(in, true)
	}
	if openCodeStore(in.Path, in.Config) {
		return parseDoc(in, literalGrammar, func(c counter, doc any) {
			for _, rec := range c.object(doc) {
				r := c.object(rec)
				c.grant(r["tokens"], "accessToken", "refreshToken")
				c.field(r, "clientInfo", "clientSecret")
			}
		})
	}
	return parseDoc(in, openCodeGrammar, func(c counter, doc any) {
		// The newer layout nests servers one level down and still accepts the
		// older one beside it, so each declaration is read in its own shape.
		for name, decl := range c.object(c.object(doc)["mcp"]) {
			if name == "servers" {
				c.servers(decl, openCodeV2Dialect)
				continue
			}
			if _, ok := decl.(map[string]any); ok {
				c.servers(map[string]any{name: decl}, openCodeV1Dialect)
			}
		}
	})
}

// openCodeStore reports whether a file is one of OpenCode's credential stores
// rather than a configuration. A file named as the configuration is one
// whatever it is called.
func openCodeStore(path string, config bool) bool {
	base := filepath.Base(path)
	return !config && (base == "auth.json" || base == "mcp-auth.json")
}

// openCodeMCPID is the identifier OpenCode gives an MCP server's credential.
var openCodeMCPID = regexp.MustCompile(`^mcp_[0-9a-f]{16}$`)

// openCodeBuiltinProviders are the providers OpenCode itself defines, whose
// credentials are AI-tool material without a local declaration.
var openCodeBuiltinProviders = []string{"openai", "anthropic", "openrouter"}

// openCodeRows counts the credential table for one of the two OpenCode sources.
// A row is an MCP credential only when its identifier, method and metadata all
// have the shape OpenCode writes for one, and an AI credential only for a
// provider known to be one. Any other row holding material belongs to neither
// with certainty, so both sources report it uninterpreted.
func openCodeRows(in fileInput, mcp bool) parsed {
	providers := openCodeProviders(in)
	var f fold
	var p parsed
	for _, row := range in.Rows {
		var v map[string]any
		if json.Unmarshal([]byte(row.Value), &v) != nil || v == nil {
			f.unrecognized = true
			continue
		}
		isMCP := openCodeMCPRow(row.Key, v)
		units := fold{fragments: in.Fragments}
		c := counter{f: &units, p: &p, g: literalGrammar}
		switch v["type"] {
		case "key":
			c.key(v["key"])
		case "oauth":
			c.grant(v, "access", "refresh")
			if isMCP {
				c.field(v, "metadata", "client", "client_secret")
			}
		case "external":
		default:
			units.unrecognized = true
		}
		if !isMCP && !providers[row.Key] {
			f.unrecognized = f.unrecognized || units.count > 0 || units.unrecognized
			continue
		}
		if isMCP != mcp {
			continue
		}
		f.absorb(&units)
	}
	f.into(&p)
	return p
}

// openCodeMCPRow reports whether a credential row has the shape OpenCode writes
// for an MCP server. A server URL alone does not make one.
func openCodeMCPRow(id string, v map[string]any) bool {
	if !openCodeMCPID.MatchString(id) || v["methodID"] != id {
		return false
	}
	meta, _ := v["metadata"].(map[string]any)
	serverURL, _ := meta["serverUrl"].(string)
	tokenType, _ := meta["tokenType"].(string)
	return serverURL != "" && tokenType != ""
}

// openCodeProviders is the set of provider identifiers whose credentials are
// AI-tool material: the built-in ones and those the local configuration
// declares. Nothing is fetched to widen it.
func openCodeProviders(in fileInput) map[string]bool {
	out := map[string]bool{}
	for _, id := range openCodeBuiltinProviders {
		out[id] = true
	}
	for _, companion := range in.Companions {
		path := companion.path()
		if openCodeStore(path, companion.Config) {
			continue
		}
		data := in.Read(path, capConfig)
		if data == nil {
			continue
		}
		doc, ok := decodeDoc(stripBOM(data), path)
		root, _ := doc.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"provider", "providers"} {
			declared, _ := root[key].(map[string]any)
			for id := range declared {
				out[id] = true
			}
		}
	}
	return out
}

// parsePi reads Pi's account store and model configuration.
func parsePi(in fileInput) parsed {
	if filepath.Base(in.Path) == "auth.json" {
		return parseDoc(in, piGrammar, func(c counter, doc any) {
			for _, rec := range c.object(doc) {
				r := c.object(rec)
				switch r["type"] {
				case "api_key":
					c.key(r["key"])
					c.env(r["env"], false)
				case "oauth":
					c.literalCounter().grant(r, "access", "refresh")
				default:
					c.f.unrecognized = true
				}
			}
		})
	}
	return parseDoc(in, piGrammar, func(c counter, doc any) {
		for _, provider := range c.object(c.object(doc)["providers"]) {
			p := c.object(provider)
			c.key(p["apiKey"])
			c.headers(p["headers"])
			for _, model := range c.list(p["models"]) {
				c.headers(c.object(model)["headers"])
			}
			for _, override := range c.object(p["modelOverrides"]) {
				c.headers(c.object(override)["headers"])
			}
		}
	})
}

// parsePiMCP reads Pi's server declarations and MCP sign-in state. Pending
// sign-in state is not a credential.
func parsePiMCP(in fileInput) parsed {
	if filepath.Base(in.Path) == "mcp-auth.json" {
		return parseDoc(in, literalGrammar, func(c counter, doc any) {
			for _, rec := range c.object(doc) {
				r := c.object(rec)
				c.grant(r["tokens"], "access_token", "refresh_token", "id_token")
				c.field(r, "clientInformation", "client_secret")
			}
		})
	}
	return parseDoc(in, piGrammar, func(c counter, doc any) {
		c.servers(c.object(doc)["mcpServers"], piDialect)
	})
}

// hermesProviderEnv are the provider key variables Hermes reads from its own
// dotenv files.
var hermesProviderEnv = map[string]bool{
	"OPENAI_API_KEY": true, "ANTHROPIC_API_KEY": true, "ANTHROPIC_TOKEN": true, "CLAUDE_CODE_OAUTH_TOKEN": true,
	"GOOGLE_API_KEY": true, "GEMINI_API_KEY": true, "GLM_API_KEY": true, "ZAI_API_KEY": true, "Z_AI_API_KEY": true,
	"KIMI_API_KEY": true, "KIMI_CODING_API_KEY": true, "KIMI_CN_API_KEY": true, "MINIMAX_API_KEY": true,
	"MINIMAX_CN_API_KEY": true, "DASHSCOPE_API_KEY": true, "ALIBABA_CODING_PLAN_API_KEY": true,
	"DEEPSEEK_API_KEY": true, "XAI_API_KEY": true, "NVIDIA_API_KEY": true, "AI_GATEWAY_API_KEY": true,
	"OPENCODE_ZEN_API_KEY": true, "OPENCODE_GO_API_KEY": true, "KILOCODE_API_KEY": true, "HF_TOKEN": true,
	"XIAOMI_API_KEY": true, "TOKENHUB_API_KEY": true, "TOKENPLAN_API_KEY": true, "OLLAMA_API_KEY": true,
	"LM_API_KEY": true, "STEPFUN_API_KEY": true, "ARCEEAI_API_KEY": true, "GMI_API_KEY": true,
	"ACTUAL_API_KEY": true, "AZURE_FOUNDRY_API_KEY": true, "OPENROUTER_API_KEY": true,
}

// hermesManaged is the value Hermes writes for a variable a password manager
// supplies at run time.
const hermesManaged = "__BITWARDEN_MANAGED__"

// hermesTokenEnv are the credential variables Hermes reads that hold a sign-in
// or service token rather than an API key, so they never leave a fragment.
var hermesTokenEnv = map[string]bool{"OP_SERVICE_ACCOUNT_TOKEN": true, "ANTHROPIC_TOKEN": true, "CLAUDE_CODE_OAUTH_TOKEN": true}

// hermesEnvBase names the variable a dotenv name stands for when Hermes reads a
// credential from it: a provider variable itself or through one of its numbered
// pool siblings, or the password manager's service token. "" for anything else.
func hermesEnvBase(name string) string {
	if name == "OP_SERVICE_ACCOUNT_TOKEN" || hermesProviderEnv[name] {
		return name
	}
	i := strings.LastIndexByte(name, '_')
	if i < 0 {
		return ""
	}
	if n, err := strconv.Atoi(name[i+1:]); err != nil || n < 2 || !hermesProviderEnv[name[:i]] {
		return ""
	}
	return name[:i]
}

// parseHermes reads a Hermes profile's dotenv files, configuration and account
// store, and the account store every profile shares.
func parseHermes(in fileInput) parsed {
	switch filepath.Base(in.Path) {
	case ".env", ".op.env":
		return observedKeys(in.Data, in.Fragments, func(data []byte, f *fold) bool {
			for name, value := range dotenvPairs(data) {
				base := hermesEnvBase(name)
				switch {
				case base == "" || value == hermesManaged || !hermesGrammar.literal(value):
				case hermesTokenEnv[base]:
					f.entry()
				default:
					f.key(value)
				}
			}
			return true
		})
	case "nous_auth.json":
		return parseDoc(in, literalGrammar, func(c counter, doc any) {
			root := c.object(doc)
			hermesGrant(c, root)
			hermesGrant(c, c.object(root["renewal"]))
		})
	case "auth.json":
		return parseDoc(in, literalGrammar, hermesAuth)
	}
	return parseDoc(in, hermesGrammar, func(c counter, doc any) {
		root := c.object(doc)
		c.key(c.at(root, "model", "api_key"))
		for _, task := range c.object(root["auxiliary"]) {
			c.key(c.at(task, "api_key"))
		}
		for _, provider := range c.list(root["custom_providers"]) {
			hermesCustomProvider(c, provider)
		}
		for _, provider := range c.object(root["providers"]) {
			hermesCustomProvider(c, provider)
		}
	})
}

// hermesCustomProvider counts one declared provider's key, under either of its
// spellings, and its extra headers.
func hermesCustomProvider(c counter, v any) {
	p := c.object(v)
	key := p["api_key"]
	if !c.g.literalAny(key) {
		key = p["apiKey"]
	}
	c.key(key)
	c.headers(p["extra_headers"])
}

// hermesGrant counts one account state: its tokens as one grant, however many
// of them and whichever aliases are kept, and the connector token it was
// exchanged for as a separate one.
func hermesGrant(c counter, m map[string]any) {
	c.grant(m, "access_token", "refresh_token", "anon_token", "agent_key", "api_key")
	c.field(m, "connectors_token", "access_token")
}

// hermesAuth counts the account store. The modern layout takes precedence; the
// legacy portal record is read only when it is absent.
func hermesAuth(c counter, doc any) {
	root := c.object(doc)
	_, providers := root["providers"].(map[string]any)
	_, pool := root["credential_pool"].(map[string]any)
	if !providers && !pool {
		hermesGrant(c, c.object(c.object(root["systems"])["nous_portal"]))
		return
	}
	for id, rec := range c.object(root["providers"]) {
		r := c.object(rec)
		if id == "openai-codex" {
			c.grant(r["tokens"], "access_token", "refresh_token", "id_token")
			continue
		}
		hermesGrant(c, r)
	}
	// A pool row borrowed from another store keeps only its source and a
	// fingerprint, which count nothing; one that still holds a secret counts.
	// A row Hermes types as an API key, which is also its reading of an untyped
	// row, keeps the key in its access token field.
	for _, rows := range c.object(root["credential_pool"]) {
		for _, row := range c.list(rows) {
			r := c.object(row)
			switch r["auth_type"] {
			case nil, "api_key":
				c.key(r["access_token"])
			default:
				c.grant(r, "access_token", "refresh_token", "agent_key", "anon_token")
			}
		}
	}
}

// parseHermesMCP reads a Hermes profile's server declarations and the sign-in
// state Hermes keeps per server.
func parseHermesMCP(in fileInput) parsed {
	name := filepath.Base(in.Path)
	switch {
	case strings.HasSuffix(name, ".meta.json"):
		return parsed{}
	case strings.HasSuffix(name, ".client.json"):
		return parseDoc(in, literalGrammar, func(c counter, doc any) { c.field(doc, "client_secret") })
	case strings.HasSuffix(name, ".json"):
		return parseDoc(in, literalGrammar, func(c counter, doc any) { c.grant(doc, "access_token", "refresh_token") })
	}
	return parseDoc(in, hermesGrammar, func(c counter, doc any) {
		c.servers(c.object(doc)["mcp_servers"], hermesDialect)
	})
}

// parseCopilotCLI reads Copilot CLI's provider registry, where every value is
// literal. Its account configuration has no established token layout, so it is
// never counted; a token store kept in it is reported rather than passed over
// as empty, and the account details beside it are not looked at.
func parseCopilotCLI(in fileInput) parsed {
	if filepath.Base(in.Path) == "config.json" {
		return parseDoc(in, literalGrammar, func(c counter, doc any) {
			tokens := c.object(doc)["copilot_tokens"]
			if holdsValues(tokens) || c.g.literalAny(tokens) {
				c.f.unrecognized = true
			}
		})
	}
	return parseDoc(in, literalGrammar, func(c counter, doc any) {
		for _, provider := range c.list(c.object(doc)["providers"]) {
			p := c.object(provider)
			c.key(p["apiKey"])
			c.key(p["bearerToken"])
			c.headers(p["headers"])
		}
	})
}

// parseCopilotCLIMCP reads Copilot CLI's server declarations, its sign-in
// fallback files and its raw secret fallback files.
func parseCopilotCLIMCP(in fileInput) parsed {
	name := filepath.Base(in.Path)
	switch filepath.Base(filepath.Dir(in.Path)) {
	case "mcp-secrets":
		return rawSecret(in.Data, in.Fragments)
	case "mcp-oauth-config":
		if strings.HasSuffix(name, ".tokens.json") {
			return parseDoc(in, literalGrammar, func(c counter, doc any) {
				c.grant(doc, "access_token", "refresh_token", "accessToken", "refreshToken")
			})
		}
		return parseDoc(in, literalGrammar, func(c counter, doc any) { c.field(doc, "client_secret") })
	}
	return parseDoc(in, copilotMCPGrammar, func(c counter, doc any) {
		c.servers(c.object(doc)["mcpServers"], portableDialect)
	})
}

// parseCursor reads Cursor's provider key slots. A plaintext slot holds the key
// as a string; a protected slot holds an encrypted buffer, empty when unset.
func parseCursor(in fileInput) parsed {
	var p parsed
	f := fold{fragments: in.Fragments}
	for _, row := range in.Rows {
		if strings.HasPrefix(row.Key, "secret://") {
			editorEnvelope(&p, &f, row.Value)
			continue
		}
		value := row.Value
		var quoted string
		if json.Unmarshal([]byte(value), &quoted) == nil {
			value = quoted
		}
		if !literalGrammar.literal(value) {
			continue
		}
		// Google keys have no recognized whole-value form.
		if strings.HasSuffix(row.Key, "/googleKey") {
			f.entry()
		} else {
			f.key(value)
		}
	}
	f.into(&p)
	return p
}

// editorEnvelope classifies an encrypted editor value: an empty buffer holds
// nothing, and anything else is opaque, never counted from its length.
func editorEnvelope(p *parsed, f *fold, value string) {
	var buf struct {
		Type string `json:"type"`
		Data []int  `json:"data"`
	}
	if json.Unmarshal([]byte(value), &buf) != nil || buf.Type != "Buffer" {
		f.unrecognized = true
		return
	}
	if len(buf.Data) > 0 {
		p.Opaque = true
	}
}

// parseCursorMCP reads Cursor's server declarations and its encrypted MCP
// sign-in rows.
func parseCursorMCP(in fileInput) parsed {
	if in.SQLite {
		var p parsed
		var f fold
		for _, row := range in.Rows {
			editorEnvelope(&p, &f, row.Value)
		}
		p.observation = f.result()
		return p
	}
	return parseDoc(in, editorGrammar, func(c counter, doc any) {
		c.workspace = projectWorkspace(in.Path, in.Home)
		c.servers(c.object(doc)["mcpServers"], cursorDialect)
	})
}

// parseVSCode reads VS Code's language model provider groups.
func parseVSCode(in fileInput) parsed {
	return parseDoc(in, editorGrammar, func(c counter, doc any) {
		for _, group := range c.list(doc) {
			g := c.object(group)
			c.key(g["apiKey"])
			c.url(g["url"])
			for _, model := range c.list(g["models"]) {
				m := c.object(model)
				c.headers(m["requestHeaders"])
				c.url(m["url"])
			}
		}
	})
}

// parseVSCodeMCP reads VS Code's server declarations, in a user, profile,
// project or workspace file, and the input values it caches in its databases.
func parseVSCodeMCP(in fileInput) parsed {
	if in.SQLite {
		return vscodeInputs(in)
	}
	return parseDoc(in, editorGrammar, func(c counter, doc any) {
		root := c.object(doc)
		switch {
		case strings.HasSuffix(in.Path, ".code-workspace"):
			root = c.object(c.object(root["settings"])["mcp"])
			c.workspace = filepath.Dir(in.Path)
		default:
			c.workspace = projectWorkspace(in.Path, in.Home)
		}
		vscodeDeclarations(c, root)
	})
}

// vscodeDeclarations counts one declaration document's servers, then the
// literal defaults of the inputs that feed a credential slot: marking an input
// as a password does not encrypt a default already written beside it.
func vscodeDeclarations(c counter, root map[string]any) {
	c.inputs = map[string]bool{}
	c.servers(root["servers"], vscodeDialect)
	for _, input := range c.list(root["inputs"]) {
		m := c.object(input)
		id, _ := m["id"].(string)
		switch key, feeds := c.inputs[id]; {
		case feeds && key:
			c.key(m["default"])
		case feeds:
			c.value(m["default"])
		}
	}
}

// vscodeCached is one cached input value.
type vscodeCached struct {
	Value any `json:"value"`
}

// vscodeInputs counts the cached input values that feed a credential slot of
// the declaration the database belongs to. A value is never assigned to a
// server it cannot be tied to, and the encrypted part of the cache is opaque.
func vscodeInputs(in fileInput) parsed {
	var p parsed
	f := fold{fragments: in.Fragments}
	for _, row := range in.Rows {
		var cache struct {
			Values  map[string]vscodeCached `json:"values"`
			Secrets json.RawMessage         `json:"secrets"`
		}
		if json.Unmarshal([]byte(row.Value), &cache) != nil {
			f.unrecognized = true
			continue
		}
		if len(cache.Secrets) > 0 && string(cache.Secrets) != "null" {
			p.Opaque = true
		}
		literal := false
		for _, v := range cache.Values {
			literal = literal || editorGrammar.literalAny(v.Value)
		}
		if !literal {
			continue
		}
		declaration, workspace, ok := vscodeDeclaration(in)
		if !ok {
			p.Unresolved = true
			continue
		}
		feeding := map[string]bool{}
		collectInputs(in, declaration, workspace, feeding)
		for name, v := range cache.Values {
			id := strings.TrimSuffix(strings.TrimPrefix(name, "${input:"), "}")
			s, ok := v.Value.(string)
			apiKey, feeds := feeding[id]
			switch {
			case !ok || !feeds || !editorGrammar.literal(s):
			case apiKey:
				f.key(s)
			default:
				f.entry()
			}
		}
	}
	f.into(&p)
	return p
}

// vscodeDeclaration names the declaration a database's cached inputs belong to:
// the profile's own file for a profile database, and for a workspace database
// the folder or workspace file its sibling record names.
func vscodeDeclaration(in fileInput) (path, workspace string, ok bool) {
	dir := filepath.Dir(in.Path)
	if filepath.Base(dir) == "globalStorage" {
		return filepath.Join(filepath.Dir(dir), "mcp.json"), "", true
	}
	data := in.Read(filepath.Join(dir, "workspace.json"), capConfig)
	if data == nil {
		return "", "", false
	}
	var record struct {
		Folder    string `json:"folder"`
		Workspace string `json:"workspace"`
	}
	if json.Unmarshal(stripBOM(data), &record) != nil {
		return "", "", false
	}
	if folder, ok := fileURIPath(record.Folder); ok {
		return filepath.Join(folder, ".vscode", "mcp.json"), folder, true
	}
	if file, ok := fileURIPath(record.Workspace); ok {
		return file, filepath.Dir(file), true
	}
	return "", "", false
}

// collectInputs records which inputs feed a credential slot of a declaration.
// Its own counts are discarded: the declaration is a file of its own, counted
// where it is read.
func collectInputs(in fileInput, path, workspace string, into map[string]bool) {
	data := in.Read(path, capConfig)
	if data == nil {
		return
	}
	doc, ok := decodeDoc(stripBOM(data), path)
	if !ok {
		return
	}
	var scratch fold
	c := counter{f: &scratch, p: &parsed{}, g: editorGrammar, dir: filepath.Dir(path), home: in.Home, workspace: workspace, inputs: into}
	root := c.object(doc)
	if strings.HasSuffix(path, ".code-workspace") {
		root = c.object(c.object(root["settings"])["mcp"])
	}
	c.servers(root["servers"], vscodeDialect)
}

// fileURIPath turns a local file URI into a path. Any other scheme names
// somewhere this scan does not reach.
func fileURIPath(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "file" || (u.Host != "" && u.Host != "localhost") || u.Path == "" {
		return "", false
	}
	p := u.Path
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p), true
}

// parseSharedMCPConfig reads a project's portable server declarations.
func parseSharedMCPConfig(in fileInput) parsed {
	return parseDoc(in, claudeGrammar, func(c counter, doc any) {
		c.servers(c.object(doc)["mcpServers"], portableDialect)
	})
}
