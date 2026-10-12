package credentials

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
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
