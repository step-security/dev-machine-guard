package credentials

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// TestParseGCPADC covers the shapes this file takes. One file is one credential
// however many of its fields are filled in, so a nested inline credential is read
// for what it settles rather than added to a count — and a material field holding
// something that is not a string is a document this build cannot account for.
func TestParseGCPADC(t *testing.T) {
	runParseCases(t, parseGCPADC, []parseCase{
		{name: "interactive login holds material", body: `{"type":"authorized_user","client_id":"id.apps.googleusercontent.com","client_secret":"value","refresh_token":"value"}`, want: obsPlain(1)},
		{name: "service account key holds material", body: `{"type":"service_account","client_email":"svc@example.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nvalue\n-----END PRIVATE KEY-----\n"}`, want: obsPlain(1)},
		// Impersonation carries the credential it goes through inside itself, so
		// the material can sit one level below the fields that describe it.
		{name: "impersonation counts the nested credential once", body: `{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/x","source_credentials":{"type":"authorized_user","client_secret":"value","refresh_token":"value"}}`, want: obsPlain(1)},
		{name: "material beside an external source is still one credential", body: `{"type":"external_account","credential_source":{"file":"/var/run/secrets/token"},"client_secret":"value"}`, want: obsPlain(1)},
		// An external account fetches its credential at run time, so nothing here
		// is material however completely the file is filled in.
		{name: "external account alone is not material", body: `{"type":"external_account","audience":"//iam.googleapis.com/x","credential_source":{"file":"/var/run/secrets/token"}}`, want: obsNone},
		{name: "impersonation with no inline source is not material", body: `{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/x"}`, want: obsNone},
		// The nested credential is read whether or not the outer object held one:
		// a nested shape this build cannot account for is uncertainty the outer
		// credential does not resolve, since the file could be carrying a second
		// credential nothing here can see.
		{name: "material beside a nested source of the wrong shape", body: `{"client_secret":"value","source_credentials":["a"]}`, want: alsoUnrec(obsPlain(1))},
		{name: "material beside a nested field of the wrong type", body: `{"client_secret":"value","source_credentials":{"refresh_token":42}}`, want: alsoUnrec(obsPlain(1))},
		{name: "a nested source that is not an object", body: `{"source_credentials":"a-name"}`, want: obsUnrec},
		{name: "a null nested source is not a failure", body: `{"source_credentials":null}`, want: obsNone},
		// A shape this build does not know is not a failure: the fields it reads
		// are simply absent, and an unrelated key proves nothing either way.
		{name: "an unfamiliar shape holds no material", body: `{"type":"some_future_credential_family","account":"a-name"}`, want: obsNone},
		{name: "null and empty fields are not material", body: `{"type":"authorized_user","client_secret":null,"refresh_token":""}`, want: obsNone},
		{name: "environment reference is not material", body: `{"type":"authorized_user","refresh_token":"${GOOGLE_REFRESH_TOKEN}"}`, want: obsNone},
		// The loader reads every one of these fields as a string, so another type
		// in one is a document this build cannot read.
		{name: "a material field of the wrong type", body: `{"refresh_token":{"nested":true}}`, want: obsUnrec},
		{name: "material beside a field of the wrong type", body: `{"client_secret":"value","refresh_token":["a"]}`, want: alsoUnrec(obsPlain(1))},
		{name: "malformed document", body: `{"type":"authorized_user",`, want: obsUnrec},
		{name: "a root that is not an object", body: "null", want: obsUnrec},
		{name: "blank file", body: "\n", want: obsNone},
	})
}

func TestParseDockerConfig(t *testing.T) {
	runParseCases(t, parseDockerConfig, []parseCase{
		// The inline field is an encoding, not a protection, so an entry that
		// carries it is material in the clear.
		{name: "inline registry auth is plaintext", body: `{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}}}`, want: obsPlain(1)},
		{name: "identity token is material", body: `{"auths":{"registry.example.com":{"identitytoken":"value"}}}`, want: obsPlain(1)},
		{name: "one registry with both fields counts once", body: `{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz","identitytoken":"value"}}}`, want: obsPlain(1)},
		{name: "registries count separately", body: `{"auths":{"a.example.com":{"auth":"b25l"},"b.example.com":{"auth":"dHdv"}}}`, want: obsPlain(2)},
		// A helper holds the secret somewhere this file does not reach, so none of
		// these is a credential in it.
		{name: "entry with no inline material", body: `{"auths":{"registry.example.com":{}},"credsStore":"desktop"}`, want: obsNone},
		{name: "default helper alone", body: `{"credsStore":"desktop"}`, want: obsNone},
		{name: "per-registry helper alone", body: `{"credHelpers":{"registry.example.com":"ecr-login"}}`, want: obsNone},
		{name: "empty auth entry", body: `{"auths":{"registry.example.com":{"auth":""}}}`, want: obsNone},
		{name: "configuration with no credential statement", body: `{"currentContext":"desktop-linux"}`, want: obsNone},
		{name: "malformed document", body: `{"auths":`, want: obsUnrec},
		// A document with no mapping at its root is not this file's shape, and
		// reading it as an object with no fields would call the file clean.
		{name: "a root that is not an object", body: "null", want: obsUnrec},
		{name: "blank file", body: "\n", want: obsNone},
	})
}

func TestParseTerraformCredentials(t *testing.T) {
	runParseCases(t, parseTerraformCredentials, []parseCase{
		{name: "host token", body: `{"credentials":{"app.terraform.io":{"token":"value"}}}`, want: obsPlain(1)},
		{name: "hosts count separately", body: `{"credentials":{"app.terraform.io":{"token":"one"},"tfe.example.com":{"token":"two"}}}`, want: obsPlain(2)},
		{name: "empty token is not material", body: `{"credentials":{"app.terraform.io":{"token":""}}}`, want: obsNone},
		{name: "environment reference is not material", body: `{"credentials":{"app.terraform.io":{"token":"${TF_TOKEN}"}}}`, want: obsNone},
		// Unrelated settings live here too, so the file's presence alone is not
		// evidence that a token was ever stored.
		{name: "valid document with no credentials block", body: `{"unrelated":true}`, want: obsNone},
		{name: "malformed document", body: `{"credentials":`, want: obsUnrec},
		{name: "a root that is not an object", body: "null", want: obsUnrec},
		{name: "blank file", body: "\n", want: obsNone},
	})
}

// TestParseGitHubCLIHosts counts only tokens written into the file. The usual
// arrangement keeps the token in an OS keystore, which is not material in any
// file this agent reads — and nothing here asks the CLI what it holds.
func TestParseGitHubCLIHosts(t *testing.T) {
	runParseCases(t, parseGitHubCLIHosts, []parseCase{
		{name: "inline token on the host", body: "example.invalid:\n    oauth_token: value\n    user: a-user\n", want: obsPlain(1)},
		{name: "inline token on an account", body: "example.invalid:\n    users:\n        a-user:\n            oauth_token: value\n", want: obsPlain(1)},
		// One host is one credential however many of its accounts carry a token.
		{name: "several accounts on one host count once", body: "example.invalid:\n    users:\n        a-user:\n            oauth_token: one\n        b-user:\n            oauth_token: two\n", want: obsPlain(1)},
		{name: "hosts count separately", body: "a.invalid:\n    oauth_token: one\nb.invalid:\n    oauth_token: two\n", want: obsPlain(2)},
		{name: "keyring-backed host holds no material", body: "example.invalid:\n    user: a-user\n    git_protocol: ssh\n", want: obsNone},
		{name: "accounts without tokens hold no material", body: "example.invalid:\n    users:\n        a-user:\n            git_protocol: ssh\n", want: obsNone},
		{name: "empty token is not material", body: "example.invalid:\n    oauth_token: \"\"\n", want: obsNone},
		{name: "valid document with no hosts", body: "{}\n", want: obsNone},
		{name: "blank file", body: "\n", want: obsNone},
		{name: "malformed document", body: "example.invalid:\n  - this is a list where a map belongs\n", want: obsUnrec},
		{name: "a root that is not a mapping", body: "null\n", want: obsUnrec},
	})
}

func TestParseKubeconfig(t *testing.T) {
	runParseCases(t, parseKubeconfig, []parseCase{
		{name: "embedded token", body: "users:\n  - name: dev\n    user:\n      token: value\n", want: obsPlain(1)},
		{name: "basic password", body: "users:\n  - name: dev\n    user:\n      username: a-user\n      password: value\n", want: obsPlain(1)},
		{name: "embedded key material", body: "users:\n  - name: dev\n    user:\n      client-key-data: " + base64PEM(testECPrivateKeyPEM()) + "\n", want: obsPlain(1)},
		// The embedded key is the one place this format can hold material that is
		// present without being usable, so the protection travels from the key.
		{name: "embedded encrypted key material", body: "users:\n  - name: dev\n    user:\n      client-key-data: " + base64PEM(testEncryptedPKCS8PEM()) + "\n", want: obsProt(1)},
		{name: "entries count separately", body: "users:\n  - name: a\n    user:\n      token: one\n  - name: b\n    user:\n      token: two\n", want: obsPlain(2)},
		// Each of these names material fetched at run time, so none is a
		// credential in this document.
		{name: "token file is not material", body: "users:\n  - name: dev\n    user:\n      tokenFile: /var/run/secrets/token\n", want: obsNone},
		{name: "key path is not material", body: "users:\n  - name: dev\n    user:\n      client-certificate: /home/a-user/.kube/client.crt\n      client-key: /home/a-user/.kube/client.key\n", want: obsNone},
		{name: "credential plugin is not material", body: "users:\n  - name: dev\n    user:\n      exec:\n        command: aws\n        args: [eks, get-token]\n", want: obsNone},
		{name: "identity provider is not material", body: "users:\n  - name: dev\n    user:\n      auth-provider:\n        name: oidc\n", want: obsNone},
		// The public half authenticates nothing without its key.
		{name: "certificate alone is not material", body: "users:\n  - name: dev\n    user:\n      client-certificate: /home/a-user/.kube/client.crt\n", want: obsNone},
		{name: "environment reference is not material", body: "users:\n  - name: dev\n    user:\n      token: ${KUBE_TOKEN}\n", want: obsNone},
		{name: "clusters with no user entries", body: "clusters:\n  - name: dev\n    cluster:\n      server: https://cluster.example.com\n", want: obsNone},
		{name: "blank file", body: "\n", want: obsNone},
		{name: "malformed document", body: "users: [ unterminated\n", want: obsUnrec},
		{name: "a root that is not a mapping", body: "null\n", want: obsUnrec},
		// This field is declared to hold a private key, so anything else in it is
		// a document this build cannot account for — even bytes that would be
		// ignored harmlessly as a file in the key directory.
		{name: "embedded key data that is not base64", body: "users:\n  - name: dev\n    user:\n      client-key-data: not-base64!!\n", want: obsUnrec},
		{name: "embedded key data that is not a key", body: "users:\n  - name: dev\n    user:\n      client-key-data: " + base64.StdEncoding.EncodeToString([]byte("not a key at all")) + "\n", want: obsUnrec},
		{name: "embedded public key is not material", body: "users:\n  - name: dev\n    user:\n      client-key-data: " + base64PEM(testCertificatePEM()) + "\n", want: obsUnrec},
		// Mixed users: the inline credential counts and the unreadable sibling
		// still costs the source its completeness.
		{name: "inline material beside unreadable key data", body: "users:\n  - name: a\n    user:\n      token: value\n  - name: b\n    user:\n      client-key-data: not-base64!!\n", want: alsoUnrec(obsPlain(1))},
		// Every field of an entry is read: a token beside key data that will not
		// parse answers nothing about the key, and letting it stand in would
		// report the entry as fully understood.
		{name: "one entry holding both a token and unreadable key data", body: "users:\n  - name: dev\n    user:\n      token: value\n      client-key-data: not-base64!!\n", want: alsoUnrec(obsPlain(1))},
		// The worst protection in an entry describes it, the same way the fold
		// over a whole source does.
		{name: "a token beside an encrypted key counts once as plaintext", body: "users:\n  - name: dev\n    user:\n      token: value\n      client-key-data: " + base64PEM(testEncryptedPKCS8PEM()) + "\n", want: obsPlain(1)},
	})
}

// base64PEM encodes a PEM document the way a kubeconfig embeds one.
func base64PEM(pem []byte) string {
	return base64.StdEncoding.EncodeToString(pem)
}

// nedb joins records into the line-oriented database shape the API client writes.
func nedb(records ...string) string {
	return strings.Join(records, "\n") + "\n"
}

// envelope is a secret value as the API client stores it with a vault key: base64
// over a JSON object of hex fields. Built from fixed hex rather than by encrypting
// anything, since the parser reads the shape and never the contents.
func envelope() string {
	body := `{"iv":"00112233445566778899aabb","t":"00112233445566778899aabbccddeeff","ad":"","d":"cafebabe"}`
	return base64.StdEncoding.EncodeToString([]byte(body))
}

// compressed is a retained request revision as the API client stores it: base64
// over gzip over the request's JSON.
func compressed(doc string) string {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(doc)); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// alsoCapped marks an expectation as one the parser stopped short on.
func alsoCapped(o observation) observation {
	o.Capped = true
	return o
}

// request is one live request record with the given authentication object and
// header list.
func request(id, auth, headers string) string {
	return `{"_id":"` + id + `","type":"Request","authentication":` + auth + `,"headers":` + headers + `}`
}

// TestParseInsomnia_Authentication covers the authentication object every request
// kind carries: the type selects the material fields, and one object is one
// credential however many of them are filled.
func TestParseInsomnia_Authentication(t *testing.T) {
	filled := func(kind, field string) string {
		return request("req_1", `{"type":"`+kind+`","`+field+`":"value"}`, "[]")
	}
	runParseCases(t, parseInsomnia, []parseCase{
		{name: "basic password", body: filled("basic", "password"), want: obsPlain(1)},
		{name: "a password that starts with a dollar sign", body: request("req_1", `{"type":"basic","password":"$value"}`, "[]"), want: obsPlain(1)},
		{name: "a password shaped like a shell reference", body: request("req_1", `{"type":"basic","password":"${VALUE}"}`, "[]"), want: obsPlain(1)},
		{name: "digest password", body: filled("digest", "password"), want: obsPlain(1)},
		{name: "ntlm password", body: filled("ntlm", "password"), want: obsPlain(1)},
		{name: "bearer token", body: filled("bearer", "token"), want: obsPlain(1)},
		{name: "single token", body: filled("singleToken", "token"), want: obsPlain(1)},
		{name: "api key value", body: filled("apikey", "value"), want: obsPlain(1)},
		{name: "oauth2 client secret", body: filled("oauth2", "clientSecret"), want: obsPlain(1)},
		{name: "oauth2 access token", body: filled("oauth2", "accessToken"), want: obsPlain(1)},
		{name: "oauth1 token secret", body: filled("oauth1", "tokenSecret"), want: obsPlain(1)},
		{name: "iam secret access key", body: filled("iam", "secretAccessKey"), want: obsPlain(1)},
		{name: "hawk key", body: filled("hawk", "key"), want: obsPlain(1)},
		{name: "asap private key", body: filled("asap", "privateKey"), want: obsPlain(1)},
		{name: "several filled fields are one credential", body: request("req_1", `{"type":"oauth2","clientSecret":"value","accessToken":"value","refreshToken":"value"}`, "[]"), want: obsPlain(1)},
		// The material is stored whether or not the request sends it.
		{name: "disabled authentication still holds material", body: request("req_1", `{"type":"basic","disabled":true,"username":"a-user","password":"value"}`, "[]"), want: obsPlain(1)},
		{name: "the empty default", body: request("req_1", `{}`, "[]"), want: obsNone},
		{name: "no authentication", body: request("req_1", `{"type":"none"}`, "[]"), want: obsNone},
		{name: "a netrc entry holds its material elsewhere", body: request("req_1", `{"type":"netrc"}`, "[]"), want: obsNone},
		{name: "a username alone", body: request("req_1", `{"type":"basic","username":"a-user"}`, "[]"), want: obsNone},
		{name: "an empty token", body: request("req_1", `{"type":"bearer","token":""}`, "[]"), want: obsNone},
		{name: "a null token", body: request("req_1", `{"type":"bearer","token":null}`, "[]"), want: obsNone},
		// A tag refers to material resolved at run time; text beside one is not
		// classified either way.
		{name: "a template reference is not material", body: request("req_1", `{"type":"bearer","token":"{{ _.api_token }}"}`, "[]"), want: obsNone},
		{name: "a tag with a filter is still a reference", body: request("req_1", `{"type":"bearer","token":"{% response 'body', 'req_2', '$.token' %}"}`, "[]"), want: obsNone},
		{name: "text mixed with a tag", body: request("req_1", `{"type":"bearer","token":"prefix-{{ _.api_token }}"}`, "[]"), want: obsUnrec},
		{name: "an unknown authentication type", body: request("req_1", `{"type":"future","token":"value"}`, "[]"), want: obsUnrec},
		{name: "a keyed object with no type", body: request("req_1", `{"disabled":false}`, "[]"), want: obsUnrec},
		{name: "a material field of the wrong type", body: request("req_1", `{"type":"basic","password":42}`, "[]"), want: obsUnrec},
		{name: "authentication that is not an object", body: request("req_1", `"bearer"`, "[]"), want: obsUnrec},
		{name: "material beside a field of the wrong type", body: request("req_1", `{"type":"oauth2","clientSecret":"value","accessToken":["a"]}`, "[]"), want: alsoUnrec(obsPlain(1))},
		{name: "requests count separately", body: nedb(filled("bearer", "token"), request("req_2", `{"type":"basic","password":"value"}`, "[]")), want: obsPlain(2)},
		{name: "other request kinds carry the same object", body: `{"_id":"ws_1","type":"WebSocketRequest","authentication":{"type":"bearer","token":"value"}}`, want: obsPlain(1)},
		{name: "a socket request", body: `{"_id":"sio_1","type":"SocketIORequest","authentication":{"type":"apikey","value":"value"}}`, want: obsPlain(1)},
		{name: "an mcp request", body: `{"_id":"mcp_1","type":"McpRequest","authentication":{"type":"oauth2","clientSecret":"value"}}`, want: obsPlain(1)},
	})
}

// TestParseInsomnia_Headers covers the header names the protocol defines as
// carrying a credential, and the gRPC spelling of the same thing.
func TestParseInsomnia_Headers(t *testing.T) {
	runParseCases(t, parseInsomnia, []parseCase{
		{name: "authorization header", body: request("req_1", `{}`, `[{"name":"Authorization","value":"Bearer value"}]`), want: obsPlain(1)},
		{name: "names match without regard to case", body: request("req_1", `{}`, `[{"name":"authorization","value":"value"},{"name":"X-Api-Key","value":"value"},{"name":"proxy-authorization","value":"value"},{"name":"API-KEY","value":"value"}]`), want: obsPlain(4)},
		{name: "an ordinary header", body: request("req_1", `{}`, `[{"name":"Content-Type","value":"application/json"}]`), want: obsNone},
		{name: "a disabled header still holds material", body: request("req_1", `{}`, `[{"name":"Authorization","value":"value","disabled":true}]`), want: obsPlain(1)},
		{name: "a template value is a reference", body: request("req_1", `{}`, `[{"name":"Authorization","value":"Bearer {{ _.token }}"}]`), want: obsUnrec},
		{name: "a pure template value", body: request("req_1", `{}`, `[{"name":"Authorization","value":"{{ _.auth }}"}]`), want: obsNone},
		{name: "an empty value", body: request("req_1", `{}`, `[{"name":"Authorization","value":""}]`), want: obsNone},
		{name: "authentication and a header count separately", body: request("req_1", `{"type":"bearer","token":"value"}`, `[{"name":"Authorization","value":"value"}]`), want: obsPlain(2)},
		{name: "a header value of the wrong type", body: request("req_1", `{}`, `[{"name":"Authorization","value":7}]`), want: obsUnrec},
		{name: "headers that are not a list", body: request("req_1", `{}`, `{"Authorization":"value"}`), want: obsUnrec},
		{name: "no headers field", body: `{"_id":"req_1","type":"Request"}`, want: obsNone},
		{name: "grpc metadata", body: `{"_id":"gr_1","type":"GrpcRequest","metadata":[{"name":"authorization","value":"value"}]}`, want: obsPlain(1)},
		{name: "grpc reflection key", body: `{"_id":"gr_1","type":"GrpcRequest","reflectionApi":{"enabled":true,"url":"https://example.invalid","apiKey":"value"}}`, want: obsPlain(1)},
		{name: "grpc metadata and reflection key", body: `{"_id":"gr_1","type":"GrpcRequest","metadata":[{"name":"authorization","value":"value"}],"reflectionApi":{"apiKey":"value"}}`, want: obsPlain(2)},
		{name: "grpc reflection without a key", body: `{"_id":"gr_1","type":"GrpcRequest","reflectionApi":{"enabled":false,"url":"","apiKey":"","module":""}}`, want: obsNone},
		{name: "grpc reflection of the wrong shape", body: `{"_id":"gr_1","type":"GrpcRequest","reflectionApi":"value"}`, want: obsUnrec},
	})
}

// TestParseInsomnia_Environments covers the two representations an environment is
// stored in, the fixed set of variable names read as credentials, and the
// envelope a secret-typed variable is wrapped in.
func TestParseInsomnia_Environments(t *testing.T) {
	env := func(data, pairs string) string {
		return `{"_id":"env_1","type":"Environment","data":` + data + `,"kvPairData":` + pairs + `}`
	}
	runParseCases(t, parseInsomnia, []parseCase{
		{name: "a token variable", body: env(`{"token":"value"}`, `null`), want: obsPlain(1)},
		{name: "a token variable shaped like a shell reference", body: env(`{"token":"$VALUE"}`, `null`), want: obsPlain(1)},
		{name: "the same variable in both representations counts once", body: env(`{"api_token":"value"}`, `[{"id":"p1","name":"api_token","value":"value","type":"str","enabled":true}]`), want: obsPlain(1)},
		{name: "names fold case and hyphens", body: env(`{"API-KEY":"value","Client_Secret":"value"}`, `null`), want: obsPlain(2)},
		{name: "a name outside the set", body: env(`{"my_token":"value","base_url":"https://example.invalid"}`, `null`), want: obsNone},
		{name: "a private ordinary environment is still in the clear", body: `{"_id":"env_1","type":"Environment","isPrivate":true,"data":{"password":"value"}}`, want: obsPlain(1)},
		{name: "a template reference", body: env(`{"token":"{{ _.base_token }}"}`, `null`), want: obsNone},
		{name: "a credential name holding something other than a string", body: env(`{"token":42}`, `null`), want: obsUnrec},
		{name: "other names may hold anything", body: env(`{"retries":3,"headers":{"a":"b"}}`, `null`), want: obsNone},
		{name: "a pair alone", body: env(`{}`, `[{"name":"password","value":"value","type":"str"}]`), want: obsPlain(1)},
		{name: "a json-typed pair under a credential name", body: env(`{}`, `[{"name":"token","value":"{\"a\":1}","type":"json"}]`), want: obsPlain(1)},
		// A secret-typed variable is counted whatever its name, by how it is held.
		{name: "a secret with the vault envelope is protected", body: env(`{"__insomnia_vault":{"anything":"`+envelope()+`"}}`, `[{"name":"anything","value":"`+envelope()+`","type":"secret"}]`), want: obsProt(1)},
		{name: "the vault mirror alone", body: env(`{"__insomnia_vault":{"anything":"`+envelope()+`"}}`, `null`), want: obsProt(1)},
		{name: "a secret pair alone", body: env(`{}`, `[{"name":"anything","value":"`+envelope()+`","type":"secret"}]`), want: obsProt(1)},
		{name: "a secret written in the clear", body: env(`{}`, `[{"name":"anything","value":"value","type":"secret"}]`), want: obsPlain(1)},
		{name: "a secret that is base64 of something other than an envelope", body: env(`{}`, `[{"name":"anything","value":"dmFsdWU=","type":"secret"}]`), want: obsPlain(1)},
		{name: "an envelope missing its ciphertext", body: env(`{}`, `[{"name":"anything","value":"`+base64.StdEncoding.EncodeToString([]byte(`{"iv":"00112233445566778899aabb","t":"00112233445566778899aabbccddeeff","ad":""}`))+`","type":"secret"}]`), want: obsUnrec},
		{name: "an envelope with a short nonce", body: env(`{}`, `[{"name":"anything","value":"`+base64.StdEncoding.EncodeToString([]byte(`{"iv":"0011","t":"00112233445566778899aabbccddeeff","ad":"","d":"cafe"}`))+`","type":"secret"}]`), want: obsUnrec},
		{name: "an envelope that is not hex", body: env(`{}`, `[{"name":"anything","value":"`+base64.StdEncoding.EncodeToString([]byte(`{"iv":"zz112233445566778899aabb","t":"00112233445566778899aabbccddeeff","ad":"","d":"cafe"}`))+`","type":"secret"}]`), want: obsUnrec},
		{name: "an empty secret", body: env(`{}`, `[{"name":"anything","value":"","type":"secret"}]`), want: obsNone},
		{name: "a secret and a plain variable fold to the clear", body: env(`{"token":"value","__insomnia_vault":{"anything":"`+envelope()+`"}}`, `null`), want: obsPlain(2)},
		{name: "one name held encrypted and in the clear is one credential in the clear", body: env(`{"__insomnia_vault":{"token":"`+envelope()+`"}}`, `[{"name":"token","value":"value","type":"str"}]`), want: obsPlain(1)},
		{name: "one name held in the clear and encrypted is one credential in the clear", body: env(`{"token":"value"}`, `[{"name":"token","value":"`+envelope()+`","type":"secret"}]`), want: obsPlain(1)},
		{name: "a vault mirror of the wrong shape", body: env(`{"__insomnia_vault":["a"]}`, `null`), want: obsUnrec},
		{name: "a null data object", body: env(`null`, `null`), want: obsNone},
		{name: "data that is not an object", body: env(`"value"`, `null`), want: obsUnrec},
		{name: "pairs that are not a list", body: env(`{}`, `{"name":"token"}`), want: obsUnrec},
		{name: "a pair with a name of the wrong type", body: env(`{}`, `[{"name":1,"value":"value","type":"str"}]`), want: obsUnrec},
		// A folder carries an environment of its own beside its request settings.
		{name: "a folder environment", body: `{"_id":"fld_1","type":"RequestGroup","environment":{"password":"value"},"kvPairData":[{"name":"password","value":"value","type":"str"}]}`, want: obsPlain(1)},
		{name: "a folder with authentication, a header and a variable", body: `{"_id":"fld_1","type":"RequestGroup","authentication":{"type":"bearer","token":"value"},"headers":[{"name":"Authorization","value":"value"}],"environment":{"token":"value"}}`, want: obsPlain(3)},
		{name: "a folder with nothing filled", body: `{"_id":"fld_1","type":"RequestGroup","environment":{},"kvPairData":[]}`, want: obsNone},
	})
}

// TestParseInsomnia_OtherRecords covers the token store and the client
// certificate settings.
func TestParseInsomnia_OtherRecords(t *testing.T) {
	runParseCases(t, parseInsomnia, []parseCase{
		{name: "stored token with template syntax is literal", body: `{"_id":"tok_1","type":"OAuth2Token","accessToken":"{{ _.access_token }}"}`, want: obsPlain(1)},
		{name: "stored refresh token with tag syntax is literal", body: `{"_id":"tok_1","type":"OAuth2Token","refreshToken":"{% token %}"}`, want: obsPlain(1)},
		{name: "stored identity token with mixed syntax is literal", body: `{"_id":"tok_1","type":"OAuth2Token","identityToken":"prefix{{ token }}"}`, want: obsPlain(1)},
		{name: "certificate passphrase with template syntax is literal", body: `{"_id":"crt_1","type":"ClientCertificate","passphrase":"{{password}}"}`, want: obsPlain(1)},
		{name: "certificate passphrase with mixed syntax is literal", body: `{"_id":"crt_1","type":"ClientCertificate","passphrase":"prefix{% password %}"}`, want: obsPlain(1)},
		{name: "an access token", body: `{"_id":"tok_1","type":"OAuth2Token","accessToken":"value","refreshToken":"","identityToken":""}`, want: obsPlain(1)},
		{name: "an identity token alone", body: `{"_id":"tok_1","type":"OAuth2Token","identityToken":"value"}`, want: obsPlain(1)},
		{name: "all three tokens are one credential", body: `{"_id":"tok_1","type":"OAuth2Token","accessToken":"value","refreshToken":"value","identityToken":"value"}`, want: obsPlain(1)},
		{name: "an emptied token record", body: `{"_id":"tok_1","type":"OAuth2Token","accessToken":"","refreshToken":"","identityToken":""}`, want: obsNone},
		{name: "a token of the wrong type", body: `{"_id":"tok_1","type":"OAuth2Token","accessToken":{"a":1}}`, want: obsUnrec},
		{name: "a certificate passphrase", body: `{"_id":"crt_1","type":"ClientCertificate","passphrase":"value","cert":"/path/to/cert.pem","key":"/path/to/key.pem","pfx":null}`, want: obsPlain(1)},
		// The paths name files this source does not read.
		{name: "certificate paths alone", body: `{"_id":"crt_1","type":"ClientCertificate","passphrase":null,"cert":"/path/to/cert.pem","key":"/path/to/key.pem","pfx":"/path/to/bundle.pfx"}`, want: obsNone},
		{name: "a passphrase of the wrong type", body: `{"_id":"crt_1","type":"ClientCertificate","passphrase":true}`, want: obsUnrec},
	})
}

func TestParseInsomnia_StoredCredentials(t *testing.T) {
	runParseCases(t, parseInsomnia, []parseCase{
		{name: "legacy git tokens", body: `{"_id":"git_1","type":"GitCredentials","token":"value","refreshToken":"value"}`, want: obsPlain(1)},
		{name: "stored tokens do not render templates", body: `{"_id":"git_1","type":"GitCredentials","token":"{{ literal }}"}`, want: obsPlain(1)},
		{name: "git oauth tokens", body: `{"_id":"git_1","type":"GitCredentials","provider":"github","credentials":{"token":"value","refreshToken":"value"}}`, want: obsPlain(1)},
		{name: "git personal access token", body: `{"_id":"git_1","type":"GitCredentials","provider":"custom","credentials":{"username":"user","password":"value"}}`, want: obsPlain(1)},
		{name: "legacy and current git tokens count once", body: `{"_id":"git_1","type":"GitCredentials","token":"value","credentials":{"token":"value"}}`, want: obsPlain(1)},
		{name: "native git has no stored credential", body: `{"_id":"git_1","type":"GitCredentials","provider":"native","author":{"name":"user"}}`, want: obsNone},
		{name: "git username alone", body: `{"_id":"git_1","type":"GitCredentials","credentials":{"username":"user"}}`, want: obsNone},
		{name: "legacy repository password", body: `{"_id":"repo_1","type":"GitRepository","credentials":{"username":"user","password":"value"}}`, want: obsPlain(1)},
		{name: "legacy repository oauth", body: `{"_id":"repo_1","type":"GitRepository","credentials":{"token":"value","oauth2format":"github"}}`, want: obsPlain(1)},
		{name: "repository reference only", body: `{"_id":"repo_1","type":"GitRepository","credentials":null,"credentialsId":"git_1","uri":"https://example.invalid/repo"}`, want: obsNone},
		{name: "malformed nested git credentials", body: `{"_id":"git_1","type":"GitCredentials","credentials":[]}`, want: obsUnrec},
		{name: "malformed token beside legacy material", body: `{"_id":"git_1","type":"GitCredentials","token":"value","credentials":{"token":3}}`, want: alsoUnrec(obsPlain(1))},
	})
}

func TestParseInsomnia_CloudCredentials(t *testing.T) {
	runParseCases(t, parseInsomnia, []parseCase{
		{name: "aws temporary credentials", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"aws","credentials":{"type":"temporary","accessKeyId":"identifier","secretAccessKey":"value","sessionToken":"value"}}`, want: obsPlain(1)},
		{name: "aws session token alone", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"aws","credentials":{"sessionToken":"value"}}`, want: obsPlain(1)},
		{name: "aws identifier alone", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"aws","credentials":{"accessKeyId":"identifier"}}`, want: obsNone},
		{name: "aws file reference", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"aws","credentials":{"type":"file","filePath":"/elsewhere/credentials","section":"default"}}`, want: obsNone},
		{name: "aws sso reference", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"aws","credentials":{"type":"sso","configFilePath":"/elsewhere/config","section":"default"}}`, want: obsNone},
		{name: "gcp file reference", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"gcp","credentials":{"serviceAccountKeyFilePath":"/elsewhere/key.json"}}`, want: obsNone},
		{name: "azure token", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"azure","credentials":{"accessToken":"value","account":{"username":"user"}}}`, want: obsPlain(1)},
		{name: "hashicorp client credentials", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"hashicorp","credentials":{"client_id":"identifier","client_secret":"value","access_token":"value"}}`, want: obsPlain(1)},
		{name: "hashicorp approle", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"hashicorp","credentials":{"role_id":"identifier","secret_id":"value"}}`, want: obsPlain(1)},
		{name: "hashicorp identifiers alone", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"hashicorp","credentials":{"role_id":"identifier","client_id":"identifier"}}`, want: obsNone},
		{name: "empty cloud record", body: `{"_id":"cloud_1","type":"CloudCredential","credentials":null}`, want: obsNone},
		{name: "unknown provider", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"future","credentials":{"token":"value"}}`, want: obsUnrec},
		{name: "malformed credentials", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"aws","credentials":true}`, want: obsUnrec},
		{name: "malformed secret beside token", body: `{"_id":"cloud_1","type":"CloudCredential","provider":"aws","credentials":{"secretAccessKey":3,"sessionToken":"value"}}`, want: alsoUnrec(obsPlain(1))},
	})
}

func TestParseInsomnia_UserSession(t *testing.T) {
	protected, err := base64.StdEncoding.DecodeString(envelope())
	if err != nil {
		t.Fatal(err)
	}
	key := `{"kty":"oct","k":"c3ludGhldGljLWtleQ"}`
	runParseCases(t, parseInsomnia, []parseCase{
		{name: "session authentication id", body: `{"_id":"usr_1","type":"UserSession","id":"value"}`, want: obsPlain(1)},
		{name: "public identity is not a credential", body: `{"_id":"usr_1","type":"UserSession","accountId":"account","email":"user@example.invalid","publicKey":{"kty":"RSA","n":"value","e":"AQAB"},"vaultSalt":"value"}`, want: obsNone},
		{name: "initial empty session", body: `{"_id":"usr_1","type":"UserSession","id":"","symmetricKey":{},"encPrivateKey":{},"vaultKey":""}`, want: obsNone},
		{name: "readable symmetric key", body: `{"_id":"usr_1","type":"UserSession","symmetricKey":` + key + `}`, want: obsPlain(1)},
		{name: "encrypted private key", body: `{"_id":"usr_1","type":"UserSession","encPrivateKey":` + string(protected) + `}`, want: obsProt(1)},
		{name: "session and both account keys", body: `{"_id":"usr_1","type":"UserSession","id":"value","symmetricKey":` + key + `,"encPrivateKey":` + string(protected) + `}`, want: obsPlain(3)},
		{name: "vault key readable fallback", body: `{"_id":"usr_1","type":"UserSession","vaultKey":"` + base64.StdEncoding.EncodeToString([]byte(key)) + `"}`, want: obsPlain(1)},
		{name: "opaque vault key is not assumed plaintext", body: `{"_id":"usr_1","type":"UserSession","vaultKey":"763130001122334455"}`, want: obsUnrec},
		{name: "opaque vault does not hide session", body: `{"_id":"usr_1","type":"UserSession","id":"value","vaultKey":"opaque"}`, want: alsoUnrec(obsPlain(1))},
		{name: "public key shape in symmetric slot", body: `{"_id":"usr_1","type":"UserSession","symmetricKey":{"kty":"RSA","n":"value"}}`, want: obsUnrec},
		{name: "missing private ciphertext", body: `{"_id":"usr_1","type":"UserSession","encPrivateKey":{"iv":"00112233445566778899aabb","t":"00112233445566778899aabbccddeeff","ad":""}}`, want: obsUnrec},
		{name: "wrong key type", body: `{"_id":"usr_1","type":"UserSession","symmetricKey":[]}`, want: obsUnrec},
		{name: "wrong session id type", body: `{"_id":"usr_1","type":"UserSession","id":3}`, want: obsUnrec},
	})
}

// TestParseInsomnia_Database covers appended revisions, tombstones and indexes.
func TestParseInsomnia_Database(t *testing.T) {
	bearer := request("req_1", `{"type":"bearer","token":"value"}`, "[]")
	two := request("req_1", `{"type":"bearer","token":"value"}`, `[{"name":"Authorization","value":"value"}]`)
	empty := request("req_1", `{}`, "[]")
	tombstone := `{"_id":"req_1","$$deleted":true}`
	index := `{"$$indexCreated":{"fieldName":"type","unique":false,"sparse":false}}`
	runParseCases(t, parseInsomnia, []parseCase{
		// Each save appends a revision; the record is still one credential.
		{name: "revisions of one record count once", body: nedb(bearer, bearer, bearer), want: obsPlain(1)},
		{name: "the largest revision sets the count", body: nedb(two, bearer), want: obsPlain(2)},
		{name: "emptying a record leaves its earlier revision readable", body: nedb(bearer, empty), want: obsPlain(1)},
		// A tombstone hides the record from the application; the bytes remain.
		{name: "a deleted record is still in the file", body: nedb(bearer, tombstone), want: obsPlain(1)},
		{name: "a tombstone alone", body: nedb(tombstone), want: obsNone},
		{name: "a compacted file holds only what is current", body: nedb(empty), want: obsNone},
		{name: "index lines are bookkeeping", body: nedb(index, `{"$$indexRemoved":"type"}`, bearer), want: obsPlain(1)},
		{name: "index lines alone", body: nedb(index), want: obsNone},
		{name: "blank lines and carriage returns", body: "\n" + bearer + "\r\n\n" + tombstone + "\r\n", want: obsPlain(1)},
		{name: "material beside a line that is not a record", body: nedb(bearer, `{"_id":"req_2","type":"Request","authentication":{`), want: alsoUnrec(obsPlain(1))},
		{name: "a record kind this build does not read", body: `{"_id":"wrk_1","type":"Workspace","name":"a-workspace"}`, want: obsUnrec},
		{name: "an export row carries no type", body: `{"_id":"req_1","_type":"request","authentication":{"type":"bearer","token":"value"}}`, want: obsUnrec},
		{name: "a record without an identifier", body: `{"type":"Request","authentication":{"type":"bearer","token":"value"}}`, want: obsUnrec},
		{name: "an identifier of the wrong type", body: `{"_id":7,"type":"Request"}`, want: obsUnrec},
		{name: "a line that is a list", body: `[{"_id":"req_1"}]`, want: obsUnrec},
		{name: "a line that is a scalar", body: `"req_1"`, want: obsUnrec},
		{name: "not a database at all", body: "PK\x03\x04binary", want: obsUnrec},
		{name: "blank file", body: "\n\n", want: obsNone},
	})
}

// TestParseInsomnia_History covers the retained request revisions, which hold
// whole earlier requests compressed and encoded, and the bound on expanding them.
func TestParseInsomnia_History(t *testing.T) {
	version := func(id, packed string) string {
		return `{"_id":"` + id + `","type":"RequestVersion","parentId":"req_1","compressedRequest":"` + packed + `"}`
	}
	inner := `{"_id":"req_1","type":"Request","authentication":{"type":"bearer","token":"value"},"headers":[]}`
	// A document that inflates past the whole budget while staying small on disk.
	oversize := `{"_id":"req_1","type":"Request","authentication":{"type":"bearer","token":"value"},"description":"` + strings.Repeat("a", insomniaMaxExpanded) + `"}`
	// Two of these fit the read cap and together exceed the expansion budget.
	half := `{"_id":"req_1","type":"Request","authentication":{"type":"bearer","token":"value"},"description":"` + strings.Repeat("a", insomniaMaxExpanded*3/5) + `"}`
	// A stream that inflates most of its bytes and then fails its checksum.
	damaged := func(doc string) string {
		raw, err := base64.StdEncoding.DecodeString(compressed(doc))
		if err != nil {
			panic(err)
		}
		raw[len(raw)-5] ^= 0xff
		return base64.StdEncoding.EncodeToString(raw)
	}
	runParseCases(t, parseInsomnia, []parseCase{
		{name: "an earlier revision holding a token", body: version("rv_1", compressed(inner)), want: obsPlain(1)},
		{name: "an earlier grpc revision", body: version("rv_1", compressed(`{"_id":"gr_1","type":"GrpcRequest","reflectionApi":{"apiKey":"value"}}`)), want: obsPlain(1)},
		{name: "revisions count separately", body: nedb(version("rv_1", compressed(inner)), version("rv_2", compressed(inner))), want: obsPlain(2)},
		{name: "a revision holding nothing", body: version("rv_1", compressed(`{"_id":"req_1","type":"Request","authentication":{}}`)), want: obsNone},
		{name: "no compressed body", body: `{"_id":"rv_1","type":"RequestVersion","compressedRequest":null}`, want: obsNone},
		{name: "an empty compressed body", body: version("rv_1", ""), want: obsNone},
		{name: "a body that is not base64", body: version("rv_1", "not base64!"), want: obsUnrec},
		{name: "a body that is not gzip", body: version("rv_1", base64.StdEncoding.EncodeToString([]byte(inner))), want: obsUnrec},
		{name: "a truncated stream", body: version("rv_1", compressed(inner)[:len(compressed(inner))/2]), want: obsUnrec},
		{name: "a stream holding something other than an object", body: version("rv_1", compressed(`["a"]`)), want: obsUnrec},
		// History holds requests; anything else inside it is a shape this build
		// cannot account for, and history cannot nest history.
		{name: "a nested revision", body: version("rv_1", compressed(version("rv_2", compressed(inner)))), want: obsUnrec},
		{name: "an environment inside history", body: version("rv_1", compressed(`{"_id":"env_1","type":"Environment","data":{"token":"value"}}`)), want: obsUnrec},
		{name: "material beside a damaged revision", body: nedb(version("rv_1", compressed(inner)), version("rv_2", "not base64!")), want: alsoUnrec(obsPlain(1))},
		// The bound stops the expansion and the revision contributes nothing:
		// nothing about it was read, so the count is a lower bound and says so.
		{name: "a revision past the expansion bound", body: version("rv_1", compressed(oversize)), want: alsoCapped(obsNone)},
		{name: "revisions exhausting the budget together", body: nedb(version("rv_1", compressed(half)), version("rv_2", compressed(half))), want: alsoCapped(obsPlain(1))},
		{name: "damaged revisions still spend the budget", body: nedb(version("rv_1", damaged(half)), version("rv_2", compressed(half))), want: alsoCapped(obsUnrec)},
	})
}

// TestParseInsomnia_CountBound holds the most one finding may report. Past it the
// count stands as a lower bound and the observation says so.
func TestParseInsomnia_CountBound(t *testing.T) {
	var body strings.Builder
	for i := 0; i <= insomniaMaxCount; i++ {
		body.WriteString(`{"_id":"tok_` + strconv.Itoa(i) + `","type":"OAuth2Token","accessToken":"value"}` + "\n")
	}
	got := parseInsomnia([]byte(body.String()))
	if want := alsoCapped(obsPlain(insomniaMaxCount)); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseInsomnia_CountBoundPreservesProtection(t *testing.T) {
	var protected strings.Builder
	for i := range insomniaMaxCount {
		protected.WriteString(`{"_id":"env_` + strconv.Itoa(i) + `","type":"Environment","data":{"__insomnia_vault":{"token":"` + envelope() + `"}}}` + "\n")
	}
	plain := `{"_id":"plain","type":"Environment","data":{"token":"value"}}` + "\n"
	runParseCases(t, parseInsomnia, []parseCase{
		{name: "exact bound stays complete", body: protected.String(), want: obsProt(insomniaMaxCount)},
		{name: "plaintext after count bound", body: protected.String() + plain, want: alsoCapped(obsPlain(insomniaMaxCount))},
		{name: "plaintext before count bound", body: plain + protected.String(), want: alsoCapped(obsPlain(insomniaMaxCount))},
	})
}

// TestParseInsomnia_ObservationCarriesNoValue pins that what the parser returns is
// counts and states only, whatever the file held.
func TestParseInsomnia_ObservationCarriesNoValue(t *testing.T) {
	marker := "MARKER-7c1e-DO-NOT-EMIT"
	bodies := []string{
		`{"_id":"git_1","type":"GitCredentials","credentials":{"token":"` + marker + `"}}`,
		`{"_id":"repo_1","type":"GitRepository","credentials":{"password":"` + marker + `"}}`,
		`{"_id":"cloud_1","type":"CloudCredential","provider":"hashicorp","credentials":{"client_secret":"` + marker + `"}}`,
		`{"_id":"usr_1","type":"UserSession","id":"` + marker + `","symmetricKey":{"kty":"oct","k":"` + marker + `"}}`,
		request("req_1", `{"type":"bearer","token":"`+marker+`"}`, `[{"name":"Authorization","value":"`+marker+`"}]`),
		`{"_id":"env_1","type":"Environment","data":{"token":"` + marker + `"},"kvPairData":[{"name":"` + marker + `","value":"` + marker + `","type":"secret"}]}`,
		`{"_id":"rv_1","type":"RequestVersion","compressedRequest":"` + compressed(request("req_1", `{"type":"bearer","token":"`+marker+`"}`, "[]")) + `"}`,
		`{"_id":"` + marker + `","type":"Request","authentication":{`,
	}
	for _, body := range bodies {
		payload, err := json.Marshal(parseInsomnia([]byte(body)))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(payload), marker) {
			t.Errorf("observation carries the value: %s", payload)
		}
	}
}
