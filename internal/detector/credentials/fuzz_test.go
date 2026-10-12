package credentials

import (
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// materialProtections is the closed vocabulary a finding may carry. Anything else
// reaches the wire as a value no reader knows how to render.
var materialProtections = map[string]bool{
	model.CredentialProtectionPlaintext: true,
	model.CredentialProtectionProtected: true,
}

// checkObservation asserts the invariants every parser owes its caller, whatever
// it was handed. The two directions matter equally: a count with no protection
// would reach a reader as a credential it cannot render, and a protection with no
// count would be a state describing nothing.
func checkObservation(t *testing.T, sourceID string, obs observation) {
	t.Helper()
	switch {
	case obs.Count < 0:
		t.Errorf("%s: negative count %d", sourceID, obs.Count)
	case obs.Count == 0:
		if obs.Protection != "" {
			t.Errorf("%s: empty observation carries protection %q", sourceID, obs.Protection)
		}
	default:
		if !materialProtections[obs.Protection] {
			t.Errorf("%s: count %d carries protection %q, which is not a material state", sourceID, obs.Count, obs.Protection)
		}
	}
}

// FuzzParseSource drives every parser with arbitrary bytes. Real inputs are bounded
// by each source's byte cap, so the risk here is not size but shape: a credential
// file is written by tools, edited by hand, and truncated by whatever wrote it last.
// A parser that panics takes the whole scan with it.
func FuzzParseSource(f *testing.F) {
	seeds := []string{
		"",
		"\n",
		bomMark,
		"\xFF\xFE\x00",
		"[default]\naws_secret_access_key = value\n",
		"[",
		"]",
		"=",
		"[a]\n=\n",
		`{"auths":{"r":{"auth":"v"}}}`,
		`{`,
		`{"credentials":{"h":{"token":"v"}}}`,
		`{"type":"authorized_user","client_secret":"v"}`,
		`{"refresh_token":{"wrong":"type"}}`,
		"users:\n  - user:\n      token: v\n",
		"users:\n  - user:\n      client-key-data: dmFsdWU=\n",
		"example.invalid:\n    oauth_token: v\n",
		"machine example.invalid login u password p\n",
		"macdef x\n",
		"machine example.invalid login password p\n",
		"https://u:p@example.invalid\n",
		"https://u:p@\n",
		"//r/:_authToken=v\n",
		"${VAULT_TOKEN}\n",
		`{"_id":"req_1","type":"Request","authentication":{"type":"bearer","token":"v"},"headers":[{"name":"Authorization","value":"v"}]}` + "\n",
		`{"_id":"req_1","$$deleted":true}` + "\n",
		`{"$$indexCreated":{"fieldName":"type","unique":false}}` + "\n",
		`{"_id":"env_1","type":"Environment","data":{"__insomnia_vault":{"k":"` + envelope() + `"}},"kvPairData":[{"name":"k","value":"` + envelope() + `","type":"secret"}]}` + "\n",
		`{"_id":"rv_1","type":"RequestVersion","compressedRequest":"` + compressed(`{"_id":"req_1","type":"Request","authentication":{"type":"bearer","token":"v"}}`) + `"}` + "\n",
		`{"_id":"rv_1","type":"RequestVersion","compressedRequest":"H4sI"}` + "\n",
		"\x00\x00\x00\x00",
		"\r\n\r\n",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, s := range sources {
			if s.Mode == readKeyDir {
				// That source is classified by the key validator the directory
				// listing drives, not through the dispatch; it is driven below.
				continue
			}
			checkObservation(t, s.ID, parseSource(s, data))
		}
		state, material, _ := classifySSHKey(data)
		switch {
		case material && !materialProtections[state]:
			t.Errorf("ssh: key classified %q, which is not a material state", state)
		case !material && state != "":
			t.Errorf("ssh: no material found but protection %q was reported", state)
		}
	})
}
