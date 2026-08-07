package credentials

import (
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// validProtections is the closed vocabulary a parser may resolve to. Anything else
// reaches the wire as a value no reader knows how to render.
var validProtections = map[string]bool{
	model.CredentialProtectionPlaintext: true,
	model.CredentialProtectionProtected: true,
	model.CredentialProtectionExternal:  true,
	model.CredentialProtectionUnknown:   true,
}

// checkObservation asserts the invariants every parser owes its caller, whatever
// it was handed.
func checkObservation(t *testing.T, sourceID string, obs observation) {
	t.Helper()
	switch {
	case obs.Count < 0:
		t.Errorf("%s: negative count %d", sourceID, obs.Count)
	case obs.Count == 0:
		// Nothing found is the one case with no protection state: there is nothing
		// for a state to describe.
		if obs.Protection != "" {
			t.Errorf("%s: empty observation carries protection %q", sourceID, obs.Protection)
		}
	default:
		if !validProtections[obs.Protection] {
			t.Errorf("%s: count %d carries protection %q, which is not a model value", sourceID, obs.Count, obs.Protection)
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
		"users:\n  - user:\n      token: v\n",
		"github.com:\n    oauth_token: v\n",
		"machine example.com login u password p\n",
		"macdef x\n",
		"https://u:p@example.com\n",
		"//r/:_authToken=v\n",
		"[credential]\n\thelper = store\n",
		`{"mcpServers":{"d":{"env":{"API_KEY":"v"}}}}`,
		"\x00\x00\x00\x00",
		"\r\n\r\n",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, s := range sources {
			if s.Mode == readStat {
				// That source is classified from its metadata; it has no parser to
				// drive because it never opens the file.
				continue
			}
			obs, hosts := parseSource(s, "config.json", data)
			checkObservation(t, s.ID, obs)
			for _, h := range hosts {
				if h.AccountCount < 0 {
					t.Errorf("%s: negative account count for a host", s.ID)
				}
			}
		}
		// The key classifier is reached through the directory listing rather than
		// the dispatch, so it is driven directly.
		if state, isKey := classifySSHKey(data); isKey && !validProtections[state] {
			t.Errorf("ssh: key classified %q, which is not a model value", state)
		}
	})
}

// FuzzParseGHStatus drives the one parser whose input is another program's output.
// That shape has changed across releases, so unfamiliar input is the expected case.
func FuzzParseGHStatus(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		`{"hosts":{}}`,
		`{"hosts":{"github.com":[{"active":true,"state":"success","scopes":"repo,read:org"}]}}`,
		`{"hosts":{"github.com":{"active":true,"state":"error"}}}`,
		`{"hosts":{"github.com":"a string where a record belongs"}}`,
		`{"hosts":[]}`,
		"unknown flag: --json\n",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		byHost, ok := parseGHStatus(data)
		if !ok {
			if byHost != nil {
				t.Error("a failed parse must return no hosts")
			}
			return
		}
		configs := []githubHostConfig{{Host: "github.com", AccountCount: 1}}
		for _, report := range githubHostReports(configs, byHost, model.CredentialScopeUnavailable) {
			if report.ScopeStatus == "" {
				t.Error("scopes must never travel without a status")
			}
			if len(report.Scopes) > 0 && report.ScopeStatus != model.CredentialScopeObserved {
				t.Errorf("scopes %v reported with status %q", report.Scopes, report.ScopeStatus)
			}
			for _, scope := range report.Scopes {
				if scope == "" {
					t.Error("an empty scope reached the wire")
				}
			}
		}
	})
}
