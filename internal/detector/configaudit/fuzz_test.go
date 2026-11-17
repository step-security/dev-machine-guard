package configaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func FuzzNPMRCSecrets(f *testing.F) {
	for _, seed := range []string{"//registry.example/:_authToken=synthetic-token", "_authToken=${TOKEN}", "\xef\xbb\xbf_auth=\"value\"\r\n", "", "\xff\x00", "[]"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		parsed, _ := parseNPMRC(data)
		for _, e := range parsed {
			if e.IsAuth && !e.IsEnvRef && e.ValueSHA256 != "" && (!strings.HasPrefix(e.DisplayValue, "***") || len(e.DisplayValue) > 7) {
				t.Fatal("auth entry exposes an unredacted value")
			}
			if e.ValueSHA256 != "" {
				if b, err := hex.DecodeString(e.ValueSHA256); err != nil || len(b) != sha256.Size {
					t.Fatal("invalid value fingerprint")
				}
			}
		}
		// Encode arbitrary bytes into a synthetic, single-line literal credential.
		token := "fuzz-token-" + hex.EncodeToString(data)
		entries, _ := parseNPMRC([]byte("//registry.example/:_authToken=" + token + "\n_auth=${DMG_FUZZ_TOKEN}\n"))
		if len(entries) != 2 {
			t.Fatal("lost controlled auth entries")
		}
		e := entries[0]
		sum := sha256.Sum256([]byte(token))
		if !e.IsAuth || e.IsEnvRef || e.ValueSHA256 != hex.EncodeToString(sum[:]) || e.DisplayValue != "***"+token[len(token)-4:] {
			t.Fatal("literal credential classification/redaction/hash changed")
		}
		b, err := json.Marshal(entries)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(token)) {
			t.Fatal("raw credential serialized")
		}
		if !entries[1].IsEnvRef || entries[1].DisplayValue != "${DMG_FUZZ_TOKEN}" {
			t.Fatal("environment reference expanded or lost")
		}
	})
}

func FuzzSwiftConfig(f *testing.F) {
	for _, s := range []string{
		`{"object":[{"original":"https://github.com/a/a.git","mirror":"http://u:p@m.example/a.git"},{"original":"git@h:a/a.git","mirror":"/srv/a"}],"version":1}`,
		`{"version":1,"registries":{"[default]":{"url":"http://r.example","supportsAvailability":false},"s":{"url":"https://u:p@r.example/x"}},` +
			`"authentication":{"r.example":{"type":"token","loginAPIPath":"/login"}},` +
			`"security":{"default":{"signing":{"onUnsigned":"silentAllow","onUntrustedCertificate":"warn"}},"registryOverrides":{"r.example":{"signing":{"onUnsigned":"silentAllow"}}}}}`,
		`{"version":2,"registries":{}}`, "", "{", "\xff\x00",
	} {
		f.Add([]byte(s))
	}
	urlKey := func(key string) bool {
		return strings.HasSuffix(key, ".url") || strings.HasSuffix(key, ".original") || strings.HasSuffix(key, ".mirror")
	}
	parse := func(t *testing.T, data []byte) []byte {
		t.Helper()
		a := &SwiftConfigSnapshot{audit: emptySwiftAudit()}
		files := []model.RubyConfigFile{{SourceID: "m"}, {SourceID: "r"}}
		a.parseMirrors(&files[0], data)
		a.parseRegistries(&files[1], data)
		findings := []model.CargoConfigFinding{}
		for _, file := range files {
			for _, s := range file.Settings {
				if !urlKey(s.Key) || s.Redacted {
					continue
				}
				if _, literal, ok := SwiftURL(s.Display); !ok || literal {
					t.Fatalf("unredacted display %q is not a clean location", s.Display)
				}
			}
			findings = append(findings, swiftFindings(file)...)
		}
		out, err := json.Marshal(struct {
			Files    []model.RubyConfigFile
			Findings []model.CargoConfigFinding
		}{files, findings})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		if !bytes.Equal(parse(t, data), parse(t, data)) {
			t.Fatal("config parse is not deterministic")
		}
		// A literal credential in any accepted URL field never reaches the wire.
		sum := sha256.Sum256(data)
		token := "fuzz-token-" + hex.EncodeToString(sum[:])
		for _, doc := range []string{
			`{"object":[{"original":"https://u:` + token + `@h/a","mirror":"https://u:` + token + `@m/a"}]}`,
			`{"version":1,"registries":{"[default]":{"url":"https://u:` + token + `@r/x"}}}`,
		} {
			if out := parse(t, []byte(doc)); bytes.Contains(out, []byte(token)) || !bytes.Contains(out, []byte(swiftLiteralSuffix)) {
				t.Fatal("literal credential serialized or not flagged")
			}
		}
	})
}
