package configaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func FuzzNPMRCSecrets(f *testing.F) {
	for _, seed := range []string{"//registry.example/:_authToken=synthetic-token", "_authToken=${TOKEN}", "\xef\xbb\xbf_auth=\"value\"\r\n", "", "\xff\x00", "[]"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		for _, e := range parseNPMRC(data) {
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
		entries := parseNPMRC([]byte("//registry.example/:_authToken=" + token + "\n_auth=${DMG_FUZZ_TOKEN}\n"))
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
