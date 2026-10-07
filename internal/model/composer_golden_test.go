package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestComposerGoldenContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/composer_inventory_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "002d4f16d55afef6abc21dd36ea2d1cccee0bd98a4c15bcb736628d43fc2879f" {
		t.Fatal("shared Composer fixture digest changed; update both producer and consumer after review")
	}
	var pair struct {
		Inventory *ComposerInventory   `json:"composer_inventory"`
		Audit     *ComposerConfigAudit `json:"composer_config_audit"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pair); err != nil {
		t.Fatal(err)
	}
	if pair.Inventory == nil || pair.Audit == nil {
		t.Fatal("missing section")
	}
	encoded, err := json.Marshal(pair)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodeGeneric(t, encoded), decodeGeneric(t, raw)) {
		t.Fatal("wire round-trip dropped a field")
	}
	seen := map[string]bool{}
	for _, s := range pair.Inventory.Sources {
		seen["status:"+s.Status] = true
	}
	for _, p := range pair.Inventory.Packages {
		seen["scope:"+p.Scope], seen["evidence:"+p.Evidence], seen["checksum:"+p.ChecksumStatus] = true, true, true
		if p.Installation != nil {
			seen["presence:"+p.Installation.Presence] = true
		}
	}
	for _, key := range []string{"scope:project", "scope:global", "scope:unknown", "evidence:declared_requirement", "evidence:locked_package", "evidence:installed_package", "status:partial", "checksum:recorded", "presence:present", "presence:absent", "presence:not_applicable"} {
		if !seen[key] {
			t.Errorf("fixture does not exercise %s", key)
		}
	}
}
