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

func TestRubyGoldenContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/ruby_inventory_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "6fbfc578f80110235d3abcbbed43bea50c8f6dab1b8e62d72425abd284ce9424" {
		t.Fatal("shared Ruby fixture digest changed; update both producer and consumer after review")
	}
	var pair struct {
		Inventory *RubyInventory   `json:"ruby_inventory"`
		Audit     *RubyConfigAudit `json:"ruby_config_audit"`
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
		seen["scope:"+p.Scope], seen["evidence:"+p.Evidence], seen["checksum:"+p.ChecksumStatus], seen["origin:"+p.Origin.Kind] = true, true, true, true
		if p.Installation != nil {
			seen["presence:"+p.Installation.Presence] = true
			if p.Installation.DefaultGem {
				seen["default_gem"] = true
			}
		}
	}
	for _, c := range pair.Audit.Contexts {
		seen["context:"+c.Manager] = true
	}
	for _, f := range pair.Audit.Findings {
		seen["finding:"+f.Code] = true
	}
	for _, key := range []string{
		"scope:project", "scope:user", "status:partial",
		"evidence:declared_requirement", "evidence:locked_package", "evidence:installed_package", "evidence:cached_package",
		"checksum:recorded", "checksum:partial", "checksum:absent",
		"origin:registry", "origin:git", "origin:path", "origin:unknown",
		"presence:present", "presence:absent", "presence:not_applicable", "default_gem",
		"context:rubygems", "context:bundler", "finding:ruby-001", "finding:ruby-002", "finding:ruby-003", "finding:ruby-004",
	} {
		if !seen[key] {
			t.Errorf("fixture does not exercise %s", key)
		}
	}
}
