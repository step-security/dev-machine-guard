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

func TestNuGetGoldenContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/nuget_inventory_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "2524e51e20a70c3e6663e64ef6537b8eadcddab2669756291db278816ff969c6" {
		t.Fatal("shared NuGet fixture digest changed; update both producer and consumer after review")
	}
	var pair struct {
		Inventory *NuGetInventory   `json:"nuget_inventory"`
		Audit     *NuGetConfigAudit `json:"nuget_config_audit"`
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
	for _, p := range pair.Inventory.Projects {
		seen["project:"+p.ProjectKind] = true
	}
	for _, p := range pair.Inventory.Packages {
		seen["scope:"+p.Scope], seen["evidence:"+p.Evidence], seen["checksum:"+p.ChecksumStatus], seen["origin:"+p.Origin.Kind] = true, true, true, true
		if p.Installation != nil {
			seen["presence:"+p.Installation.Presence] = true
		}
		for _, h := range p.RecordedChecksums {
			seen["hash:"+h.Kind] = true
		}
	}
	for _, c := range pair.Audit.Contexts {
		seen["context:"+c.ContextKind] = true
	}
	for _, f := range pair.Audit.Findings {
		seen["finding:"+f.Code] = true
	}
	for _, key := range []string{
		"scope:project", "scope:user", "scope:unknown", "status:partial",
		"evidence:declared_requirement", "evidence:locked_package", "evidence:restored_package", "evidence:cached_package", "evidence:installed_tool", "evidence:installed_template", "evidence:binary_dependency",
		"project:msbuild", "project:legacy", "project:tool_manifest", "project:file_based", "project:fsharp_script",
		"checksum:recorded", "checksum:partial", "checksum:not_recorded", "hash:content", "hash:archive",
		"origin:feed", "origin:local", "origin:unknown", "presence:present", "presence:absent",
		"context:ambient", "context:restore", "finding:nuget-001", "finding:nuget-002", "finding:nuget-003", "finding:nuget-004",
	} {
		if !seen[key] {
			t.Errorf("fixture does not exercise %s", key)
		}
	}
}
