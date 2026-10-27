package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"testing"
)

func TestCondaGoldenContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/conda_inventory_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "c1f8ecfe26760e3d92dd5210557fb14441ce7152e02fcbb62ad742b4cd22c491" {
		t.Fatal("shared Conda fixture digest changed; update both producer and consumer after review")
	}
	var pair struct {
		Inventory *CondaInventory   `json:"conda_inventory"`
		Audit     *CondaConfigAudit `json:"conda_config_audit"`
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
		seen["status:"+s.Status], seen["kind:"+s.Kind] = true, true
		for _, r := range s.Reasons {
			seen["reason:"+r] = true
		}
	}
	for _, p := range pair.Inventory.Packages {
		seen["scope:"+p.Scope], seen["evidence:"+p.Evidence], seen["checksum:"+p.ChecksumStatus], seen["origin:"+p.Origin.Kind], seen["relation:"+p.DependencyRelation] = true, true, true, true, true
		seen["subdir:"+p.Subdir], seen["version:"+p.VersionStatus] = true, true
		if p.BuildNumber != nil {
			seen["build_number:"+strconv.FormatInt(*p.BuildNumber, 10)] = true
		}
		if p.LockEnvironment != "" {
			seen["lock_environment"] = true
		}
		if p.TargetPlatform != "" {
			seen["target_platform"] = true
		}
		for _, s := range p.RequestedSpecs {
			if s == "[redacted]" {
				seen["redacted_spec"] = true
			}
		}
		if p.Installation != nil {
			seen["presence:"+p.Installation.Presence] = true
		}
	}
	for _, c := range pair.Audit.Contexts {
		switch {
		case c.EnvironmentPath != "":
			seen["context:environment"] = true
		case c.ProjectPath != "":
			seen["context:project"] = true
		default:
			seen["context:ambient"] = true
		}
	}
	for _, f := range pair.Audit.Findings {
		seen["finding:"+f.Code] = true
	}
	for _, key := range []string{
		"status:complete", "status:partial", "scope:project", "scope:user",
		"kind:project_search_root", "kind:environment_root", "kind:environment", "kind:manifest", "kind:lockfile", "kind:installed_metadata", "kind:cache_root", "kind:cached_metadata",
		"evidence:declared_requirement", "evidence:locked_package", "evidence:installed_package", "evidence:cached_package",
		"checksum:recorded", "checksum:partial", "checksum:absent", "origin:channel", "origin:local", "origin:unknown",
		"relation:direct", "relation:unknown", "version:known", "version:unknown", "subdir:noarch", "build_number:0", "lock_environment", "target_platform", "redacted_spec", "presence:present",
		"reason:identity_mismatch", "reason:unsupported_format", "reason:extraction_incomplete", "reason:path_unresolved", "reason:checksum_invalid", "reason:parse_error",
		"context:ambient", "context:environment", "context:project", "finding:conda-001", "finding:conda-002", "finding:conda-003", "finding:conda-004",
	} {
		if !seen[key] {
			t.Errorf("fixture does not exercise %s", key)
		}
	}
}
