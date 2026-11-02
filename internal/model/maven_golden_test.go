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

func TestMavenGoldenContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/maven_inventory_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "2474727b62034e5b5af39fc0a53240bd3c57434c852fcf853b0d629ac1d1226d" {
		t.Fatal("shared Maven fixture digest changed; update both producer and consumer after review")
	}
	var pair struct {
		Inventory *MavenInventory    `json:"maven_inventory"`
		Maven     *MavenConfigAudit  `json:"maven_config_audit"`
		Gradle    *GradleConfigAudit `json:"gradle_config_audit"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pair); err != nil {
		t.Fatal(err)
	}
	if pair.Inventory == nil || pair.Maven == nil || pair.Gradle == nil {
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
	for _, p := range pair.Inventory.Projects {
		seen["project:"+p.Tool] = true
	}
	for _, p := range pair.Inventory.Packages {
		seen["scope:"+p.Scope], seen["evidence:"+p.Evidence], seen["tool:"+p.Tool], seen["format:"+p.RepositoryFormat] = true, true, true, true
		seen["version:"+p.VersionStatus], seen["origin:"+p.Origin.Kind] = true, true
		if p.DeclarationRole != "" {
			seen["role:"+p.DeclarationRole] = true
		}
		if p.ProfileID != "" {
			seen["profile"] = true
		}
		if len(p.RecordedChecksums) > 0 {
			seen["checksum"] = true
		}
		if len(p.Configurations) > 0 {
			seen["configurations"] = true
		}
		for _, s := range p.RequestedSpecs {
			if s == "[redacted]" {
				seen["redacted_spec"] = true
			}
		}
		if a := p.Artifact; a != nil {
			seen["artifact_role:"+a.ArtifactRole] = true
			switch {
			case a.Classifier == nil:
				seen["classifier:unknown"] = true
			case *a.Classifier == "":
				seen["classifier:none"] = true
			default:
				seen["classifier:named"] = true
			}
			if a.FileVersion != "" {
				seen["file_version"] = true
			}
			if a.ContentKey != "" {
				seen["content_key"] = true
			}
			if a.LocalInstallMarkerPresent {
				seen["local_install_marker"] = true
			}
		}
	}
	for _, a := range []*RubyConfigAudit{pair.Maven, pair.Gradle} {
		for _, f := range a.Files {
			seen["config:"+f.Manager+":"+f.Scope] = true
		}
		for _, f := range a.Findings {
			seen["finding:"+f.Code] = true
		}
		for _, c := range a.CredentialFiles {
			seen["credential:"+c.Presence] = true
		}
	}
	for _, key := range []string{
		"status:complete", "status:partial",
		"kind:project_search_root", "kind:project", "kind:manifest", "kind:version_catalog", "kind:lockfile", "kind:verification_metadata",
		"kind:maven_repository", "kind:gradle_cache", "kind:artifact_directory", "kind:cached_artifact",
		"reason:checksum_invalid", "reason:unresolved_coordinate", "reason:redacted_requirement", "reason:unsupported_layout", "reason:parse_error",
		"project:maven", "project:gradle", "project:unknown", "scope:project", "scope:user", "scope:custom",
		"evidence:declared_dependency", "evidence:locked_package", "evidence:cached_artifact", "evidence:verification_reference",
		"tool:maven", "tool:gradle", "format:maven", "format:ivy", "format:unknown", "version:known", "version:unknown", "origin:unknown",
		"role:parent", "role:direct", "role:managed", "role:bom_import", "role:extension", "role:plugin", "role:managed_plugin", "role:plugin_dependency", "role:catalog_entry",
		"profile", "checksum", "configurations", "redacted_spec",
		"artifact_role:payload", "artifact_role:metadata", "classifier:unknown", "classifier:none", "classifier:named", "file_version", "content_key", "local_install_marker",
		"config:maven:user", "config:maven:project", "config:maven:process", "config:gradle:user", "config:gradle:project", "config:gradle:process",
		"credential:present", "credential:absent",
		"finding:maven-001", "finding:maven-002", "finding:maven-003", "finding:maven-005",
		"finding:gradle-001", "finding:gradle-003", "finding:gradle-004", "finding:gradle-005",
	} {
		if !seen[key] {
			t.Errorf("fixture does not exercise %s", key)
		}
	}
}
