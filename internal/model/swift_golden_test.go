package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSwiftGoldenContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/swift_inventory_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "531d12af966e4a0159f3350bd766d75a5e7ce8fd3beb32041995ffb7930ee143" {
		t.Fatal("shared Swift fixture digest changed; update both producer and consumer after review")
	}
	var pair struct {
		Inventory *SwiftInventory   `json:"swift_inventory"`
		Audit     *SwiftConfigAudit `json:"swift_config_audit"`
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
		seen["status:"+s.Status], seen["kind:"+s.Kind], seen["presence:"+s.Presence] = true, true, true
		for _, r := range s.Reasons {
			seen["reason:"+r] = true
		}
		switch {
		case s.DiscoveredSources == nil:
			seen["discovered:absent"] = true
		case len(s.DiscoveredSources) == 0:
			seen["discovered:empty"] = true
		}
	}
	for _, p := range pair.Inventory.Projects {
		seen["project:"+p.Tool] = true
	}
	for _, p := range pair.Inventory.Packages {
		seen["scope:"+p.Scope], seen["evidence:"+p.Evidence], seen["tool:"+p.Tool] = true, true, true
		seen["version:"+p.VersionStatus], seen["origin:"+p.Origin.Kind] = true, true
		if p.ManagedState != "" {
			seen["managed:"+p.ManagedState] = true
		}
		if p.BasedOn != nil {
			seen["based_on"] = true
		}
		if p.OriginalLocation != "" {
			seen["original_location"] = true
		}
		if p.Revision != "" && p.Version == "" {
			seen["revision_only"] = true
		}
		if strings.Contains(p.PackageName, " ") {
			seen["name_with_space"] = true
		}
		if i := p.Installation; i != nil {
			seen["installation:"+i.Presence], seen["path_status:"+i.PathStatus] = true, true
		}
		if a := p.Artifact; a != nil {
			seen["artifact:"+a.Kind] = true
			if a.URL != "" {
				seen["artifact:remote"] = true
			}
			if len(p.RecordedChecksums) == 0 {
				seen["artifact:no_checksum"] = true
			}
		}
		if len(p.RecordedChecksums) > 0 {
			seen["checksum"] = true
		}
	}
	a := pair.Audit
	for _, f := range a.Files {
		seen["config:"+f.Scope+":"+f.Status] = true
		if strings.HasSuffix(f.Path, "/.swiftpm/config") || !strings.Contains(f.Path, "/configuration/") {
			seen["config:legacy"] = true
		}
	}
	for _, f := range a.Findings {
		seen["finding:"+f.Code] = true
	}
	for _, c := range a.CredentialFiles {
		seen["credential:"+c.Presence] = true
	}
	for _, c := range a.Contexts {
		if c.ProjectPath == "" {
			seen["context:user"] = true
		} else {
			seen["context:project"] = true
		}
	}
	for _, key := range []string{
		"status:complete", "status:partial", "presence:present", "presence:absent", "reason:parse_error",
		"kind:project_search_root", "kind:project", "kind:manifest", "kind:lockfile", "kind:workspace_state",
		"kind:cache_root", "kind:cached_repository", "kind:cached_registry_package",
		"discovered:absent", "discovered:empty",
		"project:swiftpm", "project:xcode", "scope:project", "scope:user", "scope:unknown",
		"evidence:locked_package", "evidence:managed_dependency", "evidence:artifact_reference",
		"evidence:cached_repository", "evidence:cached_registry_package",
		"tool:swiftpm", "tool:xcode", "tool:unknown", "version:known", "version:unknown",
		"origin:git", "origin:registry", "origin:path", "origin:unknown",
		"managed:checkout", "managed:edited", "managed:filesystem", "based_on", "name_with_space",
		"installation:present", "installation:absent", "path_status:resolved",
		"artifact:remote", "artifact:no_checksum", "checksum",
		"config:user:present", "config:user:absent", "config:project:present", "config:process:present", "config:legacy",
		"finding:swift-001", "finding:swift-002", "finding:swift-003", "credential:present",
		"context:user", "context:project",
	} {
		if !seen[key] {
			t.Errorf("fixture does not exercise %s", key)
		}
	}
}
