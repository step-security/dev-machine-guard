package model

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// goGoldenPath holds one go_inventory and go_config_audit pair exercising
// every value a single valid payload can carry. The same bytes are the
// contract the Agent API reader is tested against.
const goGoldenPath = "testdata/go_inventory_v1_golden.json"

type goGolden struct {
	GoInventory   *GoInventory   `json:"go_inventory"`
	GoConfigAudit *GoConfigAudit `json:"go_config_audit"`
}

func loadGoGolden(t *testing.T) ([]byte, goGolden) {
	t.Helper()
	raw, err := os.ReadFile(goGoldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	// A fixture field these structs cannot hold is one this agent never sends.
	var g goGolden
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		t.Fatalf("golden payload does not fit the Go sections: %v", err)
	}
	if g.GoInventory == nil || g.GoConfigAudit == nil {
		t.Fatal("golden payload is missing a Go section")
	}
	return raw, g
}

func TestGoGolden_RoundTripsWithNoDroppedField(t *testing.T) {
	raw, g := loadGoGolden(t)
	encoded, err := json.Marshal(&g)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := decodeGeneric(t, encoded), decodeGeneric(t, raw); !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the payload\n got: %s\nwant: %s", encoded, raw)
	}
}

// TestGoGolden_ReferencesResolve: every source reference in either section
// names a source the reader can join on.
func TestGoGolden_ReferencesResolve(t *testing.T) {
	_, g := loadGoGolden(t)
	inv, audit := g.GoInventory, g.GoConfigAudit
	ids := map[string]bool{}
	for _, s := range inv.Sources {
		if ids[s.SourceID] {
			t.Errorf("duplicate source_id %s", s.SourceID)
		}
		ids[s.SourceID] = true
	}
	ref := func(id, what string) {
		if !ids[id] {
			t.Errorf("%s references unknown source %q", what, id)
		}
	}
	for _, s := range inv.Sources {
		if s.ParentSourceID != "" {
			ref(s.ParentSourceID, "parent of "+s.Path)
		}
		for _, d := range s.DiscoveredSources {
			ref(d, "discovered_sources of "+s.Path)
		}
	}
	checksums := func(ev GoChecksumEvidence, what string) {
		for _, c := range ev.RecordedChecksums {
			ref(c.SourceID, what+" checksum")
		}
	}
	replacement := func(r *GoReplacement, what string) {
		if r != nil {
			checksums(r.GoChecksumEvidence, what+" replacement")
		}
	}
	for _, p := range inv.Projects {
		ref(p.SourceID, "project "+p.ManifestPath)
		for _, r := range p.Requirements {
			checksums(r.GoChecksumEvidence, r.ModulePath)
		}
		for i := range p.Replacements {
			replacement(&p.Replacements[i], p.ManifestPath)
		}
	}
	for _, w := range inv.Workspaces {
		ref(w.SourceID, "workspace "+w.Path)
		for _, m := range w.Members {
			if m.ProjectSourceID != "" {
				ref(m.ProjectSourceID, "member "+m.DeclaredPath)
			}
		}
		for i := range w.Replacements {
			replacement(&w.Replacements[i], w.Path)
		}
	}
	for _, v := range inv.VendoredModules {
		ref(v.SourceID, "vendored "+v.ModulePath)
		checksums(v.GoChecksumEvidence, v.ModulePath)
		replacement(v.Replacement, v.ModulePath)
	}
	for _, c := range inv.CachedModules {
		ref(c.SourceID, "cached "+c.ModulePath)
		checksums(c.GoChecksumEvidence, c.ModulePath)
	}
	for _, tool := range inv.InstalledTools {
		ref(tool.SourceID, "tool "+tool.BinaryPath)
		checksums(tool.GoChecksumEvidence, tool.BinaryPath)
		replacement(tool.Replacement, tool.BinaryPath)
		for _, d := range tool.Dependencies {
			checksums(d.GoChecksumEvidence, d.ModulePath)
			replacement(d.Replacement, d.ModulePath)
		}
	}

	files := map[string]bool{}
	for _, f := range audit.Files {
		files[f.SourceID] = true
	}
	for _, f := range audit.Files {
		for _, s := range f.Settings {
			if s.SourceID != f.SourceID {
				t.Errorf("setting %s carries source %s, want its file %s", s.Key, s.SourceID, f.SourceID)
			}
		}
	}
	for _, f := range audit.Findings {
		if !files[f.SourceID] {
			t.Errorf("finding %s references unknown config file %q", f.Code, f.SourceID)
		}
	}
}

// TestGoGolden_CoversTheWholeVocabulary keeps the fixture honest: one that
// quietly stops exercising a value passes while that value goes unchecked.
func TestGoGolden_CoversTheWholeVocabulary(t *testing.T) {
	_, g := loadGoGolden(t)
	inv, audit := g.GoInventory, g.GoConfigAudit
	seen := map[string]map[string]bool{}
	see := func(what, v string) {
		if seen[what] == nil {
			seen[what] = map[string]bool{}
		}
		seen[what][v] = true
	}
	evidence := func(ev GoChecksumEvidence) {
		if ev.ChecksumStatus != "" {
			see("checksum_status", ev.ChecksumStatus)
		}
		for _, c := range ev.RecordedChecksums {
			see("checksum kind", c.Kind)
			see("checksum source", c.Source)
			see("verification", c.Verification)
		}
	}
	replacement := func(r *GoReplacement) {
		if r != nil {
			see("replacement kind", r.Kind)
			evidence(r.GoChecksumEvidence)
		}
	}
	for _, s := range inv.Sources {
		see("source kind", s.Kind)
		see("source status", s.Status)
		see("presence", s.Presence)
	}
	for _, p := range inv.Projects {
		for _, r := range p.Requirements {
			evidence(r.GoChecksumEvidence)
		}
		for i := range p.Replacements {
			replacement(&p.Replacements[i])
		}
	}
	for _, w := range inv.Workspaces {
		for i := range w.Replacements {
			replacement(&w.Replacements[i])
		}
	}
	for _, v := range inv.VendoredModules {
		evidence(v.GoChecksumEvidence)
		replacement(v.Replacement)
	}
	for _, c := range inv.CachedModules {
		evidence(c.GoChecksumEvidence)
		for _, a := range c.Artifacts {
			see("artifact kind", a.Kind)
			see("artifact status", a.Status)
		}
	}
	for _, tool := range inv.InstalledTools {
		see("version status", tool.VersionStatus)
		evidence(tool.GoChecksumEvidence)
		replacement(tool.Replacement)
		for _, d := range tool.Dependencies {
			see("version status", d.VersionStatus)
			evidence(d.GoChecksumEvidence)
			replacement(d.Replacement)
		}
	}
	for _, f := range audit.Files {
		see("config scope", f.Scope)
	}
	for _, f := range audit.Findings {
		see("finding code", f.Code)
	}

	for what, want := range map[string][]string{
		"source kind": {
			GoSourceProjectSearchRoot, GoSourceProjectManifest, GoSourceAlternateManifest, GoSourceWorkspace,
			GoSourceVendorRoot, GoSourceCacheRoot, GoSourceBinRoot, GoSourceBinary, GoSourceChecksumFile,
		},
		"source status":    {GoStatusComplete, GoStatusPartial, GoStatusSkipped},
		"presence":         {GoPresencePresent, GoPresenceAbsent, GoPresenceUnknown},
		"artifact kind":    {GoArtifactExtractedSource, GoArtifactArchivePresent},
		"artifact status":  {GoArtifactPresent, GoArtifactPartial, GoArtifactUnreadable},
		"replacement kind": {GoReplaceModule, GoReplaceLocal},
		"version status":   {GoVersionKnown, GoVersionUnknown},
		"checksum_status": {
			GoChecksumRecorded, GoChecksumAbsent, GoChecksumPartial, GoChecksumUnreadable,
			GoChecksumInvalid, GoChecksumUnsupported, GoChecksumSkipped, GoChecksumNotApplicable,
		},
		"checksum kind": {GoChecksumKindModuleContent, GoChecksumKindGoMod},
		"checksum source": {
			GoChecksumSourceProjectGoSum, GoChecksumSourceWorkspaceGoWorkSum,
			GoChecksumSourceCacheZiphash, GoChecksumSourceBinaryBuildInfo,
		},
		"verification": {GoChecksumNotVerified},
		"config scope": {GoConfigScopeUser, GoConfigScopeToolchain, GoConfigScopeProcess},
		"finding code": {"go-001", "go-002", "go-003", "go-004", "go-005", "go-006"},
	} {
		for _, v := range want {
			if !seen[what][v] {
				t.Errorf("golden payload has no %s %q", what, v)
			}
		}
	}

	// Closed sets one payload cannot show in full (three config files, one
	// status each; reasons tied to mutually exclusive states). A reader
	// matches every value against its own list, so each is spelled out here.
	for _, tt := range []struct{ got, want string }{
		{GoConfigPresent, "present"},
		{GoConfigAbsent, "absent"},
		{GoConfigDisabled, "disabled"},
		{GoConfigSkippedProtected, "skipped_protected"},
		{GoConfigUnreadable, "unreadable"},
		{GoConfigInvalid, "invalid"},
		{GoConfigUnsupported, "unsupported"},
		{GoReasonUserUnresolved, "user_unresolved"},
		{GoReasonSkippedProtected, "skipped_protected"},
		{GoReasonOutsideApprovedRoots, "outside_approved_roots"},
		{GoReasonPathUnresolved, "path_unresolved"},
		{GoReasonPermissionDenied, "permission_denied"},
		{GoReasonSizeLimit, "size_limit"},
		{GoReasonEntryLimit, "entry_limit"},
		{GoReasonDepthLimit, "depth_limit"},
		{GoReasonRecordLimit, "record_limit"},
		{GoReasonOutputSizeLimit, "output_size_limit"},
		{GoReasonDeadlineExceeded, "deadline_exceeded"},
		{GoReasonParseError, "parse_error"},
		{GoReasonUnsupportedEntry, "unsupported_entry"},
		{GoReasonRootRedirectUnknown, "root_redirect_unknown"},
		{GoReasonVendorMismatch, "vendor_mismatch"},
		{GoReasonMemberNotDiscovered, "member_not_discovered"},
		{GoReasonBuildInfoUnusable, "build_info_unusable"},
		{GoReasonChangedDuringScan, "changed_during_scan"},
		{GoReasonExtractionIncomplete, "extraction_incomplete"},
		{GoReasonAlternateManifestUnresolved, "alternate_manifest_unresolved"},
		{GoReasonProcessContextUnverified, "process_context_unverified"},
		{GoReasonCarriageReturn, "carriage_return"},
		{GoReasonDuplicateKey, "duplicate_key"},
		{GoReasonMalformedChecksumLine, "malformed_checksum_line"},
		{GoReasonUnsupportedChecksumScheme, "unsupported_checksum_scheme"},
		{GoReasonChecksumLineTooLong, "checksum_line_too_long"},
		{GoReasonChecksumLineLimit, "checksum_line_limit"},
		{GoReasonUnsupportedModfileName, "unsupported_modfile_name"},
	} {
		if tt.got != tt.want {
			t.Errorf("vocabulary value %q changed from %q", tt.got, tt.want)
		}
	}
}
