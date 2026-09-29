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

// Shared wire fixture with Agent API, including identity test vectors.
const agentPluginsGoldenPath = "testdata/agent_plugins_v1_golden.json"

// agentPluginsGolden contains the plugin, usage and skill sections of telemetry.
type agentPluginsGolden struct {
	AgentPlugins   *AgentPlugins       `json:"agent_plugins"`
	AgentSkills    []AgentSkill        `json:"agent_skills"`
	AgentSkillScan *AgentSkillScanInfo `json:"agent_skill_scan"`
}

func loadAgentPluginsGolden(t *testing.T) ([]byte, agentPluginsGolden) {
	t.Helper()
	raw, err := os.ReadFile(agentPluginsGoldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var doc agentPluginsGolden
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("golden payload does not fit the model: %v", err)
	}
	return raw, doc
}

// Strict decoding and round-tripping catch missing fields in either direction.
func TestAgentPluginsGolden_RoundTripsWithNoDroppedField(t *testing.T) {
	raw, doc := loadAgentPluginsGolden(t)
	encoded, err := json.Marshal(&doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := decodeGeneric(t, raw)
	got := decodeGeneric(t, encoded)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the payload\n got: %s\nwant: %s", encoded, raw)
	}
}

// Every wire vocabulary value must be represented in the shared fixture.
func TestAgentPluginsGolden_CoversTheWholeVocabulary(t *testing.T) {
	_, doc := loadAgentPluginsGolden(t)
	scan := doc.AgentPlugins
	if scan == nil || doc.AgentSkillScan == nil {
		t.Fatal("fixture must carry the plugin scan and skill scan info")
	}

	seen := map[string]map[string]bool{}
	mark := func(what, v string) {
		if seen[what] == nil {
			seen[what] = map[string]bool{}
		}
		seen[what][v] = true
	}
	for _, c := range scan.Contexts {
		mark("agent", c.Agent)
		mark("status", c.MarketplaceStatus)
		mark("status", c.InstallationStatus)
		for _, e := range c.Errors {
			mark("error", e.Code)
		}
		for _, m := range c.Marketplaces {
			if m.Source != nil {
				mark("source", m.Source.Kind)
			}
		}
		for _, p := range c.Plugins {
			mark("install", p.InstallationKind)
			mark("scope", p.Scope)
			mark("evidence", p.InstallationEvidence)
			if p.ManifestFormat != "" {
				mark("manifest", p.ManifestFormat)
			}
			mark("status", p.ComponentStatus)
			if p.Source != nil {
				mark("source", p.Source.Kind)
				if p.Source.CommandMode != "" {
					mark("mode", p.Source.CommandMode)
				}
			}
			for _, e := range p.Errors {
				mark("error", e.Code)
			}
			for _, comp := range p.Components {
				mark("component", comp.Kind)
				mark("status", comp.Status)
				if comp.Skill != nil {
					mark("nested source", comp.Skill.Source)
				}
			}
		}
	}
	for _, s := range doc.AgentSkills {
		mark("definition", s.DefinitionKind)
	}

	for _, tt := range []struct {
		what string
		want []string
	}{
		{"agent", []string{AgentClaudeCode, AgentCodex}},
		{"status", []string{AgentScanStatusComplete, AgentScanStatusPartial, AgentScanStatusError, AgentScanStatusUnsupported}},
		{"error", []string{AgentScanErrReadFailed, AgentScanErrParseFailed, AgentScanErrUnsupportedSchema, AgentScanErrLimitExceeded,
			AgentScanErrUnsafePath, AgentScanErrSourceChanged, AgentScanErrRootUnresolved}},
		{"source", []string{PluginSourceLocal, PluginSourceGit, PluginSourceGitHub, PluginSourceURL, PluginSourceSettings,
			PluginSourceNPM, PluginSourceArchive, PluginSourceCommand, PluginSourceAccount, PluginSourceUnknown}},
		{"mode", []string{PluginCommandModeCopy, PluginCommandModeLink}},
		{"install", []string{PluginInstallMarketplace, PluginInstallDirectory, PluginInstallSynced, PluginInstallAccount, PluginInstallUnknown}},
		{"scope", []string{PluginScopeUser, PluginScopeProject, PluginScopeLocal, PluginScopeSystem, PluginScopeUnknown}},
		{"evidence", []string{PluginEvidenceRegistry, PluginEvidenceLocalConfig, PluginEvidenceSkillDirectory, PluginEvidenceSyncedDirectory, PluginEvidenceRemoteMarker}},
		{"manifest", []string{PluginManifestClaude, PluginManifestCodex, PluginManifestCursor, PluginManifestPortable, PluginManifestCatalog, PluginManifestNone, PluginManifestUnknown}},
		{"component", []string{PluginComponentSkill, PluginComponentCommand, PluginComponentMCP, PluginComponentAgent, PluginComponentHook, PluginComponentLSP, PluginComponentApp}},
		{"nested source", []string{"claude_plugin", "codex_plugin"}},
		// An empty kind denotes SKILL.md and remains valid beside explicit kinds.
		{"definition", []string{"", AgentDefinitionSkill, AgentDefinitionCommand}},
	} {
		for _, want := range tt.want {
			if !seen[tt.what][want] {
				t.Errorf("golden payload has no %s %q", tt.what, want)
			}
		}
		if got := len(seen[tt.what]); got != len(tt.want) {
			t.Errorf("golden payload carries %d %s values, want exactly %d: %v", got, tt.what, len(tt.want), seen[tt.what])
		}
	}
}

// TestAgentPluginsGolden_Invariants pins the semantics a reader has to be able
// to rely on: explicit false and zero survive, unknown stays absent, required
// arrays are present and optional ones are not invented, a component carries
// exactly the payload its kind allows, and every identity reproduces its recipe.
func TestAgentPluginsGolden_Invariants(t *testing.T) {
	raw, doc := loadAgentPluginsGolden(t)

	// Tri-state booleans: the fixture carries an explicit false for every one, and
	// an absent one for every one, so neither can quietly collapse into the other.
	type tri struct{ f, present, absent bool }
	tris := map[string]*tri{"installed": {}, "files_present": {}, "configured_enabled": {}, "effective_enabled": {}, "auto_update_enabled": {}}
	note := func(key string, v *bool) {
		if v == nil {
			tris[key].absent = true
			return
		}
		tris[key].present = true
		if !*v {
			tris[key].f = true
		}
	}
	for _, c := range doc.AgentPlugins.Contexts {
		for _, m := range c.Marketplaces {
			note("auto_update_enabled", m.AutoUpdateEnabled)
		}
		for _, p := range c.Plugins {
			note("installed", p.Installed)
			note("files_present", p.FilesPresent)
			note("configured_enabled", p.ConfiguredEnabled)
			note("effective_enabled", p.EffectiveEnabled)
		}
	}
	for key, st := range tris {
		if !st.f || !st.present || !st.absent {
			t.Errorf("%s: want an explicit false, a true and an absent value in the fixture (false=%v present=%v absent=%v)", key, st.f, st.present, st.absent)
		}
	}
	// Explicit false survives the bytes, not just the struct.
	if !bytes.Contains(raw, []byte(`"configured_enabled": false`)) || !bytes.Contains(raw, []byte(`"auto_update_enabled": false`)) {
		t.Error("explicit false must be present in the serialized fixture")
	}
	if !bytes.Contains(raw, []byte(`"recorded_uses": 0`)) {
		t.Error("an explicit zero usage count must be present in the serialized fixture")
	}

	// A component has exactly the payload its kind names, and never another.
	for _, c := range doc.AgentPlugins.Contexts {
		for _, p := range c.Plugins {
			for _, comp := range p.Components {
				n := 0
				for _, has := range []bool{comp.Skill != nil, comp.Command != nil, comp.MCPConfig != nil} {
					if has {
						n++
					}
				}
				switch comp.Kind {
				case PluginComponentSkill, PluginComponentCommand, PluginComponentMCP:
					if n > 1 || (n == 1 && !payloadMatchesKind(comp)) {
						t.Errorf("%s: kind %q carries a payload of another kind", comp.ComponentID, comp.Kind)
					}
				default:
					if n != 0 {
						t.Errorf("%s: descriptive kind %q must carry no payload", comp.ComponentID, comp.Kind)
					}
				}
				if strings.Contains(comp.RelativePath, "..") || strings.HasPrefix(comp.RelativePath, "/") {
					t.Errorf("%s: relative_path %q must be root-relative without traversal", comp.ComponentID, comp.RelativePath)
				}
				if comp.CallableNames == nil {
					t.Errorf("%s: callable_names must be [] not omitted", comp.ComponentID)
				}
			}
			if p.Enablement == nil || p.Components == nil || p.Errors == nil {
				t.Errorf("%s: enablement/components/errors must be [] not omitted", p.InstanceID)
			}
		}
		if c.Marketplaces == nil || c.Plugins == nil || c.Errors == nil {
			t.Errorf("%s: marketplaces/plugins/errors must be [] not omitted", c.ContextID)
		}
	}
	// The required arrays render as [] in the bytes; an optional one is never
	// rendered empty.
	if !bytes.Contains(raw, []byte(`"marketplaces": []`)) {
		t.Error("an empty required array must be serialized as []")
	}
	for _, key := range []string{`"sparse_paths": []`, `"auto_update_preferences": []`, `"allowed_tools": []`, `"symlink_sources": []`} {
		if bytes.Contains(raw, []byte(key)) {
			t.Errorf("optional array %s must be omitted when empty, not rendered", key)
		}
	}

	// A standalone command is a real file with a real hash and no invented SKILL.md.
	commands := 0
	for _, s := range doc.AgentSkills {
		if s.DefinitionKind != AgentDefinitionCommand {
			continue
		}
		commands++
		if s.DefinitionPath == "" || len(s.DefinitionHash) != 64 || len(s.CallableNames) != 1 || !strings.HasPrefix(s.CallableNames[0], "/") {
			t.Errorf("command %s: needs definition_path, a 64-hex hash and one slash-prefixed callable name", s.SkillSlug)
		}
		if s.SkillMDPath != "" || s.SkillMDHash != "" || s.SkillDirPath != "" || s.FileCount != 0 {
			t.Errorf("command %s: must not carry SKILL.md or census fields", s.SkillSlug)
		}
		if s.Agent != AgentClaudeCode {
			t.Errorf("command %s: agent = %q, want %q", s.SkillSlug, s.Agent, AgentClaudeCode)
		}
	}
	if commands < 2 {
		t.Errorf("fixture carries %d standalone commands, want a user and a project one", commands)
	}
	if doc.AgentSkillScan.CommandsStatus != AgentScanStatusComplete {
		t.Errorf("commands_status = %q, want complete", doc.AgentSkillScan.CommandsStatus)
	}

	// The account plugin: installed unknown and effective_enabled absent, with a
	// configured false still recorded.
	var account *PluginObservation
	for i := range doc.AgentPlugins.Contexts {
		for j := range doc.AgentPlugins.Contexts[i].Plugins {
			if p := &doc.AgentPlugins.Contexts[i].Plugins[j]; p.InstallationKind == PluginInstallAccount {
				account = p
			}
		}
	}
	if account == nil {
		t.Fatal("fixture has no account-delivered plugin")
	}
	if account.Installed != nil || account.EffectiveEnabled != nil || account.ConfiguredEnabled == nil || *account.ConfiguredEnabled || account.RemotePluginID == "" {
		t.Error("account plugin must keep installed and effective_enabled unknown, configured_enabled false, and carry its remote id")
	}

	// Millisecond fields carry values that cannot be Unix seconds.
	if doc.AgentPlugins.CollectedAtMs < 1e12 {
		t.Error("collected_at_ms must be Unix milliseconds")
	}
}

func payloadMatchesKind(c PluginComponent) bool {
	switch c.Kind {
	case PluginComponentSkill:
		return c.Skill != nil
	case PluginComponentCommand:
		return c.Command != nil
	case PluginComponentMCP:
		return c.MCPConfig != nil
	}
	return false
}

// TestAgentPluginsGolden_IdentityVectors recomputes every device-local id from
// its coordinates with the shared recipe, so the fixture doubles as the frozen
// test vectors both repositories check against.
func TestAgentPluginsGolden_IdentityVectors(t *testing.T) {
	_, doc := loadAgentPluginsGolden(t)
	h := func(parts ...string) string {
		b, err := json.Marshal(parts)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])
	}
	for _, c := range doc.AgentPlugins.Contexts {
		if want := "ctx_" + h(c.Agent, c.ConfigRoot, c.PluginRoot); c.ContextID != want {
			t.Errorf("context_id %s != %s", c.ContextID, want)
		}
		for _, m := range c.Marketplaces {
			if want := "market_" + h(c.ContextID, m.Name); m.MarketplaceID != want {
				t.Errorf("marketplace_id %s != %s", m.MarketplaceID, want)
			}
		}
		for _, p := range c.Plugins {
			var origin string
			switch p.InstallationKind {
			case PluginInstallMarketplace:
				origin = p.MarketplaceID
			case PluginInstallAccount:
				origin = p.RemotePluginID
				if origin == "" {
					origin = p.NativeID
				}
			case PluginInstallDirectory, PluginInstallSynced:
				origin = p.SourcePath
				if origin == "" {
					origin = p.InstallPath
				}
			default:
				origin = p.NativeID
			}
			if want := "inst_" + h(c.ContextID, p.NativeID, p.InstallationKind, p.Scope, p.ProjectPath, origin); p.InstanceID != want {
				t.Errorf("instance_id %s != %s (%s)", p.InstanceID, want, p.NativeID)
			}
			for _, comp := range p.Components {
				if want := "comp_" + h(p.InstanceID, comp.Kind, comp.RelativePath, comp.DeclarationPointer, comp.Name); comp.ComponentID != want {
					t.Errorf("component_id %s != %s (%s)", comp.ComponentID, want, comp.Name)
				}
			}
		}
	}
	// Two records must never share an instance id.
	ids := map[string]bool{}
	for _, c := range doc.AgentPlugins.Contexts {
		for _, p := range c.Plugins {
			if ids[p.InstanceID] {
				t.Errorf("duplicate instance_id %s", p.InstanceID)
			}
			ids[p.InstanceID] = true
		}
	}
}
