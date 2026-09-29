package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/safepath"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// Native absence errors are needed to distinguish missing metadata from refusals.
type pluginMock struct{ *executor.Mock }

func newPluginMock() (*pluginMock, *fakeFS) {
	m := executor.NewMock()
	return &pluginMock{m}, newFakeFS(m)
}
func (m *pluginMock) GuardedFiles(_ []string, _ func(string) string, _ int64) executor.Executor {
	return m
}
func (m *pluginMock) Stat(file string) (os.FileInfo, error) {
	info, err := m.Mock.Stat(file)
	if err != nil {
		return nil, os.ErrNotExist
	}
	return info, nil
}
func (m *pluginMock) ReadDir(dir string) ([]os.DirEntry, error) {
	entries, err := m.Mock.ReadDir(dir)
	if err != nil {
		return nil, os.ErrNotExist
	}
	return entries, nil
}

func TestPluginDeclaredPaths(t *testing.T) {
	tests := []struct {
		path  string
		valid bool
	}{
		{"skills/check", true}, {"./skills/check", true}, {".", true},
		{"../secret", false}, {"skills/../../secret", false}, {"/secret", false}, {`C:\secret`, false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			_, ok := insideRoot("/plugins/example", tc.path)
			if ok != tc.valid {
				t.Fatalf("insideRoot(%q) valid = %v, want %v", tc.path, ok, tc.valid)
			}
		})
	}
}

func TestPluginExtendedDrivePath(t *testing.T) {
	if got := cleanPluginPath(`\\?\C:\Users\test\catalog\marketplace.json`); got != filepath.Clean(`C:\Users\test\catalog\marketplace.json`) {
		t.Fatalf("extended drive path: %q", got)
	}
	for _, value := range []string{`\\.\PhysicalDrive0`, `\\?\GLOBALROOT\Device\HarddiskVolume1`} {
		if cleanPluginPath(value) != filepath.Clean(value) {
			t.Fatalf("device path was reinterpreted: %q", value)
		}
	}
}

func TestPluginMacSystemAliasAbsent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS system alias")
	}
	d := NewSkillsDetector(executor.NewReal())
	s := &pluginScan{d: d, home: t.TempDir(), goos: model.PlatformDarwin}
	root := "/etc/agent-plugin-regression-not-installed"
	if state, _, err := s.stat(s.guarded(root), filepath.Join(root, "config.toml")); state != fileAbsent {
		t.Fatalf("absent system config: state=%v err=%v", state, err)
	}
}

func TestClaudeRegistryProjectSettings(t *testing.T) {
	for _, tc := range []struct {
		name, project, local string
		want                 *bool
	}{
		{"project disabled", `{"enabledPlugins":{"widgets@company":false}}`, "", boolPtr(false)},
		{"local override", `{"enabledPlugins":{"widgets@company":false}}`, `{"enabledPlugins":{"widgets@company":true}}`, boolPtr(true)},
		{"unreadable project", `{`, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			cfg, project := filepath.Join(testHome, ".claude"), filepath.Join(testHome, "project-only")
			fs.addFile(filepath.Join(cfg, "settings.json"), `{"enabledPlugins":{"widgets@company":true}}`)
			fs.addFile(filepath.Join(project, ".claude/settings.json"), tc.project)
			if tc.local != "" {
				fs.addFile(filepath.Join(project, ".claude/settings.local.json"), tc.local)
			}
			fs.commit()
			s := &pluginScan{d: NewSkillsDetector(m), home: testHome, goos: model.PlatformLinux}
			a := &claudeAdapter{s: s, gd: s.guarded(cfg), configRoot: cfg, c: s.newContext(model.AgentClaudeCode, cfg, filepath.Join(cfg, "plugins"))}
			a.layers = a.readSettingsLayers(map[string][]claudeRegistryRecord{"widgets@company": {{Scope: model.PluginScopeProject, ProjectPath: project}}})
			p := newPlugin("widgets@company", "widgets", model.PluginInstallMarketplace, model.PluginScopeProject)
			p.ProjectPath = project
			a.enablement(p)
			if !reflect.DeepEqual(p.EffectiveEnabled, tc.want) {
				t.Fatalf("effective=%v, want %v", p.EffectiveEnabled, tc.want)
			}
			user := newPlugin("widgets@company", "widgets", model.PluginInstallMarketplace, model.PluginScopeUser)
			a.enablement(user)
			if user.EffectiveEnabled == nil || !*user.EffectiveEnabled {
				t.Fatal("project override changed user installation")
			}
		})
	}
}

func TestPluginLinkedPayloadAndContainedSkill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native command-link installation is unsupported on Windows")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(home, "source")
	for _, dir := range []string{filepath.Join(payload, "skills/compress"), filepath.Join(payload, "canonical")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	definition := filepath.Join(payload, "canonical/SKILL.md")
	if err := os.WriteFile(definition, []byte(validFrontmatter("compress", "Summarize context")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../canonical/SKILL.md", filepath.Join(payload, "skills/compress/SKILL.md")); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, "installed")
	if err := os.Symlink(payload, root); err != nil {
		t.Fatal(err)
	}
	d := NewSkillsDetector(executor.NewReal())
	definitions := 0
	s := &pluginScan{d: d, ctx: context.Background(), home: home, memo: map[string]*skillScan{}, definitions: &definitions, evidence: newPluginEvidence()}
	p := newPlugin("widgets@company", "widgets", model.PluginInstallMarketplace, model.PluginScopeUser)
	p.InstanceID = "instance"
	r := &pluginRootScan{s: s, gd: s.guarded(root), p: p, root: root, attr: nestedAttr{agent: model.AgentClaudeCode}}
	dirs := r.skillDirs(filepath.Join(root, "skills"), true)
	if len(dirs) != 1 {
		t.Fatalf("linked skill directories: %v", dirs)
	}
	r.skillComponent(dirs[0], "skills/compress", "compress", "widgets:compress")
	if len(p.Components) != 1 || p.Components[0].Skill == nil || p.Components[0].ResolvedDefinitionPath != definition {
		t.Fatalf("linked definition: %+v", p.Components)
	}
	if p.ComponentStatus != model.AgentScanStatusComplete {
		t.Fatalf("linked payload incomplete: %+v", p.Errors)
	}
}

func TestPluginUsageSharesPhysicalDefinition(t *testing.T) {
	definition := filepath.Join(testHome, ".claude/skills/widgets/SKILL.md")
	skill := &model.AgentSkill{Agent: model.AgentClaudeCode, SkillName: "widgets", SkillMDPath: definition}
	result := SkillsResult{Skills: []model.AgentSkill{*skill}, Plugins: &model.AgentPlugins{Contexts: []model.AgentPluginContext{{Agent: model.AgentClaudeCode, Plugins: []model.PluginObservation{{NativeID: "widgets@skills-dir", Name: "widgets", Components: []model.PluginComponent{{Kind: model.PluginComponentSkill, Name: "widgets", DefinitionPath: definition, ResolvedDefinitionPath: definition, CallableNames: []string{"widgets"}, Skill: skill}}}}}}}, usage: &skillUsageObservations{CollectedAtMs: 100, Sources: []skillUsageSource{{SourceID: "source", Counters: []skillUsageCounter{{RawKey: "widgets", RecordedUses: 7}}}}}}
	associateSkillUsage(&result)
	for _, usage := range []*model.SkillUsage{result.Skills[0].Usage, skill.Usage} {
		if usage == nil || usage.Availability != "available" || usage.RecordedUses == nil || *usage.RecordedUses != 7 {
			t.Fatalf("shared usage: %+v", usage)
		}
	}
	result.Skills[0].DefinitionPath = filepath.Join(testHome, "other/SKILL.md")
	associateSkillUsage(&result)
	if skill.Usage.Availability != "ambiguous" {
		t.Fatalf("unrelated same-name skill inherited usage: %+v", skill.Usage)
	}
}

func TestClaudeDeclaredRootSkillCallable(t *testing.T) {
	for _, declaration := range []string{`"."`, `[".", "./skills"]`} {
		t.Run(declaration, func(t *testing.T) {
			m, fs := newPluginMock()
			root := filepath.Join(testHome, ".claude/skills/widgets")
			fs.addFile(filepath.Join(root, claudeManifestRel), `{"name":"widgets","skills":`+declaration+`}`)
			fs.addFile(filepath.Join(root, "SKILL.md"), validFrontmatter("widgets", "Review changes"))
			fs.addFile(filepath.Join(root, "skills/nested/SKILL.md"), validFrontmatter("nested", "Review details"))
			fs.commit()
			d := NewSkillsDetector(m)
			definitions := 0
			s := &pluginScan{d: d, ctx: context.Background(), home: testHome, definitions: &definitions, memo: map[string]*skillScan{}, evidence: newPluginEvidence()}
			a := &claudeAdapter{s: s, gd: s.guarded(root)}
			p := newPlugin("widgets@skills-dir", "widgets", model.PluginInstallDirectory, model.PluginScopeUser)
			p.InstallPath = root
			a.components(p, nil, nil)
			if len(p.Components) != 2 {
				t.Fatalf("components = %d, want 2", len(p.Components))
			}
			for _, c := range p.Components {
				want := "widgets:nested"
				if c.RelativePath == "SKILL.md" {
					want = "widgets"
				}
				if !reflect.DeepEqual(c.CallableNames, []string{want}) || !reflect.DeepEqual(c.Skill.CallableNames, []string{want}) {
					t.Errorf("%s callable = %v, want %s", c.RelativePath, c.CallableNames, want)
				}
			}
		})
	}
}

func TestClaudeCommandLinkedChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native command-link installation is unsupported on Windows")
	}
	for _, tc := range []struct {
		name                                   string
		outside, malformed, missing, protected bool
	}{
		{name: "native child links"},
		{name: "outside scan roots", outside: true},
		{name: "malformed marker", malformed: true},
		{name: "missing marker", missing: true},
		{name: "protected payload", protected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.protected && runtime.GOOS != "darwin" {
				t.Skip("macOS TCC protection")
			}
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root, payload := filepath.Join(home, "installed"), filepath.Join(home, "source")
			if tc.protected {
				payload = filepath.Join(home, "Documents/source")
			}
			if tc.outside {
				payload, err = filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, dir := range []string{root, filepath.Join(payload, ".claude-plugin"), filepath.Join(payload, "skills/check")} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for file, body := range map[string]string{
				filepath.Join(payload, claudeManifestRel):       `{"name":"widgets"}`,
				filepath.Join(payload, "skills/check/SKILL.md"): validFrontmatter("check", "Review changes"),
			} {
				if err := os.WriteFile(file, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{".claude-plugin", "skills"} {
				if err := os.Symlink(filepath.Join(payload, name), filepath.Join(root, name)); err != nil {
					t.Fatal(err)
				}
			}
			marker, _ := json.Marshal(map[string]string{"target": payload})
			if tc.malformed {
				marker = []byte(`{"target":`)
			}
			if !tc.missing {
				if err := os.WriteFile(filepath.Join(root, ".claude-plugin-link"), marker, 0600); err != nil {
					t.Fatal(err)
				}
			}
			d := NewSkillsDetector(executor.NewReal()).WithSkipper(tcc.New(home))
			definitions := 0
			s := &pluginScan{d: d, ctx: context.Background(), home: home, definitions: &definitions, memo: map[string]*skillScan{}, evidence: newPluginEvidence()}
			a := &claudeAdapter{s: s, gd: s.guarded(root)}
			p := newPlugin("widgets@company", "widgets", model.PluginInstallMarketplace, model.PluginScopeUser)
			p.InstallPath = root
			p.Source = &model.SourceLocator{Kind: model.PluginSourceCommand, CommandMode: model.PluginCommandModeLink}
			a.components(p, nil, nil)
			if tc.outside || tc.malformed || tc.missing || tc.protected {
				if p.ComponentStatus == model.AgentScanStatusComplete || len(p.Components) != 0 {
					t.Fatalf("unsafe payload read: %+v", p)
				}
				return
			}
			if p.InstallPath != root || p.ComponentStatus != model.AgentScanStatusComplete || len(p.Components) != 1 || p.Components[0].Skill == nil {
				t.Fatalf("linked payload = %+v, want one complete skill", p)
			}
		})
	}
}

func TestPluginBooleanUnknown(t *testing.T) {
	for _, raw := range []string{"null", "", `"false"`, "{}"} {
		if got := jsonBool(json.RawMessage(raw)); got != nil {
			t.Errorf("%q became %v, want unknown", raw, *got)
		}
	}
	for _, raw := range []string{"true", "false"} {
		if got := jsonBool(json.RawMessage(raw)); got == nil || *got != (raw == "true") {
			t.Errorf("lost explicit %s", raw)
		}
	}
}

func TestCodexGitMarketplaceMarker(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".codex")
	m.SetEnv("CODEX_HOME", home)
	fs.addFile(filepath.Join(home, "config.toml"), "[marketplaces.company]\nsource_type = 'git'\nsource = 'https://example.com/plugins.git'\n")
	fs.addFile(filepath.Join(home, ".tmp/marketplaces/company", codexMarketplaceMarker), `{"revision":"resolved","ref_name":"main"}`)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if result.Plugins == nil {
		t.Fatalf("missing plugin inventory: %+v", result.Info)
	}
	for _, c := range result.Plugins.Contexts {
		if c.Agent != model.AgentCodex {
			continue
		}
		if len(c.Marketplaces) != 1 || c.Marketplaces[0].Revision != "resolved" || c.Marketplaces[0].Source.RequestedRef != "main" {
			t.Fatalf("marker not retained: %+v", c.Marketplaces)
		}
		return
	}
	t.Fatal("missing Codex context")
}

func TestPluginStatDistinguishesMissingAndUnreadable(t *testing.T) {
	m, _ := newPluginMock()
	for _, tc := range []struct {
		name string
		err  error
		want fileState
	}{
		{"missing", os.ErrNotExist, fileAbsent},
		{"permission", os.ErrPermission, fileRefused},
		{"unresolved", &safepath.Refusal{Reason: safepath.ReasonUnresolved}, fileRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewSkillsDetector(m)
			guarded := *d
			guarded.exec = statErrorExecutor{Executor: m, err: tc.err}
			scan := pluginScan{d: d}
			state, _, _ := scan.stat(&guarded, "/plugins/test")
			if state != tc.want {
				t.Fatalf("state = %v, want %v", state, tc.want)
			}
		})
	}
}

type statErrorExecutor struct {
	executor.Executor
	err error
}

func (e statErrorExecutor) Stat(string) (os.FileInfo, error) { return nil, e.err }

func TestCodexInstallationEvidence(t *testing.T) {
	tests := []struct {
		name, config, marker string
		payload              bool
		count                int
	}{
		{name: "settings only", config: "[plugins.'test-plugin@company']\nenabled = true\n"},
		{name: "cache only", payload: true},
		{name: "marker only", marker: `{"schema_version":1,"remote_plugin_id":"test-remote"}`},
		{name: "configured payload", config: "[plugins.'test-plugin@company']\nenabled = false\n", payload: true, count: 1},
		{name: "account payload", marker: `{"schema_version":1,"remote_plugin_id":"test-remote"}`, payload: true, count: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			home := filepath.Join(testHome, ".codex")
			m.SetEnv("CODEX_HOME", home)
			fs.addFile(filepath.Join(home, "config.toml"), tc.config)
			base := filepath.Join(home, "plugins/cache/company/test-plugin")
			if tc.marker != "" {
				fs.addFile(filepath.Join(base, codexRemoteMarker), tc.marker)
			}
			if tc.payload {
				fs.addFile(filepath.Join(base, "local/.codex-plugin/plugin.json"), `{"name":"test-plugin"}`)
			}
			fs.commit()
			result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
			if got := result.Plugins.PluginCount(); got != tc.count {
				t.Fatalf("plugins = %d, want %d", got, tc.count)
			}
			if tc.marker != "" && tc.count > 0 {
				for _, c := range result.Plugins.Contexts {
					for _, p := range c.Plugins {
						if p.EffectiveEnabled != nil {
							t.Fatal("account effective state must remain unknown")
						}
					}
				}
			}
		})
	}
}

func TestClaudeLocalSourceComponents(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".claude")
	m.SetEnv("CLAUDE_CONFIG_DIR", home)
	cache := filepath.Join(home, "plugins/cache/company/test-plugin/1.0.0")
	source := filepath.Join(testHome, "test-repo")
	registry, err := json.Marshal(map[string]any{"version": 2, "plugins": map[string]any{"test-plugin@company": []map[string]string{{"scope": "user", "installPath": cache}}}})
	if err != nil {
		t.Fatal(err)
	}
	fs.addFile(filepath.Join(home, "plugins/installed_plugins.json"), string(registry))
	known, err := json.Marshal(map[string]any{"company": map[string]any{"source": map[string]string{"source": "directory", "path": source}, "installLocation": source}})
	if err != nil {
		t.Fatal(err)
	}
	fs.addFile(filepath.Join(home, "plugins/known_marketplaces.json"), string(known))
	fs.addFile(filepath.Join(source, claudeCatalogRel), `{"name":"company","plugins":[{"name":"test-plugin","source":"./plugin"}]}`)
	for _, root := range []string{cache, filepath.Join(source, "plugin")} {
		fs.addFile(filepath.Join(root, claudeManifestRel), `{"name":"test-plugin"}`)
	}
	fs.addSkill(filepath.Join(cache, "skills/stale"), "SKILL.md", validFrontmatter("stale", "stale copy"), nil)
	fs.addSkill(filepath.Join(source, "plugin/skills/current"), "SKILL.md", validFrontmatter("current", "current source"), nil)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if result.Plugins.PluginCount() != 1 {
		t.Fatalf("plugins = %+v", result.Plugins)
	}
	p := result.Plugins.Contexts[0].Plugins[0]
	if p.InstallPath != cache || p.SourcePath != filepath.Join(source, "plugin") {
		t.Fatalf("lost locations: %+v", p)
	}
	if len(p.Components) != 1 || p.Components[0].Name != "current" || p.Components[0].RelativePath != "skills/current/SKILL.md" {
		t.Fatalf("wrong source components: %+v", p.Components)
	}
}

func TestClaudeLocalSourcePreservesProjectMCP(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".claude")
	catalog := filepath.Join(testHome, "local-marketplace")
	source := filepath.Join(catalog, "plugin-project")
	cache := filepath.Join(home, "plugins/cache/company/test-plugin/1.0.0")
	registry, _ := json.Marshal(map[string]any{"version": 2, "plugins": map[string]any{"test-plugin@company": []map[string]string{{"scope": "user", "installPath": cache}}}})
	known, _ := json.Marshal(map[string]any{"company": map[string]any{"source": map[string]string{"source": "directory", "path": catalog}, "installLocation": catalog}})
	fs.addFile(filepath.Join(home, "plugins/installed_plugins.json"), string(registry))
	fs.addFile(filepath.Join(home, "plugins/known_marketplaces.json"), string(known))
	fs.addFile(filepath.Join(catalog, claudeCatalogRel), `{"name":"company","plugins":[{"name":"test-plugin","source":"./plugin-project"}]}`)
	for _, root := range []string{source, cache} {
		fs.addFile(filepath.Join(root, claudeManifestRel), `{"name":"test-plugin"}`)
	}
	config := filepath.Join(source, ".mcp.json")
	fs.addFile(config, `{"mcpServers":{"shared":{"command":"node","args":["server.js"]}}}`)
	state, _ := json.Marshal(map[string]any{"projects": map[string]any{source: map[string]any{}}})
	fs.addFile(filepath.Join(testHome, ".claude.json"), string(state))
	fs.commit()
	mcp := NewMCPDetector(m)
	enterprise := mcp.DetectEnterprise(context.Background(), nil)
	community := mcp.Detect(context.Background(), "", nil, false)
	if !slices.ContainsFunc(enterprise, func(c model.MCPConfigEnterprise) bool {
		return c.ConfigPath == config && c.ConfigSource == "project_mcp"
	}) {
		t.Fatal("missing independently registered project MCP")
	}
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if result.Plugins.PluginCount() != 1 {
		t.Fatalf("plugins = %+v", result.Plugins)
	}
	p := result.Plugins.Contexts[0].Plugins[0]
	if p.InstallPath != cache || p.SourcePath != source || !slices.ContainsFunc(p.Components, func(c model.PluginComponent) bool {
		return c.MCPConfig != nil && c.MCPConfig.ConfigPath == config
	}) {
		t.Fatalf("missing local-source plugin MCP: %+v", p)
	}
	if got := result.ReconcilePluginMCP(enterprise); !reflect.DeepEqual(got, enterprise) {
		t.Fatalf("independent enterprise MCP changed: got=%+v want=%+v", got, enterprise)
	}
	if got := result.ReconcilePluginMCPCommunity(community); !reflect.DeepEqual(got, community) {
		t.Fatalf("independent community MCP changed: got=%+v want=%+v", got, community)
	}
}

func TestPluginUsageIgnoresUnverifiedCustomState(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		partial     bool
	}{
		{name: "custom only"},
		{name: "verified home", state: `{"skillUsage":{"review":{"usageCount":2}}}`},
		{name: "partial verified home", state: `{"skillUsage":{"review":{"usageCount":2},"bad":{"usageCount":-1}}}`, partial: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			custom := filepath.Join(testHome, "custom-claude")
			m.SetEnv("CLAUDE_CONFIG_DIR", custom)
			fs.addFile(filepath.Join(custom, ".claude.json"), `{"skillUsage":{"review":{"usageCount":99}}}`)
			fs.addSkill(filepath.Join(custom, "skills/review"), "SKILL.md", validFrontmatter("review", "test"), nil)
			if tc.state != "" {
				fs.addFile(filepath.Join(testHome, ".claude.json"), tc.state)
			}
			fs.commit()
			result := NewSkillsDetector(m).DetectSkills(context.Background(), nil, nil)
			if len(result.Skills) != 1 {
				t.Fatalf("skills = %+v", result.Skills)
			}
			usage := result.Skills[0].Usage
			if tc.state == "" {
				if usage != nil && (usage.Availability == "available" || usage.RecordedUses != nil) {
					t.Fatalf("unverified state supplied usage: %+v", usage)
				}
				return
			}
			if usage == nil || usage.Availability != "available" || usage.RecordedUses == nil || *usage.RecordedUses != 2 {
				t.Fatalf("verified counter not retained: %+v", usage)
			}
			if len(result.usage.Sources) != 1 || (result.usage.Sources[0].Status == model.AgentScanStatusPartial) != tc.partial {
				t.Fatalf("incorrect usage sources: %+v", result.usage)
			}
		})
	}
}

func TestClaudeStateGuardedRead(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(outside, []byte(`{"skillUsage":{"should-not-read":{"usageCount":1}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, ".claude.json")); err != nil {
		t.Skip(err)
	}
	got := readClaudeState(executor.NewReal(), nil, home)
	if got.code != model.AgentScanErrUnsafePath || len(got.skillUsage) != 0 {
		t.Fatalf("escaped state read: %+v", got)
	}
}

func TestPluginUsageNumbers(t *testing.T) {
	m, _ := newPluginMock()
	s := pluginScan{d: NewSkillsDetector(m)}
	tests := []struct {
		raw   string
		valid bool
	}{
		{`{"usageCount":0}`, true}, {`{"usageCount":9007199254740991,"lastUsedAt":9999999999999}`, true},
		{`{"usageCount":-1}`, false}, {`{"usageCount":1.5}`, false}, {`{"usageCount":9007199254740992}`, false},
		{`{"usageCount":1,"lastUsedAt":-1}`, false}, {`{}`, false}, {`null`, false},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			got := s.usageSource(claudeState{path: "/home/.claude.json", skillUsage: map[string]json.RawMessage{"uninstalled:command": json.RawMessage(tc.raw)}}, model.AgentScanStatusComplete)
			if (len(got.Counters) == 1) != tc.valid {
				t.Fatalf("counters = %+v", got.Counters)
			}
			if !tc.valid && got.Status != model.AgentScanStatusPartial {
				t.Fatal("invalid counter was authoritative")
			}
		})
	}
}

func TestPluginVersionOrder(t *testing.T) {
	for _, tc := range []struct{ low, high string }{
		{"1.9.0", "1.10.0"}, {"1.0.0-rc.2", "1.0.0-rc.10"}, {"1.0.0-rc.10", "1.0.0"}, {"1.0.0-alpha", "1.0.0-beta"}, {"aaa", "bbb"},
	} {
		t.Run(tc.low, func(t *testing.T) {
			if compareVersionLabels(tc.low, tc.high) >= 0 || compareVersionLabels(tc.high, tc.low) <= 0 {
				t.Fatalf("wrong ordering: %s < %s", tc.low, tc.high)
			}
		})
	}
}

func TestPluginMCPFormatsAndRedaction(t *testing.T) {
	server := `{"test-server":{"command":"test-command","env":{"TOKEN":"private-value"},"headers":{"Authorization":"private-value"}}}`
	for _, tc := range []struct{ name, body string }{
		{"direct", server}, {"wrapped", `{"mcpServers":` + server + `}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			root := filepath.Join(testHome, "plugin")
			file := filepath.Join(root, ".mcp.json")
			fs.addFile(file, tc.body)
			fs.commit()
			d := NewSkillsDetector(m)
			s := &pluginScan{d: d, ctx: context.Background(), evidence: newPluginEvidence()}
			p := newPlugin("test-plugin@company", "test-plugin", model.PluginInstallMarketplace, model.PluginScopeUser)
			r := pluginRootScan{s: s, gd: d, p: p, root: root}
			r.mcpFileComponents(file, ".mcp.json", false)
			if len(p.Components) != 1 || p.Components[0].MCPConfig == nil {
				t.Fatalf("missing MCP: %+v", p.Components)
			}
			body, err := base64.StdEncoding.DecodeString(p.Components[0].MCPConfig.ConfigContentBase64)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "private-value") || strings.Contains(string(body), "headers") || strings.Contains(string(body), "env") {
				t.Fatalf("unexpected MCP fields: %s", body)
			}
		})
	}
}

func TestPluginWindowsPathIdentity(t *testing.T) {
	s := pluginScan{goos: model.PlatformWindows}
	for _, tc := range [][2]string{
		{``, ``},
		{`/`, `/`},
		{`C:\`, `c:`},
		{`C:\Users\TEST\.claude\`, `c:/users/test/.claude`},
		{`\\?\C:\Users\test\.claude`, `c:/users/test/.claude`},
		{`\\.\C:\Users\test\.claude`, `c:/users/test/.claude`},
		{`\??\C:\Users\test\.claude`, `c:/users/test/.claude`},
		{`\\SERVER\Share\plugins`, `//server/share/plugins`},
		{`\\?\UNC\SERVER\Share\plugins`, `//server/share/plugins`},
		{`//?/unc/SERVER/Share/plugins`, `//server/share/plugins`},
	} {
		if got := s.hashPath(tc[0]); got != tc[1] {
			t.Errorf("hashPath(%q) = %q, want %q", tc[0], got, tc[1])
		}
	}
}

func TestPluginWindowsContextRoundTrip(t *testing.T) {
	s := pluginScan{goos: model.PlatformWindows, d: &SkillsDetector{}}
	for _, root := range []string{`C:\Users\Test\.claude`, `\\?\C:\Users\Test\.claude`, `\\server\share\.claude`, `\\?\UNC\server\share\.claude`} {
		t.Run(root, func(t *testing.T) {
			context := s.newContext("claude-code", root, root+`\plugins`)
			data, err := json.Marshal(context)
			if err != nil {
				t.Fatal(err)
			}
			var decoded model.AgentPluginContext
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if want := cleanPluginPath(root); decoded.ConfigRoot != want {
				t.Errorf("ConfigRoot = %q, want %q", decoded.ConfigRoot, want)
			}
			if got := s.contextID(decoded.Agent, decoded.ConfigRoot, decoded.PluginRoot); decoded.ContextID != got {
				t.Errorf("ContextID = %q, want %q from serialized coordinates", decoded.ContextID, got)
			}
		})
	}
}

type changingPluginMetadata struct {
	executor.Executor
	path       string
	reads      int
	continuous bool
}

func (e *changingPluginMetadata) GuardedFiles([]string, func(string) string, int64) executor.Executor {
	return e
}
func (e *changingPluginMetadata) ReadFile(p string) ([]byte, error) {
	if p == e.path {
		e.reads++
		if e.continuous {
			return fmt.Appendf(nil, `{"name":"test-plugin","version":"%d.0.0"}`, e.reads), nil
		}
		if e.reads > 1 {
			return []byte(`{"name":"test-plugin","version":"2.0.0"}`), nil
		}
	}
	return e.Executor.ReadFile(p)
}

func TestPluginSnapshotRetriesManifestChange(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".codex")
	m.SetEnv("CODEX_HOME", home)
	fs.addFile(filepath.Join(home, "config.toml"), "[plugins.'test-plugin@company']\nenabled = true\n")
	manifest := filepath.Join(home, "plugins/cache/company/test-plugin/local/.codex-plugin/plugin.json")
	fs.addFile(manifest, `{"name":"test-plugin","version":"1.0.0"}`)
	fs.addSkill(filepath.Join(filepath.Dir(filepath.Dir(manifest)), "skills/check"), "SKILL.md", validFrontmatter("check", "test"), nil)
	fs.commit()
	exec := &changingPluginMetadata{Executor: m, path: manifest}
	result := NewSkillsDetector(exec).DetectAll(context.Background(), nil, nil)
	if result.Plugins.PluginCount() != 1 {
		t.Fatalf("plugins = %+v", result.Plugins)
	}
	p := result.Plugins.Contexts[0].Plugins[0]
	if p.ManifestVersion != "2.0.0" || len(p.Components) != 1 || exec.reads != 4 {
		t.Fatalf("snapshot: version=%s, components=%d, reads=%d", p.ManifestVersion, len(p.Components), exec.reads)
	}
}

func TestPluginFailedRegistryDoesNotPromoteCachedMCP(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".claude")
	m.SetEnv("CLAUDE_CONFIG_DIR", home)
	fs.addFile(filepath.Join(home, "plugins/installed_plugins.json"), `{`)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	configs := []model.MCPConfigEnterprise{{ConfigPath: filepath.Join(home, "plugins/cache/company/test-plugin/old/.mcp.json")}, {ConfigPath: filepath.Join(testHome, "project/.mcp.json")}}
	got := result.ReconcilePluginMCP(configs)
	if len(got) != 1 || got[0].ConfigPath != configs[1].ConfigPath {
		t.Fatalf("cached MCP became standalone: %+v", got)
	}
	if result.Plugins.Contexts[0].InstallationStatus == model.AgentScanStatusComplete {
		t.Fatal("failed registry became complete")
	}
}

func TestCodexScopedPreferencesStaySeparate(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".codex")
	project := filepath.Join(testHome, "test-repo")
	m.SetEnv("CODEX_HOME", home)
	fs.addFile(filepath.Join(home, "config.toml"), "[plugins.'test-plugin@company']\nenabled = false\n[plugins.'test-plugin@company'.mcp_servers.docs]\nenabled = true\n[plugins.'other@company'.mcp_servers.docs]\nenabled = false\n")
	fs.addFile(filepath.Join(project, ".codex/config.toml"), "[plugins.'test-plugin@company']\nenabled = true\n[plugins.'test-plugin@company'.mcp_servers.docs]\nenabled = false\n")
	fs.addFile(filepath.Join(home, "plugins/cache/company/test-plugin/local/.codex-plugin/plugin.json"), `{"name":"test-plugin"}`)
	fs.addFile(filepath.Join(home, "plugins/cache/company/test-plugin/local/.mcp.json"), `{"mcpServers":{"docs":{"url":"https://docs.example.com/mcp"},"other":{"command":"example-server"}}}`)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), []string{project}, nil)
	if result.Plugins.PluginCount() != 1 {
		t.Fatalf("plugins = %+v", result.Plugins)
	}
	p := result.Plugins.Contexts[0].Plugins[0]
	if len(p.Enablement) != 2 || p.ConfiguredEnabled == nil || *p.ConfiguredEnabled || p.EffectiveEnabled != nil {
		t.Fatalf("conflated scoped preferences: %+v", p)
	}
	for _, c := range p.Components {
		if c.Name == "docs" {
			if len(c.MCPEnablement) != 2 || !c.MCPEnablement[0].Enabled || c.MCPEnablement[1].Enabled || c.MCPEnablement[1].ProjectPath != project {
				t.Fatalf("server policy = %+v", c.MCPEnablement)
			}
		} else if len(c.MCPEnablement) != 0 {
			t.Fatalf("policy leaked to %s", c.Name)
		}
	}
	fs.addFile(filepath.Join(project, ".codex/config.toml"), "[")
	fs.commit()
	result = NewSkillsDetector(m).DetectAll(context.Background(), []string{project}, nil)
	for _, c := range result.Plugins.Contexts[0].Plugins[0].Components {
		if c.Status != model.AgentScanStatusPartial {
			t.Fatalf("failed settings reported complete: %+v", c)
		}
	}
	p.Components[0].Status = model.AgentScanStatusComplete
	p.ComponentStatus = model.AgentScanStatusComplete
	a := codexAdapter{s: &pluginScan{projectsIncomplete: true}}
	a.mcpEnablement(&p)
	if p.Components[0].Status != model.AgentScanStatusPartial {
		t.Fatal("project limit lost policy retention")
	}
}

func TestClaudeScopedEnablement(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			id := "test-plugin@company"
			p := newPlugin(id, "test-plugin", model.PluginInstallMarketplace, model.PluginScopeLocal)
			p.ProjectPath = "/repo"
			a := claudeAdapter{layers: []claudeSettingsLayer{
				{scope: model.PluginScopeUser, path: "/home/settings.json", ok: true, enabled: map[string]bool{id: mask&1 != 0}},
				{scope: model.PluginScopeProject, path: "/repo/.claude/settings.json", projectPath: "/repo", ok: true, enabled: map[string]bool{id: mask&2 != 0}},
				{scope: model.PluginScopeLocal, path: "/repo/.claude/settings.local.json", projectPath: "/repo", ok: true, enabled: map[string]bool{id: mask&4 != 0}},
			}}
			a.enablement(p)
			if p.ConfiguredEnabled == nil || *p.ConfiguredEnabled != (mask&4 != 0) || p.EffectiveEnabled == nil || *p.EffectiveEnabled != (mask&4 != 0) || len(p.Enablement) != 3 {
				t.Fatalf("wrong precedence: %+v", p)
			}
			a.layers = a.layers[:2]
			p = newPlugin(id, "test-plugin", model.PluginInstallMarketplace, model.PluginScopeLocal)
			p.ProjectPath = "/repo"
			a.enablement(p)
			if p.ConfiguredEnabled != nil || p.EffectiveEnabled == nil || *p.EffectiveEnabled != (mask&2 != 0) {
				t.Fatalf("wrong fallback: %+v", p)
			}
		})
	}
}

func TestClaudeRegistryCoverage(t *testing.T) {
	tests := []struct{ name, body, status string }{
		{"empty", `{"version":2,"plugins":{}}`, model.AgentScanStatusComplete},
		{"malformed", `{`, model.AgentScanStatusError},
		{"missing map", `{"version":2}`, model.AgentScanStatusError},
		{"unsupported", `{"version":3}`, model.AgentScanStatusUnsupported},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			home := filepath.Join(testHome, ".claude")
			m.SetEnv("CLAUDE_CONFIG_DIR", home)
			fs.addFile(filepath.Join(home, "plugins/installed_plugins.json"), tc.body)
			fs.commit()
			result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
			if result.Plugins == nil || len(result.Plugins.Contexts) != 1 {
				t.Fatalf("missing context: %+v", result.Plugins)
			}
			if got := result.Plugins.Contexts[0].InstallationStatus; got != tc.status {
				t.Fatalf("status = %s, want %s", got, tc.status)
			}
		})
	}
}

func TestClaudeSyncedPayloadEvidence(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".claude")
	m.SetEnv("CLAUDE_CONFIG_DIR", home)
	fs.addFile(filepath.Join(home, "plugins/synced/account-bucket/.marketplaces.json"), `{}`)
	fs.commit()
	if result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil); result.Plugins.PluginCount() != 0 {
		t.Fatal("account bucket became a plugin")
	}
	fs.addFile(filepath.Join(home, "plugins/synced/account-bucket/test-plugin@synced/.claude-plugin/plugin.json"), `{"name":"test-plugin"}`)
	fs.addFile(filepath.Join(home, "plugins/synced/.trash/removed/.claude-plugin/plugin.json"), `{"name":"removed"}`)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if result.Plugins.PluginCount() != 1 {
		t.Fatalf("plugins = %+v", result.Plugins)
	}
	p := result.Plugins.Contexts[0].Plugins[0]
	if p.Name != "test-plugin" || p.EffectiveEnabled != nil || p.MarketplaceID != "" {
		t.Fatalf("wrong synced state: %+v", p)
	}
}

func TestClaudeComponentSelection(t *testing.T) {
	tests := []struct {
		name, manifest, source, declared string
		strict                           *bool
		want                             []string
		status                           string
	}{
		{name: "default and custom", manifest: `{"name":"test-plugin","skills":"./extra"}`, source: `"./plugin"`, want: []string{"default", "extra"}},
		{name: "catalog supplements manifest", manifest: `{"name":"test-plugin","skills":"./extra"}`, source: `"./plugin"`, declared: `"./selected"`, want: []string{"default", "extra", "selected"}},
		{name: "shared root subset", manifest: `{"name":"test-plugin"}`, source: `"./"`, declared: `"./selected"`, want: []string{"selected"}},
		{name: "strict conflict", manifest: `{"name":"test-plugin","skills":"./extra"}`, source: `"./plugin"`, declared: `"./selected"`, strict: boolPtr(false), status: model.AgentScanStatusError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			root := filepath.Join(testHome, "test-plugin")
			fs.addFile(filepath.Join(root, claudeManifestRel), tc.manifest)
			fs.addSkill(filepath.Join(root, "skills/default"), "SKILL.md", validFrontmatter("default", "test"), nil)
			fs.addSkill(filepath.Join(root, "extra/extra"), "SKILL.md", validFrontmatter("extra", "test"), nil)
			fs.addSkill(filepath.Join(root, "selected"), "SKILL.md", validFrontmatter("selected", "test"), nil)
			fs.commit()
			d := NewSkillsDetector(m)
			definitions := 0
			s := &pluginScan{d: d, ctx: context.Background(), memo: map[string]*skillScan{}, definitions: &definitions, evidence: newPluginEvidence()}
			a := claudeAdapter{s: s, gd: d}
			p := newPlugin("test-plugin@company", "test-plugin", model.PluginInstallMarketplace, model.PluginScopeUser)
			p.InstallPath = root
			entry := &claudeCatalogEntry{Source: json.RawMessage(tc.source), Strict: tc.strict, claudeDecls: claudeDecls{Skills: json.RawMessage(tc.declared)}}
			a.components(p, entry, &claudeMarket{catalogFile: filepath.Join(testHome, "catalog.json"), catalogPointer: "/plugins"})
			var names []string
			for _, c := range p.Components {
				names = append(names, c.Name)
			}
			slices.Sort(names)
			if !slices.Equal(names, tc.want) {
				t.Fatalf("components = %v, want %v", names, tc.want)
			}
			if tc.status != "" && p.ComponentStatus != tc.status {
				t.Fatalf("coverage = %s, want %s", p.ComponentStatus, tc.status)
			}
		})
	}
}

func TestCodexPortableValidation(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		valid       bool
	}{
		{"plain", "", true}, {"unknown legacy field", `,"interface":42`, true},
		{"ignored extensions", `,"extensions":[]`, true}, {"ignored namespace", `,"extensions":{"com.openai":false}`, true},
		{"null version", `,"version":null`, false}, {"bad author", `,"author":"publisher"`, false},
		{"unknown author field", `,"author":{"company":"example"}`, false}, {"null keyword", `,"keywords":[null]`, false},
		{"descriptive version", `,"version":"preview"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(`{"$schema":"`+codexPortableSchema+`","name":"developer-tools"`+tc.extra+`}`), &fields); err != nil {
				t.Fatal(err)
			}
			_, valid := parsePortableManifest(fields)
			if valid != tc.valid {
				t.Fatalf("valid = %v, want %v", valid, tc.valid)
			}
		})
	}
	for _, name := range []string{"", "Bad", "bad--name", "bad..name", "-bad", "bad_"} {
		raw, _ := json.Marshal(name)
		if _, ok := parsePortableManifest(map[string]json.RawMessage{"name": raw}); ok {
			t.Fatalf("accepted name %q", name)
		}
	}
	m, _ := newPluginMock()
	d := NewSkillsDetector(m)
	r := &pluginRootScan{s: &pluginScan{goos: model.PlatformWindows}, gd: d, root: testHome}
	for _, tc := range []struct{ name, raw, code string }{
		{"stdio", `{"type":"stdio","command":"example-server","args":[],"env":{},"cwd":"${PLUGIN_DATA}"}`, ""},
		{"http", `{"type":"streamable-http","url":"https://docs.example.com/mcp"}`, ""},
		{"loopback", `{"type":"streamable-http","url":"http://127.0.0.1:8000/mcp"}`, ""},
		{"sse", `{"type":"sse","url":"https://docs.example.com/mcp"}`, model.AgentScanErrUnsupportedSchema},
		{"missing type", `{"command":"example-server"}`, model.AgentScanErrParseFailed},
		{"cross variant", `{"type":"stdio","command":"server","url":"https://example.com"}`, model.AgentScanErrParseFailed},
		{"null args", `{"type":"stdio","command":"server","args":null}`, model.AgentScanErrParseFailed},
		{"null argument", `{"type":"stdio","command":"server","args":[null]}`, model.AgentScanErrParseFailed},
		{"reserved env", `{"type":"stdio","command":"server","env":{"plugin_root":"anything"}}`, model.AgentScanErrParseFailed},
		{"escape", `{"type":"stdio","command":"./../server"}`, model.AgentScanErrParseFailed},
		{"absolute", `{"type":"stdio","command":"/usr/bin/server"}`, model.AgentScanErrParseFailed},
		{"bad cwd", `{"type":"stdio","command":"server","cwd":"${PLUGIN_DATA}/../escape"}`, model.AgentScanErrParseFailed},
		{"remote http", `{"type":"streamable-http","url":"http://docs.example.com/mcp"}`, model.AgentScanErrParseFailed},
		{"userinfo", `{"type":"streamable-http","url":"https://user@docs.example.com/mcp"}`, model.AgentScanErrParseFailed},
		{"duplicate headers", `{"type":"streamable-http","url":"https://docs.example.com/mcp","headers":{"Accept":"a","accept":"b"}}`, model.AgentScanErrParseFailed},
		{"unknown field", `{"type":"stdio","command":"server","enabled":true}`, model.AgentScanErrParseFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.portableMCPError(json.RawMessage(tc.raw)); got != tc.code {
				t.Fatalf("error = %q, want %q", got, tc.code)
			}
		})
	}
}

func TestCodexPortableDescriptiveComponents(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".codex")
	m.SetEnv("CODEX_HOME", home)
	fs.addFile(filepath.Join(home, "config.toml"), "[plugins.'test-plugin@company']\nenabled = false\n")
	root := filepath.Join(home, "plugins/cache/company/test-plugin/local")
	fs.addFile(filepath.Join(root, "plugin.json"), `{"$schema":"`+codexPortableSchema+`","name":"test-plugin","interface":42,"skills":"ignored","extensions":{"com.openai":{"apps":"./.app.json","hooks":"./hooks.json"}}}`)
	fs.addFile(filepath.Join(root, ".app.json"), `{"apps":{"test-app":{"id":"connector_example"}}}`)
	fs.addFile(filepath.Join(root, "hooks.json"), `{"hooks":{}}`)
	fs.addSkill(filepath.Join(root, "skills/fixed"), "SKILL.md", validFrontmatter("fixed", "test"), nil)
	fs.addSkill(filepath.Join(root, "ignored/ignored"), "SKILL.md", validFrontmatter("ignored", "test"), nil)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if result.Plugins.PluginCount() != 1 {
		t.Fatalf("plugins = %+v", result.Plugins)
	}
	p := result.Plugins.Contexts[0].Plugins[0]
	var names []string
	for _, c := range p.Components {
		names = append(names, c.Name)
		if c.Status != model.AgentScanStatusComplete {
			t.Errorf("descriptive component coverage = %s", c.Status)
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"fixed", "hooks", "test-app"}) {
		t.Fatalf("components = %v", names)
	}
	for _, envelope := range []string{
		`{"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json","mcpServers":{"docs":{"type":"streamable-http","url":"https://docs.example.com/mcp"},"invalid":{"command":"server"}}}`,
		`{"mcpServers":{"docs":{"command":"server"}}}`,
	} {
		fs.addFile(filepath.Join(root, "mcp.json"), envelope)
		fs.commit()
		result = NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
		p = result.Plugins.Contexts[0].Plugins[0]
		if p.ComponentStatus == model.AgentScanStatusComplete {
			t.Fatal("invalid MCP marked complete")
		}
		foundSkill, foundHTTP := false, false
		for _, c := range p.Components {
			foundSkill = foundSkill || c.Name == "fixed" && c.Skill != nil
			foundHTTP = foundHTTP || c.Name == "docs" && c.MCPConfig != nil
		}
		if !foundSkill || (strings.Contains(envelope, "$schema") && !foundHTTP) {
			t.Fatalf("valid siblings lost: %+v", p.Components)
		}
	}
}

func TestClaudeInlineCatalogCanonicalAlias(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".claude")
	m.SetEnv("CLAUDE_CONFIG_DIR", home)
	root := filepath.Join(home, "plugins/cache/company/test-plugin/1")
	registry, _ := json.Marshal(map[string]any{"version": 2, "plugins": map[string]any{"test-plugin@company": []map[string]string{{"scope": "user", "installPath": root}}}})
	fs.addFile(filepath.Join(home, "plugins/installed_plugins.json"), string(registry))
	fs.addFile(filepath.Join(root, claudeManifestRel), `{"name":"test-plugin"}`)
	fs.addFile(filepath.Join(home, "settings.json"), `{"additionalMarketplaces":{"ignored":{"source":{"source":"github","repo":"example/ignored"}}},"extraKnownMarketplaces":{"company":{"source":{"source":"settings","name":"company","plugins":[{"name":"test-plugin","source":{"source":"npm","package":"@example/test-plugin","version":"^1.0.0","registry":"https://user:secret@registry.example.com?token=secret"}}]},"autoUpdate":false}}}`)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	c := result.Plugins.Contexts[0]
	if len(c.Marketplaces) != 1 || c.Marketplaces[0].Name != "company" || c.Marketplaces[0].AutoUpdateEnabled == nil || *c.Marketplaces[0].AutoUpdateEnabled {
		t.Fatalf("catalog = %+v", c.Marketplaces)
	}
	if len(c.Plugins) != 1 || c.Plugins[0].Source == nil || c.Plugins[0].Source.PackageName != "@example/test-plugin" {
		t.Fatalf("payload source = %+v", c.Plugins)
	}
	data, _ := json.Marshal(result.Plugins)
	if strings.Contains(string(data), "secret") {
		t.Fatal("source credentials were serialized")
	}
}

func TestClaudeSeedRelocationAndPriority(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".claude")
	first, second := filepath.Join(testHome, "seed-one"), filepath.Join(testHome, "seed-two")
	m.SetGOOS(model.PlatformLinux)
	m.SetEnv("CLAUDE_CONFIG_DIR", home)
	m.SetEnv("CLAUDE_CODE_PLUGIN_SEED_DIR", first+":"+second)
	registry, _ := json.Marshal(map[string]any{"version": 2, "plugins": map[string]any{"test-plugin@company": []map[string]string{{"scope": "user", "installPath": "/old/build/cache/company/test-plugin/1.0.0", "version": "1.0.0"}}}})
	fs.addFile(filepath.Join(home, "plugins/installed_plugins.json"), string(registry))
	for _, seed := range []string{first, second} {
		fs.addFile(filepath.Join(seed, claudeKnownMarketplaces), `{"company":{"source":{"source":"github","repo":"example/test-repo"},"installLocation":"/old/build/marketplaces/company"}}`)
		fs.addFile(filepath.Join(seed, "marketplaces/company", claudeCatalogRel), `{"name":"company","plugins":[{"name":"test-plugin","source":"./plugin"}]}`)
		fs.addFile(filepath.Join(seed, "cache/company/test-plugin/1.0.0", claudeManifestRel), `{"name":"test-plugin"}`)
	}
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if result.Plugins.PluginCount() != 1 {
		t.Fatalf("plugins = %+v", result.Plugins)
	}
	c := result.Plugins.Contexts[0]
	if c.Plugins[0].InstallPath != filepath.Join(first, "cache/company/test-plugin/1.0.0") || c.Marketplaces[0].CatalogPath != filepath.Join(first, "marketplaces/company", claudeCatalogRel) {
		t.Fatalf("seed paths = %+v", c)
	}
}

func TestClaudeUsageFailurePreservesProjectDiscovery(t *testing.T) {
	m, fs := newPluginMock()
	project := filepath.Join(testHome, "test-repo")
	state, err := json.Marshal(map[string]any{"projects": map[string]any{project: map[string]any{}}, "skillUsage": 42})
	if err != nil {
		t.Fatal(err)
	}
	fs.addFile(filepath.Join(testHome, ".claude.json"), string(state))
	mcpPath := filepath.Join(project, ".mcp.json")
	fs.addFile(mcpPath, `{"mcpServers":{"test-server":{"command":"test-mcp","args":["--stdio"]}}}`)
	fs.addSkill(filepath.Join(project, ".claude/skills/check"), "SKILL.md", validFrontmatter("check", "test"), nil)
	fs.commit()
	st := readClaudeState(m, nil, testHome)
	if !slices.Equal(st.projects, []string{project}) || st.usageCode != model.AgentScanErrParseFailed || st.code != "" || st.projectsCode != "" {
		t.Fatalf("unrelated project discovery changed: %+v", st)
	}
	if got := discoverClaudeProjects(m); !slices.Equal(got, st.projects) {
		t.Fatalf("MCP project discovery = %v, want %v", got, st.projects)
	}
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if len(result.Skills) != 1 || result.Skills[0].ProjectPath != project || result.Info.Truncated {
		t.Fatalf("invalid usage changed project skills: %+v", result)
	}
	if result.usage == nil || len(result.usage.Sources) != 1 || result.usage.Sources[0].Status != model.AgentScanStatusError {
		t.Fatalf("usage failure not reported: %+v", result.usage)
	}
	mcp := NewMCPDetector(m)
	enterprise := mcp.DetectEnterprise(context.Background(), nil)
	community := mcp.Detect(context.Background(), "testuser", nil, false)
	if !slices.ContainsFunc(enterprise, func(c model.MCPConfigEnterprise) bool {
		return c.ConfigPath == mcpPath && c.ConfigSource == "project_mcp" && c.ConfigContentBase64 != ""
	}) || !slices.ContainsFunc(community, func(c model.MCPConfig) bool { return c.ConfigPath == mcpPath }) {
		t.Fatalf("invalid usage hid project MCP: enterprise=%+v community=%+v", enterprise, community)
	}
	if !reflect.DeepEqual(result.ReconcilePluginMCP(enterprise), enterprise) || !reflect.DeepEqual(result.ReconcilePluginMCPCommunity(community), community) {
		t.Fatal("plugin reconciliation changed standalone MCP records")
	}
}

type pluginReadOnlyExecutor struct {
	executor.Executor
	t         *testing.T
	reads     map[string]int
	panicPath string
}

func (e *pluginReadOnlyExecutor) GuardedFiles([]string, func(string) string, int64) executor.Executor {
	return e
}
func (e *pluginReadOnlyExecutor) ReadFile(p string) ([]byte, error) {
	if p == e.panicPath {
		panic("injected plugin read failure")
	}
	if filepath.Base(p) == "auth.json" || strings.Contains(p, "remote_plugin_catalog") {
		e.t.Fatalf("forbidden read: %s", p)
	}
	e.reads[p]++
	return e.Executor.ReadFile(p)
}
func (e *pluginReadOnlyExecutor) Run(context.Context, string, ...string) (string, string, int, error) {
	e.t.Fatal("inventory executed a command")
	return "", "", 1, nil
}
func (e *pluginReadOnlyExecutor) RunWithTimeout(context.Context, time.Duration, string, ...string) (string, string, int, error) {
	e.t.Fatal("inventory executed a command")
	return "", "", 1, nil
}
func (e *pluginReadOnlyExecutor) RunInDir(context.Context, string, time.Duration, string, ...string) (string, string, int, error) {
	e.t.Fatal("inventory executed a command")
	return "", "", 1, nil
}
func (e *pluginReadOnlyExecutor) RunAsUser(context.Context, string, string) (string, error) {
	e.t.Fatal("inventory executed a user command")
	return "", nil
}

func TestPluginCollectorReadOnlyAndSharedDefinition(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".claude")
	root := filepath.Join(home, "plugins/cache/company/test-plugin/1")
	skill := filepath.Join(root, "skills/check")
	registry, _ := json.Marshal(map[string]any{"version": 2, "plugins": map[string]any{"test-plugin@company": []map[string]string{{"scope": "user", "installPath": root}}}})
	fs.addFile(filepath.Join(home, "plugins/installed_plugins.json"), string(registry))
	fs.addFile(filepath.Join(root, claudeManifestRel), `{"name":"test-plugin"}`)
	fs.addSkill(skill, "SKILL.md", validFrontmatter("check", "test"), nil)
	fs.addSymlink(filepath.Join(home, "skills/check"), skill)
	fs.addFile(filepath.Join(home, "commands/review.md"), "Review this project.")
	fs.addFile(filepath.Join(testHome, ".claude.json"), `{"skillUsage":{"test-plugin:check":{"usageCount":0,"lastUsedAt":1700000000000}}}`)
	fs.commit()
	spy := &pluginReadOnlyExecutor{Executor: m, t: t, reads: map[string]int{}}
	detector := NewSkillsDetector(spy)
	detector.now = func() time.Time { return time.UnixMilli(1700000000001) }
	skillsCtx, skillsCancel := context.WithCancel(context.Background())
	defer skillsCancel()
	result := detector.DetectSkills(skillsCtx, nil, nil)
	if result.Plugins != nil || spy.reads[filepath.Join(home, "plugins/installed_plugins.json")] != 0 {
		t.Fatal("skills phase read plugin installation metadata")
	}
	if len(result.Skills) != 2 || result.usage == nil || result.Info.CommandsStatus != model.AgentScanStatusComplete {
		t.Fatalf("skills phase did not finish commands and usage: %+v", result)
	}
	info, usage := *result.Info, result.usage
	skillsCancel()
	if err := detector.DetectPlugins(context.Background(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Info.DurationMs != info.DurationMs || result.Info.Truncated != info.Truncated || result.usage != usage {
		t.Fatal("plugin phase changed completed skills or usage observations")
	}
	if result.Plugins.PluginCount() != 1 || len(result.Skills) != 2 || result.usage == nil {
		t.Fatalf("lost independent exposure: %+v", result)
	}
	if spy.reads[filepath.Join(skill, "SKILL.md")] != 1 || spy.reads[filepath.Join(testHome, ".claude.json")] != 1 {
		t.Fatalf("repeated definition/state reads: %v", spy.reads)
	}
	if result.Plugins.CollectedAtMs != result.usage.CollectedAtMs {
		t.Fatal("envelopes have different observation times")
	}
}

func TestPluginPhaseFailurePreservesSkills(t *testing.T) {
	for _, failure := range []string{"cancelled", "panic"} {
		t.Run(failure, func(t *testing.T) {
			m, fs := newPluginMock()
			home := filepath.Join(testHome, ".claude")
			registry := filepath.Join(home, "plugins/installed_plugins.json")
			fs.addFile(registry, `{"version":2,"plugins":{}}`)
			fs.addFile(filepath.Join(home, "commands/review.md"), "Review this project.")
			fs.addFile(filepath.Join(testHome, ".claude.json"), `{"skillUsage":{"review":{"usageCount":2}}}`)
			fs.commit()
			spy := &pluginReadOnlyExecutor{Executor: m, t: t, reads: map[string]int{}}
			d := NewSkillsDetector(spy)
			result := d.DetectSkills(context.Background(), nil, nil)
			before, err := json.Marshal([]any{result.Skills, result.Info, result.usage})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if failure == "cancelled" {
				cancel()
			} else {
				spy.panicPath = registry
			}
			err = d.DetectPlugins(ctx, &result)
			if failure == "panic" {
				if err == nil || result.Plugins != nil || result.evidence != nil {
					t.Fatalf("failed plugin scan must remain unreported: err=%v result=%+v", err, result)
				}
			} else {
				if err != nil || result.Plugins == nil {
					t.Fatalf("missing interrupted coverage: err=%v result=%+v", err, result)
				}
				for _, c := range result.Plugins.Contexts {
					if c.InstallationStatus == model.AgentScanStatusComplete || c.MarketplaceStatus == model.AgentScanStatusComplete {
						t.Fatalf("cancelled plugins reported complete: %+v", c)
					}
				}
			}
			after, err := json.Marshal([]any{result.Skills, result.Info, result.usage})
			if err != nil || string(after) != string(before) {
				t.Fatalf("plugin failure changed skills or usage: err=%v", err)
			}
		})
	}
}

func TestCodexPersonalCatalogAndDeclaredSkillRoot(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".codex")
	fs.addFile(filepath.Join(home, "config.toml"), "[plugins.'test-plugin@company']\nenabled = true\n")
	fs.addFile(filepath.Join(testHome, ".agents/plugins/marketplace.json"), `{"name":"company","plugins":[{"name":"test-plugin","source":"./test-plugin"}]}`)
	root := filepath.Join(home, "plugins/cache/company/test-plugin/local")
	fs.addFile(filepath.Join(root, ".codex-plugin/plugin.json"), `{"name":"test-plugin","skills":["./review","./missing"]}`)
	fs.addSkill(filepath.Join(root, "review"), "SKILL.md", validFrontmatter("review", "test"), nil)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if result.Plugins.PluginCount() != 1 {
		t.Fatalf("inventory = %+v", result.Plugins)
	}
	c := result.Plugins.Contexts[0]
	if len(c.Marketplaces) != 1 || c.Marketplaces[0].Source == nil || c.Marketplaces[0].Registered {
		t.Fatalf("discovered catalog = %+v", c.Marketplaces)
	}
	p := c.Plugins[0]
	if len(p.Components) != 2 || p.ComponentStatus != model.AgentScanStatusPartial {
		t.Fatalf("components = %+v", p)
	}
	for _, component := range p.Components {
		if component.Name == "review" && component.Skill == nil {
			t.Fatal("declared root skill was missed")
		}
		if component.Name == "missing" && component.Status != model.AgentScanStatusError {
			t.Fatal("missing declaration was treated as empty")
		}
	}
	data, err := json.Marshal(result.Plugins)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), ":null") {
		t.Fatalf("required array serialized as null: %s", data)
	}
}

func TestPluginEnvelopeBoundsKeepReferences(t *testing.T) {
	d := NewSkillsDetector(executor.NewMock())
	s := &pluginScan{d: d, goos: model.PlatformLinux, now: time.UnixMilli(1700000000000)}
	c := s.newContext(model.AgentCodex, "/home/test/.codex", "/home/test/.codex/plugins")
	for i := range maxMarketplaceObs + 1 {
		name := fmt.Sprintf("market-%03d", i)
		marketID := marketplaceID(c.ContextID, name)
		c.Marketplaces = append(c.Marketplaces, model.MarketplaceObservation{MarketplaceID: marketID, Name: name})
		p := newPlugin("test@"+name, "test", model.PluginInstallMarketplace, model.PluginScopeUser)
		p.MarketplaceID = marketID
		p.Source = &model.SourceLocator{Kind: model.PluginSourceGit, RequestedRef: strings.Repeat("x", maxPathBytes+1)}
		s.addPlugin(c, p)
	}
	result := s.finalizePluginScan([]*model.AgentPluginContext{c})
	got := result.Contexts[0]
	if len(got.Marketplaces) != maxMarketplaceObs || len(got.Plugins) != maxMarketplaceObs || got.InstallationStatus != model.AgentScanStatusPartial {
		t.Fatalf("bounds: markets=%d plugins=%d coverage=%s", len(got.Marketplaces), len(got.Plugins), got.InstallationStatus)
	}
	for _, p := range got.Plugins {
		if p.Source != nil || p.ComponentStatus != model.AgentScanStatusPartial {
			t.Fatal("unbounded source survived")
		}
	}
}

func TestClaudeMissingLSPAndMalformedCommand(t *testing.T) {
	m, fs := newPluginMock()
	root := filepath.Join(testHome, "test-plugin")
	fs.addFile(filepath.Join(root, claudeManifestRel), `{"name":"test-plugin","lspServers":"./missing.json"}`)
	fs.addFile(filepath.Join(root, "commands/check.md"), "---\nallowed-tools: [\n---\nbody")
	fs.commit()
	d := NewSkillsDetector(m)
	definitions := 0
	s := &pluginScan{d: d, ctx: context.Background(), home: testHome, definitions: &definitions, memo: map[string]*skillScan{}, evidence: newPluginEvidence()}
	a := &claudeAdapter{s: s, gd: s.guarded(root)}
	p := newPlugin("test-plugin@company", "test-plugin", model.PluginInstallMarketplace, model.PluginScopeUser)
	p.InstallPath = root
	a.components(p, nil, nil)
	if len(p.Components) != 2 || p.ComponentStatus != model.AgentScanStatusPartial {
		t.Fatalf("components = %+v", p)
	}
	for _, c := range p.Components {
		if c.Status != model.AgentScanStatusError || c.Command != nil {
			t.Fatalf("invalid definition claimed success: %+v", c)
		}
	}
}

func TestPluginSnapshotStopsAfterSecondChange(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".codex")
	fs.addFile(filepath.Join(home, "config.toml"), "[plugins.'test-plugin@company']\nenabled = true\n")
	manifest := filepath.Join(home, "plugins/cache/company/test-plugin/local/.codex-plugin/plugin.json")
	fs.addFile(manifest, `{"name":"test-plugin"}`)
	fs.commit()
	exec := &changingPluginMetadata{Executor: m, path: manifest, continuous: true}
	result := NewSkillsDetector(exec).DetectAll(context.Background(), nil, nil)
	if result.Plugins.PluginCount() != 1 || exec.reads != 4 {
		t.Fatalf("retry: reads=%d plugins=%+v", exec.reads, result.Plugins)
	}
	c := result.Plugins.Contexts[0]
	if c.InstallationStatus != model.AgentScanStatusPartial || c.Plugins[0].ComponentStatus != model.AgentScanStatusPartial {
		t.Fatalf("mixed snapshot claimed complete: %+v", c)
	}
	found := false
	for _, err := range c.Errors {
		found = found || err.Code == model.AgentScanErrSourceChanged
	}
	if !found {
		t.Fatal("missing source_changed error")
	}
}

func TestLocalPluginMCPExamplesStayOutOfStandaloneInventory(t *testing.T) {
	m, fs := newPluginMock()
	root := filepath.Join(testHome, "local-plugin")
	fs.addFile(filepath.Join(root, claudeManifestRel), `{"name":"test-plugin"}`)
	fs.commit()
	d := NewSkillsDetector(m)
	definitions := 0
	s := &pluginScan{d: d, ctx: context.Background(), home: testHome, definitions: &definitions, memo: map[string]*skillScan{}, evidence: newPluginEvidence()}
	a := &claudeAdapter{s: s, gd: s.guarded(root)}
	p := newPlugin("test-plugin@skills-dir", "test-plugin", model.PluginInstallDirectory, model.PluginScopeUser)
	p.InstallPath = root
	a.components(p, nil, nil)
	result := SkillsResult{evidence: s.evidence}
	wantEnterprise := []model.MCPConfigEnterprise{
		{ConfigSource: "project_mcp", ConfigPath: filepath.Join(testHome, "other-project/.mcp.json"), Vendor: "Project", ConfigContentBase64: "e30="},
		{ConfigSource: "project_mcp", ConfigPath: filepath.Join(root+"-project", ".mcp.json"), Vendor: "Project", ConfigContentBase64: "e30="},
	}
	wantCommunity := []model.MCPConfig{}
	for _, c := range wantEnterprise {
		wantCommunity = append(wantCommunity, model.MCPConfig{ConfigSource: c.ConfigSource, ConfigPath: c.ConfigPath, Vendor: c.Vendor})
	}
	pluginPath := filepath.Join(root, "examples/.mcp.json")
	enterprise := append([]model.MCPConfigEnterprise{{ConfigPath: pluginPath}}, wantEnterprise...)
	community := append([]model.MCPConfig{{ConfigPath: pluginPath}}, wantCommunity...)
	beforeEnterprise, beforeCommunity := slices.Clone(enterprise), slices.Clone(community)
	if got := result.ReconcilePluginMCP(enterprise); !reflect.DeepEqual(got, wantEnterprise) {
		t.Fatalf("standalone enterprise MCP changed: got=%+v want=%+v", got, wantEnterprise)
	}
	if got := result.ReconcilePluginMCPCommunity(community); !reflect.DeepEqual(got, wantCommunity) {
		t.Fatalf("standalone community MCP changed: got=%+v want=%+v", got, wantCommunity)
	}
	if !reflect.DeepEqual(enterprise, beforeEnterprise) || !reflect.DeepEqual(community, beforeCommunity) {
		t.Fatal("plugin reconciliation mutated the original MCP inventory")
	}
	if !reflect.DeepEqual((SkillsResult{}).ReconcilePluginMCP(enterprise), enterprise) || !reflect.DeepEqual((SkillsResult{}).ReconcilePluginMCPCommunity(community), community) {
		t.Fatal("unreported plugins changed the MCP inventory")
	}
}

func TestPluginMCPReconciliationPreservesConfiguredSources(t *testing.T) {
	root := filepath.Join(testHome, "local-plugin")
	config := filepath.Join(root, ".mcp.json")
	evidence := newPluginEvidence()
	evidence.owned[config] = true
	evidence.suppress(root)
	component := model.PluginComponent{Kind: model.PluginComponentMCP, Status: model.AgentScanStatusComplete, DefinitionPath: config, MCPConfig: &model.MCPConfigEnterprise{ConfigPath: config}}
	plugin := model.PluginObservation{ComponentStatus: model.AgentScanStatusComplete, Components: []model.PluginComponent{component}}
	result := SkillsResult{evidence: evidence, Plugins: &model.AgentPlugins{Contexts: []model.AgentPluginContext{{Plugins: []model.PluginObservation{plugin}}}}}
	sources := []string{"project_mcp"}
	for _, spec := range mcpConfigDefinitions {
		sources = append(sources, spec.SourceName)
	}
	for _, source := range sources {
		t.Run(source, func(t *testing.T) {
			enterprise := []model.MCPConfigEnterprise{{ConfigSource: source, ConfigPath: config, ConfigContentBase64: "e30="}}
			community := []model.MCPConfig{{ConfigSource: source, ConfigPath: config}}
			if got := result.ReconcilePluginMCP(enterprise); !reflect.DeepEqual(got, enterprise) {
				t.Fatalf("independent enterprise MCP changed: %+v", got)
			}
			if got := result.ReconcilePluginMCPCommunity(community); !reflect.DeepEqual(got, community) {
				t.Fatalf("independent community MCP changed: %+v", got)
			}
		})
	}
	for _, source := range []string{"discovered_mcp", "claude_plugin", "codex_plugin"} {
		t.Run(source, func(t *testing.T) {
			enterprise := []model.MCPConfigEnterprise{{ConfigSource: source, ConfigPath: config}}
			community := []model.MCPConfig{{ConfigSource: source, ConfigPath: config}}
			if got := result.ReconcilePluginMCP(enterprise); len(got) != 0 {
				t.Fatalf("plugin-owned walker finding retained: %+v", got)
			}
			if got := result.ReconcilePluginMCPCommunity(community); len(got) != 0 {
				t.Fatalf("plugin-owned community walker finding retained: %+v", got)
			}
		})
	}
}

func TestPluginMCPReconciliationKeepsUnrepresentedServers(t *testing.T) {
	root := filepath.Join(testHome, "plugins/cache/company/widgets/1.0.0")
	config := filepath.Join(root, ".mcp.json")
	t.Run("unregistered cache file", func(t *testing.T) {
		evidence := newPluginEvidence()
		evidence.suppress(filepath.Join(testHome, "plugins/cache"))
		result := SkillsResult{evidence: evidence}
		for _, source := range []string{"claude_plugin", "codex_plugin"} {
			if got := result.ReconcilePluginMCP([]model.MCPConfigEnterprise{{ConfigSource: source, ConfigPath: config}}); len(got) != 0 {
				t.Errorf("%s orphan cache server retained in enterprise inventory: %+v", source, got)
			}
			if got := result.ReconcilePluginMCPCommunity([]model.MCPConfig{{ConfigSource: source, ConfigPath: config}}); len(got) != 0 {
				t.Errorf("%s orphan cache server retained in community inventory: %+v", source, got)
			}
		}
	})
	for _, tc := range []struct {
		name, status                      string
		reported, component, wantRetained bool
	}{
		{name: "envelope omitted", wantRetained: true},
		{name: "component omitted", reported: true, status: model.AgentScanStatusPartial, wantRetained: true},
		{name: "some servers omitted", reported: true, component: true, status: model.AgentScanStatusPartial, wantRetained: true},
		{name: "all servers represented", reported: true, component: true, status: model.AgentScanStatusComplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence := newPluginEvidence()
			evidence.owned[config] = true
			evidence.suppress(root)
			result := SkillsResult{evidence: evidence}
			if tc.reported {
				plugin := model.PluginObservation{ComponentStatus: tc.status}
				if tc.component {
					component := model.PluginComponent{Kind: model.PluginComponentMCP, Status: model.AgentScanStatusComplete, DefinitionPath: config, MCPConfig: &model.MCPConfigEnterprise{ConfigPath: config}}
					plugin.Components = []model.PluginComponent{component}
				}
				result.Plugins = &model.AgentPlugins{Contexts: []model.AgentPluginContext{{Plugins: []model.PluginObservation{plugin}}}}
			}
			for _, source := range []string{"claude_plugin", "discovered_mcp"} {
				enterprise := result.ReconcilePluginMCP([]model.MCPConfigEnterprise{{ConfigSource: source, ConfigPath: config}})
				community := result.ReconcilePluginMCPCommunity([]model.MCPConfig{{ConfigSource: source, ConfigPath: config}})
				if (len(enterprise) == 1) != tc.wantRetained || (len(community) == 1) != tc.wantRetained {
					t.Errorf("source %q: enterprise=%d community=%d, want retained=%t", source, len(enterprise), len(community), tc.wantRetained)
				}
			}
		})
	}
}

func TestClaudeAutoUpdateScalar(t *testing.T) {
	for _, tc := range []struct {
		name  string
		prefs []model.EnablementObservation
		want  *bool
	}{
		{name: "unset"},
		{name: "managed overrides project", prefs: []model.EnablementObservation{{Scope: model.PluginScopeSystem, Enabled: true}, {Scope: model.PluginScopeProject, Enabled: false}}, want: boolPtr(true)},
		{name: "user and project conflict", prefs: []model.EnablementObservation{{Scope: model.PluginScopeUser, Enabled: true}, {Scope: model.PluginScopeProject, Enabled: false}}},
		{name: "project preferences agree", prefs: []model.EnablementObservation{{Scope: model.PluginScopeProject, Enabled: false}, {Scope: model.PluginScopeLocal, Enabled: false}}, want: boolPtr(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := autoUpdateScalar(tc.prefs); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("autoUpdateScalar() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPluginStandaloneCommandOutputBound(t *testing.T) {
	m, fs := newPluginMock()
	for i := 0; i < maxNewDefinitions+1; i++ {
		fs.addFile(filepath.Join(testHome, ".claude", "commands", fmt.Sprintf("cmd-%04d.md", i)), "Safe inert text.")
	}
	fs.commit()
	r := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	t.Logf("returned=%d configured-definition-cap=%d coverage=%s", len(r.Skills), maxNewDefinitions, r.Info.CommandsStatus)
	if len(r.Skills) != maxNewDefinitions || r.Info.CommandsStatus != model.AgentScanStatusPartial {
		t.Fatalf("unbounded command rows: got %d, cap %d", len(r.Skills), maxNewDefinitions)
	}
}

func TestPluginDeclaredSymlinkOutsidePlugin(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "plugin")
	outside := filepath.Join(home, "unrelated")
	for _, dir := range []string{root, outside} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "SKILL.md"), []byte("---\nname: unrelated\ndescription: unrelated private skill\n---\nbody"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "mcp.json"), []byte(`{"mcpServers":{"unrelated":{"command":"dummy"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "external")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	d := NewSkillsDetector(executor.NewReal())
	definitions := 0
	s := &pluginScan{d: d, ctx: context.Background(), home: home, memo: map[string]*skillScan{}, definitions: &definitions, evidence: newPluginEvidence()}
	p := newPlugin("test@catalog", "test", model.PluginInstallMarketplace, model.PluginScopeUser)
	p.InstanceID = "test"
	r := &pluginRootScan{s: s, gd: s.guarded(root), p: p, root: root, attr: nestedAttr{agent: model.AgentClaudeCode}}
	r.skillComponent(link, "external", "external", "test:external")
	r.mcpFileComponents(filepath.Join(link, "mcp.json"), "external/mcp.json", true)
	s.commands = map[string]commandMeta{filepath.Join(link, "SKILL.md"): {hash: "previously-read"}}
	r.commandComponent(filepath.Join(link, "SKILL.md"), "external/SKILL.md", "SKILL", "/test:SKILL")
	if len(p.Components) != 3 || p.ComponentStatus == model.AgentScanStatusComplete {
		t.Fatalf("escaped definitions must retain failed identities: %+v", p)
	}
	for _, c := range p.Components {
		t.Logf("kind=%s status=%s name=%s resolved=%s", c.Kind, c.Status, c.Name, c.ResolvedDefinitionPath)
		if c.Skill != nil || c.MCPConfig != nil || c.Command != nil {
			t.Errorf("read definition outside plugin via in-home symlink: %s", c.Kind)
		}
	}
}

type pluginRefusingStat struct {
	executor.Executor
	path string
}

func (e pluginRefusingStat) GuardedFiles([]string, func(string) string, int64) executor.Executor {
	return e
}

func (e pluginRefusingStat) Stat(p string) (os.FileInfo, error) {
	if p == e.path {
		return nil, os.ErrPermission
	}
	return e.Executor.Stat(p)
}

func TestPluginDefaultSkillRootRefusal(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		t.Run(provider, func(t *testing.T) {
			m, fs := newPluginMock()
			root := filepath.Join(testHome, "test-plugin")
			fs.addFile(filepath.Join(root, claudeManifestRel), `{"name":"test-plugin"}`)
			fs.commit()
			d := NewSkillsDetector(m)
			gd := *d
			gd.exec = pluginRefusingStat{Executor: m, path: filepath.Join(root, "skills")}
			n := 0
			s := &pluginScan{d: d, ctx: context.Background(), memo: map[string]*skillScan{}, definitions: &n, evidence: newPluginEvidence()}
			p := newPlugin("test-plugin@company", "test-plugin", model.PluginInstallMarketplace, model.PluginScopeUser)
			p.InstallPath = root
			if provider == "claude" {
				a := claudeAdapter{s: s, gd: &gd}
				a.components(p, nil, nil)
			} else {
				a := codexAdapter{s: s, gd: &gd}
				a.components(p)
			}
			if p.ComponentStatus == model.AgentScanStatusComplete {
				t.Fatalf("unreadable skills root returned COMPLETE with %d components", len(p.Components))
			}
		})
	}
}

func TestPluginInlineCatalogLayers(t *testing.T) {
	m, _ := newPluginMock()
	d := NewSkillsDetector(m)
	s := &pluginScan{d: d, ctx: context.Background()}
	c := s.newContext(model.AgentClaudeCode, "/home/test/.claude", "/home/test/.claude/plugins")
	a := claudeAdapter{s: s, gd: d, c: c, pluginRoot: "/home/test/.claude/plugins", markets: map[string]*claudeMarket{}}
	for _, layer := range []struct{ scope, version string }{{model.PluginScopeUser, "1.0.0"}, {model.PluginScopeProject, "2.0.0"}} {
		a.layers = append(a.layers, claudeSettingsLayer{scope: layer.scope, path: "/settings/" + layer.scope, ok: true, marketplaceKey: "extraKnownMarketplaces", marketplaces: map[string]claudeSettingsMarketplace{"company": {Source: claudeSourceSpec{Source: "settings", Plugins: []claudeCatalogEntry{{Name: "test-plugin", Version: layer.version, Source: json.RawMessage(`"./plugin"`)}}}}}})
	}
	a.readMarketplaces()
	market := a.markets["company"]
	if c.MarketplaceStatus == model.AgentScanStatusComplete || market.catalogError == "" || len(market.entries) != 0 || market.obs.Source != nil {
		t.Fatalf("conflicting scoped catalogs must remain unresolved: %+v", market)
	}
}

func TestPluginSkillCallableUsesFrontmatterName(t *testing.T) {
	m, fs := newPluginMock()
	root := filepath.Join(testHome, "test-plugin")
	fs.addSkill(filepath.Join(root, "skills/folder"), "SKILL.md", validFrontmatter("native-name", "test"), nil)
	fs.commit()
	d := NewSkillsDetector(m)
	n := 0
	s := &pluginScan{d: d, ctx: context.Background(), memo: map[string]*skillScan{}, definitions: &n, evidence: newPluginEvidence()}
	p := newPlugin("test-plugin@company", "test-plugin", model.PluginInstallMarketplace, model.PluginScopeUser)
	r := pluginRootScan{s: s, gd: d, p: p, root: root, attr: nestedAttr{agent: model.AgentClaudeCode}}
	r.skillComponent(filepath.Join(root, "skills/folder"), "skills/folder", "folder", "test-plugin:folder")
	if len(p.Components) != 1 {
		t.Fatalf("components: %+v", p.Components)
	}
	c := p.Components[0]
	if c.CallableNames[0] != "test-plugin:native-name" {
		t.Fatalf("nested skill name %q but callable %q", c.Skill.SkillName, c.CallableNames[0])
	}
}

func TestPluginCatalogFailureProtectsComponents(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".claude")
	m.SetEnv("CLAUDE_CONFIG_DIR", home)
	root := filepath.Join(home, "plugins/cache/company/test-plugin/1.0.0")
	catalog := filepath.Join(home, "plugins/marketplaces/company")
	reg, _ := json.Marshal(map[string]any{"version": 2, "plugins": map[string]any{"test-plugin@company": []any{map[string]any{"scope": "user", "installPath": root, "version": "1.0.0"}}}})
	known, _ := json.Marshal(map[string]any{"company": map[string]any{"source": map[string]any{"source": "git", "url": "https://example.com/market.git"}, "installLocation": catalog}})
	fs.addFile(filepath.Join(home, "plugins/installed_plugins.json"), string(reg))
	fs.addFile(filepath.Join(home, "plugins/known_marketplaces.json"), string(known))
	fs.addFile(filepath.Join(catalog, claudeCatalogRel), `{"name":`)
	fs.addFile(filepath.Join(root, "README.md"), "manifestless plugin")
	fs.addFile(filepath.Join(home, "skills", "unrelated", claudeManifestRel), `{ "name": "unrelated" }`)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	found := map[string]bool{}
	for _, c := range result.Plugins.Contexts {
		if c.Agent == model.AgentClaudeCode {
			for _, p := range c.Plugins {
				found[p.Name] = true
				if (p.Name == "test-plugin" && p.ComponentStatus == model.AgentScanStatusComplete) || (p.Name == "unrelated" && p.ComponentStatus != model.AgentScanStatusComplete) {
					t.Fatalf("catalog=%s; plugin components=%s/%d", c.MarketplaceStatus, p.ComponentStatus, len(p.Components))
				}
			}
		}
	}
	if !found["test-plugin"] || !found["unrelated"] {
		t.Fatalf("missing fixture plugins: %v", found)
	}
}

func TestPluginMarketplaceRegistryFailureProtectsComponents(t *testing.T) {
	for _, tc := range []struct {
		name, contents, code string
		refused              bool
	}{
		{name: "malformed", contents: `{"company":`, code: model.AgentScanErrParseFailed},
		{name: "null", contents: `null`, code: model.AgentScanErrParseFailed},
		{name: "unreadable", contents: `{}`, code: model.AgentScanErrReadFailed, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			home := filepath.Join(testHome, ".claude")
			registryPath := filepath.Join(home, "plugins", claudeKnownMarketplaces)
			installations := map[string][]claudeRegistryRecord{}
			for _, name := range []string{"dependent", "independent"} {
				root := filepath.Join(home, "plugins/cache", name, name, "1.0.0")
				installations[name+"@"+name] = []claudeRegistryRecord{{Scope: "user", InstallPath: root}}
				fs.addFile(filepath.Join(root, "README.md"), "manifestless plugin")
			}
			registry, err := json.Marshal(map[string]any{"version": 2, "plugins": installations})
			if err != nil {
				t.Fatal(err)
			}
			fs.addFile(filepath.Join(home, "plugins", claudeInstalledRegistry), string(registry))
			fs.addFile(registryPath, tc.contents)
			fs.addFile(filepath.Join(home, "settings.json"), `{"extraKnownMarketplaces":{"independent":{"source":{"source":"settings","plugins":[{"name":"independent","source":"./","lspServers":{"test":{"command":"unused"}}}]}}}}`)
			fs.addFile(filepath.Join(home, "skills/unrelated", claudeManifestRel), `{"name":"unrelated"}`)
			fs.commit()
			var exec executor.Executor = m
			if tc.refused {
				exec = pluginRefusingStat{Executor: m, path: registryPath}
			}
			result := NewSkillsDetector(exec).DetectAll(context.Background(), nil, nil)
			if result.Plugins.PluginCount() != 3 {
				t.Fatalf("missing plugins: %+v", result.Plugins)
			}
			for _, context := range result.Plugins.Contexts {
				if context.Agent != model.AgentClaudeCode {
					continue
				}
				if context.MarketplaceStatus != model.AgentScanStatusError || context.InstallationStatus != model.AgentScanStatusComplete {
					t.Fatalf("incorrect registry coverage: %+v", context)
				}
				for _, plugin := range context.Plugins {
					if plugin.Name != "dependent" {
						if plugin.ComponentStatus != model.AgentScanStatusComplete {
							t.Fatalf("independent evidence degraded: %+v", plugin)
						}
						if plugin.Name == "independent" && len(plugin.Components) != 1 {
							t.Fatalf("independent catalog lost: %+v", plugin)
						}
						continue
					}
					if plugin.ComponentStatus != model.AgentScanStatusPartial || len(plugin.Components) != 0 || plugin.Installed == nil || !*plugin.Installed {
						t.Fatalf("failed registry yielded authoritative components: %+v", plugin)
					}
					if len(plugin.Errors) != 1 || plugin.Errors[0].Code != tc.code || plugin.Errors[0].SourcePath != registryPath {
						t.Fatalf("registry failure evidence missing: %+v", plugin.Errors)
					}
				}
			}
		})
	}
}

func TestPluginProjectLimitMustDowngradeCommandCoverage(t *testing.T) {
	m, fs := newPluginMock()
	var projects []string
	for i := 0; i <= maxProjects; i++ {
		p := filepath.Join(testHome, fmt.Sprintf("repo-%03d", i))
		projects = append(projects, p)
		fs.mkdir(p)
	}
	fs.addFile(filepath.Join(projects[maxProjects], ".claude/commands/check.md"), "Review this project.")
	fs.addFile(filepath.Join(testHome, ".claude/settings.json"), "{}")
	fs.commit()
	got := NewSkillsDetector(m).DetectAll(context.Background(), projects, nil)
	if !got.Info.Truncated {
		t.Fatal("setup: expected project discovery cap")
	}
	if got.Info.CommandsStatus == model.AgentScanStatusComplete {
		t.Fatalf("omitted a known project with commands but commands_status=%s, projects=%d, commands=%d", got.Info.CommandsStatus, got.Info.ProjectsScanned, len(got.Skills))
	}
	if got.Plugins == nil {
		t.Fatal("missing plugin context")
	}
	for _, c := range got.Plugins.Contexts {
		if c.InstallationStatus == model.AgentScanStatusComplete || c.MarketplaceStatus == model.AgentScanStatusComplete {
			t.Fatalf("partial project discovery became authoritative in the plugin phase: %+v", c)
		}
	}
}

func TestPluginOversizeStateMustDowngradeSkillsAndCommands(t *testing.T) {
	m, fs := newPluginMock()
	project := filepath.Join(testHome, "only-registered-project")
	body, _ := json.Marshal(map[string]any{"projects": map[string]any{project: map[string]any{}}, "other": strings.Repeat("x", maxJSONConfigBytes)})
	fs.addFile(filepath.Join(testHome, ".claude.json"), string(body))
	fs.addSkill(filepath.Join(project, ".claude/skills/check"), "SKILL.md", validFrontmatter("check", "Check this"), nil)
	fs.addFile(filepath.Join(project, ".claude/commands/other.md"), "Check this.")
	fs.commit()
	got := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if got.usage == nil || got.usage.Sources[0].Status != model.AgentScanStatusError {
		t.Fatal("setup: expected capped state read")
	}
	if !got.Info.Truncated || got.Info.CommandsStatus == model.AgentScanStatusComplete {
		t.Fatalf("unread project registry yielded authoritative discovery: truncated=%t commands_status=%s projects=%d skills=%d", got.Info.Truncated, got.Info.CommandsStatus, got.Info.ProjectsScanned, len(got.Skills))
	}
}

func TestClaudeStateIndependentCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, state               string
		partialProjects, badUsage bool
	}{
		{"valid", `{"projects":{"/Users/testuser/repo":{}},"skillUsage":{}}`, false, false},
		{"bad usage", `{"projects":{"/Users/testuser/repo":{}},"skillUsage":42}`, false, true},
		{"bad projects", `{"projects":42,"skillUsage":{}}`, true, false},
		{"null projects", `{"projects":null,"skillUsage":{}}`, true, false},
		{"bad file", `{`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			fs.addFile(filepath.Join(testHome, ".claude.json"), tc.state)
			fs.addSkill(filepath.Join(testHome, "repo/.claude/skills/check"), "SKILL.md", validFrontmatter("check", "test"), nil)
			fs.addFile(filepath.Join(testHome, "repo/.claude/commands/run.md"), "Run this.")
			fs.commit()
			got := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
			if got.Info.Truncated != tc.partialProjects || (got.Info.CommandsStatus != model.AgentScanStatusComplete) != tc.partialProjects {
				t.Fatalf("project coverage: %+v", got.Info)
			}
			if !tc.partialProjects && (got.Info.ProjectsScanned != 1 || len(got.Skills) != 2) {
				t.Fatalf("project definitions lost: %+v", got)
			}
			if got.usage == nil || (got.usage.Sources[0].Status == model.AgentScanStatusError) != tc.badUsage {
				t.Fatalf("usage coverage: %+v", got.usage)
			}
		})
	}
}

func TestOrdinarySkillLimitPreservesCommandCoverage(t *testing.T) {
	m, fs := newPluginMock()
	for i := 0; i <= maxSkillsPerRoot; i++ {
		fs.addSkill(filepath.Join(testHome, ".claude/skills", fmt.Sprintf("skill-%04d", i)), "SKILL.md", validFrontmatter("check", "test"), nil)
	}
	fs.addFile(filepath.Join(testHome, ".claude/commands/run.md"), "Run this.")
	fs.commit()
	got := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if !got.Info.Truncated || got.Info.CommandsStatus != model.AgentScanStatusComplete {
		t.Fatalf("unrelated coverage coupled: %+v", got.Info)
	}
}

func TestPluginSharedPayloadSnapshot(t *testing.T) {
	m, fs := newPluginMock()
	home := filepath.Join(testHome, ".claude")
	root := filepath.Join(home, "plugins/cache/company/test-plugin/1.0.0")
	registry, err := json.Marshal(map[string]any{"version": 2, "plugins": map[string]any{"test-plugin@company": []any{
		map[string]any{"scope": "user", "installPath": root},
		map[string]any{"scope": "project", "projectPath": filepath.Join(testHome, "repo"), "installPath": root},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	fs.addFile(filepath.Join(home, "plugins/installed_plugins.json"), string(registry))
	fs.addFile(filepath.Join(root, claudeManifestRel), `{"name":"test-plugin"}`)
	fs.addFile(filepath.Join(root, claudeMCPFile), `{"mcpServers":{"test":{"command":"test"}}}`)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	if result.Plugins.PluginCount() != 2 {
		t.Fatalf("shared installation missing: %+v", result.Plugins)
	}
	for _, context := range result.Plugins.Contexts {
		if context.InstallationStatus != model.AgentScanStatusComplete {
			t.Fatalf("unchanged shared payload treated as changing: %+v", context)
		}
		for _, plugin := range context.Plugins {
			if plugin.ComponentStatus != model.AgentScanStatusComplete || len(plugin.Components) != 1 {
				t.Fatalf("shared payload incomplete: %+v", plugin)
			}
		}
	}
}

func TestPluginSkillUsageAssociation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		qualified bool
		duplicate bool
		command   bool
		want      string
		count     int64
	}{
		{"qualified", true, false, false, "available", 3},
		{"bare", false, false, false, "available", 8},
		{"duplicate namespace", true, true, false, "ambiguous", 0},
		{"command", true, false, true, "available", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			component := model.PluginComponent{Kind: "skill", Name: "review", RelativePath: "skills/review/SKILL.md", CallableNames: []string{"widgets:review"}, Skill: &model.AgentSkill{SkillName: "review"}}
			if tc.command {
				component.Kind = "command"
				component.Skill = nil
				component.Command = &model.AgentCommandDefinition{Name: "review"}
			}
			plugin := model.PluginObservation{Name: "widgets", NativeID: "widgets", MarketplaceID: "market-one", Components: []model.PluginComponent{component}}
			counters := []skillUsageCounter{{RawKey: "review", RecordedUses: 8}}
			if tc.qualified {
				counters = append(counters, skillUsageCounter{RawKey: "widgets:review", RecordedUses: 3})
			}
			result := SkillsResult{Plugins: &model.AgentPlugins{Contexts: []model.AgentPluginContext{{Agent: model.AgentClaudeCode, Plugins: []model.PluginObservation{plugin}}}}, usage: &skillUsageObservations{CollectedAtMs: 100, Sources: []skillUsageSource{{SourceID: "source", Counters: counters}}}}
			if tc.duplicate {
				other := plugin
				other.MarketplaceID = "market-two"
				other.Components = []model.PluginComponent{{Kind: "skill", Name: "review", RelativePath: component.RelativePath, CallableNames: component.CallableNames, Skill: &model.AgentSkill{SkillName: "review"}}}
				result.Plugins.Contexts[0].Plugins = append(result.Plugins.Contexts[0].Plugins, other)
			}
			associateSkillUsage(&result)
			usage := component.Skill
			var snapshot *model.SkillUsage
			if usage != nil {
				snapshot = usage.Usage
			} else {
				snapshot = component.Command.Usage
			}
			if snapshot == nil || snapshot.Availability != tc.want {
				t.Fatalf("usage=%+v, want %s", snapshot, tc.want)
			}
			if tc.want == "available" && (snapshot.RecordedUses == nil || *snapshot.RecordedUses != tc.count) {
				t.Fatalf("wrong selected counter: %+v", snapshot)
			}
			if tc.want == "ambiguous" && snapshot.RecordedUses != nil {
				t.Fatal("ambiguous name received a counter")
			}
		})
	}
}

func TestPluginSkillUsageStandaloneZeroAndCollision(t *testing.T) {
	result := SkillsResult{Skills: []model.AgentSkill{{Agent: model.AgentClaudeCode, SkillName: "review", SkillMDPath: "/home/test/.claude/skills/review/SKILL.md"}, {Agent: model.AgentCodex, SkillName: "review", SkillMDPath: "/home/test/.agents/skills/review/SKILL.md"}},
		usage: &skillUsageObservations{CollectedAtMs: 100, Sources: []skillUsageSource{{SourceID: "source", Counters: []skillUsageCounter{{RawKey: "review", RecordedUses: 0}}}}}}
	associateSkillUsage(&result)
	if u := result.Skills[0].Usage; u == nil || u.RecordedUses == nil || *u.RecordedUses != 0 {
		t.Fatalf("explicit zero lost: %+v", u)
	}
	if result.Skills[1].Usage != nil {
		t.Fatal("Codex inherited Claude usage")
	}
	result.Skills = append(result.Skills, model.AgentSkill{Agent: model.AgentClaudeCode, SkillName: "review", DefinitionKind: "command", DefinitionPath: "/home/test/.claude/commands/review.md"})
	associateSkillUsage(&result)
	for _, i := range []int{0, 2} {
		if u := result.Skills[i].Usage; u == nil || u.Availability != "ambiguous" || u.RecordedUses != nil {
			t.Fatalf("collision attributed: %+v", u)
		}
	}
	result.usage.Sources = nil
	associateSkillUsage(&result)
	if result.Skills[0].Usage.Availability != "unavailable" {
		t.Fatal("failed source inferred a count")
	}
}
