package detector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
	"github.com/tailscale/hujson"
	"github.com/tidwall/gjson"
	"howett.net/plist"

	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Agent configuration bounds. The backend re-applies the same numbers.
const (
	agentConfigBudget     = 30 * time.Second
	maxConfigSources      = 250
	maxConfigHooks        = 100
	maxConfigAgentBytes   = 128 << 10
	maxConfigValues       = 50
	maxConfigTextBytes    = 256
	maxConfigPathBytes    = 1024
	maxConfigHandlerBytes = 32
)

const (
	configAgentClaude  = "claude-code"
	configAgentCodex   = "codex"
	configAgentCursor  = "cursor"
	configAgentGemini  = "gemini-cli"
	configAgentCopilot = "github-copilot"

	managedPrefsDir = "/Library/Managed Preferences"
)

// configKeys are the posture keys reported per agent, in output order. A dotted
// key is a nested path first, then a literal top-level key.
var configKeys = map[string][]string{
	configAgentClaude: {
		"permissions.defaultMode", "permissions.allow", "permissions.deny",
		"permissions.disableBypassPermissionsMode", "sandbox.enabled", "sandbox.allowUnsandboxedCommands",
		"disableAllHooks", "allowManagedHooksOnly", "allowManagedMcpServersOnly", "allowManagedPermissionRulesOnly",
	},
	configAgentCodex: {"approval_policy", "approvals_reviewer", "sandbox_mode", "allow_managed_hooks_only", "features.hooks"},
	configAgentCopilot: {
		"defaultPermissionMode", "sandbox.enabled", "disableAllHooks", "allowManagedHooksOnly",
		"permissions.disableBypassPermissionsMode", "chat.tools.global.autoApprove", "chat.permissions.default",
		"chat.tools.terminal.autoApprove", "chat.agent.sandbox.enabled", "chat.useHooks",
	},
	configAgentCursor: {"approvalMode", "permissions.allow", "permissions.deny", "sandbox.mode", "terminalAllowlist", "autoRun", "type"},
	configAgentGemini: {"general.defaultApprovalMode", "tools.allowed", "tools.sandbox", "hooksConfig.enabled"},
}

// vscodePolicies maps the two VS Code policies read to the settings key they
// enforce. No other VS Code policy is read.
var vscodePolicies = []struct{ policy, key string }{
	{"ChatToolsAutoApprove", "chat.tools.global.autoApprove"},
	{"ChatHooks", "chat.useHooks"},
}

// hookCommandFields hold a command handler's text, per shell where the agent
// supports several.
var hookCommandFields = []string{"command", "bash", "powershell", "windows", "linux", "osx"}

// hookHandlerFields mark an object as a handler; an object with none of them
// declares no hook.
var hookHandlerFields = append([]string{"type", "url", "prompt", "server", "tool"}, hookCommandFields...)

// ConfigAgents selects the agents whose configuration is reported even when no
// source exists, from the AI CLI and IDE inventories.
func ConfigAgents(tools []model.AITool, ides []model.IDE) map[string]bool {
	out := map[string]bool{}
	for _, t := range tools {
		switch t.Name {
		case configAgentClaude, configAgentCodex, configAgentGemini:
			out[t.Name] = true
		case "github-copilot-cli":
			out[configAgentCopilot] = true
		case "cursor-agent":
			out[configAgentCursor] = true
		}
	}
	for _, ide := range ides {
		if ide.IDEType == "cursor" {
			out[configAgentCursor] = true
		}
	}
	return out
}

// DetectAgentConfig reports the settings sources of each AI coding agent over
// the project list the skills scan built. The section is left unset when that
// list is unavailable, the user's environment cannot be read (overrides such as
// COPILOT_HOME and XDG_CONFIG_HOME would fall back to their defaults), the
// budget expires or the reader panics, so the backend keeps its stored state
// instead of losing sources that still exist.
func (d *SkillsDetector) DetectAgentConfig(ctx context.Context, result *SkillsResult) {
	s := result.pendingPlugins
	if s == nil || s.projectsUnavailable || executor.UserEnvironmentError(s.d.exec) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, agentConfigBudget)
	defer cancel()
	s.ctx = ctx
	defer func() {
		if r := recover(); r != nil {
			result.AgentConfig = nil
		}
	}()
	c := &configScan{
		s: s, projects: slices.Concat(s.projects, s.configProjects),
		forms: homeForms(s.home, s.d.resolvePath(s.home), s.goos), fold: s.goos == model.PlatformWindows,
	}
	scan := c.run(d.configAgents)
	if ctx.Err() != nil {
		return
	}
	result.AgentConfig = scan
}

type configScan struct {
	s        *pluginScan
	projects []string // skills projects, then settings-only projects
	forms    []string // home folder spellings, longest first
	fold     bool     // Windows: ASCII case-insensitive, either slash
}

func (c *configScan) run(detected map[string]bool) *model.AgentConfigScan {
	s := c.s
	readers := []struct {
		name string
		read func(*configAgent)
	}{
		{configAgentClaude, c.claude},
		{configAgentCodex, c.codex},
		{configAgentCursor, c.cursor},
		{configAgentGemini, c.gemini},
		{configAgentCopilot, c.copilot},
	}
	scan := &model.AgentConfigScan{RepositoriesScanned: len(c.projects), Agents: []model.AgentConfig{}}
	for _, r := range readers {
		a := &configAgent{c: c, out: model.AgentConfig{Agent: r.name, Sources: []model.AgentConfigSource{}}, keys: configKeys[r.name]}
		r.read(a)
		a.finalize()
		if s.projectsCut {
			a.out.Truncated = true // project sources beyond the cut are missing
		}
		found := detected[r.name]
		if r.name == configAgentCopilot && !found {
			root := copilotConfigRoot(s.d.exec, s.home)
			st, _, _ := s.stat(s.guarded(root), root)
			found = st == fileDir
		}
		if found || len(a.out.Sources) > 0 {
			scan.Agents = append(scan.Agents, a.out)
		}
	}
	return scan
}

// ---------------------------------------------------------------------------
// Sources per agent
// ---------------------------------------------------------------------------

func (c *configScan) claude(a *configAgent) {
	s := c.s
	managed := s.managedSettingsPath()
	dropIns := filepath.Join(filepath.Dir(managed), "managed-settings.d")
	root := filepath.Clean(claudeConfigDir(s.d.exec, s.home))
	gd := s.guarded(root, filepath.Dir(managed))
	a.file(gd, model.AgentConfigScopeManaged, managed, jsoncDoc)
	for _, p := range c.jsonFiles(gd, dropIns) {
		a.file(gd, model.AgentConfigScopeManaged, p, jsoncDoc)
	}
	c.profile(a, "com.anthropic.claudecode", plainProfile, false)
	if s.goos == model.PlatformWindows {
		for _, hive := range []string{"HKLM", "HKCU"} {
			a.registry(hive+`\SOFTWARE\Policies\ClaudeCode`, "Settings", false, func(v string) (gjson.Result, bool) {
				return jsoncDoc([]byte(v))
			})
		}
	}
	a.file(gd, model.AgentConfigScopeUser, filepath.Join(root, "settings.json"), jsoncDoc)
	for _, p := range c.projects {
		for _, name := range []string{"settings.json", "settings.local.json"} {
			a.file(gd, model.AgentConfigScopeProject, filepath.Join(p, ".claude", name), jsoncDoc)
		}
	}
}

func (c *configScan) codex(a *configAgent) {
	s := c.s
	a.notify = true
	home := filepath.Join(s.home, ".codex")
	if env := s.d.exec.Getenv("CODEX_HOME"); env != "" {
		home = filepath.Clean(env)
	}
	system := s.codexSystemConfigPath()
	sysDir := filepath.Dir(system)
	gd := s.guarded(home, sysDir)
	a.file(gd, model.AgentConfigScopeManaged, system, tomlDoc)
	a.file(gd, model.AgentConfigScopeManaged, filepath.Join(sysDir, "requirements.toml"), tomlDoc)
	a.file(gd, model.AgentConfigScopeManaged, filepath.Join(sysDir, "hooks.json"), jsoncDoc)
	c.profile(a, "com.openai.codex", codexProfile, false)
	if s.goos == model.PlatformWindows {
		c.codexRequirementsPath(a)
	}
	a.file(gd, model.AgentConfigScopeUser, filepath.Join(home, "config.toml"), tomlDoc)
	a.file(gd, model.AgentConfigScopeUser, filepath.Join(home, "hooks.json"), jsoncDoc)
	for _, p := range c.projects {
		a.file(gd, model.AgentConfigScopeProject, filepath.Join(p, ".codex", "config.toml"), tomlDoc)
		a.file(gd, model.AgentConfigScopeProject, filepath.Join(p, ".codex", "hooks.json"), jsoncDoc)
	}
}

// codexRequirementsPath reads the requirements file the Codex policy value
// names. Only a local drive path is opened: a read on a network share ignores
// the context and could hold the phase past its budget.
func (c *configScan) codexRequirementsPath(a *configAgent) {
	s := c.s
	const key = `HKLM\SOFTWARE\Policies\OpenAI\Codex`
	v, found, err := readRegistryValue(s.ctx, s.d.exec, key, "RequirementsPath")
	if !found {
		return
	}
	path := key + `\RequirementsPath`
	if err != nil || !localDrivePath(v) {
		a.add(model.AgentConfigScopeManaged, model.AgentConfigChannelWindowsRegistry, path, gjson.Result{}, false, false)
		return
	}
	file := filepath.Clean(v)
	data, absent, code := s.readMetadata(s.guarded(filepath.Dir(file)), file)
	if absent || code != "" {
		a.add(model.AgentConfigScopeManaged, model.AgentConfigChannelWindowsRegistry, path, gjson.Result{}, false, false)
		return
	}
	doc, ok := tomlDoc(data)
	a.add(model.AgentConfigScopeManaged, model.AgentConfigChannelWindowsRegistry, path, doc, ok, false)
}

// localDrivePath accepts X:\... or X:/... only, never UNC or relative paths.
func localDrivePath(p string) bool {
	return len(p) >= 3 && isASCIILetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

func (c *configScan) cursor(a *configAgent) {
	s := c.s
	var managedDir string
	switch s.goos {
	case model.PlatformDarwin:
		managedDir = "/Library/Application Support/Cursor"
	case model.PlatformWindows:
		managedDir = filepath.Join(s.programData(), "Cursor")
	default:
		managedDir = "/etc/cursor"
	}
	root := filepath.Join(s.home, ".cursor")
	gd := s.guarded(root, managedDir)
	a.file(gd, model.AgentConfigScopeManaged, filepath.Join(managedDir, "hooks.json"), jsoncDoc)
	for _, name := range []string{"hooks.json", "cli-config.json", "permissions.json", "sandbox.json"} {
		a.file(gd, model.AgentConfigScopeUser, filepath.Join(root, name), jsoncDoc)
	}
	for _, p := range c.projects {
		for _, name := range []string{"hooks.json", "cli.json", "permissions.json", "sandbox.json"} {
			a.file(gd, model.AgentConfigScopeProject, filepath.Join(p, ".cursor", name), jsoncDoc)
		}
	}
}

func (c *configScan) gemini(a *configAgent) {
	s := c.s
	var managed string
	switch s.goos {
	case model.PlatformDarwin:
		managed = "/Library/Application Support/GeminiCli/settings.json"
	case model.PlatformWindows:
		managed = filepath.Join(s.programData(), "gemini-cli", "settings.json")
	default:
		managed = "/etc/gemini-cli/settings.json"
	}
	root := filepath.Join(s.home, ".gemini")
	gd := s.guarded(root, filepath.Dir(managed))
	a.file(gd, model.AgentConfigScopeManaged, managed, jsoncDoc)
	a.file(gd, model.AgentConfigScopeUser, filepath.Join(root, "settings.json"), jsoncDoc)
	for _, p := range c.projects {
		a.file(gd, model.AgentConfigScopeProject, filepath.Join(p, ".gemini", "settings.json"), jsoncDoc)
	}
}

func (c *configScan) copilot(a *configAgent) {
	s := c.s
	var managed, policyDir string
	switch s.goos {
	case model.PlatformDarwin:
		managed, policyDir = "/Library/Application Support/GitHubCopilot/managed-settings.json", "/etc/github-copilot/policy.d"
	case model.PlatformWindows:
		managed = resolveEnvPath(s.d.exec, `%ProgramFiles%\GitHubCopilot\managed-settings.json`)
		policyDir = filepath.Join(s.programData(), "GitHub", "Copilot", "policy.d")
	default:
		managed, policyDir = "/etc/github-copilot/managed-settings.json", "/etc/github-copilot/policy.d"
	}
	root := copilotConfigRoot(s.d.exec, s.home)
	gd := s.guarded(root, filepath.Dir(managed), policyDir)
	a.file(gd, model.AgentConfigScopeManaged, managed, jsoncDoc)
	for _, p := range c.jsonFiles(gd, policyDir) {
		a.file(gd, model.AgentConfigScopeManaged, p, jsoncDoc)
	}
	c.profile(a, "com.github.copilot", flatProfile, false)
	switch s.goos {
	case model.PlatformWindows:
		c.copilotRegistry(a)
		for _, p := range vscodePolicies {
			a.registry(`HKLM\Software\Policies\Microsoft\VSCode`, p.policy, true, func(v string) (gjson.Result, bool) {
				return jsonResult(map[string]any{p.key: vscodePolicyValue(v)})
			})
		}
	case model.PlatformDarwin:
		c.profile(a, "com.microsoft.VSCode", vscodePolicyProfile, true)
	default:
		const policy = "/etc/vscode/policy.json"
		data, absent, code := s.readMetadata(s.guarded(filepath.Dir(policy)), policy)
		if !absent && code == "" {
			if doc, ok := jsoncDoc(data); ok {
				doc, ok = vscodePolicyDoc(doc)
				a.add(model.AgentConfigScopeManaged, model.AgentConfigChannelFile, policy, doc, ok, true)
			}
		}
	}
	a.file(gd, model.AgentConfigScopeUser, filepath.Join(root, "settings.json"), jsoncDoc)
	for _, p := range c.jsonFiles(gd, filepath.Join(root, "hooks")) {
		a.file(gd, model.AgentConfigScopeUser, p, jsoncDoc)
	}
	for _, variant := range []string{"Code", "Code - Insiders"} {
		userRoot := s.vscodeUserRoot(variant)
		if userRoot == "" {
			continue
		}
		ex := s.vscodeReader(userRoot)
		c.vscodeSettings(a, ex, filepath.Join(userRoot, "settings.json"))
		entries, err := ex.ReadDir(filepath.Join(userRoot, "profiles"))
		if err != nil {
			continue
		}
		for _, name := range sortedEntryNames(entries) {
			c.vscodeSettings(a, ex, filepath.Join(userRoot, "profiles", name, "settings.json"))
		}
	}
	for _, p := range c.projects {
		for _, f := range c.jsonFiles(gd, filepath.Join(p, ".github", "hooks")) {
			a.file(gd, model.AgentConfigScopeProject, f, jsoncDoc)
		}
		for _, name := range []string{"settings.json", "settings.local.json"} {
			a.file(gd, model.AgentConfigScopeProject, filepath.Join(p, ".github", "copilot", name), jsoncDoc)
		}
	}
}

// copilotRegistry reads the Copilot policy key: one value per settings key,
// each holding JSON text, reported as one source.
func (c *configScan) copilotRegistry(a *configAgent) {
	const key = `HKLM\SOFTWARE\Policies\GitHubCopilot`
	values := map[string]any{}
	found, failed := false, false
	for _, name := range append(append([]string{}, a.keys...), "hooks") {
		v, ok, err := readRegistryValue(c.s.ctx, c.s.d.exec, key, name)
		if !ok {
			continue
		}
		found = true
		if err != nil {
			failed = true
			continue
		}
		values[name] = jsonOrString(v)
	}
	if !found {
		return
	}
	if failed {
		a.add(model.AgentConfigScopeManaged, model.AgentConfigChannelWindowsRegistry, key, gjson.Result{}, false, false)
		return
	}
	doc, ok := jsonResult(values)
	a.add(model.AgentConfigScopeManaged, model.AgentConfigChannelWindowsRegistry, key, doc, ok, false)
}

// vscodeSettings reads a VS Code settings file through ex, the reader from
// vscodeReader. A VS Code file is reported only when it holds a listed key, so
// a failure drops it.
func (c *configScan) vscodeSettings(a *configAgent, ex executor.Executor, path string) {
	if c.s.ctx.Err() != nil {
		return
	}
	fi, err := ex.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxJSONConfigBytes {
		return
	}
	data, err := ex.ReadFile(path)
	if err != nil || len(data) > maxJSONConfigBytes {
		return
	}
	doc, ok := jsoncDoc(data)
	a.add(model.AgentConfigScopeUser, model.AgentConfigChannelFile, path, doc, ok, true)
}

// jsonFiles lists the non-hidden *.json files of a drop-in folder, sorted. A
// folder that cannot be listed adds no source.
func (c *configScan) jsonFiles(gd *SkillsDetector, dir string) []string {
	entries, code := c.s.listDir(gd, dir)
	if code != "" {
		return nil
	}
	var out []string
	for _, name := range sortedEntryNames(entries) {
		if !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".json") {
			if e := dirEntryByName(entries, name); e != nil && !e.IsDir() {
				out = append(out, filepath.Join(dir, name))
			}
		}
	}
	return out
}

// profileDecoder turns a managed preferences plist into a settings document.
// present is false when the plist holds nothing this agent reads.
type profileDecoder func(m map[string]any) (doc gjson.Result, ok, present bool)

// profile reads the machine-wide and the scanning user's managed preferences
// for domain (macOS). The per-user file is reported under a ~ folder so the
// login name never leaves the device.
func (c *configScan) profile(a *configAgent, domain string, decode profileDecoder, vscode bool) {
	s := c.s
	if s.goos != model.PlatformDarwin {
		return
	}
	type file struct{ path, wire string }
	files := []file{{filepath.Join(managedPrefsDir, domain+".plist"), filepath.Join(managedPrefsDir, domain+".plist")}}
	roots := []string{managedPrefsDir}
	if name := c.profileUser(); name != "" {
		dir := filepath.Join(managedPrefsDir, name)
		files = append(files, file{filepath.Join(dir, domain+".plist"), filepath.Join(managedPrefsDir, "~", domain+".plist")})
		roots = append(roots, dir)
	}
	gd := s.guarded(roots...)
	for _, f := range files {
		data, absent, code := s.readMetadata(gd, f.path)
		if absent {
			continue
		}
		var m map[string]any
		if code == "" {
			if _, err := plist.Unmarshal(data, &m); err != nil {
				m = nil
			}
		}
		if m == nil {
			a.add(model.AgentConfigScopeManaged, model.AgentConfigChannelMacOSProfile, f.wire, gjson.Result{}, false, vscode)
			continue
		}
		doc, ok, present := decode(m)
		if present {
			a.add(model.AgentConfigScopeManaged, model.AgentConfigChannelMacOSProfile, f.wire, doc, ok, vscode)
		}
	}
}

// profileUser is the console user's short name, or "" when it is unknown or
// not a single path element.
func (c *configScan) profileUser() string {
	u, err := c.s.d.exec.LoggedInUserContext(c.s.ctx)
	if err != nil || u == nil || u.Username == "" {
		u, err = c.s.d.exec.CurrentUser()
	}
	if err != nil || u == nil {
		return ""
	}
	name := u.Username
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return ""
	}
	return name
}

func plainProfile(m map[string]any) (gjson.Result, bool, bool) {
	doc, ok := jsonResult(m)
	return doc, ok, true
}

// flatProfile decodes values written as JSON text, as Copilot policies are.
func flatProfile(m map[string]any) (gjson.Result, bool, bool) {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if str, ok := v.(string); ok {
			out[k] = jsonOrString(str)
			continue
		}
		out[k] = v
	}
	doc, ok := jsonResult(out)
	return doc, ok, true
}

// codexProfile decodes the base64 requirements.toml Codex reads from its
// managed preferences.
func codexProfile(m map[string]any) (gjson.Result, bool, bool) {
	v, present := m["requirements_toml_base64"]
	if !present {
		return gjson.Result{}, false, false
	}
	str, _ := v.(string)
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(str))
	if err != nil || str == "" {
		return gjson.Result{}, false, true
	}
	doc, ok := tomlDoc(data)
	return doc, ok, true
}

func vscodePolicyProfile(m map[string]any) (gjson.Result, bool, bool) {
	doc, ok := jsonResult(m)
	if !ok {
		return doc, false, true
	}
	doc, ok = vscodePolicyDoc(doc)
	return doc, ok, true
}

// vscodePolicyDoc renames the VS Code policies read to the settings keys they
// enforce.
func vscodePolicyDoc(policy gjson.Result) (gjson.Result, bool) {
	out := map[string]any{}
	for _, p := range vscodePolicies {
		if r := policy.Get(p.policy); r.Exists() {
			out[p.key] = json.RawMessage(r.Raw)
		}
	}
	return jsonResult(out)
}

// vscodePolicyValue maps a registry policy value: a DWORD is a boolean (0 is
// false), a string is kept as written.
func vscodePolicyValue(v string) any {
	if n, err := strconv.ParseUint(v, 10, 64); err == nil {
		return n != 0
	}
	return jsonOrString(v)
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

// jsoncDoc parses JSON with comments, trailing commas and a UTF-8 BOM. The top
// level must be an object.
func jsoncDoc(data []byte) (gjson.Result, bool) {
	std, err := hujson.Standardize(bytes.TrimPrefix(data, utf8BOM))
	if err != nil {
		return gjson.Result{}, false
	}
	doc := gjson.ParseBytes(std)
	return doc, doc.IsObject()
}

func tomlDoc(data []byte) (gjson.Result, bool) {
	var m map[string]any
	if err := toml.Unmarshal(data, &m); err != nil || m == nil {
		return gjson.Result{}, false
	}
	return jsonResult(m)
}

// jsonResult encodes v as a document. Map keys come out sorted, so TOML and
// plist sources (unordered by definition) are deterministic.
func jsonResult(v any) (gjson.Result, bool) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return gjson.Result{}, false
	}
	doc := gjson.ParseBytes(buf.Bytes())
	return doc, doc.IsObject()
}

func jsonOrString(v string) any {
	if json.Valid([]byte(v)) {
		return json.RawMessage(v)
	}
	return v
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

// configAgent collects the sources of one agent.
type configAgent struct {
	c      *configScan
	keys   []string
	notify bool // Codex: top-level notify is a hook
	out    model.AgentConfig
}

// file reads one settings file. A missing file adds nothing; one that exists
// but cannot be read is unreadable.
func (a *configAgent) file(gd *SkillsDetector, scope, path string, decode func([]byte) (gjson.Result, bool)) {
	data, absent, code := a.c.s.readMetadata(gd, path)
	if absent {
		return
	}
	var doc gjson.Result
	ok := false
	if code == "" {
		doc, ok = decode(data)
	}
	a.add(scope, model.AgentConfigChannelFile, path, doc, ok, false)
}

// registry reads one policy value as a source named by its value path.
func (a *configAgent) registry(key, name string, vscode bool, decode func(string) (gjson.Result, bool)) {
	v, found, err := readRegistryValue(a.c.s.ctx, a.c.s.d.exec, key, name)
	if !found {
		return
	}
	var doc gjson.Result
	ok := false
	if err == nil {
		doc, ok = decode(v)
	}
	a.add(model.AgentConfigScopeManaged, model.AgentConfigChannelWindowsRegistry, key+`\`+name, doc, ok, vscode)
}

// add records a source. Project and VS Code sources are kept only when they
// hold a listed key (or, for projects, a hook); an unreadable one is dropped.
func (a *configAgent) add(scope, channel, path string, doc gjson.Result, ok, vscode bool) {
	selective := vscode || scope == model.AgentConfigScopeProject
	if !ok && selective {
		return
	}
	src := model.AgentConfigSource{
		Scope: scope, Channel: channel, Path: a.cut(a.c.tilde(path), maxConfigPathBytes),
		State: model.AgentConfigStateUnreadable, Settings: []model.AgentConfigSetting{}, Hooks: []model.AgentConfigHook{},
	}
	if ok {
		src.State = model.AgentConfigStateRead
		src.Settings = a.settings(doc)
		if !vscode {
			src.Hooks = a.hooks(doc)
		}
	}
	if selective && len(src.Settings) == 0 && len(src.Hooks) == 0 {
		return
	}
	a.out.Sources = append(a.out.Sources, src)
}

func (a *configAgent) settings(doc gjson.Result) []model.AgentConfigSetting {
	out := []model.AgentConfigSetting{}
	for _, key := range a.keys {
		r := doc.Get(key)
		if !r.Exists() {
			r = doc.Get(strings.ReplaceAll(key, ".", `\.`))
		}
		if !r.Exists() || r.Type == gjson.Null {
			continue
		}
		set := model.AgentConfigSetting{Key: key}
		switch {
		case r.IsArray():
			var values []string
			r.ForEach(func(_, v gjson.Result) bool {
				if v.Type == gjson.String {
					values = append(values, v.Str)
				} else {
					values = append(values, compactJSON(v.Raw))
				}
				return true
			})
			set.Values = a.values(values)
		case r.IsObject():
			type entry struct{ k, v string }
			var entries []entry
			r.ForEach(func(k, v gjson.Result) bool {
				entries = append(entries, entry{k.String(), compactJSON(v.Raw)})
				return true
			})
			sort.SliceStable(entries, func(i, j int) bool { return entries[i].k < entries[j].k })
			values := make([]string, 0, len(entries))
			for _, e := range entries {
				values = append(values, e.k+"="+e.v)
			}
			set.Values = a.values(values)
		case r.Type == gjson.String:
			set.Value = a.text(r.Str)
		default:
			set.Value = a.text(r.Raw)
		}
		out = append(out, set)
	}
	return out
}

func (a *configAgent) values(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxConfigValues {
		in, a.out.Truncated = in[:maxConfigValues], true
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, a.text(v))
	}
	return out
}

// text is a value as sent: home folder to ~, secrets redacted, then cut.
func (a *configAgent) text(v string) string {
	return a.cut(redact.String(a.c.tilde(v)), maxConfigTextBytes)
}

func (a *configAgent) cut(v string, n int) string {
	out, cut := cutUTF8(v, n)
	if cut {
		a.out.Truncated = true
	}
	return out
}

// hooks lists the hooks declared in doc in file order: hooks.<event>[] holds
// either groups (a matcher plus a hooks[] of handlers) or handlers directly.
// Event values that are not lists, such as Codex trust state, are skipped.
func (a *configAgent) hooks(doc gjson.Result) []model.AgentConfigHook {
	out := []model.AgentConfigHook{}
	doc.Get("hooks").ForEach(func(event, items gjson.Result) bool {
		if !items.IsArray() {
			return true
		}
		items.ForEach(func(_, item gjson.Result) bool {
			if !item.IsObject() {
				return true
			}
			handlers := item.Get("hooks")
			if !handlers.IsArray() {
				if isHookHandler(item) {
					out = append(out, a.hook(event.String(), item.Get("matcher").String(), item))
				}
				return true
			}
			handlers.ForEach(func(_, h gjson.Result) bool {
				if h.IsObject() && isHookHandler(h) {
					out = append(out, a.hook(event.String(), item.Get("matcher").String(), h))
				}
				return true
			})
			return true
		})
		return true
	})
	if notify := doc.Get("notify"); a.notify && notify.IsArray() {
		var argv []string
		notify.ForEach(func(_, v gjson.Result) bool {
			argv = append(argv, quoteArg(v.String()))
			return true
		})
		out = append(out, a.hookText("notify", "", "command", strings.Join(argv, " ")))
	}
	return out
}

// quoteArg single-quotes an argument that holds whitespace or a quote, so the
// joined command keeps its argument boundaries and redaction sees a whole
// multiword value. A --name=value argument keeps its name outside the quotes,
// where the redactor matches it.
func quoteArg(s string) string {
	const special = " \t\r\n\f'\""
	if s != "" && !strings.ContainsAny(s, special) {
		return s
	}
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }
	if name, value, ok := strings.Cut(s, "="); ok && name != "" && !strings.ContainsAny(name, special) {
		return name + "=" + quote(value)
	}
	return quote(s)
}

// urlBase drops the query and fragment, which are never sent, so a long query
// does not push the URL past the location length bound.
func urlBase(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

func isHookHandler(h gjson.Result) bool {
	for _, f := range hookHandlerFields {
		if h.Get(f).Exists() {
			return true
		}
	}
	return false
}

func (a *configAgent) hook(event, matcher string, h gjson.Result) model.AgentConfigHook {
	handlerType, cut := normalizeHandlerType(h.Get("type").String())
	if cut {
		a.out.Truncated = true
	}
	var text string
	switch handlerType {
	case "command":
		var parts []string
		for _, f := range hookCommandFields {
			if v := h.Get(f).String(); v != "" {
				parts = append(parts, v)
			}
		}
		text = strings.Join(parts, "\n")
	case "http":
		text = sanitizeLocation(urlBase(h.Get("url").String()))
	case "mcp_tool":
		if server, tool := h.Get("server").String(), h.Get("tool").String(); server != "" || tool != "" {
			text = server + "/" + tool
		}
	case "prompt", "agent":
		text = h.Get("prompt").String()
	default:
		text = h.Get("command").String()
		if text == "" {
			text = sanitizeLocation(urlBase(h.Get("url").String()))
		}
		if text == "" {
			text = h.Get("prompt").String()
		}
	}
	return a.hookText(event, matcher, handlerType, text)
}

// hookText builds the hook record. The hash covers the redacted text before
// the display cut, so a long command keeps one identity.
func (a *configAgent) hookText(event, matcher, handlerType, text string) model.AgentConfigHook {
	text = redact.String(a.c.tilde(text))
	sum := sha256.Sum256([]byte(text))
	return model.AgentConfigHook{
		Event:          a.text(event),
		Matcher:        a.text(matcher),
		HandlerType:    handlerType,
		CommandDisplay: a.cut(text, maxConfigTextBytes),
		CommandSHA256:  hex.EncodeToString(sum[:]),
	}
}

// normalizeHandlerType normalizes a vendor handler type to [a-z0-9_]{1,32}, so a new
// type is reported rather than rejected. cut reports a length cut.
func normalizeHandlerType(t string) (string, bool) {
	if t == "" {
		return "command", false
	}
	b := []byte(strings.ToLower(t))
	for i, ch := range b {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '_' {
			b[i] = '_'
		}
	}
	if len(b) > maxConfigHandlerBytes {
		return string(b[:maxConfigHandlerBytes]), true
	}
	return string(b), false
}

// finalize orders the sources and applies the per-agent caps. Only project
// sources are dropped; every cut marks the agent truncated.
func (a *configAgent) finalize() {
	rank := map[string]int{model.AgentConfigScopeManaged: 0, model.AgentConfigScopeUser: 1, model.AgentConfigScopeProject: 2}
	srcs := a.out.Sources
	sort.SliceStable(srcs, func(i, j int) bool {
		if rank[srcs[i].Scope] != rank[srcs[j].Scope] {
			return rank[srcs[i].Scope] < rank[srcs[j].Scope]
		}
		if srcs[i].Path != srcs[j].Path {
			return srcs[i].Path < srcs[j].Path
		}
		return srcs[i].Channel < srcs[j].Channel
	})
	for len(a.out.Sources) > maxConfigSources && a.dropLastProject() {
	}
	hooks := 0
	kept := a.out.Sources[:0]
	for _, src := range a.out.Sources {
		if room := maxConfigHooks - hooks; len(src.Hooks) > room {
			src.Hooks, a.out.Truncated = src.Hooks[:room], true
		}
		hooks += len(src.Hooks)
		if src.Scope == model.AgentConfigScopeProject && len(src.Hooks) == 0 && len(src.Settings) == 0 {
			continue
		}
		kept = append(kept, src)
	}
	a.out.Sources = kept
	for encodedSize(a.out) > maxConfigAgentBytes && a.dropLastProject() {
	}
}

func (a *configAgent) dropLastProject() bool {
	for i := len(a.out.Sources) - 1; i >= 0; i-- {
		if a.out.Sources[i].Scope == model.AgentConfigScopeProject {
			a.out.Sources = append(a.out.Sources[:i], a.out.Sources[i+1:]...)
			a.out.Truncated = true
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

// homeForms lists the spellings of the home folder to replace with ~, longest
// first: home, its resolved path, and on Windows the POSIX drive forms agents
// write in rules plus the JSON-escaped form found in compact object values.
func homeForms(home, resolved, goos string) []string {
	var base []string
	for _, h := range []string{home, resolved} {
		h = strings.TrimRight(h, `/\`)
		if len(h) > 1 && !(len(h) == 2 && h[1] == ':') {
			base = append(base, h)
		}
	}
	forms := append([]string{}, base...)
	if goos == model.PlatformWindows {
		for _, h := range base {
			if len(h) > 2 && isASCIILetter(h[0]) && h[1] == ':' {
				rest := strings.ReplaceAll(h[2:], `\`, "/")
				drive := strings.ToLower(h[:1])
				forms = append(forms, "/"+drive+rest, "//"+drive+rest)
			}
			if strings.Contains(h, `\`) {
				forms = append(forms, strings.ReplaceAll(h, `\`, `\\`))
			}
		}
	}
	sort.Slice(forms, func(i, j int) bool {
		if len(forms[i]) != len(forms[j]) {
			return len(forms[i]) > len(forms[j])
		}
		return forms[i] < forms[j]
	})
	out := forms[:0]
	for _, f := range forms {
		if len(out) == 0 || out[len(out)-1] != f {
			out = append(out, f)
		}
	}
	return out
}

// tilde replaces the home folder with ~ wherever the next byte cannot continue
// a file name, so /home/al is not replaced inside /home/alice.
func (c *configScan) tilde(v string) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(v); i++ {
		n := c.homeAt(v, i)
		if n == 0 {
			continue
		}
		b.WriteString(v[last:i])
		b.WriteByte('~')
		i += n - 1
		last = i + 1
	}
	if last == 0 {
		return v
	}
	b.WriteString(v[last:])
	return b.String()
}

func (c *configScan) homeAt(v string, i int) int {
	for _, f := range c.forms {
		end := i + len(f)
		if end > len(v) || !c.sameText(v[i:end], f) {
			continue
		}
		if end < len(v) && nameByte(v[end]) {
			continue
		}
		return len(f)
	}
	return 0
}

func (c *configScan) sameText(a, b string) bool {
	if !c.fold {
		return a == b
	}
	for i := 0; i < len(a); i++ {
		x, y := lowerASCII(a[i]), lowerASCII(b[i])
		if x == '\\' {
			x = '/'
		}
		if y == '\\' {
			y = '/'
		}
		if x != y {
			return false
		}
	}
	return true
}

func nameByte(ch byte) bool {
	return isASCIILetter(ch) || ch >= '0' && ch <= '9' || ch == '.' || ch == '_' || ch == '-'
}

func lowerASCII(ch byte) byte {
	if ch >= 'A' && ch <= 'Z' {
		return ch + 'a' - 'A'
	}
	return ch
}

// cutUTF8 cuts v to at most n bytes on a rune boundary.
func cutUTF8(v string, n int) (string, bool) {
	if len(v) <= n {
		return v, false
	}
	for n > 0 && !utf8.RuneStart(v[n]) {
		n--
	}
	return v[:n], true
}

func compactJSON(raw string) string {
	var buf bytes.Buffer
	if json.Compact(&buf, []byte(raw)) != nil {
		return strings.TrimSpace(raw)
	}
	return buf.String()
}

// vscodeReader confines reads to home and the VS Code User folder. On macOS
// that folder sits in a protected tree, so the guard admits it, its contents
// and the folders on the way to it; a symlink into any other protected path
// or out of home is refused before it is followed.
func (s *pluginScan) vscodeReader(userRoot string) executor.Executor {
	return s.d.exec.GuardedFiles([]string{s.home, userRoot}, func(p string) string {
		if s.d.skipper.WithinProtected(p) && p != userRoot && !goPathWithin(p, userRoot) && !goPathWithin(userRoot, p) {
			return "tcc_protected"
		}
		return ""
	}, maxJSONConfigBytes)
}

// programData is %ProgramData%, defaulting to the system drive's folder.
func (s *pluginScan) programData() string {
	if root := s.d.exec.Getenv("ProgramData"); root != "" {
		return root
	}
	return `C:\ProgramData`
}
