package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"howett.net/plist"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

const (
	winHome    = `C:\Users\testuser`
	fakeToken  = "ghp_FAKEFAKEFAKEFAKEFAKE1234"
	emptySHA   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	prefsMac   = "/Library/Managed Preferences"
	claudeDrop = "/Library/Application Support/ClaudeCode/managed-settings.d"
)

type configFixture struct {
	m        *pluginMock
	fs       *fakeFS
	home     string
	goos     string
	projects []string
	detected map[string]bool
}

func newConfigFixture(goos string) *configFixture {
	m, fs := newPluginMock()
	m.SetGOOS(goos)
	m.SetUsername("testuser")
	home := testHome
	if goos == model.PlatformWindows {
		home = winHome
	}
	m.SetHomeDir(home)
	return &configFixture{m: m, fs: fs, home: home, goos: goos}
}

func (f *configFixture) scan(t *testing.T, exec executor.Executor) *model.AgentConfigScan {
	t.Helper()
	f.fs.commit()
	d := NewSkillsDetector(exec).WithConfigAgents(f.detected)
	r := &SkillsResult{pendingPlugins: &pluginScan{d: d, home: f.home, goos: f.goos, projects: f.projects}}
	d.DetectAgentConfig(t.Context(), r)
	return r.AgentConfig
}

func (f *configFixture) run(t *testing.T) *model.AgentConfigScan {
	t.Helper()
	got := f.scan(t, f.m)
	if got == nil {
		t.Fatal("agent_config section missing")
	}
	return got
}

func (f *configFixture) plist(t *testing.T, path string, v map[string]any) {
	t.Helper()
	data, err := plist.Marshal(v, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	f.fs.addFileBytes(path, data)
}

func agentOf(t *testing.T, scan *model.AgentConfigScan, name string) model.AgentConfig {
	t.Helper()
	for _, a := range scan.Agents {
		if a.Agent == name {
			return a
		}
	}
	t.Fatalf("agent %s not reported; agents = %+v", name, scan.Agents)
	return model.AgentConfig{}
}

func sourceList(a model.AgentConfig) []string {
	out := []string{}
	for _, s := range a.Sources {
		out = append(out, strings.Join([]string{s.Scope, s.Channel, s.Path, s.State}, " "))
	}
	return out
}

func sourceAt(t *testing.T, a model.AgentConfig, path string) model.AgentConfigSource {
	t.Helper()
	for _, s := range a.Sources {
		if s.Path == path {
			return s
		}
	}
	t.Fatalf("source %s not reported; sources = %v", path, sourceList(a))
	return model.AgentConfigSource{}
}

func hookOf(event, matcher, handlerType, text string) model.AgentConfigHook {
	display, _ := cutUTF8(text, maxConfigTextBytes)
	return model.AgentConfigHook{Event: event, Matcher: matcher, HandlerType: handlerType, CommandDisplay: display, CommandSHA256: sha256Hex([]byte(text))}
}

func wantSources(t *testing.T, a model.AgentConfig, want ...string) {
	t.Helper()
	if got := sourceList(a); !reflect.DeepEqual(got, append([]string{}, want...)) {
		t.Fatalf("sources:\n got %q\nwant %q", got, want)
	}
}

func TestAgentConfig_ClaudeSources(t *testing.T) {
	f := newConfigFixture(model.PlatformDarwin)
	project := filepath.Join(testHome, "repos", "widgets")
	f.projects = []string{project}
	f.fs.addFile(claudeManagedSettingsMac, `{"allowManagedHooksOnly": true}`)
	f.fs.addFile(claudeDrop+"/20-b.json", `{"disableAllHooks": false}`)
	f.fs.addFile(claudeDrop+"/10-a.json", `{"sandbox": {"enabled": true}}`)
	f.fs.addFile(claudeDrop+"/.hidden.json", `{"disableAllHooks": true}`)
	f.fs.addFile(claudeDrop+"/notes.txt", `x`)
	f.fs.addFile(testHome+"/.claude/settings.json", "\ufeff// user settings\n"+`{
		"permissions": {"defaultMode": "bypassPermissions", "allow": ["Read(/Users/testuser/**)", "Bash(npm test)"]},
		"env": {"SECRET": "x"},
		"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
			{"type": "command", "command": "/Users/testuser/bin/guard.sh --key `+fakeToken+`"},
			{"type": "http", "url": "https://user:pw@hooks.example.com/check?token=abc#frag", "headers": {"Authorization": "x"}},
			{"type": "mcp_tool", "server": "widgets", "tool": "audit"},
			{"type": "agent", "prompt": "review"}
		]}]},
	}`)
	f.fs.addFile(project+"/.claude/settings.json", `{"model": "opus"}`)
	f.fs.addFile(project+"/.claude/settings.local.json", `{"hooks": {"Stop": [{"hooks": [{"type": "prompt", "prompt": "summarize"}]}]}}`)
	f.plist(t, prefsMac+"/com.anthropic.claudecode.plist", map[string]any{"permissions": map[string]any{"disableBypassPermissionsMode": "disable"}})
	f.plist(t, prefsMac+"/testuser/com.anthropic.claudecode.plist", map[string]any{"disableAllHooks": true})

	a := agentOf(t, f.run(t), "claude-code")
	wantSources(t, a,
		"managed file "+claudeDrop+"/10-a.json read",
		"managed file "+claudeDrop+"/20-b.json read",
		"managed file "+claudeManagedSettingsMac+" read",
		"managed macos_profile "+prefsMac+"/com.anthropic.claudecode.plist read",
		"managed macos_profile "+prefsMac+"/~/com.anthropic.claudecode.plist read",
		"user file ~/.claude/settings.json read",
		"project file ~/repos/widgets/.claude/settings.local.json read",
	)
	user := sourceAt(t, a, "~/.claude/settings.json")
	wantSettings := []model.AgentConfigSetting{
		{Key: "permissions.defaultMode", Value: "bypassPermissions"},
		{Key: "permissions.allow", Values: []string{"Read(~/**)", "Bash(npm test)"}},
	}
	if !reflect.DeepEqual(user.Settings, wantSettings) {
		t.Errorf("settings = %+v", user.Settings)
	}
	command := user.Hooks[0].CommandDisplay
	if !strings.HasPrefix(command, "~/bin/guard.sh --key ") || strings.Contains(command, "FAKE") {
		t.Errorf("command not cleaned: %q", command)
	}
	wantHooks := []model.AgentConfigHook{
		hookOf("PreToolUse", "Bash", "command", command),
		hookOf("PreToolUse", "Bash", "http", "https://hooks.example.com/check"),
		hookOf("PreToolUse", "Bash", "mcp_tool", "widgets/audit"),
		hookOf("PreToolUse", "Bash", "agent", "review"),
	}
	if !reflect.DeepEqual(user.Hooks, wantHooks) {
		t.Errorf("hooks:\n got %+v\nwant %+v", user.Hooks, wantHooks)
	}
	if got := sourceAt(t, a, prefsMac+"/com.anthropic.claudecode.plist").Settings; len(got) != 1 || got[0].Value != "disable" {
		t.Errorf("profile settings = %+v", got)
	}
}

func TestAgentConfig_CodexSources(t *testing.T) {
	f := newConfigFixture(model.PlatformLinux)
	project := filepath.Join(testHome, "repos", "widgets")
	f.projects = []string{project}
	f.m.SetEnv("CODEX_HOME", "/opt/codex/")
	f.fs.addFile("/opt/codex/config.toml", `approval_policy = "never"
sandbox_mode = "danger-full-access"
notify = ["/Users/testuser/bin/notify", "--done"]

[features]
hooks = true

[profiles.fast]
approval_policy = "on-request"

[[hooks.PreToolUse]]
matcher = "shell"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "echo pre"

[hooks.state.abc]
trusted = true
`)
	f.fs.addFile("/etc/codex/requirements.toml", `allow_managed_hooks_only = true
[hooks]
managed_dir = "/etc/codex/hooks"
[[hooks.Stop]]
[[hooks.Stop.hooks]]
command = "audit"
`)
	f.fs.addFile(project+"/.codex/hooks.json", `{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "setup"}]}]}}`)

	a := agentOf(t, f.run(t), "codex")
	wantSources(t, a,
		"managed file /etc/codex/requirements.toml read",
		"user file /opt/codex/config.toml read",
		"project file ~/repos/widgets/.codex/hooks.json read",
	)
	user := sourceAt(t, a, "/opt/codex/config.toml")
	wantSettings := []model.AgentConfigSetting{
		{Key: "approval_policy", Value: "never"},
		{Key: "sandbox_mode", Value: "danger-full-access"},
		{Key: "features.hooks", Value: "true"},
	}
	if !reflect.DeepEqual(user.Settings, wantSettings) {
		t.Errorf("settings = %+v", user.Settings)
	}
	wantHooks := []model.AgentConfigHook{hookOf("PreToolUse", "shell", "command", "echo pre"), hookOf("notify", "", "command", "~/bin/notify --done")}
	if !reflect.DeepEqual(user.Hooks, wantHooks) {
		t.Errorf("hooks = %+v", user.Hooks)
	}
	req := sourceAt(t, a, "/etc/codex/requirements.toml")
	if len(req.Hooks) != 1 || req.Hooks[0] != hookOf("Stop", "", "command", "audit") || len(req.Settings) != 1 {
		t.Errorf("requirements = %+v", req)
	}
}

func TestAgentConfig_CodexProfile(t *testing.T) {
	f := newConfigFixture(model.PlatformDarwin)
	toml := "approval_policy = \"never\"\n[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ncommand = \"audit\"\n"
	f.plist(t, prefsMac+"/com.openai.codex.plist", map[string]any{"requirements_toml_base64": base64.StdEncoding.EncodeToString([]byte(toml))})
	f.plist(t, prefsMac+"/testuser/com.openai.codex.plist", map[string]any{"requirements_toml_base64": "%%%"})
	f.plist(t, prefsMac+"/com.github.copilot.plist", map[string]any{"sandbox.enabled": "true", "chat.useHooks": "false", "hooks": `{"preToolUse": [{"type": "command", "bash": "lint"}]}`})
	f.plist(t, prefsMac+"/testuser/com.microsoft.VSCode.plist", map[string]any{"ChatToolsAutoApprove": false, "UpdateMode": "none"})
	f.plist(t, prefsMac+"/com.microsoft.VSCode.plist", map[string]any{"UpdateMode": "none"})
	scan := f.run(t)

	codex := agentOf(t, scan, "codex")
	wantSources(t, codex,
		"managed macos_profile "+prefsMac+"/com.openai.codex.plist read",
		"managed macos_profile "+prefsMac+"/~/com.openai.codex.plist unreadable",
	)
	machine := codex.Sources[0]
	if len(machine.Settings) != 1 || machine.Settings[0].Value != "never" || len(machine.Hooks) != 1 {
		t.Errorf("codex profile = %+v", machine)
	}
	copilot := agentOf(t, scan, "github-copilot")
	wantSources(t, copilot,
		"managed macos_profile "+prefsMac+"/com.github.copilot.plist read",
		"managed macos_profile "+prefsMac+"/~/com.microsoft.VSCode.plist read",
	)
	wantSettings := []model.AgentConfigSetting{{Key: "sandbox.enabled", Value: "true"}, {Key: "chat.useHooks", Value: "false"}}
	if got := copilot.Sources[0]; !reflect.DeepEqual(got.Settings, wantSettings) || len(got.Hooks) != 1 || got.Hooks[0] != hookOf("preToolUse", "", "command", "lint") {
		t.Errorf("copilot profile = %+v", got)
	}
	if got := copilot.Sources[1].Settings; !reflect.DeepEqual(got, []model.AgentConfigSetting{{Key: "chat.tools.global.autoApprove", Value: "false"}}) {
		t.Errorf("vscode profile = %+v", got)
	}
}

func TestAgentConfig_CopilotSources(t *testing.T) {
	f := newConfigFixture(model.PlatformLinux)
	project := filepath.Join(testHome, "repos", "widgets")
	f.projects = []string{project}
	f.m.SetEnv("COPILOT_HOME", "/opt/copilot")
	f.fs.addFile("/opt/copilot/settings.json", `{"defaultPermissionMode": "allow-all"}`)
	f.fs.addFile("/opt/copilot/hooks/guard.json", `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "./guard.sh", "powershell": ".\\guard.ps1", "timeoutSec": 5}]}}`)
	f.fs.addFile("/etc/github-copilot/policy.d/10-org.json", `{"allowManagedHooksOnly": true}`)
	f.fs.addFile("/etc/vscode/policy.json", `{"ChatHooks": false, "UpdateMode": "none"}`)
	vscode := testHome + "/.config/Code/User"
	f.fs.addFile(vscode+"/settings.json", `{
		// approvals
		"chat.tools.terminal.autoApprove": {"rm": false, "npm test": { "approve": true } /* inline */},
		"editor.fontSize": 12,
	}`)
	f.fs.addFile(vscode+"/profiles/abc/settings.json", `{"editor.fontSize": 14}`)
	f.fs.addFile(vscode+"/profiles/def/settings.json", `{"chat.agent.sandbox.enabled": "on"}`)
	f.fs.addFile(project+"/.github/hooks/check.json", `{"version": 1, "hooks": {"postToolUse": [{"command": "audit", "matcher": "edit"}]}}`)
	f.fs.addFile(project+"/.github/copilot/settings.json", `{"other": 1}`)

	a := agentOf(t, f.run(t), "github-copilot")
	wantSources(t, a,
		"managed file /etc/github-copilot/policy.d/10-org.json read",
		"managed file /etc/vscode/policy.json read",
		"user file /opt/copilot/hooks/guard.json read",
		"user file /opt/copilot/settings.json read",
		"user file ~/.config/Code/User/profiles/def/settings.json read",
		"user file ~/.config/Code/User/settings.json read",
		"project file ~/repos/widgets/.github/hooks/check.json read",
	)
	if got := sourceAt(t, a, "/opt/copilot/hooks/guard.json").Hooks; len(got) != 1 || got[0] != hookOf("preToolUse", "", "command", "./guard.sh\n.\\guard.ps1") {
		t.Errorf("multi-shell hook = %+v", got)
	}
	if got := sourceAt(t, a, "/etc/vscode/policy.json").Settings; !reflect.DeepEqual(got, []model.AgentConfigSetting{{Key: "chat.useHooks", Value: "false"}}) {
		t.Errorf("vscode policy = %+v", got)
	}
	want := []model.AgentConfigSetting{{Key: "chat.tools.terminal.autoApprove", Values: []string{`npm test={"approve":true}`, "rm=false"}}}
	if got := sourceAt(t, a, "~/.config/Code/User/settings.json").Settings; !reflect.DeepEqual(got, want) {
		t.Errorf("vscode settings = %+v", got)
	}
	if got := sourceAt(t, a, "~/repos/widgets/.github/hooks/check.json").Hooks; len(got) != 1 || got[0] != hookOf("postToolUse", "edit", "command", "audit") {
		t.Errorf("project hook = %+v", got)
	}
}

func TestAgentConfig_CursorAndGemini(t *testing.T) {
	f := newConfigFixture(model.PlatformDarwin)
	project := filepath.Join(testHome, "repos", "widgets")
	f.projects = []string{project}
	f.fs.addFile("/Library/Application Support/Cursor/hooks.json", `{"version": 1, "hooks": {"beforeShellExecution": [{"command": "/opt/audit"}]}}`)
	f.fs.addFile(testHome+"/.cursor/cli-config.json", `{"approvalMode": "unrestricted", "permissions": {"allow": ["Shell(ls)"], "deny": []}, "sandbox": {"mode": "disabled"}}`)
	f.fs.addFile(testHome+"/.cursor/permissions.json", `{"terminalAllowlist": ["git"], "autoRun": true}`)
	f.fs.addFile(project+"/.cursor/sandbox.json", `{"type": "workspace_readwrite"}`)
	f.fs.addFile("/Library/Application Support/GeminiCli/settings.json", `{"tools": {"sandbox": "docker"}}`)
	f.fs.addFile(testHome+"/.gemini/settings.json", `{"general": {"defaultApprovalMode": "yolo"}, "tools": {"allowed": ["run_shell_command(git)"]}, "hooksConfig": {"enabled": true},
		"hooks": {"BeforeTool": [{"matcher": "run_shell_command", "hooks": [{"type": "command", "command": "check"}]}]}}`)
	scan := f.run(t)

	cursor := agentOf(t, scan, "cursor")
	wantSources(t, cursor,
		"managed file /Library/Application Support/Cursor/hooks.json read",
		"user file ~/.cursor/cli-config.json read",
		"user file ~/.cursor/permissions.json read",
		"project file ~/repos/widgets/.cursor/sandbox.json read",
	)
	want := []model.AgentConfigSetting{
		{Key: "approvalMode", Value: "unrestricted"},
		{Key: "permissions.allow", Values: []string{"Shell(ls)"}},
		{Key: "permissions.deny"},
		{Key: "sandbox.mode", Value: "disabled"},
	}
	if got := sourceAt(t, cursor, "~/.cursor/cli-config.json").Settings; !reflect.DeepEqual(got, want) {
		t.Errorf("cursor cli settings = %+v", got)
	}
	if got := cursor.Sources[0].Hooks; len(got) != 1 || got[0] != hookOf("beforeShellExecution", "", "command", "/opt/audit") {
		t.Errorf("cursor hook = %+v", got)
	}
	gemini := agentOf(t, scan, "gemini-cli")
	wantSources(t, gemini,
		"managed file /Library/Application Support/GeminiCli/settings.json read",
		"user file ~/.gemini/settings.json read",
	)
	if got := gemini.Sources[1]; len(got.Settings) != 3 || len(got.Hooks) != 1 || got.Hooks[0].Matcher != "run_shell_command" {
		t.Errorf("gemini user = %+v", got)
	}
}

func TestAgentConfig_WindowsRegistry(t *testing.T) {
	f := newConfigFixture(model.PlatformWindows)
	f.m.SetEnv("ProgramData", `C:\ProgramData`)
	regQuery := func(key, name, typ, data string) {
		f.m.SetCommand(fmt.Sprintf("\n%s\n    %s    %s    %s\n", key, name, typ, data), "", 0, "reg", "query", key, "/v", name)
	}
	regQuery(`HKLM\SOFTWARE\Policies\ClaudeCode`, "Settings", "REG_SZ", `{"permissions": {"defaultMode": "plan"}, "hooks": {"PreToolUse": [{"hooks": [{"command": "C:\\Users\\testuser\\guard.exe"}]}]}}`)
	regQuery(`HKCU\SOFTWARE\Policies\ClaudeCode`, "Settings", "REG_SZ", `{not json`)
	regQuery(`HKLM\SOFTWARE\Policies\GitHubCopilot`, "sandbox.enabled", "REG_SZ", "true")
	regQuery(`HKLM\SOFTWARE\Policies\GitHubCopilot`, "defaultPermissionMode", "REG_SZ", `"ask"`)
	regQuery(`HKLM\Software\Policies\Microsoft\VSCode`, "ChatToolsAutoApprove", "REG_DWORD", "0x0")
	regQuery(`HKLM\Software\Policies\Microsoft\VSCode`, "ChatHooks", "REG_DWORD", "0x1")
	scan := f.run(t)

	claude := agentOf(t, scan, "claude-code")
	wantSources(t, claude,
		`managed windows_registry HKCU\SOFTWARE\Policies\ClaudeCode\Settings unreadable`,
		`managed windows_registry HKLM\SOFTWARE\Policies\ClaudeCode\Settings read`,
	)
	if got := claude.Sources[0]; got.Settings == nil || got.Hooks == nil || len(got.Settings)+len(got.Hooks) != 0 {
		t.Errorf("unreadable lists = %+v", got)
	}
	if got := claude.Sources[1].Hooks; len(got) != 1 || got[0].CommandDisplay != `~\guard.exe` {
		t.Errorf("registry hook = %+v", got)
	}
	copilot := agentOf(t, scan, "github-copilot")
	wantSources(t, copilot,
		`managed windows_registry HKLM\SOFTWARE\Policies\GitHubCopilot read`,
		`managed windows_registry HKLM\Software\Policies\Microsoft\VSCode\ChatHooks read`,
		`managed windows_registry HKLM\Software\Policies\Microsoft\VSCode\ChatToolsAutoApprove read`,
	)
	want := []model.AgentConfigSetting{{Key: "defaultPermissionMode", Value: "ask"}, {Key: "sandbox.enabled", Value: "true"}}
	if got := copilot.Sources[0].Settings; !reflect.DeepEqual(got, want) {
		t.Errorf("copilot registry = %+v", got)
	}
	if a, b := copilot.Sources[1].Settings, copilot.Sources[2].Settings; len(a) != 1 || a[0].Value != "true" || len(b) != 1 || b[0].Value != "false" {
		t.Errorf("vscode dword mapping = %+v %+v", a, b)
	}

	f = newConfigFixture(model.PlatformWindows)
	f.detected = map[string]bool{"github-copilot": true}
	regQuery = func(key, name, typ, data string) {
		f.m.SetCommand(fmt.Sprintf("\n%s\n    %s    %s    %s\n", key, name, typ, data), "", 0, "reg", "query", key, "/v", name)
	}
	regQuery(`HKLM\Software\Policies\Microsoft\VSCode`, "ChatHooks", "REG_BINARY", "01")
	wantSources(t, agentOf(t, f.run(t), "github-copilot"))
}

func TestAgentConfig_CodexRequirementsPath(t *testing.T) {
	const key = `HKLM\SOFTWARE\Policies\OpenAI\Codex`
	tests := []struct {
		name, value, file, want string
	}{
		{"backslash drive", `D:\policy\requirements.toml`, `D:\policy\requirements.toml`, "read"},
		{"forward slash drive", `D:/policy/requirements.toml`, filepath.Clean(`D:/policy/requirements.toml`), "read"},
		{"missing file", `D:\policy\gone.toml`, "", "unreadable"},
		{"unc", `\\server\share\requirements.toml`, `\\server\share\requirements.toml`, "unreadable"},
		{"forward unc", `//server/share/requirements.toml`, filepath.Clean(`//server/share/requirements.toml`), "unreadable"},
		{"relative", `policy\requirements.toml`, `policy\requirements.toml`, "unreadable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newConfigFixture(model.PlatformWindows)
			f.m.SetCommand("\n"+key+"\n    RequirementsPath    REG_SZ    "+tc.value+"\n", "", 0, "reg", "query", key, "/v", "RequirementsPath")
			if tc.file != "" {
				f.fs.addFile(tc.file, `allow_managed_hooks_only = true`)
			}
			src := agentOf(t, f.run(t), "codex").Sources
			if len(src) != 1 || src[0].Path != key+`\RequirementsPath` || src[0].State != tc.want {
				t.Fatalf("sources = %+v, want one %s", src, tc.want)
			}
			if tc.want == "read" && len(src[0].Settings) != 1 {
				t.Errorf("settings = %+v", src[0].Settings)
			}
		})
	}
}

func TestAgentConfig_HookText(t *testing.T) {
	tests := []struct {
		name, handler, wantType, wantText string
	}{
		{"absent type", `{"command": "a"}`, "command", "a"},
		{"empty type", `{"type": "", "command": "a"}`, "command", "a"},
		{"upper type", `{"type": "HTTP", "url": "https://example.com/x?key=1"}`, "http", "https://example.com/x"},
		{"future type", `{"type": "Future-Type", "url": "https://u:p@example.com/h?key=1"}`, "future_type", "https://example.com/h"},
		{"spaced type", `{"type": "mcp tool", "server": "s", "tool": "t"}`, "mcp_tool", "s/t"},
		{"unknown command first", `{"type": "script", "command": "run", "prompt": "p"}`, "script", "run"},
		{"unknown prompt last", `{"type": "script", "prompt": "p"}`, "script", "p"},
		{"empty text", `{"type": "prompt"}`, "prompt", ""},
		{"empty mcp", `{"type": "mcp_tool"}`, "mcp_tool", ""},
		{"long query", `{"type": "http", "url": "https://example.com/hook?q=` + strings.Repeat("a", 5000) + `#f"}`, "http", "https://example.com/hook"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newConfigFixture(model.PlatformLinux)
			f.fs.addFile(testHome+"/.claude/settings.json", `{"hooks": {"E": [{"hooks": [`+tc.handler+`]}]}}`)
			hooks := agentOf(t, f.run(t), "claude-code").Sources[0].Hooks
			if want := hookOf("E", "", tc.wantType, tc.wantText); len(hooks) != 1 || hooks[0] != want {
				t.Fatalf("hook = %+v, want %+v", hooks, want)
			}
			if tc.wantText == "" && hooks[0].CommandSHA256 != emptySHA {
				t.Errorf("empty-text hash = %s", hooks[0].CommandSHA256)
			}
		})
	}
	long := strings.Repeat("x", 40)
	if got, cut := normalizeHandlerType(long); len(got) != 32 || !cut {
		t.Errorf("40-byte type = %q cut=%v", got, cut)
	}

	f := newConfigFixture(model.PlatformLinux)
	f.fs.addFile(testHome+"/.cursor/hooks.json", `{"hooks": {"E": [{"matcher": "Read"}, {}, {"matcher": "Edit(/Users/testuser/src/**)", "command": "c"}, {"matcher": "token=`+fakeToken+`", "command": "d"}]}}`)
	f.fs.addFile(testHome+"/.claude/settings.json", `{"hooks": {"E": [{"matcher": "x", "hooks": [{}, {"command": "c"}]}]}}`)
	scan := f.run(t)
	if got := agentOf(t, scan, "cursor").Sources[0].Hooks; len(got) != 2 || got[0] != hookOf("E", "Edit(~/src/**)", "command", "c") || strings.Contains(got[1].Matcher, "FAKE") {
		t.Errorf("flat hooks = %+v", got)
	}
	if got := agentOf(t, scan, "claude-code").Sources[0].Hooks; len(got) != 1 || got[0] != hookOf("E", "x", "command", "c") {
		t.Errorf("group hooks = %+v", got)
	}
}

// Every source path not covered by a per-agent test, one row each.
func TestAgentConfig_SourcePaths(t *testing.T) {
	const (
		progData  = `C:\ProgramData`
		progFiles = `C:\Program Files`
	)
	project := filepath.Join(testHome, "repos", "widgets")
	tests := []struct {
		goos, agent, path, scope string
	}{
		{model.PlatformLinux, "codex", "/etc/codex/config.toml", model.AgentConfigScopeManaged},
		{model.PlatformLinux, "codex", "/etc/codex/hooks.json", model.AgentConfigScopeManaged},
		{model.PlatformLinux, "github-copilot", "/etc/github-copilot/managed-settings.json", model.AgentConfigScopeManaged},
		{model.PlatformDarwin, "github-copilot", "/Library/Application Support/GitHubCopilot/managed-settings.json", model.AgentConfigScopeManaged},
		{model.PlatformLinux, "cursor", "/etc/cursor/hooks.json", model.AgentConfigScopeManaged},
		{model.PlatformLinux, "gemini-cli", "/etc/gemini-cli/settings.json", model.AgentConfigScopeManaged},
		{model.PlatformWindows, "claude-code", progFiles + `\ClaudeCode\managed-settings.json`, model.AgentConfigScopeManaged},
		{model.PlatformWindows, "codex", filepath.Join(progData, "OpenAI", "Codex", "config.toml"), model.AgentConfigScopeManaged},
		{model.PlatformWindows, "codex", filepath.Join(progData, "OpenAI", "Codex", "requirements.toml"), model.AgentConfigScopeManaged},
		{model.PlatformWindows, "codex", filepath.Join(progData, "OpenAI", "Codex", "hooks.json"), model.AgentConfigScopeManaged},
		{model.PlatformWindows, "github-copilot", progFiles + `\GitHubCopilot\managed-settings.json`, model.AgentConfigScopeManaged},
		{model.PlatformWindows, "github-copilot", filepath.Join(progData, "GitHub", "Copilot", "policy.d", "a.json"), model.AgentConfigScopeManaged},
		{model.PlatformWindows, "cursor", filepath.Join(progData, "Cursor", "hooks.json"), model.AgentConfigScopeManaged},
		{model.PlatformWindows, "gemini-cli", filepath.Join(progData, "gemini-cli", "settings.json"), model.AgentConfigScopeManaged},
		{model.PlatformLinux, "cursor", testHome + "/.cursor/hooks.json", model.AgentConfigScopeUser},
		{model.PlatformLinux, "cursor", testHome + "/.cursor/sandbox.json", model.AgentConfigScopeUser},
		{model.PlatformLinux, "cursor", project + "/.cursor/hooks.json", model.AgentConfigScopeProject},
		{model.PlatformLinux, "cursor", project + "/.cursor/cli.json", model.AgentConfigScopeProject},
		{model.PlatformLinux, "cursor", project + "/.cursor/permissions.json", model.AgentConfigScopeProject},
		{model.PlatformLinux, "github-copilot", project + "/.github/copilot/settings.local.json", model.AgentConfigScopeProject},
	}
	for _, tc := range tests {
		t.Run(tc.goos+" "+tc.path, func(t *testing.T) {
			f := newConfigFixture(tc.goos)
			f.m.SetEnv("ProgramData", progData)
			f.m.SetEnv("ProgramFiles", progFiles)
			f.projects = []string{project}
			content := `{"hooks": {"E": [{"command": "c"}]}}`
			if strings.HasSuffix(tc.path, ".toml") {
				content = `approval_policy = "never"`
			}
			f.fs.addFile(tc.path, content)
			want := tc.path
			if strings.HasPrefix(want, testHome+"/") {
				want = "~" + strings.TrimPrefix(want, testHome)
			}
			src := sourceAt(t, agentOf(t, f.run(t), tc.agent), want)
			if src.Scope != tc.scope || src.Channel != model.AgentConfigChannelFile || src.State != model.AgentConfigStateRead || len(src.Settings)+len(src.Hooks) != 1 {
				t.Errorf("source = %+v", src)
			}
		})
	}
}

func TestAgentConfig_Values(t *testing.T) {
	f := newConfigFixture(model.PlatformLinux)
	project := filepath.Join(testHome, "repos", "widgets")
	f.projects = []string{project}
	f.fs.addFile(testHome+"/.claude/settings.json", `{
		"permissions": {"defaultMode": null, "allow": [], "deny": ["Bash(curl https://u:`+fakeToken+`@example.com)", 7, {"a": 1}]},
		"sandbox": {"enabled": "", "allowUnsandboxedCommands": 30},
		"disableAllHooks": false
	}`)
	f.fs.addFile(project+"/.claude/settings.json", `{"permissions": {"defaultMode": null}}`)
	a := agentOf(t, f.run(t), "claude-code")
	wantSources(t, a, "user file ~/.claude/settings.json read")
	got := a.Sources[0].Settings
	want := []string{"permissions.allow []", "permissions.deny [", "sandbox.enabled ", "sandbox.allowUnsandboxedCommands 30", "disableAllHooks false"}
	if len(got) != len(want) {
		t.Fatalf("settings = %+v", got)
	}
	for i, s := range got {
		line := s.Key + " " + s.Value
		if s.Values != nil || s.Key == "permissions.allow" {
			line = s.Key + " " + fmt.Sprint(s.Values)
		}
		if !strings.HasPrefix(line, want[i]) {
			t.Errorf("setting %d = %q, want prefix %q", i, line, want[i])
		}
	}
	deny := got[1].Values
	if len(deny) != 3 || strings.Contains(deny[0], "FAKE") || deny[1] != "7" || deny[2] != `{"a":1}` {
		t.Errorf("deny = %q", deny)
	}
	data, _ := json.Marshal(a)
	if strings.Contains(string(data), "null") {
		t.Errorf("null in output: %s", data)
	}
}

func TestAgentConfig_Caps(t *testing.T) {
	t.Run("hooks and values", func(t *testing.T) {
		f := newConfigFixture(model.PlatformLinux)
		var handlers, rules []string
		for i := range 120 {
			handlers = append(handlers, fmt.Sprintf(`{"command": "c%d"}`, i))
		}
		for i := range 60 {
			rules = append(rules, fmt.Sprintf(`"Bash(r%d)"`, i))
		}
		f.fs.addFile(testHome+"/.claude/settings.json", `{"permissions": {"allow": [`+strings.Join(rules, ",")+`]}, "hooks": {"E": [{"hooks": [`+strings.Join(handlers, ",")+`]}]}}`)
		a := agentOf(t, f.run(t), "claude-code")
		if !a.Truncated || len(a.Sources[0].Hooks) != 100 || len(a.Sources[0].Settings[0].Values) != 50 {
			t.Errorf("truncated=%v hooks=%d values=%d", a.Truncated, len(a.Sources[0].Hooks), len(a.Sources[0].Settings[0].Values))
		}
	})
	t.Run("hook cap empties a project source", func(t *testing.T) {
		f := newConfigFixture(model.PlatformLinux)
		var handlers []string
		for i := range 100 {
			handlers = append(handlers, fmt.Sprintf(`{"command": "c%d"}`, i))
		}
		project := filepath.Join(testHome, "p")
		f.projects = []string{project}
		f.fs.addFile(testHome+"/.claude/settings.json", `{"hooks": {"E": [{"hooks": [`+strings.Join(handlers, ",")+`]}]}}`)
		f.fs.addFile(project+"/.claude/settings.json", `{"hooks": {"E": [{"hooks": [{"command": "late"}]}]}}`)
		a := agentOf(t, f.run(t), "claude-code")
		wantSources(t, a, "user file ~/.claude/settings.json read")
		if !a.Truncated {
			t.Error("truncated not set")
		}
	})
	t.Run("sources", func(t *testing.T) {
		f := newConfigFixture(model.PlatformLinux)
		for i := range 300 {
			p := filepath.Join(testHome, "r", fmt.Sprintf("p%03d", i))
			f.projects = append(f.projects, p)
			f.fs.addFile(p+"/.gemini/settings.json", `{"hooksConfig": {"enabled": true}}`)
		}
		a := agentOf(t, f.run(t), "gemini-cli")
		if !a.Truncated || len(a.Sources) != 250 || a.Sources[249].Path != "~/r/p249/.gemini/settings.json" {
			t.Errorf("truncated=%v sources=%d last=%s", a.Truncated, len(a.Sources), a.Sources[len(a.Sources)-1].Path)
		}
	})
	t.Run("size", func(t *testing.T) {
		f := newConfigFixture(model.PlatformLinux)
		big := strings.Repeat("y", 250)
		var handlers []string
		for i := range 10 {
			handlers = append(handlers, fmt.Sprintf(`{"command": "%s%d"}`, big, i))
		}
		for i := range 60 {
			p := filepath.Join(testHome, "r", fmt.Sprintf("p%02d", i))
			f.projects = append(f.projects, p)
			f.fs.addFile(p+"/.gemini/settings.json", `{"hooks": {"E": [{"hooks": [`+strings.Join(handlers[:1], ",")+`]}]}, "tools": {"allowed": [`+strings.Repeat(`"`+big+`",`, 49)+`"x"]}}`)
		}
		a := agentOf(t, f.run(t), "gemini-cli")
		data, _ := json.Marshal(a)
		if !a.Truncated || len(data) > maxConfigAgentBytes || len(a.Sources) == 0 || len(a.Sources) == 60 {
			t.Errorf("truncated=%v bytes=%d sources=%d", a.Truncated, len(data), len(a.Sources))
		}
	})
	t.Run("field cuts", func(t *testing.T) {
		tests := []struct{ name, file string }{
			{"event", `{"hooks": {"` + strings.Repeat("e", 300) + `": [{"hooks": [{"command": "c"}]}]}}`},
			{"matcher", `{"hooks": {"E": [{"matcher": "` + strings.Repeat("m", 300) + `", "hooks": [{"command": "c"}]}]}}`},
			{"handler type", `{"hooks": {"E": [{"hooks": [{"type": "` + strings.Repeat("t", 40) + `"}]}]}}`},
			{"value", `{"permissions": {"defaultMode": "` + strings.Repeat("v", 300) + `"}}`},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				f := newConfigFixture(model.PlatformLinux)
				f.fs.addFile(testHome+"/.claude/settings.json", tc.file)
				if a := agentOf(t, f.run(t), "claude-code"); !a.Truncated {
					t.Errorf("truncated not set: %+v", a)
				}
			})
		}
		f := newConfigFixture(model.PlatformLinux)
		deep := filepath.Join(testHome, strings.Repeat("d", 1100))
		f.projects = []string{deep}
		f.fs.addFile(deep+"/.gemini/settings.json", `{"hooksConfig": {"enabled": true}}`)
		if a := agentOf(t, f.run(t), "gemini-cli"); !a.Truncated || len(a.Sources[0].Path) != maxConfigPathBytes {
			t.Errorf("path cut: truncated=%v len=%d", a.Truncated, len(a.Sources[0].Path))
		}
	})
	t.Run("multibyte display cut hashes the full text", func(t *testing.T) {
		f := newConfigFixture(model.PlatformLinux)
		text := strings.Repeat("a", 255) + "é" + "tail"
		f.fs.addFile(testHome+"/.claude/settings.json", `{"hooks": {"E": [{"hooks": [{"command": "`+text+`"}]}]}}`)
		a := agentOf(t, f.run(t), "claude-code")
		h := a.Sources[0].Hooks[0]
		if h.CommandDisplay != strings.Repeat("a", 255) || h.CommandSHA256 != sha256Hex([]byte(text)) || !a.Truncated {
			t.Errorf("display=%d bytes hash=%s truncated=%v", len(h.CommandDisplay), h.CommandSHA256, a.Truncated)
		}
	})
}

func TestAgentConfig_UnreadableAndListings(t *testing.T) {
	f := newConfigFixture(model.PlatformLinux)
	project := filepath.Join(testHome, "repos", "widgets")
	f.projects = []string{project}
	f.fs.addFile(testHome+"/.claude/settings.json", `{"permissions": `)
	f.fs.addFile(testHome+"/.gemini/settings.json", `[1, 2]`)
	f.fs.addFile(project+"/.claude/settings.json", `{broken`)
	f.fs.addFile("/etc/claude-code/managed-settings.d/a.json", `{"disableAllHooks": true}`)
	f.fs.addFile("/etc/github-copilot/policy.d/a.json", `{"disableAllHooks": true}`)
	f.fs.addFile(testHome+"/.copilot/hooks/a.json", `{"hooks": {"E": [{"command": "c"}]}}`)
	f.fs.addFile(project+"/.github/hooks/a.json", `{"hooks": {"E": [{"command": "c"}]}}`)
	f.fs.addFile(testHome+"/.config/Code/User/profiles/p/settings.json", `{"chat.useHooks": true}`)
	failing := map[string]bool{
		"/etc/claude-code/managed-settings.d": true, "/etc/github-copilot/policy.d": true,
		testHome + "/.copilot/hooks": true, project + "/.github/hooks": true, testHome + "/.config/Code/User/profiles": true,
	}
	f.fs.commit()
	scan := f.scan(t, &listFailMock{f.m, failing})

	wantSources(t, agentOf(t, scan, "claude-code"), "user file ~/.claude/settings.json unreadable")
	wantSources(t, agentOf(t, scan, "gemini-cli"), "user file ~/.gemini/settings.json unreadable")
	wantSources(t, agentOf(t, scan, "github-copilot"))
	if src := agentOf(t, scan, "claude-code").Sources[0]; src.Settings == nil || src.Hooks == nil {
		t.Errorf("unreadable lists must be [], got %+v", src)
	}
}

type listFailMock struct {
	*pluginMock
	fail map[string]bool
}

func (m *listFailMock) GuardedFiles(_ []string, _ func(string) string, _ int64) executor.Executor {
	return m
}

func (m *listFailMock) ReadDir(dir string) ([]os.DirEntry, error) {
	if m.fail[dir] {
		return nil, errors.New("permission denied")
	}
	return m.pluginMock.ReadDir(dir)
}

func TestAgentConfig_Detection(t *testing.T) {
	tools := []model.AITool{{Name: "claude-code"}, {Name: "codex"}, {Name: "gemini-cli"}, {Name: "github-copilot-cli"}, {Name: "cursor-agent"}, {Name: "aider"}}
	want := map[string]bool{"claude-code": true, "codex": true, "gemini-cli": true, "github-copilot": true, "cursor": true}
	if got := ConfigAgents(tools, nil); !reflect.DeepEqual(got, want) {
		t.Errorf("ConfigAgents(tools) = %v", got)
	}
	if got := ConfigAgents(nil, []model.IDE{{IDEType: "cursor"}, {IDEType: "vscode"}}); !reflect.DeepEqual(got, map[string]bool{"cursor": true}) {
		t.Errorf("ConfigAgents(ides) = %v", got)
	}

	f := newConfigFixture(model.PlatformLinux)
	f.detected = map[string]bool{"codex": true}
	f.m.SetEnv("COPILOT_HOME", "/opt/copilot")
	f.fs.mkdir("/opt/copilot")
	f.fs.addFile(testHome+"/.config/Code/User/settings.json", `{"editor.fontSize": 12}`)
	scan := f.run(t)
	var names []string
	for _, a := range scan.Agents {
		names = append(names, a.Agent)
		if a.Sources == nil || len(a.Sources) != 0 {
			t.Errorf("%s sources = %#v, want []", a.Agent, a.Sources)
		}
	}
	if !reflect.DeepEqual(names, []string{"codex", "github-copilot"}) {
		t.Errorf("agents = %v", names)
	}

	f = newConfigFixture(model.PlatformLinux)
	f.fs.addFile(testHome+"/.config/Code/User/settings.json", `{"editor.fontSize": 12}`)
	if got := f.run(t); len(got.Agents) != 0 || got.Agents == nil {
		t.Errorf("VS Code alone: agents = %#v", got.Agents)
	}

	f = newConfigFixture(model.PlatformLinux)
	f.fs.mkdir(testHome + "/.copilot")
	if got := f.run(t); len(got.Agents) != 1 || got.Agents[0].Agent != "github-copilot" {
		t.Errorf("default ~/.copilot: agents = %#v", got.Agents)
	}
}

func TestAgentConfig_SectionPresence(t *testing.T) {
	run := func(s *pluginScan, ctx context.Context) *model.AgentConfigScan {
		r := &SkillsResult{pendingPlugins: s}
		if s != nil {
			s.d.DetectAgentConfig(ctx, r)
		} else {
			NewSkillsDetector(executor.NewMock()).DetectAgentConfig(ctx, r)
		}
		return r.AgentConfig
	}
	m, _ := newPluginMock()
	d := NewSkillsDetector(m)
	if run(nil, t.Context()) != nil {
		t.Error("nil pending scan reported a section")
	}
	if run(&pluginScan{d: d, home: testHome, goos: model.PlatformLinux, projectsUnavailable: true}, t.Context()) != nil {
		t.Error("unavailable project list reported a section")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if run(&pluginScan{d: d, home: testHome, goos: model.PlatformLinux}, ctx) != nil {
		t.Error("expired context reported a section")
	}
	panicking := NewSkillsDetector(&panicMock{m})
	if run(&pluginScan{d: panicking, home: testHome, goos: model.PlatformLinux}, t.Context()) != nil {
		t.Error("panic reported a section")
	}
}

type panicMock struct{ *pluginMock }

func (m *panicMock) GuardedFiles(_ []string, _ func(string) string, _ int64) executor.Executor {
	return m
}

func (m *panicMock) Stat(string) (os.FileInfo, error) { panic("stat") }

func TestAgentConfig_FromSkillsPhase(t *testing.T) {
	m, fs := newPluginMock()
	m.SetHomeDir(testHome)
	m.SetGOOS(model.PlatformLinux)
	project := filepath.Join(testHome, "repos", "widgets")
	fs.addFile(project+"/.gemini/settings.json", `{"hooksConfig": {"enabled": true}}`)
	fs.mkdir(testHome + "/.claude")
	fs.commit()
	d := NewSkillsDetector(m)
	result := d.DetectSkills(t.Context(), nil, []string{filepath.Join(testHome, "repos")})
	d.DetectAgentConfig(t.Context(), &result)
	if result.pendingPlugins == nil {
		t.Fatal("pending plugin scan cleared")
	}
	if result.AgentConfig == nil || result.AgentConfig.RepositoriesScanned != 1 {
		t.Fatalf("agent config = %+v", result.AgentConfig)
	}
	wantSources(t, agentOf(t, result.AgentConfig, "gemini-cli"), "project file ~/repos/widgets/.gemini/settings.json read")
	if err := d.DetectPlugins(t.Context(), &result); err != nil || result.Plugins == nil || len(result.Plugins.Contexts) == 0 {
		t.Errorf("plugins after agent config: %v %+v", err, result.Plugins)
	}

	done, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name, state string
		ctx         context.Context
	}{
		{"malformed file", `{"projects": `, t.Context()},
		{"malformed projects", `{"projects": 5}`, t.Context()},
		{"skills context done", `{}`, done},
	} {
		m, fs := newPluginMock()
		m.SetHomeDir(testHome)
		fs.addFile(testHome+"/.claude.json", tc.state)
		fs.addFile(testHome+"/.codex/config.toml", `approval_policy = "never"`)
		fs.commit()
		d := NewSkillsDetector(m)
		result := d.DetectSkills(tc.ctx, nil, nil)
		d.DetectAgentConfig(t.Context(), &result)
		if result.AgentConfig != nil {
			t.Errorf("%s: section reported", tc.name)
		}
	}
	m, fs = newPluginMock()
	m.SetHomeDir(testHome)
	fs.addFile(testHome+"/.codex/config.toml", `approval_policy = "never"`)
	fs.commit()
	d = NewSkillsDetector(m)
	result = d.DetectSkills(t.Context(), nil, nil)
	if d.DetectAgentConfig(t.Context(), &result); result.AgentConfig == nil {
		t.Error("missing ~/.claude.json withheld the section")
	}
}

// Settings-only repositories never change the skills or plugins results.
func TestAgentConfig_SettingsOnlyReposLeaveSkillsAlone(t *testing.T) {
	type outcome struct {
		skills  []model.AgentSkill
		info    model.AgentSkillScanInfo
		plugins string
		config  *model.AgentConfigScan
	}
	run := func(settingsOnly bool) outcome {
		m, fs := newPluginMock()
		m.SetHomeDir(testHome)
		m.SetGOOS(model.PlatformLinux)
		repos := filepath.Join(testHome, "repos")
		fs.mkdir(testHome + "/.claude")
		fs.addFile(repos+"/skilled/.claude/skills/s/SKILL.md", validFrontmatter("s", "d"))
		fs.addFile(repos+"/both/.codex/skills/t/SKILL.md", validFrontmatter("t", "d"))
		// The same folders either way; only the file names make them markers.
		names := []string{"CLAUDE.md", "notes.toml", "workflows"}
		if settingsOnly {
			names = []string{"settings.json", "config.toml", "hooks"}
		}
		fs.addFile(repos+"/both/.claude/"+names[0], `{"permissions": {"defaultMode": "plan"}}`)
		fs.addFile(repos+"/cfg-a/.claude/"+names[0], `{"permissions": {"defaultMode": "plan"}}`)
		fs.addFile(repos+"/cfg-b/.codex/"+names[1], `approval_policy = "never"`)
		fs.addFile(repos+"/cfg-c/.github/"+names[2]+"/a.json", `{"hooks": {"E": [{"command": "c"}]}}`)
		fs.commit()
		d := NewSkillsDetector(m)
		fixed := time.Unix(1_700_000_000, 0)
		d.now = func() time.Time { return fixed }
		result := d.DetectSkills(t.Context(), nil, []string{repos})
		d.DetectAgentConfig(t.Context(), &result)
		if err := d.DetectPlugins(t.Context(), &result); err != nil {
			t.Fatal(err)
		}
		info := *result.Info
		info.DurationMs = 0
		plugins, err := json.Marshal(result.Plugins)
		if err != nil {
			t.Fatal(err)
		}
		return outcome{result.Skills, info, stripDurations(t, plugins), result.AgentConfig}
	}
	base, more := run(false), run(true)
	if !reflect.DeepEqual(base.skills, more.skills) || !reflect.DeepEqual(base.info, more.info) {
		t.Errorf("skills changed:\n%+v\n%+v", base.info, more.info)
	}
	if base.plugins != more.plugins {
		t.Errorf("plugins changed:\n%s\n%s", base.plugins, more.plugins)
	}
	if more.config == nil || more.config.RepositoriesScanned != 5 {
		t.Fatalf("agent config = %+v", more.config)
	}
	wantSources(t, agentOf(t, more.config, "claude-code"),
		"project file ~/repos/both/.claude/settings.json read", "project file ~/repos/cfg-a/.claude/settings.json read")
	wantSources(t, agentOf(t, more.config, "codex"), "project file ~/repos/cfg-b/.codex/config.toml read")
	wantSources(t, agentOf(t, more.config, "github-copilot"), "project file ~/repos/cfg-c/.github/hooks/a.json read")
	for _, a := range more.config.Agents {
		if a.Truncated {
			t.Errorf("%s truncated with no cut", a.Agent)
		}
	}
}

func stripDurations(t *testing.T, data []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if strings.HasSuffix(k, "duration_ms") {
					delete(x, k)
				} else {
					walk(e)
				}
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(v)
	out, _ := json.Marshal(v)
	return string(out)
}

// A settings-only repository outside home under a search dir is reported.
func TestAgentConfig_SettingsOnlyRepoOutsideHome(t *testing.T) {
	m, fs := newPluginMock()
	m.SetHomeDir(testHome)
	m.SetGOOS(model.PlatformLinux)
	fs.addFile("/work/widgets/.cursor/hooks.json", `{"hooks": {"E": [{"command": "c"}]}}`)
	fs.commit()
	d := NewSkillsDetector(m)
	result := d.DetectSkills(t.Context(), nil, []string{"/work"})
	d.DetectAgentConfig(t.Context(), &result)
	if result.AgentConfig == nil || result.Info.ProjectsScanned != 0 {
		t.Fatalf("agent config = %+v, skills projects = %d", result.AgentConfig, result.Info.ProjectsScanned)
	}
	wantSources(t, agentOf(t, result.AgentConfig, "cursor"), "project file /work/widgets/.cursor/hooks.json read")
}

// A cut project list still reports, with every agent marked truncated.
func TestAgentConfig_ProjectCapMarksTruncated(t *testing.T) {
	t.Run("skills list", func(t *testing.T) {
		m, fs := newPluginMock()
		m.SetHomeDir(testHome)
		m.SetGOOS(model.PlatformLinux)
		var registry []string
		for i := range maxProjects + 1 {
			p := fmt.Sprintf("/r/p%03d", i)
			fs.mkdir(p)
			registry = append(registry, fmt.Sprintf("%q: {}", p))
		}
		fs.addFile(testHome+"/.claude.json", `{"projects": {`+strings.Join(registry, ",")+`}}`)
		fs.addFile("/r/p000/.claude/settings.json", `{"permissions": {"defaultMode": "plan"}}`)
		fs.addFile(testHome+"/.codex/config.toml", `approval_policy = "never"`)
		fs.commit()
		d := NewSkillsDetector(m)
		result := d.DetectSkills(t.Context(), nil, nil)
		d.DetectAgentConfig(t.Context(), &result)
		assertAllTruncated(t, result.AgentConfig, maxProjects)
	})
	t.Run("settings-only list", func(t *testing.T) {
		m, fs := newPluginMock()
		m.SetHomeDir(testHome)
		m.SetGOOS(model.PlatformLinux)
		for i := range maxProjects + 1 {
			fs.addFile(fmt.Sprintf("/r/c%03d/.gemini/settings.json", i), `{"tools": {"sandbox": true}}`)
		}
		fs.addFile(testHome+"/.codex/config.toml", `approval_policy = "never"`)
		fs.commit()
		d := NewSkillsDetector(m)
		result := d.DetectSkills(t.Context(), nil, []string{"/r"})
		d.DetectAgentConfig(t.Context(), &result)
		if result.Info.Truncated || result.Info.WalkRootsFound != 0 {
			t.Errorf("skills info changed: %+v", result.Info)
		}
		assertAllTruncated(t, result.AgentConfig, maxProjects)
	})
}

func assertAllTruncated(t *testing.T, scan *model.AgentConfigScan, repos int) {
	t.Helper()
	if scan == nil || scan.RepositoriesScanned != repos || len(scan.Agents) < 2 {
		t.Fatalf("agent config = %+v", scan)
	}
	for _, a := range scan.Agents {
		if !a.Truncated {
			t.Errorf("%s not truncated", a.Agent)
		}
	}
}

func TestAgentConfig_HomeForms(t *testing.T) {
	tests := []struct {
		name, home, resolved, goos, in, want string
	}{
		{"path", "/home/alice", "", model.PlatformLinux, "/home/alice/x", "~/x"},
		{"longer name kept", "/home/al", "", model.PlatformLinux, "/home/alice/x", "/home/alice/x"},
		{"glob", "/Users/x", "", model.PlatformDarwin, "Read(/Users/x*)", "Read(~*)"},
		{"path list", "/home/x", "", model.PlatformLinux, "PATH=/home/x:/usr/bin", "PATH=~:/usr/bin"},
		{"name byte", "/home/x", "", model.PlatformLinux, "/home/x.bak /home/x_y /home/x-z", "/home/x.bak /home/x_y /home/x-z"},
		{"case on linux", "/home/x", "", model.PlatformLinux, "/HOME/X/a", "/HOME/X/a"},
		{"windows case and slash", winHome, "", model.PlatformWindows, `c:/users/TESTUSER\a`, `~\a`},
		{"windows posix", winHome, "", model.PlatformWindows, "Read(/c/Users/testuser/**) //c/Users/testuser/b", "Read(~/**) ~/b"},
		{"windows escaped", winHome, "", model.PlatformWindows, `{"p":"C:\\Users\\testuser\\x"}`, `{"p":"~\\x"}`},
		{"resolved home", "/Users/x", "/private/Users/x", model.PlatformDarwin, "/private/Users/x/repo and /Users/x/a", "~/repo and ~/a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &configScan{forms: homeForms(tc.home, tc.resolved, tc.goos), fold: tc.goos == model.PlatformWindows}
			if got := c.tilde(tc.in); got != tc.want {
				t.Errorf("tilde(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAgentConfig_SymlinkedHome(t *testing.T) {
	f := newConfigFixture(model.PlatformLinux)
	f.m.SetSymlink(testHome, "/data/testuser")
	project := "/data/testuser/repos/widgets"
	f.projects = []string{project}
	f.fs.addFile(project+"/.claude/settings.json", `{"hooks": {"E": [{"hooks": [{"command": "/data/testuser/bin/x"}]}]}}`)
	a := agentOf(t, f.run(t), "claude-code")
	wantSources(t, a, "project file ~/repos/widgets/.claude/settings.json read")
	if got := a.Sources[0].Hooks[0].CommandDisplay; got != "~/bin/x" {
		t.Errorf("command = %q", got)
	}
}

func TestAgentConfig_Deterministic(t *testing.T) {
	build := func() []byte {
		f := newConfigFixture(model.PlatformLinux)
		f.fs.addFile(testHome+"/.codex/config.toml", "sandbox_mode = \"x\"\n[[hooks.B]]\n[[hooks.B.hooks]]\ncommand = \"b\"\n[[hooks.A]]\n[[hooks.A.hooks]]\ncommand = \"a\"\n")
		f.fs.addFile(testHome+"/.claude/settings.json", `{"hooks": {"Z": [{"hooks": [{"command": "z"}]}], "A": [{"hooks": [{"command": "a"}]}]}}`)
		data, err := json.Marshal(f.run(t))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	first, second := build(), build()
	if string(first) != string(second) {
		t.Errorf("runs differ:\n%s\n%s", first, second)
	}
	if !strings.Contains(string(first), `"event":"Z"`) || strings.Index(string(first), `"event":"Z"`) > strings.Index(string(first), `"event":"A","matcher":"","handler_type":"command","command_display":"a"`) {
		t.Errorf("JSON hooks not in file order: %s", first)
	}
}

// Config roots named by the environment may sit outside home; they are read,
// not refused by the guarded reader.
func TestAgentConfig_GuardedRoots(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	write := func(p, content string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(outside, "claude", "settings.json"), `{"disableAllHooks": true}`)
	write(filepath.Join(outside, "codex", "config.toml"), `sandbox_mode = "read-only"`)
	write(filepath.Join(outside, "copilot", "settings.json"), `{"disableAllHooks": true}`)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(outside, "claude"))
	t.Setenv("CODEX_HOME", filepath.Join(outside, "codex"))
	t.Setenv("COPILOT_HOME", filepath.Join(outside, "copilot"))
	write(filepath.Join(outside, "widgets", ".gemini", "settings.json"), `{"tools": {"sandbox": true}}`)
	t.Setenv("XDG_CONFIG_HOME", "")
	d := NewSkillsDetector(executor.NewReal()).WithSkipper(tcc.New(home))
	r := &SkillsResult{pendingPlugins: &pluginScan{d: d, home: home, goos: model.PlatformLinux, configProjects: []string{filepath.Join(outside, "widgets")}}}
	d.DetectAgentConfig(t.Context(), r)
	if r.AgentConfig == nil {
		t.Fatal("section missing")
	}
	for _, tc := range []struct{ agent, path string }{
		{"claude-code", filepath.Join(outside, "claude", "settings.json")},
		{"codex", filepath.Join(outside, "codex", "config.toml")},
		{"github-copilot", filepath.Join(outside, "copilot", "settings.json")},
		{"gemini-cli", filepath.Join(outside, "widgets", ".gemini", "settings.json")},
	} {
		if src := sourceAt(t, agentOf(t, r.AgentConfig, tc.agent), tc.path); src.State != model.AgentConfigStateRead {
			t.Errorf("%s user source = %s", tc.agent, src.State)
		}
	}
}

// The VS Code settings under ~/Library are read by their known paths even
// though the guarded reader refuses that tree, and a symlinked settings file is
// not followed into another protected folder or out of home.
func TestAgentConfig_VSCodeMacLibrary(t *testing.T) {
	const content = `{"chat.useHooks": false}`
	tests := []struct {
		name   string
		target func(home, outside string) string // symlink target; "" writes a plain file
		want   bool
		darwin bool // the protected tree exists on macOS only
	}{
		{"plain file", func(string, string) string { return "" }, true, false},
		{"link into Documents", func(home, _ string) string { return filepath.Join(home, "Documents", "x.json") }, false, true},
		{"link out of home", func(_, outside string) string { return filepath.Join(outside, "x.json") }, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.darwin && runtime.GOOS != model.PlatformDarwin {
				t.Skip("protected folders exist on macOS only")
			}
			// Resolved, so the protected folders match the paths the reader checks.
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			user := filepath.Join(home, "Library", "Application Support", "Code", "User")
			settings := filepath.Join(user, "settings.json")
			if err := os.MkdirAll(user, 0o755); err != nil {
				t.Fatal(err)
			}
			if target := tc.target(home, outside); target == "" {
				if err := os.WriteFile(settings, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, settings); err != nil {
					t.Fatal(err)
				}
			}
			d := NewSkillsDetector(executor.NewReal()).WithSkipper(tcc.New(home))
			s := &pluginScan{d: d, ctx: t.Context(), home: home, goos: model.PlatformDarwin}
			a := &configAgent{c: &configScan{s: s}, keys: configKeys[configAgentCopilot], out: model.AgentConfig{Sources: []model.AgentConfigSource{}}}
			(&configScan{s: s}).vscodeSettings(a, s.vscodeReader(user), settings)
			if got := len(a.out.Sources) == 1 && a.out.Sources[0].Settings[0].Value == "false"; got != tc.want {
				t.Errorf("read = %v, want %v; sources = %+v", got, tc.want, a.out.Sources)
			}
		})
	}
}

func TestReadRegistryValue_QueryOutput(t *testing.T) {
	const key = `HKLM\SOFTWARE\Policies\Example`
	tests := []struct {
		name, stdout, want string
		exit               int
		found, err         bool
	}{
		{"sz", "\n" + key + "\n    V    REG_SZ    a b  c\n", "a b  c", 0, true, false},
		{"expand sz", "    V    REG_EXPAND_SZ    %ProgramData%\\x\n", `%ProgramData%\x`, 0, true, false},
		{"dword", "    V    REG_DWORD    0x1f\n", "31", 0, true, false},
		{"qword", "    V    REG_QWORD    0x0\n", "0", 0, true, false},
		{"binary", "    V    REG_BINARY    01\n", "", 0, true, true},
		{"prefix name", "    VV    REG_SZ    x\n", "", 0, false, false},
		{"missing", "", "", 1, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := executor.NewMock()
			m.SetCommand(tc.stdout, "", tc.exit, "reg", "query", key, "/v", "V")
			v, found, err := readRegistryValue(t.Context(), m, key, "V")
			if v != tc.want || found != tc.found || (err != nil) != tc.err {
				t.Errorf("got (%q, %v, %v)", v, found, err)
			}
		})
	}
}
