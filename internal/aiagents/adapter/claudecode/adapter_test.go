package claudecode

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// testBinary is the absolute DMG binary path tests pass to New(). The
// uninstall matcher (managedCmdRE) is path-token-agnostic, so the
// specific value just needs to satisfy `(^|/)stepsecurity-dev-machine-guard\s+_hook\s+`.
const testBinary = "/usr/local/bin/stepsecurity-dev-machine-guard"

// newHomeWithSettings creates a tempdir-rooted ~/.claude/settings.json
// containing body and returns the home dir. The adapter under test
// computes its own settings path from home, so callers do not need to
// know the layout.
func newHomeWithSettings(t *testing.T, body string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func settingsPath(home string) string {
	return filepath.Join(home, ".claude", "settings.json")
}

func mustParse(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("settings JSON: %v", err)
	}
	return out
}

func TestInstallPreservesUserHooks(t *testing.T) {
	body := `{
		"theme": "dark",
		"hooks": {
			"PreToolUse": [
				{"matcher": "*", "hooks": [{"type": "command", "command": "echo user"}]},
				{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo bash-only"}]}
			]
		}
	}`
	home := newHomeWithSettings(t, body)
	a := New(home, testBinary)
	res, err := a.Install(context.Background())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(res.BackupFiles) == 0 {
		t.Error("expected backup file")
	}
	if len(res.WrittenFiles) == 0 {
		t.Error("expected written file")
	}

	got := mustParse(t, settingsPath(home))
	hooks := got["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)

	// Find every command across the matchers; the user's must remain.
	var commands []string
	for _, raw := range pre {
		group := raw.(map[string]any)
		for _, h := range group["hooks"].([]any) {
			hm := h.(map[string]any)
			commands = append(commands, hm["command"].(string))
		}
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "echo user") {
		t.Errorf("user hook lost; got %q", joined)
	}
	if !strings.Contains(joined, "echo bash-only") {
		t.Errorf("matcher-specific user hook lost; got %q", joined)
	}
	if !strings.Contains(joined, "stepsecurity-dev-machine-guard") {
		t.Errorf("DMG hook missing; got %q", joined)
	}

	// Theme key must survive.
	if got["theme"] != "dark" {
		t.Errorf("unrelated key lost")
	}
}

func TestUninstallRemovesOnlyManagedHooks(t *testing.T) {
	// User hooks include lookalikes that the regex match must NOT touch:
	// a tool whose name starts with the same prefix but isn't a separate
	// word; a hyphenated suffix; an absolute path that is NOT the DMG
	// binary; and an absolute-path non-DMG entry, all intentionally
	// not matched.
	body := `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "*", "hooks": [
					{"type": "command", "command": "stepsecurity-dev-machine-guardctl status"},
					{"type": "command", "command": "stepsecurity-dev-machine-guard-foo run"},
					{"type": "command", "command": "/usr/local/bin/other-tool _hook claude-code PreToolUse"},
					{"type": "command", "command": "echo user-other"}
				]}
			]
		}
	}`
	home := newHomeWithSettings(t, body)
	a := New(home, testBinary)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := a.Uninstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.HooksRemoved) == 0 {
		t.Fatal("expected at least one removal")
	}
	got := mustParse(t, settingsPath(home))
	hooks, _ := got["hooks"].(map[string]any)
	if hooks == nil {
		t.Fatal("hooks key removed despite remaining user entries")
	}
	pre := hooks["PreToolUse"].([]any)
	survivors := []string{}
	for _, raw := range pre {
		group := raw.(map[string]any)
		for _, h := range group["hooks"].([]any) {
			hm := h.(map[string]any)
			cmd, _ := hm["command"].(string)
			survivors = append(survivors, cmd)
			if isManagedCommand(cmd) {
				t.Errorf("managed command survived uninstall: %q", cmd)
			}
		}
	}
	// Each lookalike user hook must remain.
	for _, want := range []string{
		"stepsecurity-dev-machine-guardctl status",
		"stepsecurity-dev-machine-guard-foo run",
		"/usr/local/bin/other-tool _hook claude-code PreToolUse",
		"echo user-other",
	} {
		if !slices.Contains(survivors, want) {
			t.Errorf("lookalike user hook %q removed; survivors=%v", want, survivors)
		}
	}
}

// rootKeyOrder returns the top-level JSON object keys of path in the
// order they appear in the file. We tokenize via json.Decoder so the
// test does not depend on the same parser the adapter uses.
func rootKeyOrder(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("expected root '{', got %v err %v", tok, err)
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k.(string))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func TestInstallPreservesRootKeyOrder(t *testing.T) {
	// `z`, `hooks`, `a` is in non-lexical order; encoding/json + map[string]any
	// would alphabetize it to `a`, `hooks`, `z`.
	body := `{
		"z": "last",
		"hooks": {
			"PreToolUse": [
				{"matcher": "*", "hooks": [{"timeout": 5, "type": "command", "command": "echo user"}]}
			]
		},
		"a": "first"
	}`
	home := newHomeWithSettings(t, body)
	a := New(home, testBinary)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got := rootKeyOrder(t, settingsPath(home))
	want := []string{"z", "hooks", "a"}
	if len(got) != len(want) {
		t.Fatalf("root keys: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("root key order: got %v, want %v", got, want)
			break
		}
	}
}

func TestInstallPreservesUserHookEntryKeyOrder(t *testing.T) {
	// User wrote keys as `timeout`, `type`, `command`. encoding/json on
	// map[string]any would re-emit them as `command`, `timeout`, `type`.
	body := `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "Bash", "hooks": [{"timeout": 5, "type": "command", "command": "echo user"}]}
			]
		}
	}`
	home := newHomeWithSettings(t, body)
	a := New(home, testBinary)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	b, _ := os.ReadFile(settingsPath(home))
	out := string(b)
	// Find the user hook entry by command and verify timeout precedes
	// type precedes command — the user's original order.
	userIdx := strings.Index(out, `"echo user"`)
	if userIdx < 0 {
		t.Fatalf("user hook not found in output: %s", out)
	}
	entryStart := strings.LastIndex(out[:userIdx], "{")
	entryEnd := strings.Index(out[userIdx:], "}")
	if entryStart < 0 || entryEnd < 0 {
		t.Fatalf("could not locate user entry: %s", out)
	}
	entry := out[entryStart : userIdx+entryEnd+1]
	tIdx := strings.Index(entry, `"timeout"`)
	yIdx := strings.Index(entry, `"type"`)
	cIdx := strings.Index(entry, `"command"`)
	if !(tIdx >= 0 && tIdx < yIdx && yIdx < cIdx) {
		t.Errorf("user hook key order lost; entry: %s", entry)
	}
}

func TestUninstallLeavesUnrelatedKeysUntouched(t *testing.T) {
	body := `{
		"z": "last",
		"hooks": {
			"PreToolUse": [
				{"matcher": "*", "hooks": [{"timeout": 5, "type": "command", "command": "echo user"}]}
			]
		},
		"a": "first"
	}`
	home := newHomeWithSettings(t, body)
	a := New(home, testBinary)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := a.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	got := rootKeyOrder(t, settingsPath(home))
	zIdx, aIdx := -1, -1
	for i, k := range got {
		if k == "z" {
			zIdx = i
		}
		if k == "a" {
			aIdx = i
		}
	}
	if zIdx < 0 || aIdx < 0 || zIdx >= aIdx {
		t.Errorf("expected z before a in %v", got)
	}
	// The user hook must have survived.
	b, _ := os.ReadFile(settingsPath(home))
	if !strings.Contains(string(b), "echo user") {
		t.Errorf("user hook lost on uninstall: %s", b)
	}
}

func TestInstallPreservesUnrelatedRootKeys(t *testing.T) {
	body := "{\n\t\"theme\":     \"dark\",\n\t\"hooks\": {}\n}\n"
	home := newHomeWithSettings(t, body)
	a := New(home, testBinary)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	b, _ := os.ReadFile(settingsPath(home))
	out := string(b)
	if !strings.Contains(out, `"theme": "dark"`) {
		t.Errorf("unrelated theme key/value was lost:\n%s", out)
	}
}

func TestInstallNoOpDoesNotRewriteSettings(t *testing.T) {
	home := newHomeWithSettings(t, `{"theme":"dark"}`)
	a := New(home, testBinary)
	// First install brings file into desired state.
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatalf("first install: %v", err)
	}
	before, _ := os.ReadFile(settingsPath(home))
	matches, _ := filepath.Glob(settingsPath(home) + ".dmg-*.bak")
	beforeBackups := len(matches)
	// Second install should be a no-op.
	res, err := a.Install(context.Background())
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	after, _ := os.ReadFile(settingsPath(home))
	if !bytes.Equal(before, after) {
		t.Errorf("idempotent install rewrote settings:\n  before %s\n  after  %s", before, after)
	}
	matches, _ = filepath.Glob(settingsPath(home) + ".dmg-*.bak")
	if len(matches) != beforeBackups {
		t.Errorf("idempotent install created a new backup: %v", matches)
	}
	if len(res.BackupFiles) != 0 || len(res.WrittenFiles) != 0 {
		t.Errorf("expected empty file slices on no-op install, got %+v", res)
	}
}

// TestUninstallPreservesUserHookAfterManagedEntry covers an array-shift
// bug in the previous span-based renderer — it matched array elements
// by index, so removing the managed entry at index 0 could overwrite
// the user entry that shifted into index 0.
func TestUninstallPreservesUserHookAfterManagedEntry(t *testing.T) {
	body := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/stepsecurity-dev-machine-guard _hook claude-code PreToolUse","timeout":30},{"timeout":5,"type":"command","command":"echo user"}]}]}}`
	home := newHomeWithSettings(t, body)
	a := New(home, testBinary)
	if _, err := a.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	out, _ := os.ReadFile(settingsPath(home))
	if !strings.Contains(string(out), `"command": "echo user"`) {
		t.Fatalf("user hook after managed entry was lost: %s", out)
	}
	if isManagedCommand(string(out)) && strings.Contains(string(out), "stepsecurity-dev-machine-guard _hook claude-code") {
		t.Fatalf("managed entry survived uninstall: %s", out)
	}
}

// TestInstallOnAlreadyInstalledFileNoFinalNewlineIsNoOp asserts that
// an already-installed settings file without a trailing newline is
// left alone — the previous renderer always appended `\n`, creating a
// pointless backup on every install of an idempotent file.
func TestInstallOnAlreadyInstalledFileNoFinalNewlineIsNoOp(t *testing.T) {
	body := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code PreToolUse","timeout":30}]}],"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code PostToolUse","timeout":30}]}],"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code SessionStart","timeout":30}]}],"SessionEnd":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code SessionEnd","timeout":30}]}],"UserPromptSubmit":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code UserPromptSubmit","timeout":30}]}],"Stop":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code Stop","timeout":30}]}],"SubagentStop":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code SubagentStop","timeout":30}]}],"Notification":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code Notification","timeout":30}]}],"PostToolUseFailure":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code PostToolUseFailure","timeout":30}]}],"Elicitation":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code Elicitation","timeout":30}]}],"ElicitationResult":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code ElicitationResult","timeout":30}]}],"PermissionRequest":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code PermissionRequest","timeout":30}]}],"PermissionDenied":[{"matcher":"*","hooks":[{"type":"command","command":"` + testBinary + ` _hook claude-code PermissionDenied","timeout":30}]}]}}`
	home := newHomeWithSettings(t, body)
	a := New(home, testBinary)
	before, _ := os.ReadFile(settingsPath(home))
	res, err := a.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(settingsPath(home))
	if !bytes.Equal(before, after) {
		t.Fatalf("no-op install rewrote settings:\n  before %s\n  after  %s", before, after)
	}
	if len(res.BackupFiles) != 0 {
		t.Fatalf("no-op install created backup %v", res.BackupFiles)
	}
}

func TestInstallRejectsMalformedJSON(t *testing.T) {
	home := newHomeWithSettings(t, `{not json`)
	a := New(home, testBinary)
	if _, err := a.Install(context.Background()); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
	// File must remain untouched on parse failure.
	out, _ := os.ReadFile(settingsPath(home))
	if string(out) != `{not json` {
		t.Fatalf("file was modified despite parse failure: %s", out)
	}
}

// TestInstallRefreshesStaleBinaryPath asserts the self-heal behavior
// for the binary-move case: when settings already contain a managed
// entry pointing at an old absolute path, a fresh `hooks install`
// rewrites the command to the current binaryPath. Without this,
// `brew upgrade` (which relocates the binary in the Cellar) would
// silently break hooks until the user noticed.
func TestInstallRefreshesStaleBinaryPath(t *testing.T) {
	stalePath := "/old/path/stepsecurity-dev-machine-guard"
	body := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + stalePath + ` _hook claude-code PreToolUse","timeout":30}]}]}}`
	home := newHomeWithSettings(t, body)
	a := New(home, testBinary)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(settingsPath(home))
	if strings.Contains(string(out), stalePath) {
		t.Errorf("stale binary path not refreshed: %s", out)
	}
	if !strings.Contains(string(out), testBinary) {
		t.Errorf("new binary path not written: %s", out)
	}
}

func TestDetectReportsPathFromExecutor(t *testing.T) {
	home := t.TempDir()
	a := New(home, testBinary)

	// Not on $PATH → Detected=false, no error.
	mock := executor.NewMock()
	res, err := a.Detect(context.Background(), mock)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Detected {
		t.Errorf("expected Detected=false when claude not on $PATH")
	}

	// On $PATH → Detected=true with BinaryPath populated.
	mock.SetPath("claude", "/usr/local/bin/claude")
	res, err = a.Detect(context.Background(), mock)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Detected {
		t.Errorf("expected Detected=true when claude on $PATH")
	}
	if res.BinaryPath != "/usr/local/bin/claude" {
		t.Errorf("BinaryPath = %q, want /usr/local/bin/claude", res.BinaryPath)
	}
}

func TestParseEventInfersBashAsCommandExec(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	raw := []byte(`{"session_id":"s1","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"echo hi","cwd":"/tmp"}}`)
	ev, err := a.ParseEvent(context.Background(), event.HookPreToolUse, raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.ActionType != event.ActionCommandExec {
		t.Errorf("action: %s", ev.ActionType)
	}
	cmd, cwd, ok := a.ShellCommand(ev)
	if !ok || cmd == "" || cwd == "" {
		t.Errorf("expected shell command extraction")
	}
}

func TestParseEventRedactsSecretsInPayload(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	raw := []byte(`{"tool_name":"Bash","tool_input":{"command":"GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa make deploy"}}`)
	ev, err := a.ParseEvent(context.Background(), event.HookPreToolUse, raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(ev)
	if strings.Contains(string(encoded), "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Errorf("event payload still contains secret: %s", encoded)
	}
}

func TestParseEventLifecycleHooksOmitActionType(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	cases := []event.HookEvent{
		event.HookSessionStart,
		event.HookSessionEnd,
		event.HookNotification,
		event.HookStop,
		event.HookSubagentStop,
		event.HookUserPrompt,
		event.HookElicitation,
		event.HookElicitationResult,
		event.HookPermissionRequest,
		event.HookPermissionDenied,
	}
	for _, ht := range cases {
		t.Run(string(ht), func(t *testing.T) {
			ev, err := a.ParseEvent(context.Background(), ht, []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if ev.ActionType != "" {
				t.Errorf("hook %s: expected empty action_type, got %q", ht, ev.ActionType)
			}
			encoded, _ := json.Marshal(ev)
			if strings.Contains(string(encoded), `"action_type"`) {
				t.Errorf("hook %s: action_type key must be omitted from JSON, got %s", ht, encoded)
			}
		})
	}
}

func TestParseEventScrubsElicitationContent(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	raw := []byte(`{
		"mcp_server_name":"github",
		"action":"accepted",
		"content":{"otp":"123456","api_secret":"sk_live_abc","note":"hello"}
	}`)
	ev, err := a.ParseEvent(context.Background(), event.HookElicitationResult, raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(ev)
	got := string(encoded)
	for _, leak := range []string{"123456", "sk_live_abc", `"otp"`, `"api_secret"`, "hello"} {
		if strings.Contains(got, leak) {
			t.Errorf("content value leaked into payload: %s in %s", leak, got)
		}
	}
	if !strings.Contains(got, `"content_present":true`) {
		t.Errorf("expected content_present marker; got %s", got)
	}
	if !strings.Contains(got, `"action":"accepted"`) {
		t.Errorf("action should be preserved; got %s", got)
	}
}

func TestParseEventPreservesUserPromptAndRedactsSecretsInIt(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	raw := []byte(`{
		"session_id":"s",
		"cwd":"/tmp",
		"prompt":"deploy the staging service using GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}`)
	ev, err := a.ParseEvent(context.Background(), event.HookUserPrompt, raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(ev)
	got := string(encoded)
	if strings.Contains(got, `"prompt_present"`) {
		t.Errorf("prompt must be preserved, not replaced with presence marker: %s", got)
	}
	prompt, _ := ev.Payload["prompt"].(string)
	if !strings.Contains(prompt, "deploy the staging service") {
		t.Errorf("user prompt text must survive: %q", prompt)
	}
	if strings.Contains(got, "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Errorf("secret pasted into prompt leaked: %s", got)
	}
}

func TestParseEventCapturesSpecFields(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	raw := []byte(`{
		"session_id":"s1",
		"transcript_path":"/tmp/t.jsonl",
		"cwd":"/tmp",
		"hook_event_name":"PreToolUse",
		"permission_mode":"default",
		"tool_name":"Bash",
		"tool_use_id":"toolu_01abc",
		"tool_input":{"command":"echo hi"}
	}`)
	ev, err := a.ParseEvent(context.Background(), event.HookPreToolUse, raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.ToolUseID != "toolu_01abc" {
		t.Errorf("ToolUseID: %q", ev.ToolUseID)
	}
	if ev.PermissionMode != "default" {
		t.Errorf("PermissionMode: %q", ev.PermissionMode)
	}
}

func TestParseEventHookEventNameMismatchKeepsCLIHookType(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	raw := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}`)
	ev, err := a.ParseEvent(context.Background(), event.HookPreToolUse, raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.HookEvent != event.HookPreToolUse {
		t.Errorf("HookType should follow CLI arg, got %q", ev.HookEvent)
	}
	if len(ev.Errors) != 1 || ev.Errors[0].Code != "hook_event_name_mismatch" {
		t.Errorf("expected hook_event_name_mismatch error, got %+v", ev.Errors)
	}
}

func TestParseEventPopulatesHookPhase(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	cases := []struct {
		hook  event.HookEvent
		phase event.HookPhase
	}{
		{event.HookPreToolUse, event.HookPhasePreTool},
		{event.HookPostToolUse, event.HookPhasePostTool},
		{event.HookPostToolUseFailure, event.HookPhasePostToolFailure},
		{event.HookPermissionRequest, event.HookPhasePermissionRequest},
		{event.HookPermissionDenied, event.HookPhasePermissionDenied},
		{event.HookElicitation, event.HookPhaseElicitation},
		{event.HookElicitationResult, event.HookPhaseElicitationResult},
		{event.HookUserPrompt, event.HookPhaseUserPrompt},
		{event.HookSessionStart, event.HookPhaseSessionStart},
		{event.HookSessionEnd, event.HookPhaseSessionEnd},
		{event.HookNotification, event.HookPhaseNotification},
		{event.HookStop, event.HookPhaseStop},
		{event.HookSubagentStop, event.HookPhaseSubagentStop},
	}
	for _, tc := range cases {
		t.Run(string(tc.hook), func(t *testing.T) {
			ev, err := a.ParseEvent(context.Background(), tc.hook, []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if ev.HookPhase != tc.phase {
				t.Errorf("hook %s: expected phase %q, got %q", tc.hook, tc.phase, ev.HookPhase)
			}
			if string(ev.HookEvent) != string(tc.hook) {
				t.Errorf("HookEvent must remain native: got %q", ev.HookEvent)
			}
		})
	}
}

func TestParseEventPostToolUseFailureSetsErrorStatus(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	raw := []byte(`{"tool_name":"Bash","tool_input":{"command":"exit 1"},"error":"boom"}`)
	ev, err := a.ParseEvent(context.Background(), event.HookPostToolUseFailure, raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.ResultStatus != event.ResultError {
		t.Errorf("PostToolUseFailure must set result_status=error, got %q", ev.ResultStatus)
	}
}

func TestDecideResponseAllowShape(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	resp := a.DecideResponse(&event.Event{HookEvent: event.HookPreToolUse}, adapter.AllowDecision())
	encoded, _ := json.Marshal(resp)
	got := string(encoded)
	want := `{"continue":true,"suppressOutput":true}`
	if got != want {
		t.Errorf("allow shape mismatch:\n  got  %s\n  want %s", got, want)
	}
}

func TestDecideResponsePreToolUseBlockShape(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	ev := &event.Event{HookEvent: event.HookPreToolUse}
	resp := a.DecideResponse(ev, adapter.Decision{Allow: false, UserMessage: "Blocked by your organization's administrator."})
	encoded, _ := json.Marshal(resp)
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	// MUST NOT halt the agent.
	if v, ok := got["continue"]; ok && v == false {
		t.Errorf("PreToolUse block must not emit continue:false: %s", encoded)
	}
	// MUST NOT use the deprecated top-level fields.
	for _, k := range []string{"decision", "reason", "stopReason"} {
		if _, ok := got[k]; ok {
			t.Errorf("PreToolUse block must not carry deprecated %q: %s", k, encoded)
		}
	}
	hso, ok := got["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing hookSpecificOutput: %s", encoded)
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName: %v", hso["hookEventName"])
	}
	if hso["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision: %v", hso["permissionDecision"])
	}
	if hso["permissionDecisionReason"] != "Blocked by your organization's administrator." {
		t.Errorf("permissionDecisionReason: %v", hso["permissionDecisionReason"])
	}
}

func TestDecideResponseDefaultBlockMessage(t *testing.T) {
	// The user-visible deny string is "Blocked by your organization's
	// administrator." When the runtime passes a Decision with empty
	// UserMessage, the adapter must substitute this literal verbatim.
	a := New(t.TempDir(), testBinary)
	ev := &event.Event{HookEvent: event.HookPreToolUse}
	resp := a.DecideResponse(ev, adapter.Decision{Allow: false})
	encoded, _ := json.Marshal(resp)
	if !strings.Contains(string(encoded), "Blocked by your organization's administrator.") {
		t.Errorf("default deny message missing/changed: %s", encoded)
	}
}

func TestDecideResponseNonPreToolUseBlockNeverHalts(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	for _, ht := range []event.HookEvent{
		event.HookPostToolUse, event.HookSessionStart, event.HookSessionEnd,
		event.HookNotification, event.HookStop, event.HookSubagentStop,
		event.HookUserPrompt, event.HookPostToolUseFailure,
	} {
		resp := a.DecideResponse(&event.Event{HookEvent: ht}, adapter.Decision{Allow: false, UserMessage: "x"})
		encoded, _ := json.Marshal(resp)
		var got map[string]any
		_ = json.Unmarshal(encoded, &got)
		if v, ok := got["continue"]; ok && v == false {
			t.Errorf("hook %s: stray block must not emit continue:false: %s", ht, encoded)
		}
		if _, ok := got["hookSpecificOutput"]; ok {
			t.Errorf("hook %s: stray block must not synthesize hookSpecificOutput: %s", ht, encoded)
		}
	}
}

func TestDecideResponseNilEventAllows(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	resp := a.DecideResponse(nil, adapter.Decision{Allow: false, UserMessage: "should be ignored"})
	encoded, _ := json.Marshal(resp)
	if string(encoded) != `{"continue":true,"suppressOutput":true}` {
		t.Errorf("nil ev must allow, got %s", encoded)
	}
}

func TestInstallWiresPermissionHooks(t *testing.T) {
	home := t.TempDir()
	a := New(home, testBinary)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(settingsPath(home))
	for _, want := range []string{`"PermissionRequest"`, `"PermissionDenied"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("settings.json missing %s key: %s", want, b)
		}
	}
}

func TestInstallWiresElicitationHooks(t *testing.T) {
	home := t.TempDir()
	a := New(home, testBinary)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(settingsPath(home))
	for _, want := range []string{`"Elicitation"`, `"ElicitationResult"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("settings.json missing %s key: %s", want, b)
		}
	}
}

func TestInstallWiresPostToolUseFailure(t *testing.T) {
	home := t.TempDir()
	a := New(home, testBinary)
	res, err := a.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.HooksAdded, event.HookPostToolUseFailure) {
		t.Errorf("expected PostToolUseFailure in HooksAdded: %+v", res.HooksAdded)
	}
	b, _ := os.ReadFile(settingsPath(home))
	if !strings.Contains(string(b), `"PostToolUseFailure"`) {
		t.Errorf("settings.json missing PostToolUseFailure key: %s", b)
	}
}

// TestInstallCreatesParentDirWhenAbsent asserts that Install can run
// against a fresh home without ~/.claude/ existing — the atomicfile
// layer creates parent dirs and reports them in CreatedDirs so the
// install handler can chown them under root.
func TestInstallCreatesParentDirWhenAbsent(t *testing.T) {
	home := t.TempDir()
	a := New(home, testBinary)
	res, err := a.Install(context.Background())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".claude")); statErr != nil {
		t.Errorf("~/.claude/ not created: %v", statErr)
	}
	if _, statErr := os.Stat(settingsPath(home)); statErr != nil {
		t.Errorf("settings.json not created: %v", statErr)
	}
	// CreatedDirs must include ~/.claude so the install handler can
	// chown it under root.
	wantDir := filepath.Join(home, ".claude")
	if !slices.Contains(res.CreatedDirs, wantDir) {
		t.Errorf("CreatedDirs missing %q: got %v", wantDir, res.CreatedDirs)
	}
}
