package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// testBinary is the absolute DMG binary path tests pass to New(). The
// uninstall matcher (managedCmdRE) is path-token-agnostic, so the
// specific value just needs to satisfy
// `(^|/)stepsecurity-dev-machine-guard\s+_hook\s+`.
const testBinary = "/usr/local/bin/stepsecurity-dev-machine-guard"

// commandFor renders the canonical command string the adapter writes
// into hook entries for testBinary. Tests use this to assert exact
// command values without duplicating the format.
func commandFor(hookEvent event.HookEvent) string {
	return testBinary + " _hook codex " + string(hookEvent)
}

// newCodexHome returns (adapter, home, hooksPath, configPath). Files
// are NOT pre-created — callers that need pre-existing files use
// writeFile.
func newCodexHome(t *testing.T) (*Adapter, string, string, string) {
	t.Helper()
	home := t.TempDir()
	a := New(home, testBinary)
	codexDir := filepath.Join(home, ".codex")
	return a, home, filepath.Join(codexDir, "hooks.json"), filepath.Join(codexDir, "config.toml")
}

// withCodexFiles pre-creates ~/.codex/{hooks.json,config.toml} with
// the given bodies. Empty bodies skip that file.
func withCodexFiles(t *testing.T, hooksBody, cfgBody string) (*Adapter, string, string, string) {
	t.Helper()
	a, home, hooks, cfg := newCodexHome(t)
	if hooksBody != "" || cfgBody != "" {
		if err := os.MkdirAll(filepath.Dir(hooks), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if hooksBody != "" {
		writeFile(t, hooks, hooksBody)
	}
	if cfgBody != "" {
		writeFile(t, cfg, cfgBody)
	}
	return a, home, hooks, cfg
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("hooks.json not valid JSON: %v: %s", err, b)
	}
	return m
}

func readTOML(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := toml.Unmarshal(b, &m); err != nil {
		t.Fatalf("config.toml not valid TOML: %v: %s", err, b)
	}
	return m
}

func TestNameAndManagedFiles(t *testing.T) {
	a, home, hooks, cfg := newCodexHome(t)
	if a.Name() != "codex" {
		t.Errorf("Name=%q", a.Name())
	}
	mfs := a.ManagedFiles()
	if len(mfs) != 2 {
		t.Fatalf("ManagedFiles len=%d", len(mfs))
	}
	if mfs[0].Path != hooks || mfs[1].Path != cfg {
		t.Errorf("ManagedFiles paths: %+v (home=%s)", mfs, home)
	}
}

func TestSupportedHooksReturnsCopy(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	first := a.SupportedHooks()
	if len(first) != 6 {
		t.Fatalf("expected 6 hooks, got %d", len(first))
	}
	first[0] = "Mutated"
	second := a.SupportedHooks()
	if second[0] != HookSessionStart {
		t.Errorf("returned slice not a copy: %v", second)
	}
}

func TestDetectReportsPathFromExecutor(t *testing.T) {
	a := New(t.TempDir(), testBinary)

	mock := executor.NewMock()
	res, err := a.Detect(context.Background(), mock)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Detected {
		t.Errorf("expected Detected=false when codex not on $PATH")
	}

	mock.SetPath("codex", "/usr/local/bin/codex")
	res, err = a.Detect(context.Background(), mock)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Detected {
		t.Errorf("expected Detected=true when codex on $PATH")
	}
	if res.BinaryPath != "/usr/local/bin/codex" {
		t.Errorf("BinaryPath = %q, want /usr/local/bin/codex", res.BinaryPath)
	}
}

// ---------- DecideResponse ----------

func TestDecideResponseAllowEmptyObject(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	for _, ht := range supportedHookEvents {
		ev := &event.Event{HookEvent: ht, HookPhase: phaseFor(ht)}
		resp := a.DecideResponse(ev, adapter.AllowDecision())
		encoded, _ := json.Marshal(resp)
		if string(encoded) != `{}` {
			t.Errorf("hook %s: allow shape: %s", ht, encoded)
		}
	}
}

func TestDecideResponsePreToolUseDenyShape(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	ev := &event.Event{HookEvent: HookPreToolUse, HookPhase: event.HookPhasePreTool}
	resp := a.DecideResponse(ev, adapter.Decision{Allow: false, UserMessage: "Blocked by your organization's administrator."})
	encoded, _ := json.Marshal(resp)
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
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
		t.Errorf("reason: %v", hso["permissionDecisionReason"])
	}
	for _, banned := range []string{"continue", "stopReason", "suppressOutput", "updatedInput", "updatedPermissions", "interrupt", "decision", "additionalContext"} {
		if _, ok := got[banned]; ok {
			t.Errorf("must not emit %q: %s", banned, encoded)
		}
	}
}

func TestDecideResponseDefaultBlockMessage(t *testing.T) {
	// The user-visible deny string is "Blocked by your organization's
	// administrator." When the runtime passes a Decision with empty
	// UserMessage, the adapter must substitute this literal verbatim.
	a := New(t.TempDir(), testBinary)
	ev := &event.Event{HookEvent: HookPreToolUse, HookPhase: event.HookPhasePreTool}
	resp := a.DecideResponse(ev, adapter.Decision{Allow: false})
	encoded, _ := json.Marshal(resp)
	if !strings.Contains(string(encoded), "Blocked by your organization's administrator.") {
		t.Errorf("default deny message missing/changed: %s", encoded)
	}
}

func TestDecideResponseNonPreToolUseBlockReturnsEmpty(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	for _, ht := range []event.HookEvent{HookPostToolUse, HookSessionStart, HookPermissionRequest, HookUserPromptSubmit, HookStop} {
		ev := &event.Event{HookEvent: ht, HookPhase: phaseFor(ht)}
		resp := a.DecideResponse(ev, adapter.Decision{Allow: false, UserMessage: "x"})
		encoded, _ := json.Marshal(resp)
		if string(encoded) != `{}` {
			t.Errorf("hook %s: stray block must produce {}, got %s", ht, encoded)
		}
	}
}

func TestDecideResponseNilEventEmpty(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	resp := a.DecideResponse(nil, adapter.Decision{Allow: false, UserMessage: "ignored"})
	encoded, _ := json.Marshal(resp)
	if string(encoded) != `{}` {
		t.Errorf("nil event: %s", encoded)
	}
}

// ---------- ParseEvent ----------

func parse(t *testing.T, hook event.HookEvent, body string) *event.Event {
	t.Helper()
	a := New(t.TempDir(), testBinary)
	ev, err := a.ParseEvent(context.Background(), hook, []byte(body))
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	return ev
}

func TestParseSessionStartKeepsSource(t *testing.T) {
	ev := parse(t, HookSessionStart, `{"session_id":"s","source":"startup","cwd":"/tmp"}`)
	if ev.HookPhase != event.HookPhaseSessionStart {
		t.Errorf("phase: %s", ev.HookPhase)
	}
	if ev.ActionType != "" {
		t.Errorf("action_type must be empty, got %q", ev.ActionType)
	}
	if ev.Payload["source"] != "startup" {
		t.Errorf("source not preserved: %v", ev.Payload)
	}
}

func TestParseRecordsHookEventNameMismatch(t *testing.T) {
	ev := parse(t, HookSessionStart, `{"hook_event_name":"PreToolUse"}`)
	if ev.HookEvent != HookSessionStart {
		t.Errorf("HookEvent should follow CLI arg, got %q", ev.HookEvent)
	}
	if len(ev.Errors) != 1 || ev.Errors[0].Code != "hook_event_name_mismatch" {
		t.Errorf("expected mismatch error, got %+v", ev.Errors)
	}
}

func TestParsePreToolUseBashClassifies(t *testing.T) {
	ev := parse(t, HookPreToolUse, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"echo hi","cwd":"/tmp"}
	}`)
	if ev.HookPhase != event.HookPhasePreTool {
		t.Errorf("phase: %s", ev.HookPhase)
	}
	if ev.ActionType != event.ActionCommandExec {
		t.Errorf("action: %s", ev.ActionType)
	}
	a := New(t.TempDir(), testBinary)
	cmd, cwd, ok := a.ShellCommand(ev)
	if !ok || cmd == "" || cwd == "" {
		t.Errorf("shell extraction failed: cmd=%q cwd=%q ok=%v", cmd, cwd, ok)
	}
}

func TestParsePreToolUseBashRedactsSecrets(t *testing.T) {
	ev := parse(t, HookPreToolUse, `{"tool_name":"Bash","tool_input":{"command":"GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa make deploy"}}`)
	encoded, _ := json.Marshal(ev)
	if strings.Contains(string(encoded), "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Errorf("secret leaked: %s", encoded)
	}
}

func TestParsePreToolUseApplyPatchIsFileWriteNotShell(t *testing.T) {
	ev := parse(t, HookPreToolUse, `{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch ***"}}`)
	if ev.ActionType != event.ActionFileWrite {
		t.Errorf("action: %s", ev.ActionType)
	}
	a := New(t.TempDir(), testBinary)
	if _, _, ok := a.ShellCommand(ev); ok {
		t.Errorf("apply_patch must not be treated as shell")
	}
}

func TestParsePreToolUseMCPClassifies(t *testing.T) {
	ev := parse(t, HookPreToolUse, `{"tool_name":"mcp__filesystem__read_file","tool_input":{"path":"/tmp"}}`)
	if ev.ActionType != event.ActionMCPInvocation {
		t.Errorf("action: %s", ev.ActionType)
	}
}

func TestParsePermissionRequestNoActionType(t *testing.T) {
	ev := parse(t, HookPermissionRequest, `{"tool_name":"Bash","tool_input":{"command":"rm -rf /","description":"delete world"}}`)
	if ev.HookPhase != event.HookPhasePermissionRequest {
		t.Errorf("phase: %s", ev.HookPhase)
	}
	if ev.ActionType != "" {
		t.Errorf("action_type must be empty, got %q", ev.ActionType)
	}
	ti := ev.Payload["tool_input"].(map[string]any)
	if ti["description"] != "delete world" {
		t.Errorf("description not preserved: %v", ti)
	}
}

func TestParsePostToolUseSuccess(t *testing.T) {
	ev := parse(t, HookPostToolUse, `{"tool_name":"Bash","tool_input":{"command":"echo hi"},"tool_response":"hi"}`)
	if ev.ResultStatus != event.ResultSuccess {
		t.Errorf("result_status: %s", ev.ResultStatus)
	}
	if ev.Payload["tool_response"] != "hi" {
		t.Errorf("tool_response not preserved: %v", ev.Payload)
	}
}

func TestParseUserPromptKeepsRedactedPrompt(t *testing.T) {
	ev := parse(t, HookUserPromptSubmit, `{"prompt":"deploy with GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	encoded, _ := json.Marshal(ev)
	got := string(encoded)
	if strings.Contains(got, "prompt_present") {
		t.Errorf("prompt must be preserved, not stub: %s", got)
	}
	if strings.Contains(got, "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Errorf("secret in prompt leaked: %s", got)
	}
	if !strings.Contains(ev.Payload["prompt"].(string), "deploy") {
		t.Errorf("prompt text lost: %v", ev.Payload["prompt"])
	}
}

func TestParseStopScrubsLastAssistantMessage(t *testing.T) {
	ev := parse(t, HookStop, `{"last_assistant_message":"hello world"}`)
	encoded, _ := json.Marshal(ev)
	got := string(encoded)
	if strings.Contains(got, "hello world") {
		t.Errorf("last_assistant_message leaked: %s", got)
	}
	if !strings.Contains(got, `"last_assistant_message_present":true`) {
		t.Errorf("expected presence marker: %s", got)
	}
}

func TestParseInvalidJSONReturnsError(t *testing.T) {
	a := New(t.TempDir(), testBinary)
	_, err := a.ParseEvent(context.Background(), HookPreToolUse, []byte(`{not json`))
	if err == nil {
		t.Error("expected error on invalid JSON")
	}
}

func TestParseAgentNameIsCodex(t *testing.T) {
	ev := parse(t, HookSessionStart, `{}`)
	if ev.AgentName != "codex" {
		t.Errorf("AgentName: %s", ev.AgentName)
	}
}

func TestParsePopulatesCommonFields(t *testing.T) {
	ev := parse(t, HookPreToolUse, `{
		"session_id":"sess",
		"cwd":"/tmp",
		"permission_mode":"default",
		"tool_name":"Bash",
		"tool_use_id":"tu_1",
		"tool_input":{"command":"echo"}
	}`)
	if ev.SessionID != "sess" || ev.WorkingDirectory != "/tmp" || ev.PermissionMode != "default" || ev.ToolName != "Bash" || ev.ToolUseID != "tu_1" {
		t.Errorf("fields: %+v", ev)
	}
}

func TestPhaseForUnknown(t *testing.T) {
	if phaseFor("Bogus") != event.HookPhaseUnknown {
		t.Errorf("phaseFor unknown: %s", phaseFor("Bogus"))
	}
}

// ---------- Install ----------

func TestInstallCreatesHooksAndFeatureFlag(t *testing.T) {
	a, _, hooks, cfg := newCodexHome(t)
	res, err := a.Install(context.Background())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(res.HooksAdded) != len(supportedHookEvents) {
		t.Errorf("expected all hooks added, got %v", res.HooksAdded)
	}
	got := readJSON(t, hooks)
	hooksMap, ok := got["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks key missing: %v", got)
	}
	for _, ht := range supportedHookEvents {
		if _, ok := hooksMap[string(ht)]; !ok {
			t.Errorf("hook %s missing from output: %v", ht, hooksMap)
		}
	}
	pre := hooksMap["PreToolUse"].([]any)[0].(map[string]any)
	if pre["matcher"] != "*" {
		t.Errorf("PreToolUse matcher: %v", pre["matcher"])
	}
	innerPre := pre["hooks"].([]any)[0].(map[string]any)
	if innerPre["command"] != commandFor(HookPreToolUse) {
		t.Errorf("PreToolUse command: %v (want %s)", innerPre["command"], commandFor(HookPreToolUse))
	}
	if innerPre["timeout"].(float64) != 30 {
		t.Errorf("PreToolUse timeout: %v", innerPre["timeout"])
	}
	// SessionStart matcher is the literal startup|resume|clear.
	ss := hooksMap["SessionStart"].([]any)[0].(map[string]any)
	if ss["matcher"] != "startup|resume|clear" {
		t.Errorf("SessionStart matcher: %v", ss["matcher"])
	}
	// UserPromptSubmit and Stop omit matcher.
	ups := hooksMap["UserPromptSubmit"].([]any)[0].(map[string]any)
	if _, has := ups["matcher"]; has {
		t.Errorf("UserPromptSubmit must omit matcher: %v", ups)
	}
	stop := hooksMap["Stop"].([]any)[0].(map[string]any)
	if _, has := stop["matcher"]; has {
		t.Errorf("Stop must omit matcher: %v", stop)
	}

	// Feature flag.
	cfgMap := readTOML(t, cfg)
	features, ok := cfgMap["features"].(map[string]any)
	if !ok {
		t.Fatalf("features table missing: %v", cfgMap)
	}
	if features["codex_hooks"] != true {
		t.Errorf("codex_hooks not true: %v", features)
	}

	// InstallResult tracks both files written under root chown.
	if !slices.Contains(res.WrittenFiles, hooks) {
		t.Errorf("WrittenFiles missing hooks.json: %v", res.WrittenFiles)
	}
	if !slices.Contains(res.WrittenFiles, cfg) {
		t.Errorf("WrittenFiles missing config.toml: %v", res.WrittenFiles)
	}
}

func TestInstallPreservesUnrelatedHooksAndConfig(t *testing.T) {
	a, _, hooks, cfg := withCodexFiles(t,
		`{
			"hooks": {
				"PreToolUse": [
					{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo user"}]}
				],
				"PluginEvent": [
					{"matcher": "*", "hooks": [{"type": "command", "command": "echo plugin"}]}
				]
			}
		}`,
		`model = "gpt-5"
[features]
other_flag = true
`)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := readJSON(t, hooks)
	hooksMap := got["hooks"].(map[string]any)
	pre := hooksMap["PreToolUse"].([]any)
	commands := []string{}
	for _, raw := range pre {
		group := raw.(map[string]any)
		for _, h := range group["hooks"].([]any) {
			hm := h.(map[string]any)
			commands = append(commands, hm["command"].(string))
		}
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "echo user") {
		t.Errorf("user PreToolUse hook lost; got %q", joined)
	}
	if !strings.Contains(joined, commandFor(HookPreToolUse)) {
		t.Errorf("DMG PreToolUse hook missing; got %q", joined)
	}
	if _, ok := hooksMap["PluginEvent"]; !ok {
		t.Error("unrelated PluginEvent removed")
	}

	cfgMap := readTOML(t, cfg)
	if cfgMap["model"] != "gpt-5" {
		t.Errorf("unrelated config key lost: %v", cfgMap)
	}
	features := cfgMap["features"].(map[string]any)
	if features["other_flag"] != true {
		t.Errorf("unrelated features key lost: %v", features)
	}
	if features["codex_hooks"] != true {
		t.Errorf("codex_hooks not enabled: %v", features)
	}
}

func TestInstallIdempotent(t *testing.T) {
	a, _, hooks, _ := newCodexHome(t)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := readJSON(t, hooks)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := readJSON(t, hooks)
	firstBytes, _ := json.Marshal(first)
	secondBytes, _ := json.Marshal(second)
	if string(firstBytes) != string(secondBytes) {
		t.Errorf("install not idempotent:\n  first  %s\n  second %s", firstBytes, secondBytes)
	}
}

func TestInstallOnMalformedTOMLFails(t *testing.T) {
	a, _, _, _ := withCodexFiles(t, "", `[features
broken`)
	if _, err := a.Install(context.Background()); err == nil {
		t.Fatal("expected install error on malformed TOML")
	}
}

// TestInstallMalformedTOMLDoesNotMutateHooks asserts the multi-file
// safety invariant: a malformed config.toml must abort install BEFORE
// hooks.json is touched. Otherwise an install can leave hooks.json
// mutated while config.toml stays broken — a forbidden partial-write
// state.
func TestInstallMalformedTOMLDoesNotMutateHooks(t *testing.T) {
	a, _, hooks, _ := withCodexFiles(t,
		`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo user"}]}]}}`,
		`[features
broken`)
	original, err := os.ReadFile(hooks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Install(context.Background()); err == nil {
		t.Fatal("expected install error on malformed TOML")
	}
	got, _ := os.ReadFile(hooks)
	if string(got) != string(original) {
		t.Errorf("hooks.json must not be mutated when config.toml fails:\n  pre  %s\n  post %s", original, got)
	}
	matches, _ := filepath.Glob(hooks + ".dmg-backup.*")
	if len(matches) > 0 {
		t.Errorf("hooks.json backup should not exist on aborted install: %v", matches)
	}
}

// TestInstallMovesManagedEntryFromStaleMatcher: a pre-existing managed
// entry under the wrong matcher (e.g. PreToolUse pinned to `Bash`)
// silently narrows audit coverage. Install must move it to the desired
// matcher.
func TestInstallMovesManagedEntryFromStaleMatcher(t *testing.T) {
	staleBody := `{
		"hooks": {
			"PreToolUse": [
				{"matcher":"Bash","hooks":[
					{"type":"command","command":"` + commandFor(HookPreToolUse) + `","timeout":30,"statusMessage":"old"}
				]}
			]
		}
	}`
	a, _, hooks, _ := withCodexFiles(t, staleBody, "")
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := readJSON(t, hooks)
	pre := got["hooks"].(map[string]any)["PreToolUse"].([]any)
	for _, raw := range pre {
		group := raw.(map[string]any)
		matcher, _ := group["matcher"].(string)
		for _, h := range group["hooks"].([]any) {
			hm := h.(map[string]any)
			cmd, _ := hm["command"].(string)
			if isManagedCommand(cmd) && matcher != "*" {
				t.Errorf("managed entry remained under stale matcher %q: %+v", matcher, group)
			}
		}
	}
}

// TestInstallRefreshesStaleBinaryPath asserts the binary-move
// self-heal: when hooks.json contains a managed entry pointing at an
// old absolute path, a fresh install rewrites the command in-place.
// Without this, `brew upgrade` (which relocates the binary in the
// Cellar) would silently break hooks.
func TestInstallRefreshesStaleBinaryPath(t *testing.T) {
	stalePath := "/old/path/stepsecurity-dev-machine-guard"
	body := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + stalePath + ` _hook codex PreToolUse","timeout":30,"statusMessage":"old"}]}]}}`
	a, _, hooks, _ := withCodexFiles(t, body, "")
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(hooks)
	if strings.Contains(string(out), stalePath) {
		t.Errorf("stale binary path not refreshed: %s", out)
	}
	if !strings.Contains(string(out), testBinary) {
		t.Errorf("new binary path not written: %s", out)
	}
}

// rootKeyOrder returns the top-level JSON object keys of path in
// source order.
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

func TestInstallPreservesHooksJSONKeyOrder(t *testing.T) {
	a, _, hooks, _ := withCodexFiles(t, `{
		"z": "last",
		"hooks": {
			"PreToolUse": [
				{"matcher": "Bash", "hooks": [{"timeout": 5, "type": "command", "command": "echo user"}]}
			]
		},
		"a": "first"
	}`, "")
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := rootKeyOrder(t, hooks), []string{"z", "hooks", "a"}; !slices.Equal(got, want) {
		t.Errorf("root key order: got %v, want %v", got, want)
	}
	b, _ := os.ReadFile(hooks)
	out := string(b)
	userIdx := strings.Index(out, `"echo user"`)
	if userIdx < 0 {
		t.Fatalf("user hook not found in output: %s", out)
	}
	entryStart := strings.LastIndex(out[:userIdx], "{")
	entryEnd := strings.Index(out[userIdx:], "}")
	entry := out[entryStart : userIdx+entryEnd+1]
	tIdx := strings.Index(entry, `"timeout"`)
	yIdx := strings.Index(entry, `"type"`)
	cIdx := strings.Index(entry, `"command"`)
	if !(tIdx >= 0 && tIdx < yIdx && yIdx < cIdx) {
		t.Errorf("user hook key order lost; entry: %s", entry)
	}
}

func TestInstallPreservesConfigTOMLBytes(t *testing.T) {
	a, _, _, cfg := withCodexFiles(t, "", `# user header comment
model = "gpt-5"

[features]
sandbox = "workspace-write"

[telemetry]
enabled = true
`)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cfg)
	s := string(got)
	for _, want := range []string{
		"# user header comment",
		`model = "gpt-5"`,
		`sandbox = "workspace-write"`,
		"[telemetry]",
		"enabled = true",
		"codex_hooks = true",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q in output; got: %s", want, s)
		}
	}
	// Order: telemetry must still come AFTER features (which now contains codex_hooks).
	featIdx := strings.Index(s, "[features]")
	telIdx := strings.Index(s, "[telemetry]")
	chIdx := strings.Index(s, "codex_hooks")
	if !(featIdx < chIdx && chIdx < telIdx) {
		t.Errorf("table order disturbed: %s", s)
	}
}

// TestInstallSecondInstallIsByteStableNoOp: the codex hooks.json
// install path skips backup + write entirely when the file is already
// in desired state.
func TestInstallSecondInstallIsByteStableNoOp(t *testing.T) {
	a, _, hooks, _ := newCodexHome(t)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(hooks)
	matches, _ := filepath.Glob(hooks + ".dmg-backup.*")
	beforeBackups := len(matches)
	res, err := a.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(hooks)
	if !bytes.Equal(before, after) {
		t.Errorf("idempotent install rewrote hooks.json")
	}
	matches, _ = filepath.Glob(hooks + ".dmg-backup.*")
	if len(matches) != beforeBackups {
		t.Errorf("idempotent install created a new backup: %v", matches)
	}
	if slices.Contains(res.WrittenFiles, hooks) {
		t.Errorf("expected hooks.json absent from WrittenFiles on no-op install, got %v", res.WrittenFiles)
	}
}

func TestInstallNoOpDoesNotRewriteConfigTOML(t *testing.T) {
	a, _, _, cfg := withCodexFiles(t, "", `[features]
codex_hooks = true
sandbox = "workspace-write"
`)
	original, _ := os.ReadFile(cfg)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cfg)
	if string(got) != string(original) {
		t.Errorf("config.toml byte-mutated despite already-enabled flag:\n  pre  %s\n  post %s", original, got)
	}
	matches, _ := filepath.Glob(cfg + ".dmg-backup.*")
	if len(matches) > 0 {
		t.Errorf("unexpected backup created: %v", matches)
	}
}

// TestInstallCreatesParentDirWhenAbsent asserts that Install can run
// against a fresh home without ~/.codex/ existing — the atomicfile
// layer creates parent dirs and reports them in CreatedDirs so the
// install handler can chown them under root.
func TestInstallCreatesParentDirWhenAbsent(t *testing.T) {
	a, home, _, _ := newCodexHome(t)
	res, err := a.Install(context.Background())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	codexDir := filepath.Join(home, ".codex")
	if _, statErr := os.Stat(codexDir); statErr != nil {
		t.Errorf("~/.codex/ not created: %v", statErr)
	}
	if !slices.Contains(res.CreatedDirs, codexDir) {
		t.Errorf("CreatedDirs missing %q: got %v", codexDir, res.CreatedDirs)
	}
}

// ---------- Uninstall ----------

func TestUninstallLeavesUnrelatedHooks(t *testing.T) {
	body := `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "*", "hooks": [
					{"type": "command", "command": "stepsecurity-dev-machine-guardctl status"},
					{"type": "command", "command": "/usr/local/bin/other-tool _hook claude-code PreToolUse"},
					{"type": "command", "command": "legacy-tool _hook codex PreToolUse"},
					{"type": "command", "command": "echo user"}
				]}
			]
		}
	}`
	a, _, hooks, _ := withCodexFiles(t, body, "")
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := a.Uninstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.HooksRemoved) == 0 {
		t.Fatal("expected at least one hook removed")
	}
	got := readJSON(t, hooks)
	hooksMap, _ := got["hooks"].(map[string]any)
	if hooksMap == nil {
		t.Fatal("hooks key removed despite remaining user entries")
	}
	pre := hooksMap["PreToolUse"].([]any)
	survivors := []string{}
	for _, raw := range pre {
		group := raw.(map[string]any)
		for _, h := range group["hooks"].([]any) {
			hm := h.(map[string]any)
			cmd := hm["command"].(string)
			survivors = append(survivors, cmd)
			if isManagedCommand(cmd) {
				t.Errorf("managed command survived uninstall: %q", cmd)
			}
		}
	}
	for _, want := range []string{
		"stepsecurity-dev-machine-guardctl status",
		"/usr/local/bin/other-tool _hook claude-code PreToolUse",
		"legacy-tool _hook codex PreToolUse",
		"echo user",
	} {
		if !slices.Contains(survivors, want) {
			t.Errorf("user/lookalike hook %q removed; survivors=%v", want, survivors)
		}
	}
	noteSeen := false
	for _, n := range res.Notes {
		if strings.Contains(n, "feature flag") {
			noteSeen = true
		}
	}
	if !noteSeen {
		t.Errorf("expected feature-flag note: %v", res.Notes)
	}
}

// TestUninstallPreservesUserHookAfterManagedEntry covers the
// array-shift bug fixed by the gjson/sjson refactor — the previous
// span-based renderer matched array elements by index, so removing
// the managed entry at index 0 could overwrite the user entry that
// shifted into index 0.
func TestUninstallPreservesUserHookAfterManagedEntry(t *testing.T) {
	body := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + commandFor(HookPreToolUse) + `","timeout":30,"statusMessage":"dev-machine-guard: checking tool use"},{"timeout":5,"type":"command","command":"echo user"}]}]}}`
	a, _, hooks, _ := withCodexFiles(t, body, "")
	if _, err := a.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(hooks)
	if !strings.Contains(string(out), `"command": "echo user"`) {
		t.Fatalf("user hook after managed entry was lost: %s", out)
	}
	if isManagedCommand(string(out)) && strings.Contains(string(out), commandFor(HookPreToolUse)) {
		t.Fatalf("managed entry survived uninstall: %s", out)
	}
}

func TestUninstallPreservesHooksJSONUserKeyOrder(t *testing.T) {
	a, _, hooks, _ := withCodexFiles(t, `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "Bash", "hooks": [{"timeout": 5, "type": "command", "command": "echo user"}]}
			]
		}
	}`, "")
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(hooks)
	out := string(b)
	if !strings.Contains(out, "echo user") {
		t.Fatalf("user hook lost on uninstall: %s", out)
	}
	userIdx := strings.Index(out, `"echo user"`)
	entryStart := strings.LastIndex(out[:userIdx], "{")
	entryEnd := strings.Index(out[userIdx:], "}")
	entry := out[entryStart : userIdx+entryEnd+1]
	tIdx := strings.Index(entry, `"timeout"`)
	yIdx := strings.Index(entry, `"type"`)
	cIdx := strings.Index(entry, `"command"`)
	if !(tIdx >= 0 && tIdx < yIdx && yIdx < cIdx) {
		t.Errorf("user hook key order lost on uninstall; entry: %s", entry)
	}
}

func TestUninstallLeavesFeatureFlagEnabled(t *testing.T) {
	// Uninstall must NOT revert `[features].codex_hooks = true`. Other
	// tools may have wired up their own hooks that depend on it being on.
	a, _, _, cfg := newCodexHome(t)
	if _, err := a.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfgMap := readTOML(t, cfg)
	features, ok := cfgMap["features"].(map[string]any)
	if !ok {
		t.Fatalf("features table missing after uninstall: %v", cfgMap)
	}
	if features["codex_hooks"] != true {
		t.Errorf("codex_hooks was reverted on uninstall: %v", features)
	}
}
