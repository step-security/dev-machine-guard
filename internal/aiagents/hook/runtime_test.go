package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	cc "github.com/step-security/dev-machine-guard/internal/aiagents/adapter/claudecode"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// captured holds the events the runtime hands to UploadEvent during a
// test. UploadEvent is the single test seam for inspecting the
// constructed event.
type captured struct {
	mu     sync.Mutex
	events []event.Event
	errs   []errLogEntry
}

type errLogEntry struct {
	Stage, Code, Message, EventID string
}

func (c *captured) capture() func(context.Context, event.Event) error {
	return func(_ context.Context, ev event.Event) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.events = append(c.events, ev)
		return nil
	}
}

func (c *captured) logError() func(stage, code, message, eventID string) {
	return func(stage, code, message, eventID string) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.errs = append(c.errs, errLogEntry{stage, code, message, eventID})
	}
}

func newRuntime(t *testing.T, stdin io.Reader, stdout, stderr io.Writer) (*Runtime, *captured) {
	t.Helper()
	cap := &captured{}
	rt := &Runtime{
		Adapter:     cc.New(t.TempDir(), "/usr/local/bin/stepsecurity-dev-machine-guard"),
		Exec:        executor.NewMock(),
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
		Now:         func() time.Time { return time.Now().UTC() },
		UploadEvent: cap.capture(),
		LogError:    cap.logError(),
	}
	return rt, cap
}

func TestRunHappyPathBashHook(t *testing.T) {
	stdin := strings.NewReader(`{
		"session_id":"abc",
		"cwd":"/tmp/work",
		"tool_name":"Bash",
		"tool_input":{"command":"npm install lodash","cwd":"/tmp/work"}
	}`)
	var stdout, stderr bytes.Buffer
	rt, cap := newRuntime(t, stdin, &stdout, &stderr)

	if err := rt.Run(context.Background(), event.HookPreToolUse); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// stdout MUST be a Claude-compatible allow response.
	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
		t.Fatalf("stdout not JSON: %v: %q", err, stdout.Bytes())
	}
	if resp["continue"] != true {
		t.Errorf("expected continue=true, got %v", resp["continue"])
	}

	if len(cap.events) != 1 {
		t.Fatalf("expected 1 uploaded event, got %d", len(cap.events))
	}
	ev := cap.events[0]
	if ev.HookEvent != event.HookPreToolUse {
		t.Errorf("hook_event: %v", ev.HookEvent)
	}
	if ev.ActionType != event.ActionCommandExec {
		t.Errorf("action_type: %v", ev.ActionType)
	}
	if ev.Classifications == nil || !ev.Classifications.IsShellCommand {
		t.Errorf("expected is_shell_command classification: %+v", ev.Classifications)
	}
	if !ev.Classifications.IsPackageManager {
		t.Errorf("expected is_package_manager classification: %+v", ev.Classifications)
	}
}

func TestRunMalformedPayloadReturnsAllow(t *testing.T) {
	stdin := strings.NewReader(`{not valid json`)
	var stdout, stderr bytes.Buffer
	rt, cap := newRuntime(t, stdin, &stdout, &stderr)

	err := rt.Run(context.Background(), event.HookPreToolUse)
	if err == nil {
		t.Fatal("expected internal error on parse failure")
	}
	// Even on parse failure stdout must still be the allow response.
	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
		t.Fatalf("stdout not JSON: %v: %q", err, stdout.Bytes())
	}
	if resp["continue"] != true {
		t.Errorf("expected continue=true even on parse failure, got %v", resp)
	}
	// No event uploaded when ParseEvent fails — the runtime drops the
	// event and only logs the error to errors.jsonl.
	if len(cap.events) != 0 {
		t.Errorf("expected no upload on parse failure, got %d", len(cap.events))
	}
	// The error must surface through the logger seam.
	found := false
	for _, e := range cap.errs {
		if e.Stage == "parse" && e.Code == "parse_error" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected parse_error in error log, got %+v", cap.errs)
	}
}

func TestRunInputTooLargeReturnsAllow(t *testing.T) {
	big := bytes.Repeat([]byte("a"), int(MaxStdinBytes)+10)
	var stdout, stderr bytes.Buffer
	rt, cap := newRuntime(t, bytes.NewReader(big), &stdout, &stderr)

	err := rt.Run(context.Background(), event.HookPreToolUse)
	if !errors.Is(err, errInputTooLarge) {
		t.Fatalf("expected errInputTooLarge, got %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "{") {
		t.Errorf("stdout should be JSON allow response: %q", stdout.String())
	}
	// Oversize payload short-circuits before parse → no upload, errlog hit.
	if len(cap.events) != 0 {
		t.Errorf("expected no upload on input_too_large, got %d", len(cap.events))
	}
	found := false
	for _, e := range cap.errs {
		if e.Stage == "stdin" && e.Code == "input_too_large" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected input_too_large in error log, got %+v", cap.errs)
	}
}

// Direct mcp__ tool invocation flows through PreToolUse with
// action_type:"mcp_invocation" and is_mcp_related:true. No
// enrichments.mcp block — the server identity already lives in
// tool_name; backends split it at query time.
func TestRunMCPDirectToolInvocation(t *testing.T) {
	stdin := strings.NewReader(`{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"mcp__github__search",
		"tool_input":{"query":"hi"}
	}`)
	var stdout, stderr bytes.Buffer
	rt, cap := newRuntime(t, stdin, &stdout, &stderr)
	if err := rt.Run(context.Background(), event.HookPreToolUse); err != nil {
		t.Fatal(err)
	}
	if len(cap.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(cap.events))
	}
	ev := cap.events[0]
	if ev.ActionType != event.ActionMCPInvocation {
		t.Errorf("action_type: %v", ev.ActionType)
	}
	if ev.Classifications == nil || !ev.Classifications.IsMCPRelated {
		t.Errorf("expected is_mcp_related: %+v", ev.Classifications)
	}
	if ev.Enrichments != nil && ev.Enrichments.MCP != nil {
		t.Errorf("direct mcp__ tool calls must NOT carry enrichments.mcp: %+v", ev.Enrichments)
	}
}

// Shell-launched MCP keeps its shell context AND gets MCP enrichment.
// Both classifications must be set; the original shell command is
// preserved in enrichments.shell.command.
func TestRunMCPShellLaunchedKeepsShellContext(t *testing.T) {
	stdin := strings.NewReader(`{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"npx -y @modelcontextprotocol/server-filesystem /tmp"}
	}`)
	var stdout, stderr bytes.Buffer
	rt, cap := newRuntime(t, stdin, &stdout, &stderr)
	if err := rt.Run(context.Background(), event.HookPreToolUse); err != nil {
		t.Fatal(err)
	}
	ev := cap.events[0]
	if ev.ActionType != event.ActionCommandExec {
		t.Errorf("action_type: %v", ev.ActionType)
	}
	if ev.Classifications == nil || !ev.Classifications.IsShellCommand || !ev.Classifications.IsMCPRelated {
		t.Errorf("expected both shell+mcp classifications: %+v", ev.Classifications)
	}
	if ev.Enrichments == nil || ev.Enrichments.Shell == nil || ev.Enrichments.Shell.Command == "" {
		t.Errorf("shell enrichment missing: %+v", ev.Enrichments)
	}
	mcp := ev.Enrichments.MCP
	if mcp == nil || mcp.ServerName != "server-filesystem" || mcp.Kind != "local" {
		t.Errorf("mcp enrichment: %+v", mcp)
	}
	if mcp.ServerCommand == "" {
		t.Errorf("expected redacted server_command in mcp enrichment: %+v", mcp)
	}
}

// PermissionRequest / PermissionDenied carrying an mcp__<server>__<tool>
// tool_name must be flagged is_mcp_related so the audit pipeline
// captures permission prompts and auto-denials around MCP servers.
// They are not tool calls themselves, so action_type stays empty, and
// no enrichments.mcp block is emitted — server identity is already in
// tool_name.
func TestRunMCPPermissionEventClassifiedFromToolName(t *testing.T) {
	for _, ht := range []event.HookEvent{event.HookPermissionRequest, event.HookPermissionDenied} {
		t.Run(string(ht), func(t *testing.T) {
			stdin := strings.NewReader(`{
				"session_id":"s",
				"cwd":"/tmp",
				"tool_name":"mcp__github__search",
				"tool_input":{"query":"hi"}
			}`)
			var stdout, stderr bytes.Buffer
			rt, cap := newRuntime(t, stdin, &stdout, &stderr)
			if err := rt.Run(context.Background(), ht); err != nil {
				t.Fatal(err)
			}
			ev := cap.events[0]
			if ev.ActionType != "" {
				t.Errorf("%s must omit action_type: %v", ht, ev.ActionType)
			}
			if ev.Classifications == nil || !ev.Classifications.IsMCPRelated {
				t.Errorf("expected is_mcp_related: %+v", ev.Classifications)
			}
			if ev.Enrichments != nil && ev.Enrichments.MCP != nil {
				t.Errorf("permission events must NOT carry enrichments.mcp: %+v", ev.Enrichments)
			}
		})
	}
}

// Permission events for non-MCP tools must NOT set is_mcp_related.
func TestRunPermissionEventNonMCPNotFlagged(t *testing.T) {
	stdin := strings.NewReader(`{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"ls"}
	}`)
	var stdout, stderr bytes.Buffer
	rt, cap := newRuntime(t, stdin, &stdout, &stderr)
	if err := rt.Run(context.Background(), event.HookPermissionRequest); err != nil {
		t.Fatal(err)
	}
	ev := cap.events[0]
	if ev.Classifications != nil && ev.Classifications.IsMCPRelated {
		t.Errorf("Bash permission events must not be flagged MCP: %+v", ev.Classifications)
	}
}

// Elicitation hooks are inherently MCP. is_mcp_related is set from the
// hook event itself; no enrichments.mcp block is emitted — the payload
// already carries mcp_server_name.
func TestRunMCPElicitationFlaggedFromHookEvent(t *testing.T) {
	stdin := strings.NewReader(`{
		"session_id":"s",
		"cwd":"/tmp",
		"mcp_server_name":"github",
		"message":"approve"
	}`)
	var stdout, stderr bytes.Buffer
	rt, cap := newRuntime(t, stdin, &stdout, &stderr)
	if err := rt.Run(context.Background(), event.HookElicitation); err != nil {
		t.Fatal(err)
	}
	ev := cap.events[0]
	if ev.ActionType != "" {
		t.Errorf("Elicitation must omit action_type: %v", ev.ActionType)
	}
	if ev.Classifications == nil || !ev.Classifications.IsMCPRelated {
		t.Errorf("expected is_mcp_related from hook event: %+v", ev.Classifications)
	}
	if ev.Enrichments != nil && ev.Enrichments.MCP != nil {
		t.Errorf("elicitation events must NOT carry enrichments.mcp: %+v", ev.Enrichments)
	}
	if ev.Payload["mcp_server_name"] != "github" {
		t.Errorf("payload should preserve mcp_server_name: %v", ev.Payload)
	}
}

// Elicitation URLs go through the redactor only; user:pass@host
// userinfo and ?token= query params must be scrubbed in payload.url.
func TestRunMCPElicitationURLRedacted(t *testing.T) {
	stdin := strings.NewReader(`{
		"mcp_server_name":"github",
		"url":"https://user:secret@mcp.example.com:8443/auth?token=zzz"
	}`)
	var stdout, stderr bytes.Buffer
	rt, cap := newRuntime(t, stdin, &stdout, &stderr)
	if err := rt.Run(context.Background(), event.HookElicitation); err != nil {
		t.Fatal(err)
	}
	ev := cap.events[0]
	url, _ := ev.Payload["url"].(string)
	if strings.Contains(url, "secret") || strings.Contains(url, "user:") {
		t.Errorf("userinfo leaked into payload.url: %q", url)
	}
	if strings.Contains(url, "token=zzz") {
		t.Errorf("query token leaked into payload.url: %q", url)
	}
	if !strings.Contains(url, "mcp.example.com:8443") {
		t.Errorf("host should be preserved: %q", url)
	}
}

// Upload failure must be silently absorbed: the agent still gets the
// allow response; the upload error is recorded in the error log
// without leaking sensitive material from the message.
func TestRunUploadFailureFailsOpen(t *testing.T) {
	stdin := strings.NewReader(`{
		"session_id":"abc",
		"cwd":"/tmp/work",
		"tool_name":"Bash",
		"tool_input":{"command":"ls"}
	}`)
	var stdout, stderr bytes.Buffer
	cap := &captured{}
	rt := &Runtime{
		Adapter:  cc.New(t.TempDir(), "/usr/local/bin/stepsecurity-dev-machine-guard"),
		Exec:     executor.NewMock(),
		Stdin:    stdin,
		Stdout:   &stdout,
		Stderr:   &stderr,
		Now:      func() time.Time { return time.Now().UTC() },
		LogError: cap.logError(),
	}
	uploadCalled := 0
	rt.UploadEvent = func(ctx context.Context, ev event.Event) error {
		uploadCalled++
		return errors.New("backend down: connection refused")
	}

	if err := rt.Run(context.Background(), event.HookPreToolUse); err != nil {
		t.Fatalf("Run returned error on upload failure: %v", err)
	}
	if uploadCalled != 1 {
		t.Errorf("UploadEvent called %d times, want 1", uploadCalled)
	}

	// Agent response is still a valid allow.
	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
		t.Fatalf("stdout not JSON: %v: %q", err, stdout.Bytes())
	}
	if resp["continue"] != true {
		t.Errorf("expected continue=true on upload failure, got %v", resp)
	}

	// Error log must record the failure tagged with upload_error.
	found := false
	for _, e := range cap.errs {
		if e.Stage == "ingest" && e.Code == "upload_error" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected upload_error in error log, got %+v", cap.errs)
	}
}

// When no UploadEvent is wired (any runtime without enterprise config),
// the runtime must still complete — just with no upload attempt.
func TestRunSkipsUploadWithoutSeam(t *testing.T) {
	stdin := strings.NewReader(`{
		"session_id":"s","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}
	}`)
	var stdout, stderr bytes.Buffer
	rt := &Runtime{
		Adapter: cc.New(t.TempDir(), "/usr/local/bin/stepsecurity-dev-machine-guard"),
		Exec:    executor.NewMock(),
		Stdin:   stdin,
		Stdout:  &stdout,
		Stderr:  &stderr,
		Now:     func() time.Time { return time.Now().UTC() },
	}

	if err := rt.Run(context.Background(), event.HookPreToolUse); err != nil {
		t.Fatal(err)
	}
	// Stdout should still be the allow response.
	if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "{") {
		t.Errorf("stdout should be JSON allow response: %q", stdout.String())
	}
}
