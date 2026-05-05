package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aieventc "github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/config"
)

// withStubUploader replaces uploaderFactory with a capturing factory for
// the duration of the test. RunHook calls config.Load(), which mutates
// process-wide config globals from a developer's real
// ~/.stepsecurity/config.json — so we also snapshot-and-restore those
// globals to keep tests isolated from each other and from the host.
// The returned slice records every event the runtime tried to upload.
func withStubUploader(t *testing.T) *[]aieventc.Event {
	t.Helper()
	prev := uploaderFactory
	var mu sync.Mutex
	captured := make([]aieventc.Event, 0)
	uploaderFactory = func() func(context.Context, aieventc.Event) error {
		return func(_ context.Context, ev aieventc.Event) error {
			mu.Lock()
			defer mu.Unlock()
			captured = append(captured, ev)
			return nil
		}
	}
	prevCID, prevEP, prevAK := config.CustomerID, config.APIEndpoint, config.APIKey
	t.Cleanup(func() {
		uploaderFactory = prev
		config.CustomerID = prevCID
		config.APIEndpoint = prevEP
		config.APIKey = prevAK
	})
	return &captured
}

// TestRunHook_FailOpenContract asserts the fail-open contract on every
// ERROR path: exit 0, empty stdout, empty stderr. These cases MUST keep
// passing as the stub grows into the real runtime in ticket 2.8 — adding
// parsing, stdin handling, policy evaluation, and upload paths must not
// introduce any non-zero exit or any stderr noise on these inputs.
//
// Valid calls (well-formed agent + event) are deliberately excluded:
// they're a different contract — exit 0 + a valid agent-allow JSON body
// on stdout — and belong in a separate wire-format test added with 2.8.
func TestRunHook_FailOpenContract(t *testing.T) {
	withStubUploader(t)
	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"only agent", []string{"claude-code"}},
		{"only agent (codex)", []string{"codex"}},
		{"unsupported agent", []string{"windsurf", "PreToolUse"}},
		{"empty agent", []string{"", "PreToolUse"}},
		{"empty event", []string{"claude-code", ""}},
		{"trailing extras", []string{"claude-code", "PreToolUse", "extra", "args"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			rc := RunHook(bytes.NewReader(nil), &stdout, &stderr, tc.args)
			if rc != 0 {
				t.Errorf("expected exit 0 (fail-open contract), got %d", rc)
			}
			if stdout.Len() != 0 {
				t.Errorf("expected empty stdout on error path, got %q", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("expected empty stderr on error path, got %q", stderr.String())
			}
		})
	}
}

// TestRunHook_ValidPayloadEmitsAllow exercises the wire-format contract
// for well-formed inputs: a recognized agent + event with a parseable
// payload returns exit 0 and emits a valid JSON allow response on stdout.
// This pins the success path that the fail-open test deliberately
// excludes.
func TestRunHook_ValidPayloadEmitsAllow(t *testing.T) {
	withStubUploader(t)
	cases := []struct {
		name      string
		agent     string
		hookEvent string
		payload   string
		// expectAllowKey is "continue" for Claude (non-empty allow body)
		// and "" for Codex (allow body is the empty object {}).
		expectAllowKey string
	}{
		{
			name:           "claude-code PreToolUse Bash",
			agent:          "claude-code",
			hookEvent:      "PreToolUse",
			payload:        `{"tool_name":"Bash","tool_input":{"command":"ls"}}`,
			expectAllowKey: "continue",
		},
		{
			name:           "codex PreToolUse Bash",
			agent:          "codex",
			hookEvent:      "PreToolUse",
			payload:        `{"tool_name":"Bash","tool_input":{"command":"ls"}}`,
			expectAllowKey: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			rc := RunHook(strings.NewReader(tc.payload), &stdout, &stderr, []string{tc.agent, tc.hookEvent})
			if rc != 0 {
				t.Errorf("expected exit 0, got %d", rc)
			}
			if stderr.Len() != 0 {
				t.Errorf("expected empty stderr, got %q", stderr.String())
			}
			body := bytes.TrimSpace(stdout.Bytes())
			var resp map[string]any
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("stdout not valid JSON: %v: %q", err, body)
			}
			if tc.expectAllowKey != "" && resp[tc.expectAllowKey] != true {
				t.Errorf("expected %q=true in allow response, got %v", tc.expectAllowKey, resp)
			}
			if tc.expectAllowKey == "" && len(resp) != 0 {
				t.Errorf("expected empty-object allow response, got %v", resp)
			}
		})
	}
}

// TestRunHook_RealUploadWiring exercises the entire Phase 3 path
// without the uploaderFactory stub: RunHook → config.Load → newUploader
// → ingest.Client → httptest.Server. This is the only test that
// proves config-staged credentials actually drive a real POST through
// the wire-format we ship; the seam-stubbed tests above intentionally
// short-circuit before that wiring.
func TestRunHook_RealUploadWiring(t *testing.T) {
	type captured struct {
		method string
		path   string
		auth   string
		ua     string
		body   []byte
	}
	gotCh := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotCh <- captured{
			method: r.Method,
			path:   r.URL.Path,
			auth:   r.Header.Get("Authorization"),
			ua:     r.Header.Get("User-Agent"),
			body:   body,
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	// Stage credentials BEFORE config.Load runs inside RunHook. Load
	// only overrides placeholder (`{{...}}`) globals, so these stay put.
	prevCID, prevEP, prevAK := config.CustomerID, config.APIEndpoint, config.APIKey
	config.CustomerID = "cus_e2e"
	config.APIEndpoint = srv.URL
	config.APIKey = "sk_e2e_secret"
	t.Cleanup(func() {
		config.CustomerID = prevCID
		config.APIEndpoint = prevEP
		config.APIKey = prevAK
	})

	// Deliberately do NOT call withStubUploader — we want the real
	// uploaderFactory → newUploader → ingest.New path to run.
	var stdout, stderr bytes.Buffer
	rc := RunHook(
		strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`),
		&stdout, &stderr,
		[]string{"claude-code", "PreToolUse"},
	)
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", rc, stderr.String())
	}

	var got captured
	select {
	case got = <-gotCh:
	case <-time.After(3 * time.Second):
		t.Fatal("no upload received within 3s — wiring broken")
	}

	if got.method != http.MethodPost {
		t.Errorf("method=%s, want POST", got.method)
	}
	if got.path != "/v1/cus_e2e/ai-agents/events" {
		t.Errorf("path=%q, want /v1/cus_e2e/ai-agents/events", got.path)
	}
	if got.auth != "Bearer sk_e2e_secret" {
		t.Errorf("auth=%q", got.auth)
	}
	if !strings.HasPrefix(got.ua, "dev-machine-guard/") {
		t.Errorf("user-agent=%q, want dev-machine-guard/<version>", got.ua)
	}
	var arr []map[string]any
	if err := json.Unmarshal(got.body, &arr); err != nil {
		t.Fatalf("body not JSON array: %v: %q", err, got.body)
	}
	if len(arr) != 1 {
		t.Fatalf("expected 1 event, got %d: %v", len(arr), arr)
	}
	if arr[0]["customer_id"] != "cus_e2e" {
		t.Errorf("event.customer_id=%v, want cus_e2e", arr[0]["customer_id"])
	}
	if arr[0]["hook_event"] != string(aieventc.HookPreToolUse) {
		t.Errorf("event.hook_event=%v, want %q", arr[0]["hook_event"], aieventc.HookPreToolUse)
	}
}

// TestRunHook_InvokesUploaderSeam pins the Phase 3 wiring: a valid
// `_hook claude-code PreToolUse` invocation must dispatch through
// uploaderFactory(). The factory itself decides whether a real upload
// happens (it returns nil when enterprise config is missing); this
// test only checks that the runtime calls the seam the factory
// returns.
func TestRunHook_InvokesUploaderSeam(t *testing.T) {
	captured := withStubUploader(t)

	var stdout, stderr bytes.Buffer
	rc := RunHook(
		strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`),
		&stdout, &stderr,
		[]string{"claude-code", "PreToolUse"},
	)
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	if len(*captured) != 1 {
		t.Fatalf("uploader called %d times, want 1", len(*captured))
	}
	if (*captured)[0].HookEvent != aieventc.HookPreToolUse {
		t.Errorf("uploaded event hook=%q, want PreToolUse", (*captured)[0].HookEvent)
	}
}
