package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	aieventc "github.com/step-security/dev-machine-guard/internal/aiagents/event"
)

// TestStress_ConcurrentHookInvocations is a best-effort stress test:
// many independent RunHook callers sharing a single HOME (settings
// file, errors.jsonl, uploader seam) must each return exit 0 with a
// valid allow body. We do NOT check throughput — the purpose is to
// flush out data races, panics that survive the recover, or stdout
// corruption from interleaved writes.
//
// Marked perf-sensitive (skipped under -short): in-process N=64 routinely
// finishes in well under a second, but some CI runners stutter on the
// concurrent map/redact paths and we don't want to flake the basic
// `go test -short ./...` invocation.
func TestStress_ConcurrentHookInvocations(t *testing.T) {
	if testing.Short() {
		t.Skip("perf-sensitive; skipped under -short")
	}

	withErrorLog(t)
	home := t.TempDir()
	// Same HOME-vs-USERPROFILE caveat as the smoke test: os.UserHomeDir
	// reads different env vars by platform. Set both so this stress
	// runs identically on Unix and Windows CI.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	// Stand up a thread-safe upload counter via the same factory the
	// real wiring uses. withStubUploader installs a single capture
	// closure (mutex-guarded) and the runtime reuses it across every
	// concurrent call — so the test exercises the actual seam contract.
	captured := withStubUploader(t)

	const N = 64
	const payload = `{"tool_name":"Bash","tool_input":{"command":"ls"}}`

	var wg sync.WaitGroup
	var nonZeroExits, badJSON, missingContinue atomic.Int32
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			var stdout, stderr bytes.Buffer
			rc := RunHook(strings.NewReader(payload), &stdout, &stderr,
				[]string{"claude-code", "PreToolUse"})
			if rc != 0 {
				nonZeroExits.Add(1)
				return
			}
			var resp map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
				badJSON.Add(1)
				return
			}
			if resp["continue"] != true {
				missingContinue.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := nonZeroExits.Load(); got != 0 {
		t.Errorf("non-zero exits: %d/%d (fail-open contract violated under load)", got, N)
	}
	if got := badJSON.Load(); got != 0 {
		t.Errorf("malformed stdout JSON: %d/%d (interleaved writes?)", got, N)
	}
	if got := missingContinue.Load(); got != 0 {
		t.Errorf("missing continue=true: %d/%d", got, N)
	}
	// One uploaded event per invocation; if any goroutine swallowed its
	// upload silently the count diverges and we miss telemetry under
	// load — exactly the regression this test exists to catch.
	if got := len(*captured); got != N {
		t.Errorf("uploader seam called %d times, want %d", got, N)
	}
	// Spot-check the captured events for the expected shape — a
	// data-race that scrambled fields would show up here even when the
	// count matched.
	for _, ev := range *captured {
		if ev.HookEvent != aieventc.HookPreToolUse {
			t.Errorf("captured event hook=%q, want PreToolUse", ev.HookEvent)
			break
		}
	}

	// Independently of upload, the runtime hits errors.jsonl any time
	// identity probing or enrichment fails on the hot path. We don't
	// require the file to exist (the happy path produces no errors)
	// but if it does, every line must be a complete JSON record — a
	// truncated or interleaved line proves the unlocked O_APPEND
	// contract from §1.16 broke under N=64.
	assertErrorLogIsClean(t)
}

func assertErrorLogIsClean(t *testing.T) {
	t.Helper()
	path := errorLogPath()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// Happy-path stress runs produce no error log — that's expected
		// and not interesting. Any other read error (perms, IO) is a
		// real test setup problem and should fail loudly.
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("errors log read failed: %v", err)
	}
	if len(data) == 0 {
		return
	}
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Errorf("errors.jsonl line %d not valid JSON (interleaved append?): %q", i, line)
		}
	}
}
