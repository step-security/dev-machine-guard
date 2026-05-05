package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

const testBinary = "/usr/local/bin/stepsecurity-dev-machine-guard"

func TestAdapterForAgentClaudeCode(t *testing.T) {
	a, err := adapterForAgent("claude-code", t.TempDir(), testBinary)
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "claude-code" {
		t.Errorf("Name=%q", a.Name())
	}
	if len(a.ManagedFiles()) != 1 {
		t.Errorf("expected 1 managed file, got %v", a.ManagedFiles())
	}
}

func TestAdapterForAgentCodex(t *testing.T) {
	a, err := adapterForAgent("codex", t.TempDir(), testBinary)
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "codex" {
		t.Errorf("Name=%q", a.Name())
	}
	if len(a.ManagedFiles()) != 2 {
		t.Errorf("expected 2 managed files, got %v", a.ManagedFiles())
	}
}

func TestAdapterForAgentUnsupportedListsBoth(t *testing.T) {
	_, err := adapterForAgent("cursor", t.TempDir(), testBinary)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, want := range []string{"claude-code", "codex"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error must mention %q, got %q", want, msg)
		}
	}
	// The unsupported name itself must appear so the user sees what
	// they typed.
	if !strings.Contains(msg, "cursor") {
		t.Errorf("error must echo the bad name; got %q", msg)
	}
}

func TestSupportedAgentsListIsCanonical(t *testing.T) {
	want := []string{"claude-code", "codex"}
	if len(SupportedAgents) != len(want) {
		t.Fatalf("SupportedAgents len: got %v, want %v", SupportedAgents, want)
	}
	for i, n := range want {
		if SupportedAgents[i] != n {
			t.Errorf("SupportedAgents[%d]: got %q, want %q", i, SupportedAgents[i], n)
		}
	}
}

func TestAllAdaptersReturnsBothInDeclaredOrder(t *testing.T) {
	all := allAdapters(t.TempDir(), testBinary)
	if len(all) != 2 {
		t.Fatalf("expected 2 adapters, got %d", len(all))
	}
	if all[0].Name() != "claude-code" {
		t.Errorf("[0] Name=%q, want claude-code", all[0].Name())
	}
	if all[1].Name() != "codex" {
		t.Errorf("[1] Name=%q, want codex", all[1].Name())
	}
}

// TestSelectAdaptersExplicitAgentSkipsDetection: an explicit `--agent
// claude-code` is an unconditional opt-in. The user's claude binary
// may not be on $PATH (e.g. they're about to install it, or invoke it
// from an unusual location); we MUST still construct and return that
// adapter.
func TestSelectAdaptersExplicitAgentSkipsDetection(t *testing.T) {
	mock := executor.NewMock() // empty PATH
	got, err := selectAdapters(context.Background(), "claude-code", t.TempDir(), testBinary, mock)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name() != "claude-code" {
		t.Errorf("explicit --agent claude-code: got %v, want [claude-code]", names(got))
	}

	got, err = selectAdapters(context.Background(), "codex", t.TempDir(), testBinary, mock)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name() != "codex" {
		t.Errorf("explicit --agent codex: got %v, want [codex]", names(got))
	}
}

func TestSelectAdaptersExplicitUnsupportedReturnsError(t *testing.T) {
	mock := executor.NewMock()
	_, err := selectAdapters(context.Background(), "cursor", t.TempDir(), testBinary, mock)
	if err == nil {
		t.Fatal("expected error on unsupported agent")
	}
}

// TestSelectAdaptersDetectsByLookPath asserts that detection is by
// `executor.LookPath`, NOT by settings file existence. Settings files
// must NOT be present in this test (TempDir is empty), and yet both
// adapters must show up because their CLI binaries are on $PATH.
func TestSelectAdaptersDetectsByLookPath(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("claude", "/usr/local/bin/claude")
	mock.SetPath("codex", "/usr/local/bin/codex")

	got, err := selectAdapters(context.Background(), "", t.TempDir(), testBinary, mock)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected both detected, got %v", names(got))
	}
	if got[0].Name() != "claude-code" || got[1].Name() != "codex" {
		t.Errorf("order: got %v, want [claude-code codex]", names(got))
	}
}

func TestSelectAdaptersFiltersUndetectedAgents(t *testing.T) {
	// Only claude on $PATH — codex must be filtered out.
	mock := executor.NewMock()
	mock.SetPath("claude", "/usr/local/bin/claude")

	got, err := selectAdapters(context.Background(), "", t.TempDir(), testBinary, mock)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name() != "claude-code" {
		t.Errorf("got %v, want [claude-code]", names(got))
	}
}

func TestSelectAdaptersNoneDetectedReturnsEmpty(t *testing.T) {
	// Neither on $PATH — no error, just empty list. The install
	// handler is responsible for emitting a "no agents detected"
	// diagnostic.
	mock := executor.NewMock()
	got, err := selectAdapters(context.Background(), "", t.TempDir(), testBinary, mock)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list when nothing on $PATH, got %v", names(got))
	}
}

// TestSelectAdaptersDoesNotGateOnSettingsFile asserts that with the
// binary on $PATH and NO settings file on disk, the adapter is still
// selected. Gating on settings file presence would return an empty
// list here.
func TestSelectAdaptersDoesNotGateOnSettingsFile(t *testing.T) {
	home := t.TempDir() // no ~/.claude or ~/.codex anywhere
	mock := executor.NewMock()
	mock.SetPath("claude", "/usr/local/bin/claude")

	got, err := selectAdapters(context.Background(), "", home, testBinary, mock)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name() != "claude-code" {
		t.Errorf("settings-file gating leaked back in: got %v", names(got))
	}
}

func names(adapters []adapter.Adapter) []string {
	out := make([]string, len(adapters))
	for i, a := range adapters {
		out[i] = a.Name()
	}
	return out
}
