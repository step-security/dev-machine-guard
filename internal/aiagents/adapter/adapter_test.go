package adapter_test

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// stubAdapter is the minimal type that satisfies adapter.Adapter. The
// var assignment below is a compile-time assertion that the interface
// is implementable as currently defined — if a method is added or its
// signature changes, this file fails to build, surfacing the breakage
// to every implementer at once.
type stubAdapter struct{}

func (stubAdapter) Name() string                     { return "stub" }
func (stubAdapter) SupportedHooks() []event.HookEvent { return nil }
func (stubAdapter) ManagedFiles() []adapter.ManagedFile {
	return nil
}
func (stubAdapter) Detect(context.Context, executor.Executor) (adapter.DetectionResult, error) {
	return adapter.DetectionResult{}, nil
}
func (stubAdapter) Install(context.Context) (adapter.InstallResult, error) {
	return adapter.InstallResult{}, nil
}
func (stubAdapter) Uninstall(context.Context) (adapter.UninstallResult, error) {
	return adapter.UninstallResult{}, nil
}
func (stubAdapter) ParseEvent(context.Context, event.HookEvent, []byte) (*event.Event, error) {
	return nil, nil
}
func (stubAdapter) ShellCommand(*event.Event) (string, string, bool) {
	return "", "", false
}
func (stubAdapter) DecideResponse(*event.Event, adapter.Decision) adapter.HookResponse {
	return nil
}

var _ adapter.Adapter = stubAdapter{}

func TestAllowDecisionIsAllow(t *testing.T) {
	d := adapter.AllowDecision()
	if !d.Allow {
		t.Error("AllowDecision().Allow must be true")
	}
	if d.UserMessage != "" {
		t.Errorf("AllowDecision().UserMessage = %q, want empty", d.UserMessage)
	}
}

func TestZeroValueResultsAreUsable(t *testing.T) {
	// The install/uninstall handlers iterate the result slices; a
	// zero value must be safe to iterate without nil-check ceremony
	// at the call site.
	var ir adapter.InstallResult
	for range ir.HooksAdded {
		t.Fatal("zero InstallResult should iterate zero times")
	}
	for range ir.WrittenFiles {
		t.Fatal("zero InstallResult should iterate zero times")
	}
	for range ir.BackupFiles {
		t.Fatal("zero InstallResult should iterate zero times")
	}
	for range ir.CreatedDirs {
		t.Fatal("zero InstallResult should iterate zero times")
	}

	var ur adapter.UninstallResult
	for range ur.HooksRemoved {
		t.Fatal("zero UninstallResult should iterate zero times")
	}
	for range ur.WrittenFiles {
		t.Fatal("zero UninstallResult should iterate zero times")
	}
	for range ur.BackupFiles {
		t.Fatal("zero UninstallResult should iterate zero times")
	}
}

func TestDetectionResultZeroValueIsNotDetected(t *testing.T) {
	var dr adapter.DetectionResult
	if dr.Detected {
		t.Error("zero DetectionResult.Detected should be false")
	}
	if dr.BinaryPath != "" {
		t.Errorf("zero DetectionResult.BinaryPath = %q, want empty", dr.BinaryPath)
	}
}
