package identity

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// hangingExec wraps a Mock and overrides Run to block until the supplied
// context is cancelled. Used to verify the 1s probe timeout actually fires
// instead of waiting forever for an unresponsive shell-out.
type hangingExec struct {
	*executor.Mock
	runCalls atomic.Int32
}

func (h *hangingExec) Run(ctx context.Context, _ string, _ ...string) (string, string, int, error) {
	h.runCalls.Add(1)
	<-ctx.Done()
	return "", "", 124, ctx.Err()
}

func (h *hangingExec) RunWithTimeout(ctx context.Context, _ time.Duration, name string, args ...string) (string, string, int, error) {
	return h.Run(ctx, name, args...)
}

func (h *hangingExec) RunInDir(ctx context.Context, _ string, _ time.Duration, name string, args ...string) (string, string, int, error) {
	return h.Run(ctx, name, args...)
}

// ReadFile must also fail or the Linux/Darwin fallbacks bypass the hang.
// Mock returns an error for unstubbed paths — that's the behavior we want.
// hangingExec inherits Mock's ReadFile, so no override needed.

func TestResolve_HappyPath_Darwin(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetCommand(`"IOPlatformSerialNumber" = "ABCXYZ123"`, "", 0, "ioreg", "-l")
	mock.SetCommand("14.5\n", "", 0, "sw_vers", "-productVersion")
	mock.SetEnv("USER_EMAIL", "subham@stepsecurity.io")

	got := Resolve(context.Background(), mock, "cust-42")

	if got.CustomerID != "cust-42" {
		t.Errorf("CustomerID = %q, want cust-42", got.CustomerID)
	}
	if got.DeviceID != "ABCXYZ123" {
		t.Errorf("DeviceID = %q, want ABCXYZ123 (from ioreg)", got.DeviceID)
	}
	if got.UserIdentity != "subham@stepsecurity.io" {
		t.Errorf("UserIdentity = %q, want subham@stepsecurity.io (from USER_EMAIL)", got.UserIdentity)
	}
}

func TestResolve_PassesUnknownThrough(t *testing.T) {
	// No stubs registered for ioreg / sw_vers / system_profiler — Mock.Run
	// returns errors for unstubbed commands, which device.Gather translates
	// to its `"unknown"` sentinel. The shim must not rewrite that.
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	// Don't set USER_EMAIL etc. — and Mock.LoggedInUser falls back to
	// CurrentUser which has username "testuser" by default. Override that
	// path so we land on `"unknown"` for UserIdentity too.
	mock.SetUsername("")

	got := Resolve(context.Background(), mock, "cust-42")

	if got.DeviceID != "unknown" {
		t.Errorf("DeviceID = %q, want %q", got.DeviceID, "unknown")
	}
	// UserIdentity falls back through env vars then LoggedInUser; with
	// empty env and empty username, expect "unknown" or "" — accept either,
	// since the contract is "don't synthesize, pass through what device
	// returns." device.Gather returns the empty username here, not
	// "unknown", so we just assert the shim didn't replace it.
	if got.UserIdentity != "" && got.UserIdentity != "unknown" {
		t.Errorf("UserIdentity = %q, want passthrough of what device.Gather emits (\"\" or \"unknown\")",
			got.UserIdentity)
	}
}

func TestResolve_HungExecutorTimesOutWithin1s(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	hung := &hangingExec{Mock: mock}

	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	got := Resolve(parent, hung, "cust-42")
	elapsed := time.Since(start)

	// Allow generous slack for CI noise but hard-cap at 1.5s — well under
	// the 15s hook budget. If this ever drifts, the hot path is at risk.
	if elapsed > 1500*time.Millisecond {
		t.Errorf("Resolve took %s under hung executor, want < 1.5s (probe timeout is 1s)", elapsed)
	}
	if elapsed < 900*time.Millisecond {
		// The probe should have actually run, not bailed instantly.
		t.Errorf("Resolve took %s, expected ~1s (probe timeout)", elapsed)
	}

	// With every Run call hung-then-cancelled, device.Gather returns its
	// "unknown" sentinel — confirm the shim passes it through.
	if got.DeviceID != "unknown" {
		t.Errorf("DeviceID under hung exec = %q, want %q", got.DeviceID, "unknown")
	}
	if got.CustomerID != "cust-42" {
		t.Errorf("CustomerID = %q, want passthrough cust-42", got.CustomerID)
	}
}

// Compile-time check: hangingExec must satisfy executor.Executor so that
// device.Gather (which takes the interface) can call it. If the interface
// grows a method we don't override, the embedded Mock fills it in.
var _ executor.Executor = (*hangingExec)(nil)
