package bgpriority

import (
	"errors"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// swapApply replaces the per-OS implementation for one test and restores it.
func swapApply(t *testing.T, fn func() (string, error)) *int {
	t.Helper()
	calls := 0
	orig := applyImpl
	applyImpl = func() (string, error) {
		calls++
		return fn()
	}
	t.Cleanup(func() { applyImpl = orig })
	return &calls
}

func TestApply_EscapeHatchSkipsImplementation(t *testing.T) {
	mock := executor.NewMock()
	mock.SetEnv(EnvDisable, "1")
	calls := swapApply(t, func() (string, error) { return "should not run", nil })

	Apply(mock, progress.NewLogger(progress.LevelInfo))

	if *calls != 0 {
		t.Errorf("applyImpl called %d times with %s=1, want 0", *calls, EnvDisable)
	}
}

func TestApply_ErrorIsToleratedAndDoesNotPanic(t *testing.T) {
	mock := executor.NewMock()
	calls := swapApply(t, func() (string, error) { return "", errors.New("EPERM") })

	Apply(mock, progress.NewLogger(progress.LevelInfo))

	if *calls != 1 {
		t.Errorf("applyImpl called %d times, want 1", *calls)
	}
}

func TestApply_AppliedPathInvokesImplementationOnce(t *testing.T) {
	tests := []struct {
		name string
		env  string
	}{
		{name: "env unset", env: ""},
		{name: "env set to non-1", env: "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			if tc.env != "" {
				mock.SetEnv(EnvDisable, tc.env)
			}
			calls := swapApply(t, func() (string, error) { return "test band", nil })

			Apply(mock, progress.NewLogger(progress.LevelInfo))

			if *calls != 1 {
				t.Errorf("applyImpl called %d times, want 1", *calls)
			}
		})
	}
}

func TestApply_NoOpPlatformDescLogsNothing(t *testing.T) {
	mock := executor.NewMock()
	calls := swapApply(t, func() (string, error) { return "", nil })

	// Empty desc + nil error is the apply_other contract; Apply must accept it.
	Apply(mock, progress.NewLogger(progress.LevelInfo))

	if *calls != 1 {
		t.Errorf("applyImpl called %d times, want 1", *calls)
	}
}
