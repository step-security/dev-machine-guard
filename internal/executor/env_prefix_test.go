package executor

import "testing"

func TestHasEnvPrefix(t *testing.T) {
	const prefix = "DMG_TEST_ENV_PREFIX_"
	t.Setenv(prefix+"EMPTY", "")
	if !NewReal().HasEnvPrefix(prefix) || NewReal().HasEnvPrefix(prefix+"ABSENT_") {
		t.Fatal("environment names must count even when values are empty")
	}
	m := NewMock()
	m.SetEnv(prefix+"EMPTY", "")
	if !m.HasEnvPrefix(prefix) || m.HasEnvPrefix(prefix+"ABSENT_") {
		t.Fatal("mock differs from real environment presence")
	}
	// This method must forward directly; sourcing a user's shell would miss the
	// mock's value and cross the static scanner's execution boundary.
	if !NewUserAwareExecutor(m, "developer").HasEnvPrefix(prefix) {
		t.Fatal("user-aware wrapper did not preserve process-only lookup")
	}
}
