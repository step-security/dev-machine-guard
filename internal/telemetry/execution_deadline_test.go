package telemetry

import (
	"testing"
	"time"
)

func TestExecutionDeadlineFromEnv(t *testing.T) {
	cases := []struct {
		name string
		env  string
		set  bool
		want time.Duration
	}{
		{"unset", "", false, 4 * time.Hour},
		{"empty", "", true, 4 * time.Hour},
		{"zero disables", "0", true, 0},
		{"off disables", "off", true, 0},
		{"valid duration 2h", "2h", true, 2 * time.Hour},
		{"valid duration 30m", "30m", true, 30 * time.Minute},
		{"valid duration 45m30s", "45m30s", true, 45*time.Minute + 30*time.Second},
		{"invalid string falls back", "junk", true, 4 * time.Hour},
		{"negative falls back", "-5m", true, 4 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Always set the var (to "" for the unset cases) so the test is
			// hermetic: a value inherited from the host or a CI job must not
			// leak into the "unset" cases. os.Getenv treats truly-unset and
			// empty identically, so "" exercises the same fall-through path.
			if tc.set {
				t.Setenv("STEPSEC_MAX_EXECUTION_DURATION", tc.env)
			} else {
				t.Setenv("STEPSEC_MAX_EXECUTION_DURATION", "")
			}
			got := ExecutionDeadlineFromEnv()
			if got != tc.want {
				t.Errorf("ExecutionDeadlineFromEnv() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ExecutionDeadline adds a config-file fallback for scheduler-fired runs that
// never see the loader-exported env var: env > config > default.
func TestExecutionDeadline_EnvThenConfigThenDefault(t *testing.T) {
	cases := []struct {
		name      string
		env       string
		setEnv    bool
		configVal string
		want      time.Duration
	}{
		// Env present and valid always wins over config.
		{"env wins over config", "2h", true, "8h", 2 * time.Hour},
		{"env off disables despite config", "off", true, "8h", 0},
		// Env absent/unparseable falls through to the config value.
		{"config used when env unset", "", false, "8h", 8 * time.Hour},
		{"config used when env empty", "", true, "8h", 8 * time.Hour},
		{"config off disables when env unset", "", false, "off", 0},
		{"env junk falls through to config", "junk", true, "30m", 30 * time.Minute},
		// Neither source usable → built-in default.
		{"config junk falls back to default", "", false, "junk", 4 * time.Hour},
		{"both empty falls back to default", "", false, "", 4 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Always set the var (to "" when setEnv is false) so an inherited
			// host/CI value can't bypass the config-fallback cases under test.
			if tc.setEnv {
				t.Setenv("STEPSEC_MAX_EXECUTION_DURATION", tc.env)
			} else {
				t.Setenv("STEPSEC_MAX_EXECUTION_DURATION", "")
			}
			got := ExecutionDeadline(tc.configVal)
			if got != tc.want {
				t.Errorf("ExecutionDeadline(%q) env=%q set=%v = %v, want %v",
					tc.configVal, tc.env, tc.setEnv, got, tc.want)
			}
		})
	}
}
