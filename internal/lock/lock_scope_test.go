package lock

import "testing"

func TestScopedTarget(t *testing.T) {
	tests := []struct{ name, base, scope, want string }{
		{"empty scope keeps the default", "/tmp/stepsecurity-dev-machine-guard.flock", "", "/tmp/stepsecurity-dev-machine-guard.flock"},
		{"unix path keeps its extension", "/tmp/stepsecurity-dev-machine-guard.flock", "dev1", "/tmp/stepsecurity-dev-machine-guard-dev1.flock"},
		{"windows mutex name", "StepSecurityDevMachineGuard", "dev1", "StepSecurityDevMachineGuard-dev1"},
		{"already suffixed is unchanged", "StepSecurityDevMachineGuard-dev1", "dev1", "StepSecurityDevMachineGuard-dev1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scopedTarget(tc.base, tc.scope); got != tc.want {
				t.Errorf("scopedTarget(%q, %q) = %q, want %q", tc.base, tc.scope, got, tc.want)
			}
		})
	}
}
