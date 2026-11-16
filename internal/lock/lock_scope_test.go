package lock

import "testing"

func TestScopedTarget(t *testing.T) {
	tests := []struct{ name, base, scope, want string }{
		{"empty scope keeps the default", "/tmp/stepsecurity-dev-machine-guard.flock", "", "/tmp/stepsecurity-dev-machine-guard.flock"},
		{"unix path keeps its extension", "/tmp/stepsecurity-dev-machine-guard.flock", "dev1", "/tmp/stepsecurity-dev-machine-guard-dev1.flock"},
		{"windows mutex name", "StepSecurityDevMachineGuard", "dev1", "StepSecurityDevMachineGuard-dev1"},
		{"already suffixed is unchanged", "StepSecurityDevMachineGuard-dev1", "dev1", "StepSecurityDevMachineGuard-dev1"},
		{"dotted scope on a unix path", "/tmp/stepsecurity-dev-machine-guard.flock", "j.doe", "/tmp/stepsecurity-dev-machine-guard-j.doe.flock"},
		{"dotted scope on a mutex name", "StepSecurityDevMachineGuard", "j.doe", "StepSecurityDevMachineGuard-j.doe"},
		{"dotted scope already suffixed", "StepSecurityDevMachineGuard-j.doe", "j.doe", "StepSecurityDevMachineGuard-j.doe"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scopedTarget(tc.base, tc.scope); got != tc.want {
				t.Errorf("scopedTarget(%q, %q) = %q, want %q", tc.base, tc.scope, got, tc.want)
			}
		})
	}
}

func TestUnscopedTarget(t *testing.T) {
	tests := []struct{ name, target, scope, want string }{
		{"empty scope", "/tmp/stepsecurity-dev-machine-guard-dev1.flock", "", "/tmp/stepsecurity-dev-machine-guard-dev1.flock"},
		{"unix path", "/tmp/stepsecurity-dev-machine-guard-dev1.flock", "dev1", "/tmp/stepsecurity-dev-machine-guard.flock"},
		{"unix path, dotted scope", "/tmp/stepsecurity-dev-machine-guard-j.doe.flock", "j.doe", "/tmp/stepsecurity-dev-machine-guard.flock"},
		{"mutex name", "StepSecurityDevMachineGuard-dev1", "dev1", "StepSecurityDevMachineGuard"},
		{"mutex name, dotted scope", "StepSecurityDevMachineGuard-j.doe", "j.doe", "StepSecurityDevMachineGuard"},
		{"unscoped target is unchanged", "StepSecurityDevMachineGuard", "dev1", "StepSecurityDevMachineGuard"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := unscopedTarget(tc.target, tc.scope); got != tc.want {
				t.Errorf("unscopedTarget(%q, %q) = %q, want %q", tc.target, tc.scope, got, tc.want)
			}
			if got := unscopedTarget(scopedTarget(tc.want, tc.scope), tc.scope); tc.scope != "" && got != tc.want {
				t.Errorf("round trip of %q with scope %q = %q", tc.want, tc.scope, got)
			}
		})
	}
}
