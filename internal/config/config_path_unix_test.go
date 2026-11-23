//go:build !windows

package config

import (
	"os"
	"testing"
)

// Root only trusts a root-owned file nobody else can write; an unprivileged
// user trusts whatever it can read.
func TestInstallTreeFileTrustedFor(t *testing.T) {
	tests := []struct {
		name  string
		euid  int
		owner uint32
		perm  os.FileMode
		want  bool
	}{
		{"user reads own file", 501, 501, 0o600, true},
		{"user reads a world-writable file", 501, 0, 0o666, true},
		{"root reads root-owned 0600", 0, 0, 0o600, true},
		{"root reads root-owned 0644", 0, 0, 0o644, true},
		{"root rejects a user-owned file", 0, 501, 0o600, false},
		{"root rejects a group-writable root file", 0, 0, 0o664, false},
		{"root rejects a world-writable root file", 0, 0, 0o646, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := installTreeFileTrustedFor(tc.euid, tc.owner, tc.perm); got != tc.want {
				t.Errorf("installTreeFileTrustedFor(%d, %d, %o) = %v, want %v", tc.euid, tc.owner, tc.perm, got, tc.want)
			}
		})
	}
}
