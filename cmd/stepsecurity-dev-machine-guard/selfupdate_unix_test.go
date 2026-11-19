//go:build !windows

package main

import (
	"testing"

	"github.com/step-security/dev-machine-guard/internal/cli"
)

// A WSL guest scan (launched by the Windows agent with both identity flags)
// never runs the macOS/Linux updater: the host's MSI updater owns dmg-linux.
func TestWSLGuestRunSkipsSelfUpdate(t *testing.T) {
	tests := []struct {
		name string
		cfg  *cli.Config
		want bool
	}{
		{"nil config", nil, false},
		{"plain run", &cli.Config{}, false},
		{"host serial only", &cli.Config{WSLHostSerial: "SER1"}, false},
		{"distro id only", &cli.Config{WSLDistroID: "d-1"}, false},
		{"wsl guest", &cli.Config{WSLHostSerial: "SER1", WSLDistroID: "d-1"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := wslGuestRun(tc.cfg); got != tc.want {
				t.Errorf("wslGuestRun() = %v, want %v", got, tc.want)
			}
		})
	}
}
