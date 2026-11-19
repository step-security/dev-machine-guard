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

// The smoke's self-check receives the running install's --config and
// --install-dir; both spellings are read, nothing else is.
func TestSelfCheckOverrides(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantConfig  string
		wantInstall string
	}{
		{"none", nil, "", ""},
		{"equals forms", []string{"--config=/a/config.json", "--install-dir=/a"}, "/a/config.json", "/a"},
		{"space forms", []string{"--config", "/b/config.json", "--install-dir", "/b"}, "/b/config.json", "/b"},
		{"unrelated flags ignored", []string{"--verbose", "--force-scan"}, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotConfig, gotInstall := selfCheckOverrides(tc.args)
			if gotConfig != tc.wantConfig || gotInstall != tc.wantInstall {
				t.Errorf("selfCheckOverrides(%v) = %q, %q; want %q, %q", tc.args, gotConfig, gotInstall, tc.wantConfig, tc.wantInstall)
			}
		})
	}
}
