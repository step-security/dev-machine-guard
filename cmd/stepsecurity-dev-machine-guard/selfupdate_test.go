package main

import (
	"context"
	"errors"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/launcher"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunSelfUpdateArgs(t *testing.T) {
	if code := runSelfUpdate(nil); code != 2 {
		t.Fatalf("no --system: %d", code)
	}
	if code := runSelfUpdate([]string{"--user"}); code != 2 {
		t.Fatalf("unknown flag: %d", code)
	}
	if runtime.GOOS != "windows" {
		if code := runSelfUpdate([]string{"--system"}); code != 2 {
			t.Fatalf("non-Windows --system: %d", code)
		}
	}
}

func TestUpdateLogRotates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", "update.log")
	logf := newUpdateLog(p)
	logf("hello %d", 1)
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "hello 1") {
		t.Fatalf("log = %q, %v", b, err)
	}
	if err := os.WriteFile(p, make([]byte, updateLogMaxBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	logf("after")
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Fatalf("not rotated: %v", err)
	}
}

// STEPSEC_BOOTSTRAP_FALLBACK=<reason>[:<version>] (dmg-boot): reason is
// the part before the first ':'; the suffix names the version that was
// missing or failed (update_from; else state.json's current); update_to is
// the version actually run (STEPSEC_BOOTSTRAP_VERSION, else this binary).
func TestParseBootstrapFallback(t *testing.T) {
	for _, tc := range []struct{ env, named, ran, self, reason, from, to string }{
		{"current_missing:1.20.0", "1.20.0", "1.19.0", "1.19.0", "current_missing", "1.20.0", "1.19.0"},
		{"start_failed:1.20.0", "1.20.0", "1.18.0", "1.18.0", "start_failed", "1.20.0", "1.18.0"},
		{"state_corrupt", "", "1.18.0", "1.18.0", "state_corrupt", "", "1.18.0"},
		{"state_missing", "1.20.0", "", "1.18.0", "state_missing", "1.20.0", "1.18.0"},
		{"bad:not-a-version", "1.20.0", "x", "1.18.0", "bad", "1.20.0", "1.18.0"},
	} {
		reason, from, to := parseBootstrapFallback(tc.env, tc.named, tc.ran, tc.self)
		if reason != tc.reason || from != tc.from || to != tc.to {
			t.Errorf("%q: got (%q,%q,%q), want (%q,%q,%q)", tc.env, reason, from, to, tc.reason, tc.from, tc.to)
		}
	}
}

// B4(d) end to end: the real bootstrap `run` falls back and the env it hands
// the agent parses into the event the spec describes.
func TestBootstrapFallbackEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed bool // versions\1.20.0 present
		failStart bool // ...but it fails to start
		reason    string
	}{
		{"current dir missing", false, false, "current_missing"},
		{"current fails to start", true, true, "start_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			l := updatestate.Layout{InstallRoot: filepath.Join(root, "pf"), DataRoot: filepath.Join(root, "pd")}
			writeVer := func(dir string) {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				for _, f := range updatestate.VersionFiles {
					if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			}
			cur, _ := updatestate.ParseVersion("1.20.0")
			seed, _ := updatestate.ParseVersion("1.19.0")
			writeVer(l.SeedDir(seed))
			if tc.installed {
				writeVer(l.VersionDir(cur))
			}
			if err := os.MkdirAll(l.StateDir(), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := updatestate.Save(l.StateFile(), &updatestate.State{Schema: 1, Current: "1.20.0"}); err != nil {
				t.Fatal(err)
			}
			var events [][3]string
			b := launcher.NewBootstrap(filepath.Join(l.InstallRoot, "stepsecurity-dev-machine-guard-bootstrap.exe"), func() bool { return false })
			b.Layout = l
			b.Out = io.Discard
			b.Spawn = func(path string, _, env []string, _ time.Duration, onStart func()) launcher.SpawnResult {
				if tc.failStart && strings.Contains(path, "1.20.0") {
					return launcher.SpawnResult{Err: errors.New("boom")}
				}
				get := func(k string) string {
					for _, kv := range env {
						if v, ok := strings.CutPrefix(kv, k+"="); ok {
							return v
						}
					}
					return ""
				}
				onStart()
				// The agent side: state.json's current, then the env.
				st, _, _ := updatestate.Load(l.StateFile())
				reason, from, to := parseBootstrapFallback(get(telemetry.EnvBootstrapFallback), st.Current, get(telemetry.EnvBootstrapVersion), "9.9.9")
				events = append(events, [3]string{reason, from, to})
				return launcher.SpawnResult{Started: true}
			}
			if code := b.Run([]string{"send-telemetry"}); code != 0 {
				t.Fatalf("bootstrap run = %d", code)
			}
			if len(events) != 1 || events[0] != [3]string{tc.reason, "1.20.0", "1.19.0"} {
				t.Fatalf("agent saw %v, want [%s 1.20.0 1.19.0]", events, tc.reason)
			}
		})
	}
}

// D23/R-C2-13: the SYSTEM self-check resolves its id like the updater
// (device.SystemID): with no shared device-id file and a failed hardware
// probe it must not write one (the old root path minted a UUID or
// MachineGuid there, flipping user scans' identity).
func TestSystemSelfCheckNeverWritesSharedID(t *testing.T) {
	device.ResetIDCache()
	t.Cleanup(device.ResetIDCache)
	m := executor.NewMock()
	m.SetGOOS("windows")
	m.SetIsRoot(true) // SYSTEM; no wmic/powershell answers: the probe fails
	cache := filepath.Join(t.TempDir(), "state", "device-id")
	_ = selfCheckDeviceID(context.Background(), m, true, cache)
	if b, err := m.ReadFile(`C:\ProgramData\StepSecurity\device-id`); err == nil && len(b) > 0 {
		t.Fatalf("SYSTEM self-check wrote the shared device-id: %q", b)
	}
}
