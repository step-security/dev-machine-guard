package telemetry

import (
	"errors"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

var errFakeSpawn = errors.New("simulated spawn failure")

func uidPtr(v uint32) *uint32 { return &v }

func wslScanMock(t *testing.T, binary string) *executor.Mock {
	t.Helper()
	m := executor.NewMock()
	m.SetGOOS(model.PlatformWindows)
	m.SetFile(binary, []byte("elf"))
	t.Setenv(wslLinuxBinaryEnv, binary)
	return m
}

func hostDevice(distros ...model.WSLDistro) *model.Device {
	return &model.Device{
		SerialNumber: "host-serial-1",
		WSL: &model.WSLInfo{
			Presence: model.WSLPresenceYes, Installed: true, Distros: distros,
		},
	}
}

func outcomes(res []wslScanResult) map[string]string {
	out := map[string]string{}
	for _, r := range res {
		out[r.Distro] = r.Outcome
	}
	return out
}

// TestTriggerWSLScans_OnlyRunningDistros is the product promise: we never start
// a stopped distro, and `wsl -e` would, so this check is the enforcement.
func TestTriggerWSLScans_OnlyRunningDistros(t *testing.T) {
	m := wslScanMock(t, `C:\agent\dmg-linux`)
	log := progress.NewNoop()

	dev := hostDevice(
		model.WSLDistro{Name: "Debian", DistroID: "{aaa}", Running: true, DefaultUID: uidPtr(1000)},
		model.WSLDistro{Name: "Ubuntu", DistroID: "{bbb}", Running: false, DefaultUID: uidPtr(1000)},
	)
	res := triggerWSLScans(m, log, &cli.Config{WSLScanEnabled: true}, dev)

	got := outcomes(res)
	if got["Debian"] != wslScanLaunched {
		t.Errorf("Debian = %q, want launched", got["Debian"])
	}
	if got["Ubuntu"] != wslScanSkippedNotRunning {
		t.Errorf("Ubuntu = %q, want skipped_not_running", got["Ubuntu"])
	}
	if len(m.DetachedCalls) != 1 {
		t.Fatalf("expected exactly one spawn, got %v", m.DetachedCalls)
	}
	call := m.DetachedCalls[0]
	for _, want := range []string{
		"wsl.exe -d Debian -e /mnt/c/agent/dmg-linux",
		"send-telemetry",
		"--wsl-host-serial=host-serial-1",
		"--wsl-distro-id={aaa}",
	} {
		if !strings.Contains(call, want) {
			t.Errorf("spawn missing %q\ngot: %s", want, call)
		}
	}
	// -u would scan root's home and report a clean machine.
	if strings.Contains(call, " -u ") {
		t.Errorf("spawn must not pass -u: %s", call)
	}
	// The guest gates itself under the derived id we hand it, so forcing the
	// scan would defeat the tenant's cadence for every distro.
	if strings.Contains(call, "--force-scan") {
		t.Errorf("spawn must not force the guest's scan: %s", call)
	}
	if !strings.Contains(call, "--config=") {
		t.Errorf("spawn must tell the guest where the tenant config is: %s", call)
	}
}

func TestTriggerWSLScans_Skips(t *testing.T) {
	log := progress.NewNoop()

	t.Run("root-only distro has no user home worth scanning", func(t *testing.T) {
		m := wslScanMock(t, `C:\agent\dmg-linux`)
		res := triggerWSLScans(m, log, &cli.Config{WSLScanEnabled: true},
			hostDevice(model.WSLDistro{Name: "Imported", DistroID: "{aaa}", Running: true, DefaultUID: uidPtr(0)}))
		if outcomes(res)["Imported"] != wslScanSkippedNoUser {
			t.Errorf("got %q, want skipped_no_user", outcomes(res)["Imported"])
		}
		if len(m.DetachedCalls) != 0 {
			t.Errorf("must not spawn: %v", m.DetachedCalls)
		}
	})

	t.Run("distro with no id cannot be paired", func(t *testing.T) {
		m := wslScanMock(t, `C:\agent\dmg-linux`)
		res := triggerWSLScans(m, log, &cli.Config{WSLScanEnabled: true},
			hostDevice(model.WSLDistro{Name: "Legacy", Running: true, DefaultUID: uidPtr(1000)}))
		if outcomes(res)["Legacy"] != wslScanSkippedNoDistroID {
			t.Errorf("got %q, want skipped_no_distro_id", outcomes(res)["Legacy"])
		}
	})

	t.Run("directive off means nothing is triggered", func(t *testing.T) {
		m := wslScanMock(t, `C:\agent\dmg-linux`)
		res := triggerWSLScans(m, log, &cli.Config{WSLScanEnabled: false},
			hostDevice(model.WSLDistro{Name: "Debian", DistroID: "{aaa}", Running: true, DefaultUID: uidPtr(1000)}))
		if res != nil || len(m.DetachedCalls) != 0 {
			t.Errorf("tenant opt-out must trigger nothing: %v / %v", res, m.DetachedCalls)
		}
	})

	t.Run("host without a usable serial cannot pair a guest", func(t *testing.T) {
		m := wslScanMock(t, `C:\agent\dmg-linux`)
		dev := hostDevice(model.WSLDistro{Name: "Debian", DistroID: "{aaa}", Running: true, DefaultUID: uidPtr(1000)})
		dev.SerialNumber = "unknown"
		if res := triggerWSLScans(m, log, &cli.Config{WSLScanEnabled: true}, dev); res != nil {
			t.Errorf("want nothing triggered, got %v", res)
		}
		if len(m.DetachedCalls) != 0 {
			t.Errorf("must not spawn: %v", m.DetachedCalls)
		}
	})

	t.Run("no linux binary on the host", func(t *testing.T) {
		m := executor.NewMock()
		m.SetGOOS(model.PlatformWindows)
		t.Setenv(wslLinuxBinaryEnv, `C:\nope\dmg-linux`)
		res := triggerWSLScans(m, log, &cli.Config{WSLScanEnabled: true},
			hostDevice(model.WSLDistro{Name: "Debian", DistroID: "{aaa}", Running: true, DefaultUID: uidPtr(1000)}))
		if res != nil || len(m.DetachedCalls) != 0 {
			t.Errorf("missing binary must skip cleanly: %v / %v", res, m.DetachedCalls)
		}
	})
}

// A launch failure must be reported per distro and must not stop the others.
func TestTriggerWSLScans_LaunchFailureIsIsolated(t *testing.T) {
	m := wslScanMock(t, `C:\agent\dmg-linux`)
	m.StartDetachedErr = errFakeSpawn
	res := triggerWSLScans(m, progress.NewNoop(), &cli.Config{WSLScanEnabled: true},
		hostDevice(
			model.WSLDistro{Name: "Debian", DistroID: "{aaa}", Running: true, DefaultUID: uidPtr(1000)},
			model.WSLDistro{Name: "Alpine", DistroID: "{bbb}", Running: true, DefaultUID: uidPtr(1000)},
		))
	if len(res) != 2 {
		t.Fatalf("want a result per distro, got %v", res)
	}
	for _, r := range res {
		if r.Outcome != wslScanFailed {
			t.Errorf("%s = %q, want failed", r.Distro, r.Outcome)
		}
		if r.Err == "" {
			t.Errorf("%s: failure must carry a reason", r.Distro)
		}
	}
}

func TestWindowsPathToWSL(t *testing.T) {
	cases := map[string]string{
		// The MSI installs here, so this is the production path — note the
		// space. It needs no quoting because the spawn passes argv directly
		// with no shell in between.
		`C:\Program Files\StepSecurity\dmg-linux`: "/mnt/c/Program Files/StepSecurity/dmg-linux",
		`C:\ProgramData\StepSecurity\config.json`: "/mnt/c/ProgramData/StepSecurity/config.json",
		`D:\tools\dmg-linux`:                      "/mnt/d/tools/dmg-linux",
		`c:\lower`:                                "/mnt/c/lower",
		"/already/posix":                          "/already/posix",
		"":                                        "",
	}
	for in, want := range cases {
		if got := windowsPathToWSL(in); got != want {
			t.Errorf("windowsPathToWSL(%q) = %q, want %q", in, got, want)
		}
	}
}
