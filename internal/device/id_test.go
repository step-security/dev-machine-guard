package device

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// countingExec counts hardware probes (Linux DMI reads).
type countingExec struct {
	*executor.Mock
	probes atomic.Int32
}

func (c *countingExec) ReadFile(path string) ([]byte, error) {
	if path == "/sys/class/dmi/id/product_serial" {
		c.probes.Add(1)
	}
	return c.Mock.ReadFile(path)
}

func TestSerialNumberResolvesOncePerProcess(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ResetIDCache()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("HW-1\n"))
	exec := &countingExec{Mock: mock}

	first := SerialNumber(context.Background(), exec)
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("HW-2\n"))
	second := Gather(context.Background(), exec).SerialNumber
	if first != "HW-1" || second != first {
		t.Fatalf("ids = %q, %q; want HW-1 twice", first, second)
	}
	if n := exec.probes.Load(); n != 1 {
		t.Fatalf("probes = %d, want 1", n)
	}
}

func TestSerialNumberDoesNotCacheFailure(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ResetIDCache()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if got := SerialNumber(expired, mock); got != "unknown" {
		t.Fatalf("first = %q", got)
	}
	mock.SetFile("/etc/machine-id", []byte("mid-1\n"))
	if got := SerialNumber(context.Background(), mock); got != "mid-1" {
		t.Fatalf("retry = %q, want mid-1", got)
	}
}

const linuxIDFile = "/etc/stepsecurity/device-id"

func TestMachineWideIDSharedBetweenRootAndUser(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ctx := context.Background()

	// Root, no prior root report of the serial: persists machine-id, the ID
	// user contexts can read too.
	ResetIDCache()
	root := executor.NewMock()
	root.SetGOOS("linux")
	root.SetIsRoot(true)
	root.SetFile("/sys/class/dmi/id/product_serial", []byte("HW-SERIAL\n"))
	root.SetFile("/etc/machine-id", []byte("machine-id-1\n"))
	if got := SerialNumber(ctx, root); got != "machine-id-1" {
		t.Fatalf("root = %q", got)
	}
	persisted, err := root.ReadFile(linuxIDFile)
	if err != nil || string(persisted) != "machine-id-1\n" {
		t.Fatalf("persisted = %q, %v", persisted, err)
	}

	// User: DMI unreadable, would otherwise fall to machine-id.
	ResetIDCache()
	user := executor.NewMock()
	user.SetGOOS("linux")
	user.SetFile("/etc/machine-id", []byte("machine-id-1\n"))
	user.SetFile(linuxIDFile, persisted)
	if got := SerialNumber(ctx, user); got != "machine-id-1" {
		t.Fatalf("user = %q, want root's persisted ID", got)
	}
	if _, err := user.ReadFile(linuxIDFile); err != nil {
		t.Fatal(err)
	}
}

func TestMachineWideIDFile(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		root       bool
		want       string
		wantFile   string
		machineID  string
	}{
		{"user prefers file over probe", " PERSISTED \n", false, "PERSISTED", " PERSISTED \n", ""},
		{"user ignores placeholder file", "Default string\n", false, "PROBED", "Default string\n", ""},
		{"user ignores empty file", "\n", false, "PROBED", "\n", ""},
		{"user never writes", "", false, "PROBED", "", ""},
		// Healing needs machine-id readable to tell a stale file from a
		// persisted machine-id.
		{"root refreshes stale file", "OTHER\n", true, "PROBED", "PROBED\n", "mid-1"},
		{"root writes missing file", "", true, "PROBED", "PROBED\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(ResetIDCache)
			ResetIDCache()
			mock := executor.NewMock()
			mock.SetGOOS("linux")
			mock.SetIsRoot(tc.root)
			mock.SetFile("/sys/class/dmi/id/product_serial", []byte("PROBED\n"))
			if tc.machineID != "" {
				mock.SetFile("/etc/machine-id", []byte(tc.machineID+"\n"))
			}
			if tc.file != "" {
				mock.SetFile(linuxIDFile, []byte(tc.file))
			}
			if got := SerialNumber(context.Background(), mock); got != tc.want {
				t.Fatalf("id = %q, want %q", got, tc.want)
			}
			got, _ := mock.ReadFile(linuxIDFile)
			if string(got) != tc.wantFile {
				t.Fatalf("file = %q, want %q", got, tc.wantFile)
			}
		})
	}
}

func TestMachineIDFilePerOS(t *testing.T) {
	if got := machineIDFile("windows"); got != `C:\ProgramData\StepSecurity\device-id` {
		t.Errorf("windows = %q", got)
	}
	for _, goos := range []string{"linux", "darwin"} {
		if got := machineIDFile(goos); got != linuxIDFile {
			t.Errorf("%s = %q", goos, got)
		}
	}
}

func TestConfiguredIDBeatsMachineWideFile(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ResetIDCache()
	old := config.DeviceID
	t.Cleanup(func() { config.DeviceID = old })
	config.DeviceID = "custom-1"
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetFile(linuxIDFile, []byte("PERSISTED\n"))
	dev := Gather(context.Background(), mock)
	if got := ID(dev); got != "custom-1" {
		t.Fatalf("ID = %q, want override", got)
	}
	if dev.SerialNumber != "PERSISTED" {
		t.Fatalf("serial = %q, want machine-wide ID", dev.SerialNumber)
	}
}

func TestGeneratedIDWhenAllSourcesFail(t *testing.T) {
	for _, root := range []bool{false, true} {
		userFile := filepath.Join(t.TempDir(), "device-id")
		old := userIDFile
		userIDFile = func() string { return userFile }
		t.Cleanup(func() { userIDFile = old; ResetIDCache() })

		mock := executor.NewMock()
		mock.SetGOOS("linux")
		mock.SetIsRoot(root)
		var ids [2]string
		for run := range ids {
			ResetIDCache()
			ids[run] = SerialNumber(context.Background(), mock)
		}
		if _, err := uuid.Parse(ids[0]); err != nil || ids[1] != ids[0] {
			t.Fatalf("root=%v ids = %q, want one stable UUID", root, ids)
		}
		wantFile, otherFile := userFile, linuxIDFile
		if root {
			wantFile, otherFile = linuxIDFile, userFile
		}
		if got, _ := mock.ReadFile(wantFile); string(got) != ids[0]+"\n" {
			t.Fatalf("root=%v %s = %q", root, wantFile, got)
		}
		if _, err := mock.ReadFile(otherFile); err == nil {
			t.Fatalf("root=%v unexpectedly wrote %s", root, otherFile)
		}
	}
}

func TestNoGeneratedIDOnTimeout(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ResetIDCache()
	userFile := filepath.Join(t.TempDir(), "device-id")
	old := userIDFile
	userIDFile = func() string { return userFile }
	t.Cleanup(func() { userIDFile = old })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	got := SerialNumber(ctx, mock)
	if _, err := mock.ReadFile(userFile); err == nil {
		t.Fatal("persisted an ID minted after the budget ran out")
	}
	if id := ID(model.Device{SerialNumber: got}); id != "" {
		t.Fatalf("ID = %q, want empty rather than a placeholder", id)
	}
}

func TestRootKeepsStoredIDWhenProbeFallsBack(t *testing.T) {
	for _, tc := range []struct{ name, file, want, wantFile string }{
		{"keeps stored hardware ID", "HW-1\n", "HW-1", "HW-1\n"},
		{"writes fallback when nothing stored", "", "mid-1", "mid-1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(ResetIDCache)
			ResetIDCache()
			mock := executor.NewMock()
			mock.SetGOOS("linux")
			mock.SetIsRoot(true)
			mock.SetFile("/etc/machine-id", []byte("mid-1\n"))
			if tc.file != "" {
				mock.SetFile(linuxIDFile, []byte(tc.file))
			}
			if got := SerialNumber(context.Background(), mock); got != tc.want {
				t.Fatalf("id = %q, want %q", got, tc.want)
			}
			if got, _ := mock.ReadFile(linuxIDFile); string(got) != tc.wantFile {
				t.Fatalf("file = %q, want %q", got, tc.wantFile)
			}
		})
	}
}

// racingExec simulates another process publishing an ID first, or a failed write.
type racingExec struct {
	*executor.Mock
	winner string
	err    error
}

func (r *racingExec) CreateFileOnce(path string, data []byte, perm os.FileMode) error {
	if r.err != nil {
		return r.err
	}
	r.SetFile(path, []byte(r.winner))
	return r.Mock.CreateFileOnce(path, data, perm)
}

func TestGeneratedIDRaceAndPersistFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		exec     *racingExec
		userFile bool
		want     string
	}{
		{"loser adopts winner", &racingExec{winner: "WINNER-ID\n"}, true, "WINNER-ID"},
		{"write failure", &racingExec{err: errors.New("read-only")}, true, "unknown"},
		{"no storage", &racingExec{}, false, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := ""
			if tc.userFile {
				path = filepath.Join(t.TempDir(), "device-id")
			}
			old := userIDFile
			userIDFile = func() string { return path }
			t.Cleanup(func() { userIDFile = old; ResetIDCache() })
			ResetIDCache()
			tc.exec.Mock = executor.NewMock()
			tc.exec.SetGOOS("linux")
			if got := SerialNumber(context.Background(), tc.exec); got != tc.want {
				t.Fatalf("id = %q, want %q", got, tc.want)
			}
		})
	}
}

// The first root run must not give a machine a second identity: the DMI
// serial is kept only if root already reported it; otherwise machine-id, which
// user contexts have been reporting.
func TestFirstRootRunKeepsReportedLinuxID(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ctx := context.Background()
	const rootCache = "/root/.stepsecurity/last-run.json"
	cache := func(id, configured string) []byte {
		return []byte(`{"run_gate":{"device_id":"` + id + `","configured_device_id":"` + configured + `"}}`)
	}
	cases := []struct {
		name      string
		rootCache []byte
		machineID string
		want      string
	}{
		{"no history uses machine-id", nil, "mid-1", "mid-1"},
		{"root reported serial keeps serial", cache("HW-SERIAL", ""), "mid-1", "HW-SERIAL"},
		{"root reported machine-id keeps machine-id", cache("mid-1", ""), "mid-1", "mid-1"},
		{"configured override is not history", cache("HW-SERIAL", "custom"), "mid-1", "mid-1"},
		{"no machine-id falls back to serial", nil, "", "HW-SERIAL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ResetIDCache()
			m := executor.NewMock()
			m.SetGOOS("linux")
			m.SetIsRoot(true)
			m.SetFile("/sys/class/dmi/id/product_serial", []byte("HW-SERIAL\n"))
			if tc.machineID != "" {
				m.SetFile("/etc/machine-id", []byte(tc.machineID+"\n"))
			}
			if tc.rootCache != nil {
				m.SetFile(rootCache, tc.rootCache)
			}
			if got := SerialNumber(ctx, m); got != tc.want {
				t.Fatalf("root = %q, want %q", got, tc.want)
			}
			persisted, _ := m.ReadFile(linuxIDFile)
			if string(persisted) != tc.want+"\n" {
				t.Fatalf("persisted = %q, want %q", persisted, tc.want)
			}
			// A later user run reads the persisted ID: still one identity.
			ResetIDCache()
			u := executor.NewMock()
			u.SetGOOS("linux")
			u.SetFile("/etc/machine-id", []byte("mid-1\n"))
			u.SetFile(linuxIDFile, persisted)
			if got := SerialNumber(ctx, u); got != tc.want {
				t.Fatalf("user after root = %q, want %q", got, tc.want)
			}
			// The next root run keeps it rather than "healing" it to the serial.
			ResetIDCache()
			if got := SerialNumber(ctx, m); got != tc.want {
				t.Fatalf("second root run = %q, want %q", got, tc.want)
			}
			if again, _ := m.ReadFile(linuxIDFile); string(again) != tc.want+"\n" {
				t.Fatalf("second root run rewrote the file to %q", again)
			}
		})
	}
}

// A later root run that can't read /etc/machine-id must keep the persisted
// machine-id rather than replace it with the DMI serial.
func TestRootKeepsPersistedMachineIDWhenMachineIDUnreadable(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ctx := context.Background()
	ResetIDCache()
	m := executor.NewMock()
	m.SetGOOS("linux")
	m.SetIsRoot(true)
	m.SetFile("/sys/class/dmi/id/product_serial", []byte("HW-SERIAL\n"))
	m.SetFile("/etc/machine-id", []byte("mid-1\n"))
	if got := SerialNumber(ctx, m); got != "mid-1" {
		t.Fatalf("first root run = %q, want mid-1", got)
	}

	ResetIDCache()
	m.SetFile("/etc/machine-id", []byte(""))
	if got := SerialNumber(ctx, m); got != "mid-1" {
		t.Fatalf("root run without machine-id = %q, want mid-1", got)
	}
	if persisted, _ := m.ReadFile(linuxIDFile); string(persisted) != "mid-1\n" {
		t.Fatalf("persisted = %q, want mid-1", persisted)
	}
}
