package selfupdate

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

// envHelper makes the test binary act as a staged agent: `<bin> self-check`
// prints a SelfCheck whose version is the name of the directory holding the
// binary (versions\<v>\...). DMG_SU_SMOKE_FAIL=<v>[,<v>] fails it, and
// DMG_SU_SMOKE_HANG=1 hangs it.
const envHelper = "DMG_SU_TEST_HELPER"

// envRole selects a helper role registered in helperRoles (the kill matrix
// registers "updater": one selfupdate.Run tick as a subprocess).
const envRole = "DMG_SU_TEST_ROLE"

var helperRoles = map[string]func() int{}

func TestMain(m *testing.M) {
	if os.Getenv(envHelper) == "1" && len(os.Args) > 1 && os.Args[1] == "self-check" {
		proctest.Guard()
		os.Exit(helperSelfCheck())
	}
	if role := os.Getenv(envRole); helperRoles[role] != nil {
		if role == "sleep" {
			proctest.GuardDeadline() // TestSmokeKillsGrandchildren: the job must kill it
		} else {
			proctest.Guard()
		}
		os.Exit(helperRoles[role]())
	}
	os.Exit(proctest.Main(m))
}

func init() {
	// "sleep": a grandchild that outlives a hung self-check unless a job
	// kills it.
	helperRoles["sleep"] = func() int { time.Sleep(time.Hour); return 0 }
}

func helperSelfCheck() int {
	exe, _ := os.Executable()
	v := filepath.Base(filepath.Dir(exe))
	if pidFile := os.Getenv("DMG_SU_SMOKE_GRANDCHILD"); pidFile != "" {
		cmd := exec.Command(exe)
		cmd.Env = append(os.Environ(), envRole+"=sleep", envHelper+"=0")
		if err := cmd.Start(); err == nil {
			_ = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
		}
	}
	if os.Getenv("DMG_SU_SMOKE_HANG") == "1" {
		time.Sleep(time.Hour)
	}
	for _, bad := range strings.Split(os.Getenv("DMG_SU_SMOKE_FAIL"), ",") {
		if bad == v {
			return 3
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(SelfCheck{Version: v, DeviceID: "dev-1", ConfigOK: true})
	return 0
}

// copySelf copies the test binary to dst.
func copySelf(t testing.TB, dst string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
