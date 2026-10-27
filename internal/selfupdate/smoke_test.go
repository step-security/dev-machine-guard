package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

func TestRunSmoke(t *testing.T) {
	t.Setenv(envHelper, "1")
	exe := filepath.Join(t.TempDir(), "1.20.0", "agent.exe")
	copySelf(t, exe)
	ctx := context.Background()
	if err := RunSmoke(ctx, exe, mustV("1.20.0")); err != nil {
		t.Fatalf("good smoke: %v", err)
	}
	if err := RunSmoke(ctx, exe, mustV("1.21.0")); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("wrong version: %v", err)
	}
	t.Setenv("DMG_SU_SMOKE_FAIL", "1.20.0")
	if err := RunSmoke(ctx, exe, mustV("1.20.0")); err == nil {
		t.Fatal("failing self-check passed")
	}
	t.Setenv("DMG_SU_SMOKE_FAIL", "")
	t.Setenv("DMG_SU_SMOKE_HANG", "1")
	knobOverrides = map[knob]time.Duration{knobSmokeTimeout: 2 * time.Second}
	defer func() { knobOverrides = map[knob]time.Duration{} }()
	start := time.Now()
	if err := RunSmoke(ctx, exe, mustV("1.20.0")); !errors.Is(err, ErrSmokeTimeout) {
		t.Fatalf("hung self-check: %v", err)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatal("smoke timeout not enforced")
	}
}

func TestCheckSelfCheck(t *testing.T) {
	v := mustV("1.20.0")
	for out, ok := range map[string]bool{
		`{"version":"1.20.0","device_id":"d","config_ok":true}`:       true,
		`{"version":"1.20.0","device_id":"","config_ok":true}`:        false,
		`{"version":"1.20.0","device_id":"unknown","config_ok":true}`: false,
		`{"version":"1.20.0","device_id":"d","config_ok":false}`:      false,
		`not json`: false,
	} {
		if err := checkSelfCheck([]byte(out), v); (err == nil) != ok {
			t.Errorf("%s: err = %v", out, err)
		}
	}
	var b limitedBuffer
	b.max = 4
	_, _ = b.Write([]byte("abcdef"))
	if b.String() != "abcd" {
		t.Fatalf("limitedBuffer = %q", b.String())
	}
}

// FR1-1: the smoke limit exceeds the self-check's worst-case internal wait
// (its device-id probe) by a clear margin.
func TestSmokeBudgetExceedsSelfCheckWaits(t *testing.T) {
	if knobDefaults[knobSmokeTimeout] < SelfCheckProbeTimeout+smokeMargin {
		t.Fatalf("smoke %s < self-check probe %s + margin %s", knobDefaults[knobSmokeTimeout], SelfCheckProbeTimeout, smokeMargin)
	}
}

func init() {
	// "flood": writes 2 MiB to stdout and stderr.
	helperRoles["flood"] = func() int {
		chunk := []byte(strings.Repeat("x", 1<<20))
		for i := 0; i < 2; i++ {
			_, _ = os.Stdout.Write(chunk)
			_, _ = os.Stderr.Write(chunk)
		}
		return 0
	}
}

// Copilot 4356483290: os/exec copies a child's pipe with io.Copy, which
// must not bypass the cap through an io.ReaderFrom.
func TestLimitedBufferCapsExecPipe(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := proctest.Command(t, exe)
	cmd.Env = append(cmd.Env, envRole+"=flood")
	stdout := &limitedBuffer{max: 64 << 10}
	stderr := &limitedBuffer{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 64<<10 || stderr.Len() != 4<<10 {
		t.Fatalf("captured stdout %d, stderr %d bytes; want 65536, 4096", stdout.Len(), stderr.Len())
	}
}
