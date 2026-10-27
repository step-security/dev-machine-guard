package selfupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// SelfCheckProbeTimeout bounds the self-check's device-id probe; smokeMargin
// is the headroom the smoke limit keeps above it (startup, config load).
const (
	SelfCheckProbeTimeout = 10 * time.Second
	smokeMargin           = 30 * time.Second
)

// ErrSmokeTimeout means the self-check didn't answer within the smoke
// limit: retried, not held against the version, until it repeats.
var ErrSmokeTimeout = errors.New("self-check timed out")

// SelfCheck is the `agent self-check` output (spec Contracts: CLI).
type SelfCheck struct {
	Version  string `json:"version"`
	DeviceID string `json:"device_id"`
	ConfigOK bool   `json:"config_ok"`
}

// limitedBuffer keeps at most max bytes. The buffer is a named field so no
// io.ReaderFrom leaks out: io.Copy (os/exec's pipe copier) must go through
// Write.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) Len() int       { return b.buf.Len() }
func (b *limitedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *limitedBuffer) String() string { return b.buf.String() }

// RunSmoke runs `<exe> self-check` with the smoke time limit and checks
// that it exits 0 reporting version want, a loaded config and a device id.
func RunSmoke(ctx context.Context, exe string, want updatestate.Version) error {
	ctx, cancel := context.WithTimeout(ctx, duration(knobSmokeTimeout))
	defer cancel()
	// #nosec G204 -- exe is a verified, manifest-checked version dir binary.
	cmd := exec.CommandContext(ctx, exe, "self-check")
	stdout := &limitedBuffer{max: 64 << 10}
	stderr := &limitedBuffer{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	prepareSmoke(cmd)
	if err := runSmokeCmd(cmd); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%w after %s", ErrSmokeTimeout, duration(knobSmokeTimeout))
		}
		return fmt.Errorf("self-check: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return checkSelfCheck(stdout.Bytes(), want)
}

func checkSelfCheck(out []byte, want updatestate.Version) error {
	var sc SelfCheck
	if err := json.Unmarshal(bytes.TrimSpace(out), &sc); err != nil {
		return fmt.Errorf("self-check output is not JSON: %w", err)
	}
	switch {
	case sc.Version != want.String():
		return fmt.Errorf("self-check reports version %q, want %s", sc.Version, want)
	case !sc.ConfigOK:
		return fmt.Errorf("self-check could not load the config")
	case strings.TrimSpace(sc.DeviceID) == "" || sc.DeviceID == "unknown":
		return fmt.Errorf("self-check resolved no device id")
	}
	return nil
}
