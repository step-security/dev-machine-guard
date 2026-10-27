//go:build darwin

package runtimeinv

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// The walk honours the run's TCC skipper: nothing under ~/Documents is read.
func TestWalkHonoursTCCSkipper(t *testing.T) {
	f := newFixture(t)
	home := f.path("home")
	f.file("home/Documents/node-v20.0.0/bin/node", "\x7fELF", true)
	f.file("home/tools/node-v22.0.0/bin/node", "\x7fELF", true)
	s := (&Scanner{exec: executor.NewReal(), goos: "darwin", home: home,
		rootsOverride: []walkRoot{{home, 5, nil, 0}}}).WithSkipper(tcc.ForRun(home, nil, nil))
	out, _, _ := s.Scan(context.Background())
	if len(out) != 1 || out[0].ExecutablePath != f.path("home/tools/node-v22.0.0/bin/node") {
		t.Fatalf("got %+v; ~/Documents must be skipped", out)
	}
}
