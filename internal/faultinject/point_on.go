//go:build selfupdate_faults

package faultinject

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Enabled reports whether fault injection is compiled in.
const Enabled = true

// Baked holds faults set at link time
// (-ldflags "-X github.com/step-security/dev-machine-guard/internal/faultinject.Baked=<spec>").
// It is merged with DMG_FAULT, Baked first.
var Baked string

const (
	envFault = "DMG_FAULT"
	envTrace = "DMG_FAULT_TRACE"
)

// exit and isSystem are swapped by tests.
var (
	exit               = os.Exit
	isSystem           = runningAsSystem
	stderr   io.Writer = os.Stderr
)

// Point acts on the first fault configured for name, if any. A malformed
// DMG_FAULT or Baked spec ends the process with MalformedExitCode and the
// MalformedMarker on stderr: a typo must never let a fault test pass without
// injecting anything, nor pass for a crash (exit 2 is a Bad run, D5).
// Drivers call Validate before launching, so this is the last line.
func Point(name string) error {
	trace(name)
	rules, err := parse(Baked + "," + os.Getenv(envFault))
	if err != nil {
		fmt.Fprintf(stderr, "%s %s/Baked: %v\n", MalformedMarker, envFault, err)
		exit(MalformedExitCode)
		return fmt.Errorf("%w: %v", ErrInjected, err) // only reached when exit is stubbed
	}
	for _, r := range rules {
		if r.checkpoint != name {
			continue
		}
		if r.principal != "" && (r.principal == "system") != isSystem() {
			continue
		}
		return act(name, r.action)
	}
	return nil
}

func act(name, action string) error {
	switch action {
	case "kill":
		exit(137)
	case "err":
		return fmt.Errorf("%w: err at %s", ErrInjected, name)
	case "diskfull":
		return fmt.Errorf("%w: diskfull at %s: %w", ErrInjected, name, errDiskFull)
	case "panic":
		// A real Go panic, so recover() paths run as in a crash.
		panic(fmt.Sprintf("faultinject: panic at %s", name))
	case "hang":
		for {
			time.Sleep(time.Hour)
		}
	default:
		if d, ok := sleepAction(action); ok {
			time.Sleep(d) // then continue normally
			return nil
		}
		if n, ok := strings.CutPrefix(action, "exit"); ok {
			if code, err := strconv.Atoi(n); err == nil && code >= 0 {
				exit(code)
				return nil // only reached when exit is stubbed
			}
		}
		return fmt.Errorf("%w: unknown action %q at %s", ErrInjected, action, name)
	}
	return nil // only reached when exit is stubbed
}

func trace(name string) {
	path := os.Getenv(envTrace)
	if path == "" {
		return
	}
	// #nosec G304 -- test-only trace file chosen by the harness.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	_, _ = f.WriteString(name + "\n")
	_ = f.Close()
}
