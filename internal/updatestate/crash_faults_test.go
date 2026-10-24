//go:build selfupdate_faults

package updatestate

import (
	"testing"

	"github.com/step-security/dev-machine-guard/internal/faultinject"
)

// TestSaveAtomicUnderInjectedFaults drives the real faultinject checkpoints
// through DMG_FAULT for every prefix the spec names.
func TestSaveAtomicUnderInjectedFaults(t *testing.T) {
	for _, prefix := range []string{"S6", "rollback", "adopt"} {
		for _, tc := range []struct {
			action, at string
			code       int
			current    string
		}{
			{"kill", "state-temp", 137, "1.18.2"},
			{"kill", "state-renamed", 137, "1.19.0"},
			{"err", "state-temp", 91, "1.18.2"},
			{"diskfull", "state-temp", 91, "1.18.2"},
			{"err", "state-renamed", 91, "1.19.0"},
		} {
			name := prefix + "." + tc.at
			t.Run(name+":"+tc.action, func(t *testing.T) {
				if err := faultinject.Validate(name + ":" + tc.action); err != nil {
					t.Fatal(err)
				}
				code, st := runCrash(t, prefix, "DMG_FAULT="+name+":"+tc.action)
				if code != tc.code || st.Current != tc.current {
					t.Fatalf("exit %d current %s, want %d %s", code, st.Current, tc.code, tc.current)
				}
			})
		}
	}
}
