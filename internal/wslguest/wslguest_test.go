package wslguest_test

import (
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/wslguest"
)

// A half-pair identifies nothing, so it must not produce an id at all.
func TestDeviceID_RequiresBothHalves(t *testing.T) {
	for _, c := range [][2]string{{"", ""}, {"host-1", ""}, {"", "{aaa}"}, {" ", "{aaa}"}} {
		if got := wslguest.DeviceID(c[0], c[1]); got != "" {
			t.Errorf("DeviceID(%q, %q) = %q, want empty", c[0], c[1], got)
		}
	}
}

// TestDeviceID_StableAndUnique: re-scans must converge on one record,
// and two distros on the same host must never collide — which they would if we
// used the hostname they all share.
func TestDeviceID_StableAndUnique(t *testing.T) {
	a := wslguest.DeviceID("host-1", "{aaa}")
	if a != wslguest.DeviceID("host-1", "{aaa}") {
		t.Error("not deterministic — a re-scan would create a second device record")
	}
	if a == wslguest.DeviceID("host-1", "{bbb}") {
		t.Error("two distros on one host collided")
	}
	if a == wslguest.DeviceID("host-2", "{aaa}") {
		t.Error("the same distro id on two hosts collided")
	}
	// Case differences in a Windows serial or GUID must not fork the identity.
	if a != wslguest.DeviceID("HOST-1", "{AAA}") {
		t.Error("case change forked the device id")
	}
	if len(a) != 36 || strings.Count(a, "-") != 4 {
		t.Errorf("device id %q is not uuid-shaped", a)
	}
}
