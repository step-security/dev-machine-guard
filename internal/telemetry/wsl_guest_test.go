package telemetry

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestWSLGuestFromConfig(t *testing.T) {
	if got := wslGuestFromConfig(nil); got != nil {
		t.Errorf("nil config: got %+v, want nil", got)
	}
	// A partial pair identifies nothing, so it must not half-identify the run.
	for _, c := range []cli.Config{
		{},
		{WSLHostSerial: "host-1"},
		{WSLDistroID: "{aaa}"},
		{WSLHostSerial: "  ", WSLDistroID: "{aaa}"},
	} {
		if got := wslGuestFromConfig(&c); got != nil {
			t.Errorf("partial pair %+v: got %+v, want nil", c, got)
		}
	}

	got := wslGuestFromConfig(&cli.Config{WSLHostSerial: " host-1 ", WSLDistroID: " {aaa} "})
	if got == nil || got.HostDeviceID != "host-1" || got.DistroID != "{aaa}" {
		t.Fatalf("got %+v, want trimmed host-1/{aaa}", got)
	}
}

// TestPayload_WSLGuest_WireContract locks the shape agent-api's
// ddbmodels.DeviceWSLGuest unmarshals; a tag drift silently unpairs every guest.
func TestPayload_WSLGuest_WireContract(t *testing.T) {
	b, err := json.Marshal(&Payload{
		CustomerID: "c", DeviceID: "d",
		WSLGuest: &model.WSLGuest{HostDeviceID: "host-1", DistroID: "{aaa}"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"wsl_guest":`, `"host_device_id":"host-1"`, `"distro_id":"{aaa}"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("payload missing %s\ngot: %s", want, b)
		}
	}
}

// A host agent must never emit the block.
func TestPayload_WSLGuest_OmittedWhenNil(t *testing.T) {
	b, err := json.Marshal(&Payload{CustomerID: "c", DeviceID: "d"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "wsl_guest") {
		t.Errorf("nil guest must be omitted, got: %s", b)
	}
}
