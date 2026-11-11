package device

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestImageBuilder_SwitchIsBoundToThisMachine(t *testing.T) {
	dir := withMachineStateDir(t, "EnterpriseMultiSession", false) // currentMachineID pinned to SER1
	mock := executor.NewMock()
	if ImageBuilderActive(mock) {
		t.Fatal("no marker yet, but the switch reads active")
	}
	if err := SetImageBuilder(mock, true); err != nil {
		t.Fatalf("SetImageBuilder(on): %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, imageBuilderMarkerFile))
	if err != nil {
		t.Fatal(err)
	}
	var m imageBuilderMarker
	if err := json.Unmarshal(data, &m); err != nil || m.MachineID != "SER1" || m.Since == 0 {
		t.Fatalf("marker = %s (err %v), want machine_id SER1 and a since stamp", data, err)
	}
	if !ImageBuilderActive(mock) {
		t.Fatal("marker bound to this machine must switch scans off")
	}
	if err := SetImageBuilder(mock, false); err != nil {
		t.Fatalf("SetImageBuilder(off): %v", err)
	}
	// Off leaves an empty marker (the slot stays SYSTEM's on a hardened
	// state dir), which reads as none.
	if data, err := os.ReadFile(filepath.Join(dir, imageBuilderMarkerFile)); err != nil || len(data) != 0 {
		t.Fatalf("marker after switching off: data=%q err=%v, want an empty file", data, err)
	}
	if ImageBuilderActive(mock) {
		t.Fatal("an empty marker must read as switched off")
	}
	if err := SetImageBuilder(mock, false); err != nil {
		t.Fatalf("switching off twice must be a no-op: %v", err)
	}
}

func TestImageBuilder_ForeignOrUnboundMarkerIsIgnored(t *testing.T) {
	dir := withMachineStateDir(t, "EnterpriseMultiSession", false)
	mock := executor.NewMock()
	for name, body := range map[string]string{
		"builder's marker on a clone": `{"machine_id":"BUILDER-0000","since":1}`,
		"no machine id":               `{"since":1}`,
		"garbage":                     `{not json`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, imageBuilderMarkerFile), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if ImageBuilderActive(mock) {
				t.Fatal("a marker that does not name this machine must not switch scans off")
			}
		})
	}
}

func TestImageBuilder_RefusesWithoutAMachineID(t *testing.T) {
	withMachineStateDir(t, "EnterpriseMultiSession", false)
	prev := currentMachineID
	currentMachineID = func(executor.Executor) string { return "" }
	t.Cleanup(func() { currentMachineID = prev })
	if err := SetImageBuilder(executor.NewMock(), true); err == nil {
		t.Fatal("switching on without a usable machine id must fail: an unbound marker would silence every clone")
	}
}
