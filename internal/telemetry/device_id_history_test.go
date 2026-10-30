package telemetry

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func withHistoryPath(t *testing.T, path string) {
	t.Helper()
	orig := lastUploadedDeviceIDPath
	lastUploadedDeviceIDPath = func() string { return path }
	t.Cleanup(func() { lastUploadedDeviceIDPath = orig })
}

func TestPreviousDeviceID(t *testing.T) {
	path := filepath.Join(t.TempDir(), lastUploadedDeviceIDName)
	tests := []struct {
		name    string
		stored  *string // nil = no file
		current string
		want    string
	}{
		{name: "no history", current: "C02X", want: ""},
		{name: "unchanged", stored: ptr("C02X\n"), current: "C02X", want: ""},
		{name: "unchanged ignores surrounding space", stored: ptr("  C02X \n"), current: " C02X", want: ""},
		{name: "configured id replaced the serial", stored: ptr("C02X\n"), current: "custom-dev-01", want: "C02X"},
		{name: "configured id removed", stored: ptr("custom-dev-01\n"), current: "C02X", want: "custom-dev-01"},
		{name: "empty file", stored: ptr("\n"), current: "C02X", want: ""},
		{name: "unknown is not an identity", stored: ptr("unknown\n"), current: "C02X", want: ""},
		{name: "oversized file", stored: ptr(strings.Repeat("x", maxDeviceIDLen+1)), current: "C02X", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withHistoryPath(t, path)
			m := executor.NewMock()
			if tt.stored != nil {
				m.SetFile(path, []byte(*tt.stored))
			}
			if got := previousDeviceID(m, tt.current); got != tt.want {
				t.Fatalf("previousDeviceID = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPreviousDeviceIDNoPath(t *testing.T) {
	withHistoryPath(t, "")
	if got := previousDeviceID(executor.NewMock(), "C02X"); got != "" {
		t.Fatalf("previousDeviceID with no path = %q, want empty", got)
	}
}

func TestRecordUploadedDeviceID(t *testing.T) {
	path := filepath.Join(t.TempDir(), lastUploadedDeviceIDName)
	withHistoryPath(t, path)
	m := executor.NewMock()

	if err := recordUploadedDeviceID(m, "C02X"); err != nil {
		t.Fatal(err)
	}
	if got := previousDeviceID(m, "custom-dev-01"); got != "C02X" {
		t.Fatalf("after recording C02X, previous = %q, want C02X", got)
	}

	// The next accepted upload under the new ID ends the change.
	if err := recordUploadedDeviceID(m, "custom-dev-01"); err != nil {
		t.Fatal(err)
	}
	if got := previousDeviceID(m, "custom-dev-01"); got != "" {
		t.Fatalf("after recording the new ID, previous = %q, want empty", got)
	}

	// Unusable IDs never overwrite the history.
	for _, bad := range []string{"", "  ", "unknown"} {
		if err := recordUploadedDeviceID(m, bad); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := m.ReadFile(path)
	if got := strings.TrimSpace(string(data)); got != "custom-dev-01" {
		t.Fatalf("stored = %q after unusable IDs, want custom-dev-01", got)
	}
}

// A failed upload doesn't record, so a change made in between still reports
// the last ID the backend actually holds (A -> B fails -> C reports A).
func TestUnacceptedUploadKeepsHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), lastUploadedDeviceIDName)
	withHistoryPath(t, path)
	m := executor.NewMock()
	if err := recordUploadedDeviceID(m, "A"); err != nil {
		t.Fatal(err)
	}
	if got := previousDeviceID(m, "B"); got != "A" {
		t.Fatalf("previous for B = %q, want A", got)
	}
	// B's upload fails: nothing recorded.
	if got := previousDeviceID(m, "C"); got != "A" {
		t.Fatalf("previous for C = %q, want A", got)
	}
}

func TestPayloadPreviousDeviceIDOmittedWhenEmpty(t *testing.T) {
	data, err := json.Marshal(&Payload{DeviceID: "C02X"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "previous_device_id") {
		t.Fatalf("empty previous_device_id was serialized: %s", data)
	}
	data, err = json.Marshal(&Payload{DeviceID: "custom-dev-01", PreviousDeviceID: "C02X"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"previous_device_id":"C02X"`) {
		t.Fatalf("previous_device_id missing: %s", data)
	}
}

func ptr(s string) *string { return &s }
