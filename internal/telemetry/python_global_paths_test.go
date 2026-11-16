package telemetry

import (
	"encoding/base64"
	"github.com/step-security/dev-machine-guard/internal/model"
	"testing"
)

func TestPythonGlobalDeltaHashIncludesInstallationPaths(t *testing.T) {
	scan := func(payload string) []model.PythonScanResult {
		return []model.PythonScanResult{{PackageManager: "pip", RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(payload))}}
	}
	old := globalRecordsFromPython(scan(`[{"name":"requests","version":"2"}]`))[0].Hash
	first := globalRecordsFromPython(scan(`[{"name":"requests","version":"2","install_paths":["/one"]}]`))[0].Hash
	moved := globalRecordsFromPython(scan(`[{"name":"requests","version":"2","install_paths":["/two"]}]`))[0].Hash
	if old == first || first == moved {
		t.Fatalf("expected distinct hashes after upgrade and path move: %q %q %q", old, first, moved)
	}
}
