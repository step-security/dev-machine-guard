package browserext

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

func TestDetect_OSVersionConsent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("real Darwin skipper")
	}
	for _, tc := range []struct {
		name, version string
		include       *bool
		wantScan      bool
	}{
		{"26-default", "26.5.1", nil, true},
		{"26-off", "26.5.1", new(false), true},
		{"27-default", "27.0", nil, false},
		{"27-off", "27.0", new(false), false},
		{"27-explicit-include", "27.0", new(true), true},
		{"28-default", "28.0", nil, false},
		{"unknown-default", "", nil, false},
		{"malformed-default", "not-a-version", nil, false},
		{"malformed-minor", "26.invalid", nil, false},
		{"malformed-patch", "26.5.invalid", nil, false},
		{"empty-component", "26..1", nil, false},
		{"trailing-dot", "26.", nil, false},
		{"signed-major", "+26.5.1", nil, false},
		{"extra-component", "26.5.1.2", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := tempHome(t)
			root := filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
			localState(t, root, "Default")
			securePrefs(t, root, "Default", `"`+idA+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}}`)
			var skipper *tcc.Skipper
			if tcc.Enabled(tc.include) {
				skipper = tcc.New(home)
			}
			info := newDetector(model.PlatformDarwin).WithOSVersion(tc.version).WithSkipper(skipper).Detect(context.Background(), testUser(home))
			if info == nil {
				t.Fatal("missing coverage")
			}
			assertPayloadInvariants(t, info)
			got := coverageFor(t, info, browserChrome)
			if tc.wantScan {
				if got.Status != model.BrowserCoverageScanned || len(findingsFor(info, browserChrome)) != 1 {
					t.Fatalf("got %s/%s with %d findings", got.Status, got.ReasonCode, len(findingsFor(info, browserChrome)))
				}
			} else if got.Status != model.BrowserCoverageFailed || got.ReasonCode != model.BrowserExtReasonRefusedTCC || info.ScanComplete || len(info.Findings) != 0 {
				t.Fatalf("unexpected coverage %s/%s complete=%v findings=%d", got.Status, got.ReasonCode, info.ScanComplete, len(info.Findings))
			}
		})
	}
}
