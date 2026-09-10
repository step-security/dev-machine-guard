package rungate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// gateServer routes Evaluate's check-in to a server answering status (0 = 200)
// and body, clears the environment escapes so each test states the ones it
// wants, and counts the check-ins made.
func gateServer(t *testing.T, status int, body string) *atomic.Int32 {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	prevEndpoint, prevKey, prevCustomer := config.APIEndpoint, config.APIKey, config.CustomerID
	config.APIEndpoint, config.APIKey, config.CustomerID = srv.URL, "test-key", "acme"
	t.Cleanup(func() { config.APIEndpoint, config.APIKey, config.CustomerID = prevEndpoint, prevKey, prevCustomer })
	t.Setenv("STEPSEC_FORCE_SCAN", "")
	t.Setenv("STEPSEC_DISABLE_RUN_GATE", "")
	return &hits
}

// seedDeviceID leaves a prior run's cache with a known device id so Evaluate
// never probes the serial.
func seedDeviceID(t *testing.T) {
	t.Helper()
	d := Directive{Mode: ModeFull, GatingEnabled: true, EffectiveIntervalMinutes: 240}
	if err := recordCheckin("SER-CACHED", d, time.Unix(1_753_160_800, 0)); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
}

func evaluate(t *testing.T, forceScan bool) Result {
	t.Helper()
	return Evaluate(context.Background(), executor.NewMock(), progress.NewNoop(), forceScan, "")
}

// assertNothingRemembered pins the no-persistence rule: the state file never
// carries the credential setting in any shape.
func assertNothingRemembered(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if s := string(raw); strings.Contains(s, "scanners") || strings.Contains(s, "credential") {
		t.Fatalf("credential setting persisted: %s", s)
	}
}

const fullDirective = `"scan_directive":{"mode":"full","reason":"due","gating_enabled":true,"effective_interval_minutes":240}`

func TestEvaluateResolvesCredentialSetting(t *testing.T) {
	for _, tt := range []struct {
		name         string
		body         string
		status       int
		wantDisabled bool
		wantSkip     bool
	}{
		{name: "explicit false", body: `{` + fullDirective + `,"scanners":{"credentials":{"enabled":false}}}`, wantDisabled: true},
		{name: "explicit true", body: `{` + fullDirective + `,"scanners":{"credentials":{"enabled":true}}}`},
		{name: "scanners missing", body: `{` + fullDirective + `}`},
		{name: "enabled null", body: `{` + fullDirective + `,"scanners":{"credentials":{"enabled":null}}}`},
		{name: "enabled not a boolean", body: `{` + fullDirective + `,"scanners":{"credentials":{"enabled":"false"}}}`},
		{name: "unknown sibling scanner ignored", body: `{` + fullDirective + `,"scanners":{"other":{"enabled":false}}}`},
		{name: "unknown sibling beside credentials", body: `{` + fullDirective + `,"scanners":{"other":{"enabled":true},"credentials":{"enabled":false}}}`, wantDisabled: true},
		{name: "malformed body", body: `{"scan_directive":`},
		{name: "server error", status: http.StatusInternalServerError},
		{name: "false without any directive", body: `{"scanners":{"credentials":{"enabled":false}}}`, wantDisabled: true},
		{name: "false with invalid directive", body: `{"scan_directive":{"mode":7},"scanners":{"credentials":{"enabled":false}}}`, wantDisabled: true},
		{name: "false on a skip directive", body: `{"scan_directive":{"mode":"skip","reason":"not_due"},"scanners":{"credentials":{"enabled":false}}}`, wantDisabled: true, wantSkip: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := withTempState(t)
			seedDeviceID(t)
			gateServer(t, tt.status, tt.body)

			res := evaluate(t, false)
			if res.CredentialScanningDisabled != tt.wantDisabled || res.Skip != tt.wantSkip {
				t.Fatalf("result = %+v, want disabled=%v skip=%v", res, tt.wantDisabled, tt.wantSkip)
			}
			assertNothingRemembered(t, path)
		})
	}
}

// TestEvaluateForgetsEarlierFalse: every invocation starts enabled. A false
// from one run does not carry into the next when that run's check-in fails
// or says nothing.
func TestEvaluateForgetsEarlierFalse(t *testing.T) {
	path := withTempState(t)
	seedDeviceID(t)
	for _, step := range []struct {
		name         string
		status       int
		body         string
		wantDisabled bool
	}{
		{name: "false", body: `{` + fullDirective + `,"scanners":{"credentials":{"enabled":false}}}`, wantDisabled: true},
		{name: "then check-in fails", status: http.StatusServiceUnavailable},
		{name: "false again", body: `{` + fullDirective + `,"scanners":{"credentials":{"enabled":false}}}`, wantDisabled: true},
		{name: "then setting omitted", body: `{` + fullDirective + `}`},
		{name: "false once more", body: `{"scanners":{"credentials":{"enabled":false}}}`, wantDisabled: true},
		{name: "then explicit true", body: `{` + fullDirective + `,"scanners":{"credentials":{"enabled":true}}}`},
	} {
		gateServer(t, step.status, step.body)
		if res := evaluate(t, false); res.CredentialScanningDisabled != step.wantDisabled {
			t.Fatalf("%s: result = %+v, want disabled=%v", step.name, res, step.wantDisabled)
		}
		assertNothingRemembered(t, path)
	}
}

// TestEvaluateCadenceBypassesStillResolveCredentials: --force-scan,
// STEPSEC_FORCE_SCAN and STEPSEC_DISABLE_RUN_GATE win the cadence decision but
// still check in once, so a fresh false applies. Everything else about a
// bypassed run stays as it was before the check-in existed: nothing is
// persisted and the response's wsl_directive is not applied.
func TestEvaluateCadenceBypassesStillResolveCredentials(t *testing.T) {
	const body = `{"scan_directive":{"mode":"skip","reason":"not_due","gating_enabled":true,"effective_interval_minutes":60},` +
		`"wsl_directive":{"enabled":true,"reason":"tenant"},"scanners":{"credentials":{"enabled":false}}}`
	for _, tt := range []struct {
		name       string
		forceFlag  bool
		env        string
		wantReason string
	}{
		{name: "--force-scan", forceFlag: true, wantReason: "forced"},
		{name: "STEPSEC_FORCE_SCAN", env: "STEPSEC_FORCE_SCAN", wantReason: "forced"},
		{name: "STEPSEC_DISABLE_RUN_GATE", env: "STEPSEC_DISABLE_RUN_GATE", wantReason: "kill_switch"},
	} {
		t.Run(tt.name+" fresh false", func(t *testing.T) {
			withTempState(t)
			seedDeviceID(t)
			before, _ := readState()
			hits := gateServer(t, 0, body)
			if tt.env != "" {
				t.Setenv(tt.env, "1")
			}

			res := evaluate(t, tt.forceFlag)
			if res.Skip || res.Reason != tt.wantReason || !res.CredentialScanningDisabled {
				t.Fatalf("result = %+v, want proceed with reason %s and credentials disabled", res, tt.wantReason)
			}
			if hits.Load() != 1 {
				t.Fatalf("check-in calls = %d, want 1", hits.Load())
			}
			if res.WSL.Enabled {
				t.Fatal("a bypassed run must not enable WSL scanning from the directive")
			}
			if after, _ := readState(); after != before {
				t.Fatalf("bypassed run persisted check-in state: %+v -> %+v", before, after)
			}
		})
		t.Run(tt.name+" check-in fails", func(t *testing.T) {
			withTempState(t)
			seedDeviceID(t)
			gateServer(t, http.StatusServiceUnavailable, "")
			if tt.env != "" {
				t.Setenv(tt.env, "1")
			}

			res := evaluate(t, tt.forceFlag)
			if res.Skip || res.Reason != tt.wantReason || res.CredentialScanningDisabled {
				t.Fatalf("result = %+v, want proceed with reason %s and credentials enabled", res, tt.wantReason)
			}
		})
	}
}

// TestEvaluateNormalRunAppliesWSLDirective: the bypass parity above is not a
// regression in the normal path, which still honours wsl_directive.
func TestEvaluateNormalRunAppliesWSLDirective(t *testing.T) {
	withTempState(t)
	seedDeviceID(t)
	gateServer(t, 0, `{`+fullDirective+`,"wsl_directive":{"enabled":true,"reason":"tenant"}}`)

	res := evaluate(t, false)
	if res.Skip || !res.WSL.Enabled || res.WSL.Reason != "tenant" || res.CredentialScanningDisabled {
		t.Fatalf("result = %+v, want proceed with WSL enabled and credentials enabled", res)
	}
}

// TestEvaluateNoDeviceIDScans: without a usable device id there is no check-in,
// so credentials stay enabled and the escapes keep their own reasons.
func TestEvaluateNoDeviceIDScans(t *testing.T) {
	for _, tt := range []struct {
		name       string
		forceFlag  bool
		wantReason string
	}{
		{name: "gated", wantReason: "no_device_id"},
		{name: "forced", forceFlag: true, wantReason: "forced"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			withTempState(t)
			hits := gateServer(t, 0, `{`+fullDirective+`,"scanners":{"credentials":{"enabled":false}}}`)

			// The mock executor answers no serial probe, so the device id is unusable.
			res := evaluate(t, tt.forceFlag)
			if res.Skip || res.Reason != tt.wantReason || res.CredentialScanningDisabled {
				t.Fatalf("result = %+v, want fail-open with reason %s and credentials enabled", res, tt.wantReason)
			}
			if hits.Load() != 0 {
				t.Fatalf("check-in calls = %d, want 0", hits.Load())
			}
		})
	}
}

// TestEvaluateIgnoresStaleCacheFields: a state file left behind by an earlier
// build that stored the setting neither disables scanning nor breaks the reader.
func TestEvaluateIgnoresStaleCacheFields(t *testing.T) {
	const stale = `{"schema_version":1,"run_gate":{"device_id":"SER-CACHED","gating_enabled":true,` +
		`"effective_interval_minutes":240,"directive_fetched_at":1753160800,` +
		`"scanners":{"credentials":{"enabled":false}},"credential_scanning_enabled":false}}`
	for name, status := range map[string]int{"setting omitted": 0, "check-in fails": http.StatusServiceUnavailable} {
		t.Run(name, func(t *testing.T) {
			path := withTempState(t)
			if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
				t.Fatalf("seed: %v", err)
			}
			gateServer(t, status, `{`+fullDirective+`}`)

			res := evaluate(t, false)
			if res.CredentialScanningDisabled {
				t.Fatalf("result = %+v, want credentials enabled", res)
			}
			if st, ok := readState(); !ok || st.DeviceID != "SER-CACHED" {
				t.Fatalf("stale fields broke the reader: %+v ok=%v", st, ok)
			}
		})
	}
}
