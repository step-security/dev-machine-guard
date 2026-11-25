package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

func TestPostRunStatusFailedPayload(t *testing.T) {
	var got map[string]any
	var calls atomic.Int32
	status := atomic.Int32{}
	status.Store(503)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/test-customer/developer-mdm-agent/telemetry/run-status" || r.Header.Get("Authorization") != "Bearer sk-test-123" {
			t.Errorf("path=%s auth=%s", r.URL.Path, r.Header.Get("Authorization"))
		}
		b, _ := io.ReadAll(r.Body)
		got = nil
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()

	// A 5xx is retried once, then reported.
	if err := PostRunStatusFailed(context.Background(), srv.Client(), "dev-1", "on_device_firewall_api_failed: x", "firewall"); err == nil || calls.Load() != 2 {
		t.Fatalf("5xx: err=%v calls=%d", err, calls.Load())
	}
	status.Store(200)
	if err := PostRunStatusFailed(context.Background(), srv.Client(), "dev-1", "on_device_firewall_api_failed: x", "firewall"); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"device_id": "dev-1", "status": "failed", "agent_version": buildinfo.Version, "platform": runtime.GOOS,
		"invocation_method": "firewall", "error_message": "on_device_firewall_api_failed: x",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if _, err := uuid.Parse(got["execution_id"].(string)); err != nil {
		t.Errorf("execution_id %v is not a UUID", got["execution_id"])
	}
	// A 4xx is final.
	calls.Store(0)
	status.Store(400)
	if err := PostRunStatusFailed(context.Background(), srv.Client(), "dev-1", "x: y", "firewall"); err == nil || calls.Load() != 1 {
		t.Fatalf("4xx: err=%v calls=%d", err, calls.Load())
	}
	if err := PostRunStatusFailed(context.Background(), srv.Client(), "", "x: y", "firewall"); err == nil {
		t.Fatal("no device id accepted")
	}
}
