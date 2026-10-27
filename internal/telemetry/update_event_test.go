package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

func TestPostUpdateEventPayload(t *testing.T) {
	var got map[string]any
	var path, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		got = nil
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()

	err := PostUpdateEvent(context.Background(), srv.Client(), UpdateEvent{
		ExecutionID: "e-1", DeviceID: "dev-1", InstallChannel: "msi",
		Event: "update_rolled_back", From: "1.20.0", To: "1.19.0", Error: "bad_runs",
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/v1/test-customer/developer-mdm-agent/telemetry/run-status" || auth != "Bearer sk-test-123" {
		t.Fatalf("path=%s auth=%s", path, auth)
	}
	want := map[string]any{
		"execution_id": "e-1", "device_id": "dev-1", "status": "update", "agent_version": buildinfo.Version,
		"platform": runtime.GOOS, "invocation_method": "update", "install_channel": "msi",
		"update_event": "update_rolled_back", "update_from": "1.20.0", "update_to": "1.19.0", "error_message": "bad_runs",
	}
	if len(got) != len(want) {
		t.Fatalf("payload keys = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}

	// Optional fields are omitted when empty; error_message is capped.
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'x'
	}
	if err := PostUpdateEvent(context.Background(), srv.Client(), UpdateEvent{
		ExecutionID: "e-2", DeviceID: "dev-1", InstallChannel: "msi", Event: "update_check_failed", Error: string(long),
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["update_from"]; ok {
		t.Fatal("empty update_from sent")
	}
	if n := len(got["error_message"].(string)); n != 2048 {
		t.Fatalf("error_message len = %d", n)
	}
}

func TestPostUpdateEventRetriesAndRejects(t *testing.T) {
	var calls atomic.Int32
	status := atomic.Int32{}
	status.Store(503)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()
	ev := UpdateEvent{ExecutionID: "e", DeviceID: "d", InstallChannel: "msi", Event: "update_ok"}

	if err := PostUpdateEvent(context.Background(), srv.Client(), ev); err == nil || errors.Is(err, ErrUpdateEventRejected) {
		t.Fatalf("5xx: %v", err)
	}
	if calls.Load() != updateEventAttempts {
		t.Fatalf("attempts = %d", calls.Load())
	}
	calls.Store(0)
	status.Store(400)
	if err := PostUpdateEvent(context.Background(), srv.Client(), ev); !errors.Is(err, ErrUpdateEventRejected) {
		t.Fatalf("4xx: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("4xx retried: %d", calls.Load())
	}
	calls.Store(0)
	for _, bad := range []UpdateEvent{
		{ExecutionID: "e", DeviceID: "d", Event: "update_ok"},
		{ExecutionID: "e", DeviceID: "d", InstallChannel: "msi", Event: "update_rolled_back", To: "1.19.0"},
	} {
		if err := PostUpdateEvent(context.Background(), srv.Client(), bad); !errors.Is(err, ErrUpdateEventRejected) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid event reached the backend")
	}
	ev.DeviceID = ""
	if err := PostUpdateEvent(context.Background(), srv.Client(), ev); err == nil {
		t.Fatal("event without device id posted")
	}
}

func TestStartedMarkerOnlyAfterAcceptedStarted(t *testing.T) {
	status := atomic.Int32{}
	status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()
	log := progress.NewLogger(progress.LevelError)

	if !reportRunStatus(context.Background(), log, "x", "d", runStatusStarted, "", "install") {
		t.Fatal("2xx not reported as accepted")
	}
	status.Store(400)
	if reportRunStatus(context.Background(), log, "x", "d", runStatusStarted, "", "install") {
		t.Fatal("4xx reported as accepted")
	}

	runs := filepath.Join(t.TempDir(), "runs", "1.20.0.json")
	for _, id := range []string{"run-a", "run-b"} {
		if err := updatestate.AppendRun(runs, updatestate.RunRecord{RunID: id, Version: "1.20.0", At: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(EnvRunRecord, runs)
	t.Setenv(EnvRunID, "run-a")
	if err := markRunStarted(); err != nil {
		t.Fatal(err)
	}
	recs := updatestate.ReadRuns(runs)
	if len(recs) != 2 || !recs[0].Started || recs[1].Started {
		t.Fatalf("records = %+v", recs)
	}
	t.Setenv(EnvRunRecord, "relative.json")
	if err := markRunStarted(); err == nil {
		t.Fatal("relative run record path accepted")
	}
	t.Setenv(EnvRunRecord, "")
	if err := markRunStarted(); err != nil {
		t.Fatalf("unset env: %v", err)
	}
}

// R-C2-3: only a permanent validation reject (400/422) drops an event;
// auth, timeout, rate-limit and server errors are retried.
func TestUpdateEventStatusPolicy(t *testing.T) {
	status := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()
	ev := UpdateEvent{ExecutionID: "e", DeviceID: "d", InstallChannel: "msi", Event: "update_ok"}
	for code, drop := range map[int]bool{400: true, 422: true, 401: false, 403: false, 408: false, 429: false, 500: false, 503: false} {
		status.Store(int32(code))
		err := PostUpdateEvent(context.Background(), srv.Client(), ev)
		if err == nil || errors.Is(err, ErrUpdateEventRejected) != drop {
			t.Errorf("HTTP %d: err=%v, want dropped=%v", code, err, drop)
		}
	}
}

func TestExitCodeForRunErrors(t *testing.T) {
	if ExitCode(fmt.Errorf("%w: boom", ErrPanic)) != 2 || ExitCode(errors.New("offline")) != 1 {
		t.Fatal("ExitCode mapping wrong")
	}
}
