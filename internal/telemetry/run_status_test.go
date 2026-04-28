package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// withEnterpriseConfig temporarily patches config to look enterprise-enabled
// and points APIEndpoint at the given test server. Restores on return.
func withEnterpriseConfig(t *testing.T, endpoint string) func() {
	t.Helper()
	savedKey, savedCustomer, savedEndpoint := config.APIKey, config.CustomerID, config.APIEndpoint
	config.APIKey = "sk-test-123"
	config.CustomerID = "test-customer"
	config.APIEndpoint = endpoint
	return func() {
		config.APIKey, config.CustomerID, config.APIEndpoint = savedKey, savedCustomer, savedEndpoint
	}
}

func TestReportRunStatus_StartedRetriesOn5xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()

	log := progress.NewLogger(progress.LevelInfo)
	reportRunStatus(context.Background(), log, "11111111-2222-4333-8444-555555555555", "dev-1", runStatusStarted, "")

	if got := atomic.LoadInt32(&calls); got != int32(runStatusStartedAttempts) {
		t.Fatalf("expected %d retries on 5xx, got %d", runStatusStartedAttempts, got)
	}
}

func TestReportRunStatus_StartedStopsAfter2xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()

	log := progress.NewLogger(progress.LevelInfo)
	reportRunStatus(context.Background(), log, "11111111-2222-4333-8444-555555555555", "dev-1", runStatusStarted, "")

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 call on 2xx, got %d", got)
	}
}

func TestReportRunStatus_DoesNotRetryOn4xx(t *testing.T) {
	// 4xx is terminal: validation or auth rejection; retrying cannot help.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()

	log := progress.NewLogger(progress.LevelInfo)
	reportRunStatus(context.Background(), log, "11111111-2222-4333-8444-555555555555", "dev-1", runStatusStarted, "")

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 call for 4xx (no retry), got %d", got)
	}
}

func TestReportRunStatus_FailedRetriesOn5xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()

	log := progress.NewLogger(progress.LevelInfo)
	reportRunStatus(context.Background(), log, "11111111-2222-4333-8444-555555555555", "dev-1", runStatusFailed, "boom")

	if got := atomic.LoadInt32(&calls); got != int32(runStatusFailedAttempts) {
		t.Fatalf("expected %d retries on 5xx for failed, got %d", runStatusFailedAttempts, got)
	}
}

func TestReportRunStatus_FailedIncludesErrorMessage(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()

	log := progress.NewLogger(progress.LevelInfo)
	reportRunStatus(context.Background(), log, "11111111-2222-4333-8444-555555555555", "dev-1", runStatusFailed, "context deadline exceeded")

	if gotBody["status"] != runStatusFailed {
		t.Errorf("status = %q, want %q", gotBody["status"], runStatusFailed)
	}
	if gotBody["error_message"] != "context deadline exceeded" {
		t.Errorf("error_message = %q, want %q", gotBody["error_message"], "context deadline exceeded")
	}
	if gotBody["execution_id"] == "" {
		t.Errorf("execution_id missing from body: %+v", gotBody)
	}
}

func TestReportRunStatus_SkipsSucceededAndUnknownStatus(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()

	log := progress.NewLogger(progress.LevelInfo)
	reportRunStatus(context.Background(), log, "11111111-2222-4333-8444-555555555555", "dev-1", "succeeded", "")
	reportRunStatus(context.Background(), log, "11111111-2222-4333-8444-555555555555", "dev-1", "cancelled", "")

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected zero HTTP calls for non-agent statuses, got %d", got)
	}
}

func TestReportRunStatus_SkipsWhenNotEnterprise(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer srv.Close()

	// Restore config after test. Default config.APIKey is the placeholder, which
	// makes IsEnterpriseMode return false.
	savedKey := config.APIKey
	config.APIKey = "{{API_KEY}}"
	defer func() { config.APIKey = savedKey }()

	log := progress.NewLogger(progress.LevelInfo)
	reportRunStatus(context.Background(), log, "11111111-2222-4333-8444-555555555555", "dev-1", runStatusStarted, "")

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected zero calls when not in enterprise mode, got %d", got)
	}
}

func TestReportRunStatus_SkipsEmptyExecutionID(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()

	log := progress.NewLogger(progress.LevelInfo)
	reportRunStatus(context.Background(), log, "", "dev-1", runStatusStarted, "")

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected zero calls when execution_id is empty, got %d", got)
	}
}

func TestReportRunStatus_AbortsRetriesOnCtxCancel(t *testing.T) {
	// Server hangs — every attempt will hit the per-attempt timeout, but we
	// cancel the parent context mid-run to confirm retries stop.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(runStatusHTTPTimeout + 2*time.Second)
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after the first attempt completes (~runStatusHTTPTimeout) so we
	// land in the backoff select where ctx.Done wins.
	time.AfterFunc(runStatusHTTPTimeout+100*time.Millisecond, cancel)

	log := progress.NewLogger(progress.LevelInfo)
	done := make(chan struct{})
	start := time.Now()
	go func() {
		reportRunStatus(ctx, log, "11111111-2222-4333-8444-555555555555", "dev-1", runStatusStarted, "")
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		// Should be close to the first-attempt timeout, well under the full
		// retry budget (~runStatusHTTPTimeout * runStatusStartedAttempts).
		budget := runStatusHTTPTimeout*2 + 500*time.Millisecond
		if elapsed > budget {
			t.Fatalf("reportRunStatus took %s, expected ≤ %s once ctx is cancelled", elapsed, budget)
		}
	case <-time.After(runStatusHTTPTimeout*int64Attempts() + 5*time.Second):
		t.Fatal("reportRunStatus did not return")
	}
}

func int64Attempts() time.Duration {
	return time.Duration(runStatusStartedAttempts)
}
