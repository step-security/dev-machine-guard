package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

const (
	runStatusStarted       = "started"
	runStatusFailed        = "failed"
	runStatusCancelled     = "cancelled by user"
	runStatusMaxErrorChars = 2000
	runStatusHTTPTimeout   = 3 * time.Second

	// Retry counts per status. "started" is load-bearing for attempt
	// visibility — we retry harder so a single transient network blip
	// does not lose the signal that the run was attempted. "failed"
	// fires during shutdown, so one retry covers the common case.
	runStatusStartedAttempts = 3
	runStatusFailedAttempts  = 2
	runStatusRetryBackoff    = 500 * time.Millisecond
)

// reportRunStatus POSTs a lifecycle transition to the backend with a small
// retry budget. Never returns an error: running the scan is the priority.
//
// status must be "started" or "failed". Passing "succeeded" (or any other
// value) is a defensive no-op — success is written by the backend worker
// after it persists the uploaded telemetry.
func reportRunStatus(ctx context.Context, log *progress.Logger,
	executionID, deviceID, status, errMsg string) {

	if !config.IsEnterpriseMode() {
		return
	}
	if status != runStatusStarted && status != runStatusFailed {
		return
	}
	if executionID == "" {
		return
	}

	payload := map[string]string{
		"execution_id":  executionID,
		"device_id":     deviceID,
		"status":        status,
		"agent_version": buildinfo.Version,
		"platform":      runtime.GOOS,
	}
	if status == runStatusFailed {
		if errMsg == "" {
			// Backend rejects a "failed" report with no error_message.
			errMsg = "unspecified failure"
		}
		if len(errMsg) > runStatusMaxErrorChars {
			errMsg = errMsg[:runStatusMaxErrorChars]
		}
		payload["error_message"] = errMsg
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Progress("run-status: marshal error: %v", err)
		return
	}

	endpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/telemetry/run-status",
		config.APIEndpoint, config.CustomerID)

	attempts := runStatusFailedAttempts
	if status == runStatusStarted {
		attempts = runStatusStartedAttempts
	}

	for i := 1; i <= attempts; i++ {
		if i > 1 {
			// Fixed short backoff. Keeps the total time budget bounded so
			// retries don't visibly delay the scan start.
			select {
			case <-time.After(runStatusRetryBackoff):
			case <-ctx.Done():
				log.Progress("run-status: parent context done, abandoning retries")
				return
			}
		}
		if postRunStatusOnce(ctx, log, endpoint, body, status, i, attempts) {
			return
		}
	}
}

// postRunStatusOnce performs a single HTTP attempt. Returns true on a 2xx
// or 4xx (terminal — retrying a bad request will not help). Returns false
// on transport errors or 5xx so the caller can retry.
func postRunStatusOnce(ctx context.Context, log *progress.Logger,
	endpoint string, body []byte, status string, attempt, maxAttempts int) bool {

	cctx, cancel := context.WithTimeout(ctx, runStatusHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Progress("run-status[%s %d/%d]: request error: %v", status, attempt, maxAttempts, err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.APIKey)
	req.Header.Set("X-Agent-Version", buildinfo.Version)

	client := &http.Client{Timeout: runStatusHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		log.Progress("run-status[%s %d/%d]: POST error: %v", status, attempt, maxAttempts, err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 300 {
		return true
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		log.Progress("run-status[%s]: HTTP %d (terminal, no retry)", status, resp.StatusCode)
		return true
	}
	log.Progress("run-status[%s %d/%d]: HTTP %d from backend", status, attempt, maxAttempts, resp.StatusCode)
	return false
}
