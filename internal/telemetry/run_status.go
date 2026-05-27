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
	runStatusStartedAttempts  = 3
	runStatusFailedAttempts   = 2
	runStatusProgressAttempts = 2
	runStatusRetryBackoff     = 500 * time.Millisecond

	// runStatusHeartbeatInterval is how often the telemetry run posts a
	// status_info snapshot while a scan is in flight. Phase-boundary posts
	// fire on top of this so a fast run still surfaces phase completions
	// without waiting for the next tick.
	runStatusHeartbeatInterval = 5 * time.Minute
)

// runStatusBody is the JSON shape posted to /telemetry/run-status. Fields
// marked omitempty are unset for terminal posts; status_info is only sent
// on progress updates (status == "started" with phase data attached).
type runStatusBody struct {
	ExecutionID      string         `json:"execution_id"`
	DeviceID         string         `json:"device_id"`
	Status           string         `json:"status"`
	AgentVersion     string         `json:"agent_version"`
	Platform         string         `json:"platform"`
	InvocationMethod string         `json:"invocation_method,omitempty"`
	ErrorMessage     string         `json:"error_message,omitempty"`
	StatusInfo       *RunStatusInfo `json:"status_info,omitempty"`
}

// reportRunStatus POSTs a lifecycle transition to the backend with a small
// retry budget. Never returns an error: running the scan is the priority.
//
// status must be "started" or "failed". Passing "succeeded" (or any other
// value) is a defensive no-op — success is written by the backend worker
// after it persists the uploaded telemetry. invocationMethod identifies
// whether this run was triggered by an installed scheduler or a manual CLI
// invocation; an empty string is tolerated (the backend treats it as
// "unknown") so this stays callable from contexts that haven't detected it.
func reportRunStatus(ctx context.Context, log *progress.Logger,
	executionID, deviceID, status, errMsg, invocationMethod string) {

	if !config.IsEnterpriseMode() {
		return
	}
	if status != runStatusStarted && status != runStatusFailed {
		return
	}
	if executionID == "" {
		return
	}

	body := runStatusBody{
		ExecutionID:      executionID,
		DeviceID:         deviceID,
		Status:           status,
		AgentVersion:     buildinfo.Version,
		Platform:         runtime.GOOS,
		InvocationMethod: invocationMethod,
	}
	if status == runStatusFailed {
		if errMsg == "" {
			// Backend rejects a "failed" report with no error_message.
			errMsg = "unspecified failure"
		}
		if len(errMsg) > runStatusMaxErrorChars {
			errMsg = errMsg[:runStatusMaxErrorChars]
		}
		body.ErrorMessage = errMsg
	}

	attempts := runStatusFailedAttempts
	if status == runStatusStarted {
		attempts = runStatusStartedAttempts
	}
	postRunStatusWithRetry(ctx, log, body, attempts)
}

// postProgress sends an idempotent in-flight progress snapshot. The backend
// treats this as status=started with status_info populated — it upserts the
// progress fields without touching the row's terminal state. Best-effort: a
// dropped heartbeat is recovered by the next tick five minutes later, so we
// keep the retry budget low (matching "failed") and never block the scan.
func postProgress(ctx context.Context, log *progress.Logger,
	executionID, deviceID, invocationMethod string, info RunStatusInfo) {

	if !config.IsEnterpriseMode() {
		return
	}
	if executionID == "" {
		return
	}

	infoCopy := info // RunStatusInfo is a struct of slice + scalars; copy is cheap
	body := runStatusBody{
		ExecutionID:      executionID,
		DeviceID:         deviceID,
		Status:           runStatusStarted, // backend distinguishes progress vs terminal by presence of status_info
		AgentVersion:     buildinfo.Version,
		Platform:         runtime.GOOS,
		InvocationMethod: invocationMethod,
		StatusInfo:       &infoCopy,
	}
	postRunStatusWithRetry(ctx, log, body, runStatusProgressAttempts)
}

func postRunStatusWithRetry(ctx context.Context, log *progress.Logger,
	body runStatusBody, attempts int) {

	encoded, err := json.Marshal(body)
	if err != nil {
		log.Progress("run-status: marshal error: %v", err)
		return
	}

	endpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/telemetry/run-status",
		config.APIEndpoint, config.CustomerID)

	for i := 1; i <= attempts; i++ {
		if i > 1 {
			// Fixed short backoff. Keeps the total time budget bounded so
			// retries don't visibly delay the scan start.
			select {
			case <-time.After(runStatusRetryBackoff):
			case <-ctx.Done():
				// Demoted to Debug: parent ctx done means clean shutdown
				// (or operator-initiated cancel that already logged its
				// own reason). No need to add a second progress-level
				// noise line in the normal "scan finished successfully,
				// last progress post got cut off by cancelRun()" flow.
				log.Debug("run-status: parent context done, abandoning retries")
				return
			}
		}
		if postRunStatusOnce(ctx, log, endpoint, encoded, body.Status, i, attempts) {
			return
		}
	}
}

// postRunStatusOnce performs a single HTTP attempt. Returns true on a 2xx
// or 4xx (terminal — retrying a bad request will not help). Returns false
// on transport errors or 5xx so the caller can retry.
//
// Treats parent-ctx cancellation as terminal-and-quiet: the only time we
// observe ctx.Err() != nil here is shutdown (cancelRun fired). Logging a
// "POST error: context canceled" at progress level on every successful
// scan — because the final phase-boundary post raced the deferred
// cancelRun — would mislead operators into thinking the run failed.
func postRunStatusOnce(ctx context.Context, log *progress.Logger,
	endpoint string, body []byte, status string, attempt, maxAttempts int) bool {

	// Short-circuit when the scan ctx is already done — no point opening a
	// connection just to have it cancelled mid-handshake.
	if ctx.Err() != nil {
		log.Debug("run-status[%s %d/%d]: skipped (parent context done)", status, attempt, maxAttempts)
		return true
	}

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
		// Distinguish shutdown-induced cancellation from a real transport
		// error. If the parent ctx is done, this was clean shutdown — log
		// at debug and return terminal so the caller doesn't burn a retry
		// on an already-cancelled context.
		if ctx.Err() != nil {
			log.Debug("run-status[%s %d/%d]: aborted at shutdown: %v", status, attempt, maxAttempts, err)
			return true
		}
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
