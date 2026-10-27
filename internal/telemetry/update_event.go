package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

const (
	runStatusUpdate         = "update"
	invocationMethodUpdate  = "update"
	updateEventAttempts     = 3
	updateEventHTTPTimeout  = 10 * time.Second
	updateEventRetryBackoff = time.Second
	updateEventMaxError     = 2048
	runLockWait             = 5 * time.Second
)

// UpdateEvent is one self-update event (spec Contracts: Update event),
// posted to run-status with status "update".
type UpdateEvent struct {
	ExecutionID    string
	DeviceID       string
	InstallChannel string // "msi" | "loader"
	Event          string
	From, To       string
	Error          string
}

type updateEventBody struct {
	ExecutionID      string `json:"execution_id"`
	DeviceID         string `json:"device_id"`
	Status           string `json:"status"`
	AgentVersion     string `json:"agent_version"`
	Platform         string `json:"platform"`
	InvocationMethod string `json:"invocation_method"`
	InstallChannel   string `json:"install_channel"`
	UpdateEvent      string `json:"update_event"`
	UpdateFrom       string `json:"update_from,omitempty"`
	UpdateTo         string `json:"update_to,omitempty"`
	ErrorMessage     string `json:"error_message,omitempty"`
}

// ErrUpdateEventRejected means the backend answered 400/422: retrying the
// same event cannot help.
var ErrUpdateEventRejected = errors.New("run-status rejected the update event")

// PostUpdateEvent posts ev with a small retry budget. agent_version is
// always this process's version. It returns nil only on a 2xx, and
// ErrUpdateEventRejected only for 400/422 (or an event that can't be valid).
func PostUpdateEvent(ctx context.Context, client *http.Client, ev UpdateEvent) error {
	if !config.IsEnterpriseMode() {
		return errors.New("not in enterprise mode")
	}
	if ev.DeviceID == "" {
		return errors.New("no device id")
	}
	// agent-api requires install_channel and, for a rollback, update_from;
	// such an event can never be accepted, so it is reported as rejected.
	if ev.InstallChannel != "msi" && ev.InstallChannel != "loader" {
		return fmt.Errorf("%w: install_channel %q", ErrUpdateEventRejected, ev.InstallChannel)
	}
	if ev.Event == "update_rolled_back" && ev.From == "" {
		return fmt.Errorf("%w: update_rolled_back without update_from", ErrUpdateEventRejected)
	}
	if len(ev.Error) > updateEventMaxError {
		ev.Error = ev.Error[:updateEventMaxError]
	}
	body, err := json.Marshal(updateEventBody{
		ExecutionID: ev.ExecutionID, DeviceID: ev.DeviceID, Status: runStatusUpdate,
		AgentVersion: buildinfo.Version, Platform: runtime.GOOS, InvocationMethod: invocationMethodUpdate,
		InstallChannel: ev.InstallChannel, UpdateEvent: ev.Event,
		UpdateFrom: ev.From, UpdateTo: ev.To, ErrorMessage: ev.Error,
	})
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/telemetry/run-status", config.APIEndpoint, config.CustomerID)
	if client == nil {
		client = http.DefaultClient
	}
	var last error
	for i := 0; i < updateEventAttempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(updateEventRetryBackoff):
			}
		}
		last = postUpdateEventOnce(ctx, client, endpoint, body)
		if last == nil || errors.Is(last, ErrUpdateEventRejected) {
			return last
		}
	}
	return last
}

func postUpdateEventOnce(ctx context.Context, client *http.Client, endpoint string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, updateEventHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.APIKey)
	req.Header.Set("X-Agent-Version", buildinfo.Version)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity:
		// A permanent validation reject: the same body can never succeed.
		return fmt.Errorf("%w: HTTP %d", ErrUpdateEventRejected, resp.StatusCode)
	}
	// 401/403 (key rotation, WAF), 408, 429 and 5xx are transient.
	return fmt.Errorf("run-status: HTTP %d", resp.StatusCode)
}

// Env set by the bootstrap for scan runs (spec Contracts: Run record).
const (
	EnvRunRecord         = "STEPSEC_RUN_RECORD"
	EnvRunID             = "STEPSEC_RUN_ID"
	EnvBootstrapVersion  = "STEPSEC_BOOTSTRAP_VERSION"
	EnvBootstrapFallback = "STEPSEC_BOOTSTRAP_FALLBACK"
)

// markRunStarted sets the started marker on this launch's record
// (STEPSEC_RUN_ID) in the bootstrap's run file right after run-status
// "started" was accepted. Best-effort.
func markRunStarted() error {
	path, runID := os.Getenv(EnvRunRecord), os.Getenv(EnvRunID)
	if path == "" || runID == "" {
		return nil
	}
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".json") {
		return fmt.Errorf("%s=%q is not an absolute .json path", EnvRunRecord, path)
	}
	// Same lock and bounded wait as the bootstrap's run-record writes.
	return updatestate.MarkRunStartedLocked(path, runID, runLockWait)
}
