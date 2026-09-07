package rungate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

// checkinTimeout caps the whole check-in round-trip. The gate runs before any
// beacon on every scheduler wakeup, so it must give up fast and fail open —
// an offline laptop pays this once per wakeup.
const checkinTimeout = 5 * time.Second

// maxDirectiveBytes bounds the response read. A directive is ~200 bytes;
// anything near the cap is not our backend.
const maxDirectiveBytes = 64 << 10

// Checkin asks the backend whether this device is due for a full run. The
// gating decision rides the existing run-config response (its scan_directive
// block), so there is no dedicated endpoint:
// GET /v1/{customer}/developer-mdm-agent/run-config?device_id=…[&last_run_at=…]
// lastRunAt (unix seconds, 0 = unknown) is the agent's own last successful
// upload stamp, sent as insurance against lost or laggy ingest on the backend
// side. Only scan_directive is read here; detection_rules/policy in the same
// response are ignored (the scan path fetches run-config for those in its own
// phase). Errors are redacted (the URL embeds the customer id and the header
// carries the tenant key). A near-verbatim sibling of rules/fetch.go.
func Checkin(ctx context.Context, endpoint, apiKey, customerID, deviceID string, lastRunAt int64) (Directive, WSLDirective, error) {
	endpoint = strings.TrimSpace(endpoint)
	apiKey = strings.TrimSpace(apiKey)
	if endpoint == "" || apiKey == "" {
		return Directive{}, WSLDirective{}, errors.New("rungate: missing endpoint or api key")
	}
	if strings.TrimSpace(customerID) == "" {
		return Directive{}, WSLDirective{}, errors.New("rungate: empty customer_id")
	}
	if strings.TrimSpace(deviceID) == "" {
		return Directive{}, WSLDirective{}, errors.New("rungate: empty device_id")
	}

	target := strings.TrimRight(endpoint, "/") +
		"/v1/" + url.PathEscape(customerID) +
		"/developer-mdm-agent/run-config?device_id=" + url.QueryEscape(deviceID)
	if lastRunAt > 0 {
		target += "&last_run_at=" + strconv.FormatInt(lastRunAt, 10)
	}

	ctx, cancel := context.WithTimeout(ctx, checkinTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Directive{}, WSLDirective{}, fmt.Errorf("rungate: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := (&http.Client{Timeout: checkinTimeout}).Do(req)
	if err != nil {
		return Directive{}, WSLDirective{}, fmt.Errorf("rungate: transport: %s", redact.String(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxDirectiveBytes))
		return Directive{}, WSLDirective{}, fmt.Errorf("rungate: unexpected status %d: %s",
			resp.StatusCode, redact.String(strings.TrimSpace(string(snippet))))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectiveBytes))
	if err != nil {
		return Directive{}, WSLDirective{}, fmt.Errorf("rungate: read body: %w", err)
	}
	var env runConfigEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Directive{}, WSLDirective{}, fmt.Errorf("rungate: decode body: %w", err)
	}
	// A 200 with no scan_directive is an unknown shape (or an older backend
	// that predates run gating) — surface it as an error so the caller fails
	// open rather than trusting a zero value.
	if env.ScanDirective == nil || env.ScanDirective.Mode == "" {
		return Directive{}, WSLDirective{}, errors.New("rungate: response carried no scan_directive")
	}
	// wsl_directive is optional and fails closed: a backend that does not send
	// it yields the zero value, i.e. distro scanning off.
	var wsl WSLDirective
	if env.WSLDirective != nil {
		wsl = *env.WSLDirective
	}
	return *env.ScanDirective, wsl, nil
}

// skipBeaconTimeout bounds the gated-skip heartbeat POST. Kept short: it is
// best-effort and must never delay the fast exit of a skipped wakeup.
const skipBeaconTimeout = 5 * time.Second

// skipBeaconBody is the run-status POST for a gated skip. It mirrors the
// backend's APIV2SubmitTelemetryRunStatus request (the status="skipped"
// branch): a standalone check-in row, no started/terminal lifecycle.
type skipBeaconBody struct {
	ExecutionID    string `json:"execution_id"`
	DeviceID       string `json:"device_id"`
	Status         string `json:"status"`
	AgentVersion   string `json:"agent_version"`
	Platform       string `json:"platform"`
	SkipReason     string `json:"skip_reason,omitempty"`
	NextEligibleAt int64  `json:"next_eligible_at,omitempty"`
}

// PostSkipBeacon best-effort reports a gated-skip heartbeat to the backend so
// the console can show that the agent checked in and was told not to scan (a
// gated skip otherwise leaves no server-side trace). Fire-and-forget by
// contract: any error (offline, non-200) is returned for a debug log only and
// never affects the run — the gate has already decided to skip. A fresh UUID
// per skip makes each a standalone row; the backend gives them a short TTL.
func PostSkipBeacon(ctx context.Context, endpoint, apiKey, customerID, deviceID, reason string, nextEligibleAt int64) error {
	endpoint = strings.TrimSpace(endpoint)
	apiKey = strings.TrimSpace(apiKey)
	if endpoint == "" || apiKey == "" || strings.TrimSpace(customerID) == "" || strings.TrimSpace(deviceID) == "" {
		return errors.New("rungate: missing endpoint/key/customer/device for skip beacon")
	}

	execID, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("rungate: skip beacon uuid: %w", err)
	}
	payload, err := json.Marshal(skipBeaconBody{
		ExecutionID:    execID.String(),
		DeviceID:       deviceID,
		Status:         "skipped", // backend runStatusSkipped; distinct from the directive Mode "skip"
		AgentVersion:   buildinfo.Version,
		Platform:       runtime.GOOS,
		SkipReason:     reason,
		NextEligibleAt: nextEligibleAt,
	})
	if err != nil {
		return fmt.Errorf("rungate: marshal skip beacon: %w", err)
	}

	target := strings.TrimRight(endpoint, "/") +
		"/v1/" + url.PathEscape(customerID) +
		"/developer-mdm-agent/telemetry/run-status"

	ctx, cancel := context.WithTimeout(ctx, skipBeaconTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("rungate: build skip beacon request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := (&http.Client{Timeout: skipBeaconTimeout}).Do(req)
	if err != nil {
		return fmt.Errorf("rungate: skip beacon transport: %s", redact.String(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDirectiveBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rungate: skip beacon unexpected status %d", resp.StatusCode)
	}
	return nil
}
