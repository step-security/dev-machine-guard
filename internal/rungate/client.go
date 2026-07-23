package rungate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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

// Checkin asks the backend whether this device is due for a full run:
// GET /v1/{customer}/developer-mdm-agent/run-directive?device_id=…[&last_run_at=…]
// lastRunAt (unix seconds, 0 = unknown) is the agent's own last successful
// upload stamp, sent as insurance against lost or laggy ingest on the backend
// side. Errors are redacted (the URL embeds the customer id and the header
// carries the tenant key). A near-verbatim sibling of rules/fetch.go.
func Checkin(ctx context.Context, endpoint, apiKey, customerID, deviceID string, lastRunAt int64) (Directive, error) {
	endpoint = strings.TrimSpace(endpoint)
	apiKey = strings.TrimSpace(apiKey)
	if endpoint == "" || apiKey == "" {
		return Directive{}, errors.New("rungate: missing endpoint or api key")
	}
	if strings.TrimSpace(customerID) == "" {
		return Directive{}, errors.New("rungate: empty customer_id")
	}
	if strings.TrimSpace(deviceID) == "" {
		return Directive{}, errors.New("rungate: empty device_id")
	}

	target := strings.TrimRight(endpoint, "/") +
		"/v1/" + url.PathEscape(customerID) +
		"/developer-mdm-agent/run-directive?device_id=" + url.QueryEscape(deviceID)
	if lastRunAt > 0 {
		target += "&last_run_at=" + strconv.FormatInt(lastRunAt, 10)
	}

	ctx, cancel := context.WithTimeout(ctx, checkinTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Directive{}, fmt.Errorf("rungate: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := (&http.Client{Timeout: checkinTimeout}).Do(req)
	if err != nil {
		return Directive{}, fmt.Errorf("rungate: transport: %s", redact.String(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxDirectiveBytes))
		return Directive{}, fmt.Errorf("rungate: unexpected status %d: %s",
			resp.StatusCode, redact.String(strings.TrimSpace(string(snippet))))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectiveBytes))
	if err != nil {
		return Directive{}, fmt.Errorf("rungate: read body: %w", err)
	}
	var env directiveEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Directive{}, fmt.Errorf("rungate: decode body: %w", err)
	}
	// A 200 with no directive object is an unknown shape — surface it as an
	// error so the caller fails open rather than trusting a zero value.
	if env.Directive.Mode == "" {
		return Directive{}, errors.New("rungate: response carried no directive")
	}
	return env.Directive, nil
}
