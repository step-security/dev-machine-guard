package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

// FeatureKeyHooks mirrors agent-api's DeveloperMDMFeatureAIAgentsHooksInstall.
// Constant in both repos must match for the toggle to plumb through.
const FeatureKeyHooks = "ai_agents_hooks_install"

// DefaultFetchTimeout caps a single Fetch round-trip. Matches
// ingest.DefaultHookUploadTimeout for consistency with the existing
// HTTP timeout budget; the reconciler runs off the scheduled tick,
// not the hot path, so a 5s ceiling is comfortable.
const DefaultFetchTimeout = 5 * time.Second

// maxBodyBytes bounds the response read to avoid memory bloat from a
// pathological backend. The real payload is < 1 KiB; 64 KiB is plenty
// of slack.
const maxBodyBytes = 64 * 1024

// FetchResult is what one successful Fetch resolves to. Today there is
// only a single toggle; future fields land here as the contract grows.
type FetchResult struct {
	Enabled bool
}

// Fetcher returns the desired feature state for one device.
type Fetcher interface {
	Fetch(ctx context.Context, customerID, deviceID string) (FetchResult, error)
}

// HTTPFetcher is the production Fetcher. Safe for concurrent use; the
// underlying *http.Client owns connection state.
type HTTPFetcher struct {
	endpoint string
	apiKey   string
	http     *http.Client
}

// NewHTTPFetcher constructs a Fetcher from a strict enterprise config
// (the same gate the upload path uses). Returns ok=false when the
// config is incomplete — the caller treats nil as "skip reconcile",
// matching how upload disables itself in community mode.
func NewHTTPFetcher(cfg ingest.Config, h *http.Client) (*HTTPFetcher, bool) {
	endpoint := strings.TrimSpace(cfg.APIEndpoint)
	apiKey := strings.TrimSpace(cfg.APIKey)
	if endpoint == "" || apiKey == "" {
		return nil, false
	}
	if h == nil {
		h = &http.Client{Timeout: DefaultFetchTimeout}
	}
	return &HTTPFetcher{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		http:     h,
	}, true
}

// featuresEnvelope is the agent-api response shape:
//
//	{"features": {"ai_agents_hooks_install": {"enabled": bool}, ...}}
type featuresEnvelope struct {
	Features map[string]featureState `json:"features"`
}

type featureState struct {
	Enabled bool `json:"enabled"`
}

// Fetch issues the GET against /developer-mdm-agent/features. Missing
// feature key in the response ⇒ Enabled=false (matches server-side
// baseline-disabled default; backend keeps unset features out of the
// map rather than emitting a zero entry).
func (c *HTTPFetcher) Fetch(ctx context.Context, customerID, deviceID string) (FetchResult, error) {
	if c == nil {
		return FetchResult{}, errors.New("state: nil fetcher")
	}
	if strings.TrimSpace(customerID) == "" {
		return FetchResult{}, errors.New("state: empty customer_id")
	}
	if strings.TrimSpace(deviceID) == "" {
		return FetchResult{}, errors.New("state: empty device_id")
	}

	endpoint := c.endpoint +
		"/v1/" + url.PathEscape(customerID) +
		"/developer-mdm-agent/features?device_id=" + url.QueryEscape(deviceID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return FetchResult{}, fmt.Errorf("state: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := c.http.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("state: transport: %s", redact.String(err.Error()))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		return FetchResult{}, fmt.Errorf("state: unexpected status %d: %s",
			resp.StatusCode, redact.String(strings.TrimSpace(string(snippet))))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return FetchResult{}, fmt.Errorf("state: read body: %w", err)
	}
	var env featuresEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return FetchResult{}, fmt.Errorf("state: decode body: %w", err)
	}
	return FetchResult{Enabled: env.Features[FeatureKeyHooks].Enabled}, nil
}
