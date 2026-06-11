package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// defaultFetchTimeout caps a single run-config round-trip.
const defaultFetchTimeout = 5 * time.Second

// maxBundleBytes bounds the response read. Rule bundles are far larger than the
// feature toggle but still small; 4 MiB is generous headroom.
const maxBundleBytes = 4 << 20

// runConfigEnvelope is the run-config response shape. Only detection_rules is
// consumed today; future fields (policy, scan_directives) are additive.
type runConfigEnvelope struct {
	DetectionRules RuleSet `json:"detection_rules"`
}

// Fetcher returns the RuleSet for one device. Implemented by HTTPFetcher and
// stubbed in tests.
type Fetcher interface {
	Fetch(ctx context.Context, customerID, deviceID string) (RuleSet, error)
}

// HTTPFetcher fetches the run-config bundle over TLS + bearer auth. It is a
// near-verbatim clone of internal/aiagents/state/fetcher.go, differing only in
// the URL path and decode target. Safe for concurrent use.
type HTTPFetcher struct {
	endpoint string
	apiKey   string
	http     *http.Client
}

// NewHTTPFetcher constructs an HTTPFetcher from the enterprise config. Returns
// ok=false when endpoint/apiKey are missing — the caller treats that as "no
// rules" (scan nothing).
func NewHTTPFetcher(endpoint, apiKey string, h *http.Client) (*HTTPFetcher, bool) {
	endpoint = strings.TrimSpace(endpoint)
	apiKey = strings.TrimSpace(apiKey)
	if endpoint == "" || apiKey == "" {
		return nil, false
	}
	if h == nil {
		h = &http.Client{Timeout: defaultFetchTimeout}
	}
	return &HTTPFetcher{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		http:     h,
	}, true
}

// Fetch issues GET /v1/{customer}/developer-mdm-agent/run-config?device_id=…
// and returns the (unprepared) RuleSet from the envelope. Errors are redacted.
func (c *HTTPFetcher) Fetch(ctx context.Context, customerID, deviceID string) (RuleSet, error) {
	if c == nil {
		return RuleSet{}, errors.New("rules: nil fetcher")
	}
	if strings.TrimSpace(customerID) == "" {
		return RuleSet{}, errors.New("rules: empty customer_id")
	}
	if strings.TrimSpace(deviceID) == "" {
		return RuleSet{}, errors.New("rules: empty device_id")
	}

	endpoint := c.endpoint +
		"/v1/" + url.PathEscape(customerID) +
		"/developer-mdm-agent/run-config?device_id=" + url.QueryEscape(deviceID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return RuleSet{}, fmt.Errorf("rules: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := c.http.Do(req)
	if err != nil {
		return RuleSet{}, fmt.Errorf("rules: transport: %s", redact.String(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes))
		return RuleSet{}, fmt.Errorf("rules: unexpected status %d: %s",
			resp.StatusCode, redact.String(strings.TrimSpace(string(snippet))))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes))
	if err != nil {
		return RuleSet{}, fmt.Errorf("rules: read body: %w", err)
	}
	var env runConfigEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return RuleSet{}, fmt.Errorf("rules: decode body: %w", err)
	}
	return env.DetectionRules, nil
}

// FetchOrEmpty fetches and validates the RuleSet, returning an empty RuleSet on
// ANY failure (nil fetcher, transport, non-200, oversized body, decode, or
// Prepare rejection). It logs the reason and never returns an error — a failing
// rules API must never fail the run. An empty RuleSet makes Scan a
// no-op.
func FetchOrEmpty(ctx context.Context, f Fetcher, customerID, deviceID string, log *progress.Logger) RuleSet {
	if log == nil {
		log = progress.NewNoop()
	}
	if f == nil {
		log.Warn("malicious_file_scan: rule fetch failed (no fetcher configured) — skipping scan this run")
		return RuleSet{}
	}
	rs, err := f.Fetch(ctx, customerID, deviceID)
	if err != nil {
		log.Warn("malicious_file_scan: rule fetch failed (%s) — skipping scan this run", redact.String(err.Error()))
		return RuleSet{}
	}
	if err := rs.Prepare(); err != nil {
		log.Warn("malicious_file_scan: rule bundle invalid (%s) — skipping scan this run", redact.String(err.Error()))
		return RuleSet{}
	}
	log.Debug("malicious_file_scan: fetched rules count=%d source=backend", len(rs.Rules))
	return rs
}

// LoadFileOrEmpty loads a RuleSet from a local JSON file (the dev-only
// --rules-file flag), accepting either a bare RuleSet or a run-config envelope.
// Returns an empty RuleSet on any error. Mirrors FetchOrEmpty's fail-safe
// contract so an offline run degrades exactly like a failed backend fetch.
func LoadFileOrEmpty(path string, log *progress.Logger) RuleSet {
	if log == nil {
		log = progress.NewNoop()
	}
	data, err := os.ReadFile(path) // #nosec G304 -- dev-only flag; operator-supplied path
	if err != nil {
		log.Warn("malicious_file_scan: rules-file read failed (%s) — skipping scan this run", redact.String(err.Error()))
		return RuleSet{}
	}
	var rs RuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		log.Warn("malicious_file_scan: rules-file parse failed (%s) — skipping scan this run", redact.String(err.Error()))
		return RuleSet{}
	}
	if len(rs.Rules) == 0 {
		var env runConfigEnvelope
		if err := json.Unmarshal(data, &env); err == nil && len(env.DetectionRules.Rules) > 0 {
			rs = env.DetectionRules
		}
	}
	if err := rs.Prepare(); err != nil {
		log.Warn("malicious_file_scan: rules-file invalid (%s) — skipping scan this run", redact.String(err.Error()))
		return RuleSet{}
	}
	log.Debug("malicious_file_scan: fetched rules count=%d source=local-file", len(rs.Rules))
	return rs
}
