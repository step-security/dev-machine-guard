package devmdm

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

// DefaultHTTPTimeout caps a single fetch or report round-trip. Enforcement runs
// off the scheduled tick, not a hot path, so a 5s ceiling is comfortable and
// matches the hook fetcher's budget.
const DefaultHTTPTimeout = 5 * time.Second

// maxBodyBytes bounds a response read. The compiled extensions.allowed payload
// is well under 1 KiB in practice; 256 KiB is generous slack while still
// bounding a pathological backend.
const maxBodyBytes = 256 * 1024

// EffectivePolicy is the parsed FR-19 fetch contract. It is the agent-side
// mirror of agent-api's EffectivePolicyResponse. Policy carries the compiled
// VS Code extensions.allowed object as canonical JSON (sorted keys) — the exact
// bytes the backend hashed — so the agent writes it verbatim and never
// re-serializes (re-serialization could reorder keys and break the backend's
// byte-exact applied==desired check).
type EffectivePolicy struct {
	Category    string
	Clear       bool
	Policy      json.RawMessage
	Hash        string
	GeneratedAt string
}

// policyEnvelope is the wire shape (must match agent-api
// EffectivePolicyResponse). Unknown fields are ignored, so a backend still
// emitting legacy extras (e.g. the removed min_vscode_version) stays
// compatible.
type policyEnvelope struct {
	Category    string          `json:"category"`
	Clear       bool            `json:"clear"`
	Policy      json.RawMessage `json:"policy,omitempty"`
	Hash        string          `json:"hash,omitempty"`
	GeneratedAt string          `json:"generated_at"`
}

// Fetcher returns the effective policy for one device + category.
type Fetcher interface {
	Fetch(ctx context.Context, customerID, deviceID, category string) (EffectivePolicy, error)
}

// HTTPFetcher is the production Fetcher. Safe for concurrent use.
type HTTPFetcher struct {
	endpoint string
	apiKey   string
	http     *http.Client
}

// NewHTTPFetcher builds a Fetcher from the same strict enterprise-config gate
// the upload path uses (ingest.Config). ok=false on incomplete config — the
// caller treats that as "skip enforcement", matching the hook reconciler.
func NewHTTPFetcher(cfg ingest.Config, h *http.Client) (*HTTPFetcher, bool) {
	endpoint := strings.TrimSpace(cfg.APIEndpoint)
	apiKey := strings.TrimSpace(cfg.APIKey)
	if endpoint == "" || apiKey == "" {
		return nil, false
	}
	if h == nil {
		h = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return &HTTPFetcher{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		http:     h,
	}, true
}

// Fetch issues GET
// /v1/:customer/developer-mdm-agent/devices/:device_id/effective-policy?category=…
// over the existing agent auth channel (Bearer tenant key). It returns a parsed
// EffectivePolicy or an error. Any error is the reconciler's signal to NO-OP
// (never wipe enforcement on a transient failure or malformed payload):
//   - transport / non-200 status → error;
//   - body that is not a JSON object → error;
//   - a non-clear result missing policy or hash → error (a malformed policy
//     must not be written, and must not be mistaken for a clear);
//   - a non-clear policy that is not itself a JSON object → error (a string or
//     array written verbatim could even read back "compliant").
func (c *HTTPFetcher) Fetch(ctx context.Context, customerID, deviceID, category string) (EffectivePolicy, error) {
	if c == nil {
		return EffectivePolicy{}, errors.New("devmdm: nil fetcher")
	}
	if strings.TrimSpace(customerID) == "" {
		return EffectivePolicy{}, errors.New("devmdm: empty customer_id")
	}
	if strings.TrimSpace(deviceID) == "" {
		return EffectivePolicy{}, errors.New("devmdm: empty device_id")
	}
	if strings.TrimSpace(category) == "" {
		category = CategoryIDEExtension
	}

	endpoint := c.endpoint +
		"/v1/" + url.PathEscape(customerID) +
		"/developer-mdm-agent/devices/" + url.PathEscape(deviceID) +
		"/effective-policy?category=" + url.QueryEscape(category)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return EffectivePolicy{}, fmt.Errorf("devmdm: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := c.http.Do(req)
	if err != nil {
		return EffectivePolicy{}, fmt.Errorf("devmdm: transport: %s", redact.String(err.Error()))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		return EffectivePolicy{}, fmt.Errorf("devmdm: unexpected status %d: %s",
			resp.StatusCode, redact.String(strings.TrimSpace(string(snippet))))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return EffectivePolicy{}, fmt.Errorf("devmdm: read body: %w", err)
	}
	var env policyEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return EffectivePolicy{}, fmt.Errorf("devmdm: decode body: %w", err)
	}

	ep := EffectivePolicy{
		Category:    strings.TrimSpace(env.Category),
		Clear:       env.Clear,
		Policy:      env.Policy,
		Hash:        strings.TrimSpace(env.Hash),
		GeneratedAt: env.GeneratedAt,
	}
	if ep.Category == "" {
		ep.Category = category
	}
	if !ep.Clear {
		if len(ep.Policy) == 0 || ep.Hash == "" {
			return EffectivePolicy{}, errors.New("devmdm: malformed policy: clear=false but policy or hash missing")
		}
		// The compiled policy is always a JSON object. Shape is checked here so a
		// malformed payload no-ops at the reconciler; value-level validation stays
		// backend-owned.
		if !isJSONObject(ep.Policy) {
			return EffectivePolicy{}, errors.New("devmdm: malformed policy: policy is not a JSON object")
		}
	}
	return ep, nil
}

// isJSONObject reports whether raw's first JSON token opens an object. The
// envelope already passed json.Unmarshal, so raw is syntactically valid JSON —
// only the shape needs checking.
func isJSONObject(raw json.RawMessage) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		}
		return b == '{'
	}
	return false
}
