package devicepolicy

import (
	"bytes"
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

	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

// DefaultHTTPTimeout caps a single fetch or report round-trip. Enforcement runs
// off the scheduled tick, not a hot path, so a 5s ceiling is comfortable and
// matches the hook fetcher's budget.
const DefaultHTTPTimeout = 5 * time.Second

// maxBodyBytes bounds the small reads: the non-200 error snippet and the
// Reporter's non-2xx snippet + body drain. The compiled extensions.allowed
// payload is well under 1 KiB; 256 KiB is generous slack while still bounding a
// pathological backend error body from inflating an error string / log line.
const maxBodyBytes = 256 * 1024

// maxRunConfigBytes bounds the run-config success-body read. The policy slice
// is tiny, but the run-config document also carries the detection-rules bundle,
// and json.Unmarshal must parse the whole document to reach `policy` — a
// mid-bundle 256 KiB truncation would yield invalid JSON, a spurious fetch
// error, and silently-stopped enforcement. 4 MiB mirrors the rules fetcher's
// own maxBundleBytes. Kept separate from maxBodyBytes so the small
// error-snippet / drain reads stay bounded at 256 KiB.
const maxRunConfigBytes = 4 << 20

// EffectivePolicy is the parsed device-policy directive, lifted from the
// `policy` sub-object of the run-config response (it mirrors agent-api's
// EffectivePolicyResponse). Policy carries the compiled policy object as
// canonical JSON — the exact bytes the backend hashed — kept RAW because its
// shape is per-category: for ide_extension it is the settings map (VS Code
// setting id, e.g. "extensions.allowed" / "extensions.gallery.serviceUrl", → that
// setting's compiled value), for package_config it is the npm registry object.
// Each category decodes what it needs; the agent writes the compiled values
// verbatim and never re-serializes (re-serialization could reorder keys and break
// the backend's byte-exact applied==desired check). Policy identity is
// (Category, Target); Target defaults to vscode for ide_extension. Enforcement
// selects the channel: "mdm" is verify-only (probe and report, never a write),
// "dmg" or "" is the write-and-verify path. A zero EffectivePolicy
// (present()==false) means run-config carried no directive for this
// category/target → reconciler no-op.
type EffectivePolicy struct {
	Category    string
	Target      string
	Clear       bool
	Policy      json.RawMessage
	Hash        string
	GeneratedAt string
	Enforcement string
}

// present reports whether the backend expressed a policy directive for this
// category — a value to enforce, or an explicit clear. The fetcher guarantees
// clear=false ⇒ a non-empty policy object, so the only successful-fetch state
// with neither is "no policy in run-config" (absent), which the reconciler
// treats as a no-op (NEVER a clear).
func (ep EffectivePolicy) present() bool { return ep.Clear || len(ep.Policy) > 0 }

// policyEnvelope is the wire shape of the run-config `policy` sub-object (must
// match agent-api EffectivePolicyResponse). `policy` stays raw for the same
// per-category reason as EffectivePolicy.Policy. Unknown fields are ignored, so a
// backend emitting extra fields the agent does not model stays compatible.
type policyEnvelope struct {
	Category    string          `json:"category"`
	Target      string          `json:"target"`
	Clear       bool            `json:"clear"`
	Policy      json.RawMessage `json:"policy,omitempty"`
	Hash        string          `json:"hash,omitempty"`
	GeneratedAt string          `json:"generated_at"`
	Enforcement string          `json:"enforcement,omitempty"` // "dmg" | "mdm" | ""
}

// Fetcher returns the effective policy for one device + category + target.
type Fetcher interface {
	Fetch(ctx context.Context, customerID, deviceID, category, target string) (EffectivePolicy, error)
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
// /v1/:customer/developer-mdm-agent/run-config?device_id=…&category=…&target=…
// over the existing agent auth channel (Bearer tenant key) and lifts the
// device-policy directive from the response's `policy` sub-object. An empty
// category defaults to ide_extension and an empty target to vscode. It returns a
// parsed EffectivePolicy or an error. Any error is the reconciler's signal to
// NO-OP (never wipe enforcement on a transient failure or malformed payload):
//   - transport / non-200 status → error;
//   - body that is not valid JSON → error;
//   - a non-clear result missing policy or hash → error (a malformed policy
//     must not be written, and must not be mistaken for a clear);
//   - a non-clear policy that is not itself a JSON object → error (a string or
//     array written verbatim could even read back "compliant");
//   - a non-clear ide_extension policy whose settings map does not carry an
//     extensions.allowed object → error (validateCategoryPolicy). The check is
//     category-gated: a package_config policy legitimately has no such key.
//
// An omitted/null `policy` is NOT an error: it means run-config carried no
// directive for this category/target (a degraded/rules-only response, an older
// backend not yet emitting policy, or an unknown category/target). Fetch returns
// a zero EffectivePolicy (present()==false) and a nil error, and the reconciler
// no-ops. Unassignment is signaled by the explicit clear:true directive, never
// by absence. A response whose `policy` omits `target` defaults to the requested
// target.
func (c *HTTPFetcher) Fetch(ctx context.Context, customerID, deviceID, category, target string) (EffectivePolicy, error) {
	if c == nil {
		return EffectivePolicy{}, errors.New("devicepolicy: nil fetcher")
	}
	if strings.TrimSpace(customerID) == "" {
		return EffectivePolicy{}, errors.New("devicepolicy: empty customer_id")
	}
	if strings.TrimSpace(deviceID) == "" {
		return EffectivePolicy{}, errors.New("devicepolicy: empty device_id")
	}
	if strings.TrimSpace(category) == "" {
		category = CategoryIDEExtension
	}
	if strings.TrimSpace(target) == "" {
		target = TargetVSCode
	}

	endpoint := c.endpoint +
		"/v1/" + url.PathEscape(customerID) +
		"/developer-mdm-agent/run-config?device_id=" + url.QueryEscape(deviceID) +
		"&category=" + url.QueryEscape(category) +
		"&target=" + url.QueryEscape(target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return EffectivePolicy{}, fmt.Errorf("devicepolicy: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := c.http.Do(req)
	if err != nil {
		return EffectivePolicy{}, fmt.Errorf("devicepolicy: transport: %s", redact.String(err.Error()))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		return EffectivePolicy{}, fmt.Errorf("devicepolicy: unexpected status %d: %s",
			resp.StatusCode, redact.String(strings.TrimSpace(string(snippet))))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRunConfigBytes))
	if err != nil {
		return EffectivePolicy{}, fmt.Errorf("devicepolicy: read body: %w", err)
	}
	// Decode only the `policy` sub-object of run-config; sibling fields
	// (detection_rules, …) are ignored. The pointer distinguishes an
	// omitted/null policy (no directive) from a present one.
	var env struct {
		Policy *policyEnvelope `json:"policy"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return EffectivePolicy{}, fmt.Errorf("devicepolicy: decode body: %w", err)
	}
	if env.Policy == nil {
		// Run-config carried no policy for this category → caller no-ops. NOT an
		// error and NOT a clear; unassignment is the explicit clear:true directive.
		return EffectivePolicy{}, nil
	}
	p := env.Policy

	ep := EffectivePolicy{
		Category:    strings.TrimSpace(p.Category),
		Target:      strings.TrimSpace(p.Target),
		Clear:       p.Clear,
		Policy:      p.Policy,
		Hash:        strings.TrimSpace(p.Hash),
		GeneratedAt: p.GeneratedAt,
		Enforcement: strings.TrimSpace(p.Enforcement),
	}
	// Reject a response scoped to a different category/target than requested
	// (backend bug, proxy/cache mixup). Acting on it could enforce — or worse,
	// clear — the wrong pair. An empty field is not a mismatch; it defaults to
	// the requested value just below.
	if ep.Category != "" && ep.Category != category {
		return EffectivePolicy{}, fmt.Errorf("devicepolicy: response category %q does not match requested %q", ep.Category, category)
	}
	if ep.Target != "" && ep.Target != target {
		return EffectivePolicy{}, fmt.Errorf("devicepolicy: response target %q does not match requested %q", ep.Target, target)
	}
	if ep.Category == "" {
		ep.Category = category
	}
	if ep.Target == "" {
		ep.Target = target
	}
	if !ep.Clear {
		// A non-clear directive must carry a policy object and a hash.
		if len(ep.Policy) == 0 || ep.Hash == "" {
			return EffectivePolicy{}, errors.New("devicepolicy: malformed policy: clear=false but policy or hash missing")
		}
		// The compiled policy is always a JSON object, in EVERY category. Shape is
		// checked here so a malformed payload no-ops at the reconciler; a
		// string/array/scalar written verbatim could even read back "compliant".
		if !isJSONObject(ep.Policy) {
			return EffectivePolicy{}, errors.New("devicepolicy: malformed policy: policy is not a JSON object")
		}
		if err := validateCategoryPolicy(ep.Category, ep.Policy); err != nil {
			return EffectivePolicy{}, err
		}
	}
	return ep, nil
}

// validateCategoryPolicy applies the per-category structural checks that top-level
// object shape does not cover. It is category-GATED on purpose: the raw policy is
// shaped differently per category, so an ide_extension key requirement must never
// be imposed on a package_config object.
//
//   - ide_extension: extensions.allowed is the mandatory core of the policy, it
//     MUST be present and a JSON object. This rejects an allowlist-missing settings
//     map (e.g. a gallery-only response) before it can be written and read back
//     "compliant". The only other supported setting is an optional HTTPS gallery URL.
//   - package_config: object shape is sufficient here. The npm structure
//     (ecosystem / registry_url / auth) is validated downstream by
//     RenderNPMRCBlock, which rejects a malformed policy before any write.
func validateCategoryPolicy(category string, policy json.RawMessage) error {
	if category != CategoryIDEExtension {
		return nil
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(policy, &settings); err != nil {
		return fmt.Errorf("devicepolicy: malformed policy: settings map: %w", err)
	}
	allow, ok := settings[allowedExtensionsSettingKey]
	if !ok {
		return errors.New("devicepolicy: malformed policy: settings missing " + allowedExtensionsSettingKey)
	}
	if !isJSONObject(allow) {
		return errors.New("devicepolicy: malformed policy: " + allowedExtensionsSettingKey + " is not a JSON object")
	}
	for key, value := range settings {
		switch key {
		case allowedExtensionsSettingKey:
		case galleryServiceURLSettingKey:
			var raw string
			if err := json.Unmarshal(value, &raw); err != nil || raw == "" || len(raw) > 2048 || raw != strings.TrimSpace(raw) ||
				strings.IndexFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
				return errors.New("devicepolicy: malformed policy: invalid gallery URL")
			}
			u, err := url.Parse(raw)
			if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || strings.Contains(raw, "#") {
				return errors.New("devicepolicy: malformed policy: invalid gallery URL")
			}
			if port := u.Port(); port != "" {
				n, err := strconv.Atoi(port)
				if err != nil || n < 1 || n > 65535 {
					return errors.New("devicepolicy: malformed policy: invalid gallery URL")
				}
			}
		default:
			return errors.New("devicepolicy: malformed policy: unsupported IDE setting")
		}
	}
	return nil
}

// isJSONObject reports whether raw's first JSON token opens an object. Callers
// pass syntactically valid JSON (decoded by json.Unmarshal, or json.Valid-checked
// first), so only the shape needs checking.
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

// ComplianceReport is the agent's POST body: the verification result it
// computed on-device. It is the agent-side mirror of agent-api's
// complianceReport. AppliedHash is the backend's hash echoed verbatim — never
// recomputed locally — so the backend's byte-exact applied==desired check
// (which gates the `compliant` verdict) can succeed. In verify-only (mdm) mode
// AppliedHash is empty and Observed instead carries the OS-managed policy the
// agent read, keyed by VS Code setting id (the same keys as the desired policy)
// so the backend can diff like-for-like and decide drift — the agent does not
// judge match. EvaluatedEnforcement names the canonical channel the cycle
// actually ran — "dmg" or "mdm" (an empty or unrecognized request resolves to
// "dmg") — so the backend can gate on an exact match. Observed is omitted when
// empty.
type ComplianceReport struct {
	Category             string          `json:"category"`
	Target               string          `json:"target"`
	State                string          `json:"state"`
	AppliedHash          string          `json:"applied_hash"`
	EvaluatedHash        string          `json:"evaluated_hash,omitempty"`
	AgentVersion         string          `json:"agent_version"`
	Platform             string          `json:"platform"`
	Observed             json.RawMessage `json:"observed,omitempty"`
	EvaluatedEnforcement string          `json:"evaluated_enforcement,omitempty"`
}

// Reporter submits a compliance report for one device.
type Reporter interface {
	Report(ctx context.Context, customerID, deviceID string, r ComplianceReport) error
}

// HTTPReporter is the production Reporter.
type HTTPReporter struct {
	endpoint string
	apiKey   string
	http     *http.Client
}

// NewHTTPReporter builds a Reporter from the strict enterprise-config gate.
// ok=false on incomplete config.
func NewHTTPReporter(cfg ingest.Config, h *http.Client) (*HTTPReporter, bool) {
	endpoint := strings.TrimSpace(cfg.APIEndpoint)
	apiKey := strings.TrimSpace(cfg.APIKey)
	if endpoint == "" || apiKey == "" {
		return nil, false
	}
	if h == nil {
		h = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return &HTTPReporter{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		http:     h,
	}, true
}

// Report issues POST
// /v1/:customer/developer-mdm-agent/devices/:device_id/compliance over the
// existing agent auth channel — a dedicated endpoint, NOT the telemetry
// payload. The backend rejects an unregistered device_id (400) and records the
// per-device state; it computes desired_hash itself and decides compliant vs
// pending. A non-2xx is returned as an error for the caller to log.
func (c *HTTPReporter) Report(ctx context.Context, customerID, deviceID string, r ComplianceReport) error {
	if c == nil {
		return errors.New("devicepolicy: nil reporter")
	}
	if strings.TrimSpace(customerID) == "" {
		return errors.New("devicepolicy: empty customer_id")
	}
	if strings.TrimSpace(deviceID) == "" {
		return errors.New("devicepolicy: empty device_id")
	}
	if r.Category == "" {
		r.Category = CategoryIDEExtension
	}
	if r.Target == "" {
		r.Target = TargetVSCode
	}

	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("devicepolicy: marshal report: %w", err)
	}

	endpoint := c.endpoint +
		"/v1/" + url.PathEscape(customerID) +
		"/developer-mdm-agent/devices/" + url.PathEscape(deviceID) +
		"/compliance"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("devicepolicy: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("devicepolicy: transport: %s", redact.String(err.Error()))
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		return fmt.Errorf("devicepolicy: unexpected status %d: %s",
			resp.StatusCode, redact.String(strings.TrimSpace(string(snippet))))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
	return nil
}

// AgentVersion returns the running agent version reported in compliance
// payloads. Centralized here so the report and any diagnostics agree.
func AgentVersion() string { return buildinfo.Version }
