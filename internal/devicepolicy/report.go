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
	"strings"

	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

// ComplianceReport is the agent's POST body: the verification result it
// computed on-device. It is the agent-side mirror of agent-api's
// complianceReport. AppliedHash is the backend's hash echoed verbatim — never
// recomputed locally — so the backend's byte-exact applied==desired check
// (which gates the `compliant` verdict) can succeed.
type ComplianceReport struct {
	Category     string `json:"category"`
	State        string `json:"state"`
	AppliedHash  string `json:"applied_hash"`
	AgentVersion string `json:"agent_version"`
	Platform     string `json:"platform"`
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
