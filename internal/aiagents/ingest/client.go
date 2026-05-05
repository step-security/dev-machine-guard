package ingest

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
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

// DefaultHookUploadTimeout caps how long the hot path will wait on the
// backend per hook invocation. Each hook is a fresh process, so every
// upload pays a cold TCP+TLS handshake; tighter caps proved fragile
// under load. Past this, the right answer is an async sidecar approach,
// not a bigger sync timeout.
const DefaultHookUploadTimeout = 5 * time.Second

// maxErrorBody bounds how much of a non-success response body the
// client reads into error messages, capping the redacted error log.
const maxErrorBody = 1024

// Client posts events to a single configured endpoint. Safe to share
// across goroutines; the underlying *http.Client carries connection
// state.
type Client struct {
	endpoint string
	apiKey   string
	http     *http.Client
}

// New returns a client when the supplied Config has all enterprise
// credentials present and non-placeholder. The bool is false when no
// upload should be attempted; callers MUST treat that as a no-op rather
// than an error. The gate matches Snapshot's: trims surrounding
// whitespace, then rejects empty values and `{{...}}` placeholders.
// New owns the gate so a caller passing a hand-built Config (not the
// product of Snapshot) cannot bypass it.
func New(cfg Config, h *http.Client) (*Client, bool) {
	customer := strings.TrimSpace(cfg.CustomerID)
	endpoint := strings.TrimSpace(cfg.APIEndpoint)
	apiKey := strings.TrimSpace(cfg.APIKey)
	if !valid(customer) || !valid(endpoint) || !valid(apiKey) {
		return nil, false
	}
	if h == nil {
		h = &http.Client{Timeout: DefaultHookUploadTimeout}
	}
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		http:     h,
	}, true
}

// UploadEvents POSTs events to /v1/{customer_id}/ai-agents/events as a
// raw JSON array. Each event already carries its own schema_version,
// identity, and policy fields, so no envelope wraps the array — the
// backend reads the indexed columns directly from each event.
//
// Statuses 200, 201, 202, and 409 are treated as success. 409 is
// success because backend ingestion is idempotent on
// (device_id, event_id); duplicate retries must not become client
// errors.
func (c *Client) UploadEvents(ctx context.Context, customerID string, events []event.Event) error {
	if c == nil {
		return errors.New("ingest: nil client")
	}
	if strings.TrimSpace(customerID) == "" {
		return errors.New("ingest: empty customer_id")
	}

	// Copy by value so any later mutation of the caller's events cannot
	// race the in-flight request body.
	body, err := json.Marshal(append([]event.Event(nil), events...))
	if err != nil {
		return fmt.Errorf("ingest: marshal events: %w", err)
	}

	endpoint := c.endpoint + "/v1/" + url.PathEscape(customerID) + "/ai-agents/events"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ingest: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("ingest: transport: %s", redact.String(err.Error()))
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusConflict:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		return nil
	}

	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	return fmt.Errorf("ingest: unexpected status %d: %s",
		resp.StatusCode, redact.String(strings.TrimSpace(string(snippet))))
}
