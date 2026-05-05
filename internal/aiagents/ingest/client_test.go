package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
)

func okClientConfig() Config {
	return Config{
		CustomerID:  "cus_123",
		APIEndpoint: "https://dmg.example.com",
		APIKey:      "sk_secret_value",
	}
}

func TestNewDisabledWhenAnyFieldMissing(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty", Config{}},
		{"missing key", Config{CustomerID: "c", APIEndpoint: "https://x"}},
		{"missing endpoint", Config{CustomerID: "c", APIKey: "k"}},
		{"missing customer", Config{APIEndpoint: "https://x", APIKey: "k"}},
		{"placeholder key", Config{CustomerID: "c", APIEndpoint: "https://x", APIKey: "{{API_KEY}}"}},
		{"placeholder endpoint", Config{CustomerID: "c", APIEndpoint: "{{API_ENDPOINT}}", APIKey: "k"}},
		{"placeholder customer", Config{CustomerID: "{{CUSTOMER_ID}}", APIEndpoint: "https://x", APIKey: "k"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := New(tc.cfg, nil)
			if ok || c != nil {
				t.Errorf("expected disabled client, got ok=%v c=%v", ok, c)
			}
		})
	}
}

func TestNewEnabledWithFullConfig(t *testing.T) {
	c, ok := New(okClientConfig(), nil)
	if !ok || c == nil {
		t.Fatal("expected enabled client")
	}
}

// New owns the same trim+placeholder gate as Snapshot. A caller that
// constructs Config{} by hand (rather than via Snapshot) must not be
// able to slip whitespace-only credentials past New.
func TestNewRejectsWhitespaceOnlyFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"whitespace customer", Config{CustomerID: "   ", APIEndpoint: "https://x", APIKey: "k"}},
		{"whitespace endpoint", Config{CustomerID: "c", APIEndpoint: "\t\n", APIKey: "k"}},
		{"whitespace key", Config{CustomerID: "c", APIEndpoint: "https://x", APIKey: "  "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := New(tc.cfg, nil)
			if ok || c != nil {
				t.Errorf("expected disabled client on whitespace-only field, got ok=%v", ok)
			}
		})
	}
}

// roundTripFn is an http.RoundTripper backed by a function. Tests use
// it to inspect the outgoing request without spinning up a real
// listener for every assertion.
type roundTripFn func(*http.Request) (*http.Response, error)

func (f roundTripFn) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUploadEventsRequestShape(t *testing.T) {
	var got *http.Request
	var gotBody []byte
	rt := roundTripFn(func(r *http.Request) (*http.Response, error) {
		got = r
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})

	cfg := okClientConfig()
	cfg.APIEndpoint = "https://dmg.example.com/" // trailing slash on purpose
	c, ok := New(cfg, &http.Client{Transport: rt})
	if !ok {
		t.Fatal("client disabled")
	}

	ev := event.Event{
		SchemaVersion: event.SchemaVersion,
		EventID:       "abc",
		Timestamp:     time.Now().UTC(),
		AgentName:     "claude-code",
		HookEvent:     event.HookPreToolUse,
		ResultStatus:  event.ResultObserved,
		CustomerID:    "cus_123",
		DeviceID:      "C02ABCD1234",
		UserIdentity:  "alice@example.com",
	}
	if err := c.UploadEvents(context.Background(), "cus_123", []event.Event{ev}); err != nil {
		t.Fatalf("UploadEvents: %v", err)
	}

	if got.Method != http.MethodPost {
		t.Errorf("method=%s want POST", got.Method)
	}
	if got.URL.String() != "https://dmg.example.com/v1/cus_123/ai-agents/events" {
		t.Errorf("url=%s — want /v1/cus_123/ai-agents/events", got.URL)
	}
	if h := got.Header.Get("Authorization"); h != "Bearer sk_secret_value" {
		t.Errorf("Authorization header=%q", h)
	}
	if h := got.Header.Get("Content-Type"); h != "application/json" {
		t.Errorf("Content-Type header=%q", h)
	}
	if h := got.Header.Get("User-Agent"); !strings.HasPrefix(h, "dev-machine-guard/") {
		t.Errorf("User-Agent header=%q — want dev-machine-guard/<version>", h)
	}

	// Body must be a raw JSON array — no envelope.
	var arr []map[string]any
	if err := json.Unmarshal(gotBody, &arr); err != nil {
		t.Fatalf("body not a JSON array: %v: %q", err, gotBody)
	}
	if len(arr) != 1 {
		t.Fatalf("expected 1 event in array, got %d: %v", len(arr), arr)
	}
	first := arr[0]
	for _, key := range []string{"event_id", "customer_id", "device_id", "user_identity"} {
		if v, ok := first[key]; !ok || v == "" {
			t.Errorf("array[0].%s missing or empty: %v", key, first[key])
		}
	}
	if first["event_id"] != "abc" || first["customer_id"] != "cus_123" {
		t.Errorf("array[0] identity fields mismatched: %v", first)
	}
}

func TestUploadEventsURLEscapesCustomerID(t *testing.T) {
	var gotURL string
	rt := roundTripFn(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})
	c, _ := New(okClientConfig(), &http.Client{Transport: rt})
	if err := c.UploadEvents(context.Background(), "cus/with slash", []event.Event{{}}); err != nil {
		t.Fatalf("UploadEvents: %v", err)
	}
	if !strings.Contains(gotURL, "/v1/cus%2Fwith%20slash/ai-agents/events") {
		t.Errorf("customer_id not URL-escaped: %s", gotURL)
	}
}

func TestUploadEventsRejectsEmptyCustomerID(t *testing.T) {
	c, _ := New(okClientConfig(), &http.Client{})
	if err := c.UploadEvents(context.Background(), "  ", []event.Event{{}}); err == nil {
		t.Error("expected error for empty customer_id")
	}
}

func TestUploadEventsSuccessStatuses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusConflict} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			rt := roundTripFn(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Body:       io.NopCloser(strings.NewReader("ok")),
					Header:     make(http.Header),
				}, nil
			})
			c, _ := New(okClientConfig(), &http.Client{Transport: rt})
			err := c.UploadEvents(context.Background(), "cus_123", []event.Event{{}})
			if err != nil {
				t.Errorf("status %d treated as failure: %v", status, err)
			}
		})
	}
}

func TestUploadEvents500ReturnsErrorWithoutAPIKey(t *testing.T) {
	rt := roundTripFn(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("internal explosion")),
			Header:     make(http.Header),
		}, nil
	})
	c, _ := New(okClientConfig(), &http.Client{Transport: rt})
	err := c.UploadEvents(context.Background(), "cus_123", []event.Event{{}})
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if strings.Contains(err.Error(), "sk_secret_value") {
		t.Errorf("API key leaked into error: %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error does not mention status code: %v", err)
	}
}

func TestUploadEventsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	cfg := okClientConfig()
	cfg.APIEndpoint = srv.URL
	c, _ := New(cfg, srv.Client())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := c.UploadEvents(ctx, "cus_123", []event.Event{{}})
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context cancellation in error, got %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("cancel did not return promptly: %v", d)
	}
}

// Nil receiver is a fail-open contract: a runtime that disabled upload
// (no Client constructed) must not panic if it accidentally calls into
// a nil client.
func TestUploadEventsNilReceiver(t *testing.T) {
	var c *Client
	err := c.UploadEvents(context.Background(), "cus_123", []event.Event{{}})
	if err == nil {
		t.Error("expected error from nil receiver")
	}
}
