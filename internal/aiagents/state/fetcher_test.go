package state

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
)

func newTestServer(t *testing.T, status int, body string) (*httptest.Server, *HTTPFetcher) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", got)
		}
		if got := r.URL.Query().Get("device_id"); got != "dev-1" {
			t.Errorf("device_id = %q, want dev-1", got)
		}
		if !strings.Contains(r.URL.Path, "/developer-mdm-agent/features") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	f, ok := NewHTTPFetcher(ingest.Config{APIEndpoint: srv.URL, APIKey: "test-key"}, srv.Client())
	if !ok {
		t.Fatal("NewHTTPFetcher returned ok=false on valid config")
	}
	return srv, f
}

func TestFetcherEnabled(t *testing.T) {
	_, f := newTestServer(t, 200, `{"features":{"ai_agents_hooks_install":{"enabled":true}}}`)
	res, err := f.Fetch(context.Background(), "cust", "dev-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.Enabled {
		t.Fatal("Enabled should be true")
	}
}

func TestFetcherDisabled(t *testing.T) {
	_, f := newTestServer(t, 200, `{"features":{"ai_agents_hooks_install":{"enabled":false}}}`)
	res, err := f.Fetch(context.Background(), "cust", "dev-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Enabled {
		t.Fatal("Enabled should be false")
	}
}

func TestFetcherMissingKeyMeansDisabled(t *testing.T) {
	// Server omits the key entirely: the agent-api baseline-disabled
	// default keeps features out of the map until a customer-level
	// override exists.
	_, f := newTestServer(t, 200, `{"features":{}}`)
	res, err := f.Fetch(context.Background(), "cust", "dev-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Enabled {
		t.Fatal("missing feature key must read as disabled")
	}
}

func TestFetcherNon200IsError(t *testing.T) {
	_, f := newTestServer(t, 500, `{"error":"boom"}`)
	if _, err := f.Fetch(context.Background(), "cust", "dev-1"); err == nil {
		t.Fatal("5xx should propagate as error")
	}
}

func TestFetcherUnauthorizedIsError(t *testing.T) {
	_, f := newTestServer(t, 401, `{"error":"unauth"}`)
	if _, err := f.Fetch(context.Background(), "cust", "dev-1"); err == nil {
		t.Fatal("401 should propagate as error")
	}
}

func TestFetcherMalformedBodyIsError(t *testing.T) {
	_, f := newTestServer(t, 200, `not json`)
	if _, err := f.Fetch(context.Background(), "cust", "dev-1"); err == nil {
		t.Fatal("malformed body should propagate as error")
	}
}

func TestFetcherEmptyCustomerIDIsError(t *testing.T) {
	_, f := newTestServer(t, 200, `{"features":{}}`)
	if _, err := f.Fetch(context.Background(), "", "dev-1"); err == nil {
		t.Fatal("empty customer should error")
	}
}

func TestFetcherEmptyDeviceIDIsError(t *testing.T) {
	_, f := newTestServer(t, 200, `{"features":{}}`)
	if _, err := f.Fetch(context.Background(), "cust", ""); err == nil {
		t.Fatal("empty device should error")
	}
}

func TestNewHTTPFetcherRejectsIncompleteConfig(t *testing.T) {
	if _, ok := NewHTTPFetcher(ingest.Config{APIEndpoint: "", APIKey: "k"}, nil); ok {
		t.Fatal("missing endpoint should yield ok=false")
	}
	if _, ok := NewHTTPFetcher(ingest.Config{APIEndpoint: "https://x", APIKey: ""}, nil); ok {
		t.Fatal("missing api key should yield ok=false")
	}
}
