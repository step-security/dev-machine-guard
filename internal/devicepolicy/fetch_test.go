package devicepolicy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
)

func newFetchServer(t *testing.T, status int, body string) (*httptest.Server, *HTTPFetcher) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", got)
		}
		if got := r.URL.Query().Get("category"); got != CategoryIDEExtension {
			t.Errorf("category = %q, want %q", got, CategoryIDEExtension)
		}
		if !strings.Contains(r.URL.Path, "/developer-mdm-agent/devices/dev-1/effective-policy") {
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

func TestFetchPolicy(t *testing.T) {
	// min_vscode_version is no longer part of the contract; it stays in the
	// fixture to prove a backend still emitting legacy fields is tolerated.
	body := `{"category":"ide_extension","clear":false,` +
		`"policy":{"*":false,"ms-python.python":true},` +
		`"hash":"sha256:abc","min_vscode_version":"1.96.0","generated_at":"2026-06-08T00:00:00Z"}`
	_, f := newFetchServer(t, 200, body)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if ep.Clear {
		t.Fatal("clear should be false")
	}
	if ep.Hash != "sha256:abc" {
		t.Fatalf("hash = %q", ep.Hash)
	}
	// Policy must round-trip as the canonical bytes the backend sent.
	if got := string(ep.Policy); !strings.Contains(got, `"ms-python.python":true`) {
		t.Fatalf("policy = %s", got)
	}
}

func TestFetchClear(t *testing.T) {
	_, f := newFetchServer(t, 200, `{"category":"ide_extension","clear":true,"generated_at":"2026-06-08T00:00:00Z"}`)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !ep.Clear {
		t.Fatal("clear should be true")
	}
}

func TestFetchMalformedBodyIsError(t *testing.T) {
	_, f := newFetchServer(t, 200, `not json`)
	if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension); err == nil {
		t.Fatal("malformed body must be an error (→ reconciler no-op)")
	}
}

func TestFetchNonClearMissingPolicyIsError(t *testing.T) {
	// clear=false but no policy/hash → malformed; must not be written or mistaken
	// for a clear.
	_, f := newFetchServer(t, 200, `{"category":"ide_extension","clear":false,"generated_at":"x"}`)
	if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension); err == nil {
		t.Fatal("non-clear result missing policy/hash must be an error")
	}
}

func TestFetchNonObjectPolicyIsError(t *testing.T) {
	// A policy that is not a JSON object must never reach the writer: written
	// verbatim it could even read back as "compliant".
	for _, body := range []string{
		`{"category":"ide_extension","clear":false,"policy":"bad","hash":"sha256:x","generated_at":"x"}`,
		`{"category":"ide_extension","clear":false,"policy":[],"hash":"sha256:x","generated_at":"x"}`,
		`{"category":"ide_extension","clear":false,"policy":42,"hash":"sha256:x","generated_at":"x"}`,
		`{"category":"ide_extension","clear":false,"policy":null,"hash":"sha256:x","generated_at":"x"}`,
	} {
		_, f := newFetchServer(t, 200, body)
		if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension); err == nil {
			t.Fatalf("non-object policy must be an error, body: %s", body)
		}
	}
}

func TestFetchNon200IsError(t *testing.T) {
	_, f := newFetchServer(t, 500, `{"error":"boom"}`)
	if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension); err == nil {
		t.Fatal("5xx should propagate as error")
	}
}

func TestFetchEmptyIDsAreErrors(t *testing.T) {
	_, f := newFetchServer(t, 200, `{"clear":true,"generated_at":"x"}`)
	if _, err := f.Fetch(context.Background(), "", "dev-1", CategoryIDEExtension); err == nil {
		t.Fatal("empty customer should error")
	}
	if _, err := f.Fetch(context.Background(), "cust", "", CategoryIDEExtension); err == nil {
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
