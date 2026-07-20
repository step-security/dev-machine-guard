package devicepolicy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
)

// newPolicyFetchServer is a fetch server that asserts the request carries the
// EXPECTED category/target query and returns a fixed body. Unlike newFetchServer
// (pinned to ide_extension/vscode) it lets a test drive any requested pair —
// needed by the identity checks below, which turn on the (category, target) the
// RESPONSE claims versus the one the agent asked for.
func newPolicyFetchServer(t *testing.T, wantCategory, wantTarget, body string) *HTTPFetcher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("category"); got != wantCategory {
			t.Errorf("request category = %q, want %q", got, wantCategory)
		}
		if got := r.URL.Query().Get("target"); got != wantTarget {
			t.Errorf("request target = %q, want %q", got, wantTarget)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	f, ok := NewHTTPFetcher(ingest.Config{APIEndpoint: srv.URL, APIKey: "test-key"}, srv.Client())
	if !ok {
		t.Fatal("NewHTTPFetcher returned ok=false on valid config")
	}
	return f
}

func TestFetchRejectsMismatchedResponseCategory(t *testing.T) {
	// The agent asked for ide_extension/vscode; the response claims a DIFFERENT
	// category (backend bug, proxy/cache mixup). Enforcing it would apply the
	// wrong pair — Fetch must reject it before the reconciler ever sees it.
	body := `{"policy":{"category":"package_config","target":"vscode","clear":false,` +
		`"policy":{"x":true},"hash":"sha256:h","generated_at":"x"}}`
	f := newPolicyFetchServer(t, CategoryIDEExtension, TargetVSCode, body)
	_, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err == nil || !strings.Contains(err.Error(), "category") {
		t.Fatalf("mismatched response category must error, got %v", err)
	}
}

func TestFetchRejectsMismatchedResponseTarget(t *testing.T) {
	// Category matches but the response targets a different IDE family — still the
	// wrong pair to act on.
	body := `{"policy":{"category":"ide_extension","target":"jetbrains","clear":false,` +
		`"policy":{"x":true},"hash":"sha256:h","generated_at":"x"}}`
	f := newPolicyFetchServer(t, CategoryIDEExtension, TargetVSCode, body)
	_, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("mismatched response target must error, got %v", err)
	}
}

func TestFetchRejectsMismatchedClearDirective(t *testing.T) {
	// The most dangerous mixup: a clear:true scoped to the WRONG pair. If it
	// slipped through, the reconciler would remove an unrelated category's value.
	// The identity check fires before clear is ever surfaced as a directive.
	body := `{"policy":{"category":"package_config","target":"npm","clear":true,"generated_at":"x"}}`
	f := newPolicyFetchServer(t, CategoryIDEExtension, TargetVSCode, body)
	_, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err == nil {
		t.Fatal("a clear scoped to a different category/target must be rejected, not surfaced as a clear")
	}
}

func TestFetchPackageConfigTargetRoundTrips(t *testing.T) {
	// The generic fetcher carries the package_config/npm pair end to end: the
	// request query is scoped to it and a matching response parses back cleanly.
	body := `{"policy":{"category":"package_config","target":"npm","clear":false,` +
		`"policy":{"registry":"https://npm.pkg.example/"},"hash":"sha256:npm","generated_at":"x"}}`
	f := newPolicyFetchServer(t, CategoryPackageConfig, TargetNPM, body)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryPackageConfig, TargetNPM)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if ep.Category != CategoryPackageConfig || ep.Target != TargetNPM {
		t.Fatalf("round-trip identity = %q/%q, want %q/%q",
			ep.Category, ep.Target, CategoryPackageConfig, TargetNPM)
	}
	if ep.Hash != "sha256:npm" || !ep.present() {
		t.Fatalf("ep = %+v, want present with hash sha256:npm", ep)
	}
}
