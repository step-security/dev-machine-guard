package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func newServer(t *testing.T, status int, body string) (*HTTPFetcher, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q", got)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	f, ok := NewHTTPFetcher(srv.URL, "test-key", srv.Client())
	if !ok {
		t.Fatal("NewHTTPFetcher returned ok=false")
	}
	return f, srv
}

const validBundle = `{"detection_rules":{"rules":[
  {"id":"r1","revision":"a1","file_globs":["**/setup.js"],
   "groups":[{"id":"g","conditions":[{"id":"c","kind":"regex","pattern":"eval\\("}]}]}
]}}`

func TestFetchOrEmptySuccess(t *testing.T) {
	f, _ := newServer(t, http.StatusOK, validBundle)
	rs := FetchOrEmpty(context.Background(), f, "cust", "dev", nil)
	if len(rs.Rules) != 1 || rs.Rules[0].ID != "r1" {
		t.Fatalf("unexpected ruleset: %+v", rs)
	}
	// Prepared: compiled glob + regex present.
	if len(rs.Rules[0].globs) != 1 || rs.Rules[0].Groups[0].Conditions[0].re == nil {
		t.Error("FetchOrEmpty must return a Prepared RuleSet")
	}
}

func TestFetchOrEmptyFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"not found", http.StatusNotFound, "nope"},
		{"server error", http.StatusInternalServerError, "boom"},
		{"bad json", http.StatusOK, "{not json"},
		{"fails prepare (bad regex)", http.StatusOK,
			`{"detection_rules":{"rules":[{"id":"r","file_globs":["**/x"],"groups":[{"id":"g","conditions":[{"id":"c","kind":"regex","pattern":"("}]}]}]}}`},
		{"fails prepare (no glob)", http.StatusOK,
			`{"detection_rules":{"rules":[{"id":"r","file_globs":[]}]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newServer(t, tc.status, tc.body)
			rs := FetchOrEmpty(context.Background(), f, "cust", "dev", nil)
			if len(rs.Rules) != 0 {
				t.Errorf("expected empty ruleset on failure, got %+v", rs)
			}
		})
	}
}

func TestFetchOrEmptyNilFetcher(t *testing.T) {
	if rs := FetchOrEmpty(context.Background(), nil, "c", "d", nil); len(rs.Rules) != 0 {
		t.Errorf("nil fetcher should yield empty, got %+v", rs)
	}
	// A typed-nil *HTTPFetcher (e.g. NewHTTPFetcher ok=false) must also be safe.
	var typedNil *HTTPFetcher
	if rs := FetchOrEmpty(context.Background(), typedNil, "c", "d", nil); len(rs.Rules) != 0 {
		t.Errorf("typed-nil fetcher should yield empty, got %+v", rs)
	}
}

func TestNewHTTPFetcherMissingConfig(t *testing.T) {
	if _, ok := NewHTTPFetcher("", "key", nil); ok {
		t.Error("missing endpoint should return ok=false")
	}
	if _, ok := NewHTTPFetcher("https://x", "", nil); ok {
		t.Error("missing apiKey should return ok=false")
	}
}

func TestLoadFileOrEmpty(t *testing.T) {
	dir := t.TempDir()

	bare := filepath.Join(dir, "bare.json")
	if err := os.WriteFile(bare, []byte(`{"rules":[{"id":"b","file_globs":["**/x"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if rs := LoadFileOrEmpty(bare, nil); len(rs.Rules) != 1 || rs.Rules[0].ID != "b" {
		t.Errorf("bare ruleset: %+v", rs)
	}

	env := filepath.Join(dir, "env.json")
	if err := os.WriteFile(env, []byte(validBundle), 0o600); err != nil {
		t.Fatal(err)
	}
	if rs := LoadFileOrEmpty(env, nil); len(rs.Rules) != 1 || rs.Rules[0].ID != "r1" {
		t.Errorf("envelope ruleset: %+v", rs)
	}

	if rs := LoadFileOrEmpty(filepath.Join(dir, "missing.json"), nil); len(rs.Rules) != 0 {
		t.Errorf("missing file should yield empty, got %+v", rs)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"rules":[{"id":"b","file_globs":["../x"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if rs := LoadFileOrEmpty(bad, nil); len(rs.Rules) != 0 {
		t.Errorf("invalid ruleset should yield empty, got %+v", rs)
	}
}
