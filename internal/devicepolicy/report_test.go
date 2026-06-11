package devicepolicy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
)

func TestReportPostsToComplianceEndpoint(t *testing.T) {
	var gotPath, gotAuth, gotMethod string
	var gotBody ComplianceReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"message":"compliance recorded"}`))
	}))
	t.Cleanup(srv.Close)

	rep, ok := NewHTTPReporter(ingest.Config{APIEndpoint: srv.URL, APIKey: "test-key"}, srv.Client())
	if !ok {
		t.Fatal("NewHTTPReporter ok=false on valid config")
	}
	err := rep.Report(context.Background(), "cust", "dev-1", ComplianceReport{
		Category: CategoryIDEExtension, State: StateCompliant, AppliedHash: "sha256:abc",
		AgentVersion: "1.13.0", Platform: "windows",
	})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %s, want POST", gotMethod)
	}
	if !strings.Contains(gotPath, "/developer-mdm-agent/devices/dev-1/compliance") {
		t.Fatalf("path = %s", gotPath)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotBody.State != StateCompliant || gotBody.AppliedHash != "sha256:abc" {
		t.Fatalf("body = %+v", gotBody)
	}
	if gotBody.Category != CategoryIDEExtension || gotBody.Platform != "windows" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestReportNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"unknown device for this customer"}`))
	}))
	t.Cleanup(srv.Close)
	rep, _ := NewHTTPReporter(ingest.Config{APIEndpoint: srv.URL, APIKey: "k"}, srv.Client())
	if err := rep.Report(context.Background(), "cust", "dev-1", ComplianceReport{State: StateCompliant}); err == nil {
		t.Fatal("400 should propagate as error")
	}
}

func TestReportDefaultsCategory(t *testing.T) {
	var gotCategory string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body ComplianceReport
		_ = json.Unmarshal(b, &body)
		gotCategory = body.Category
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	rep, _ := NewHTTPReporter(ingest.Config{APIEndpoint: srv.URL, APIKey: "k"}, srv.Client())
	if err := rep.Report(context.Background(), "cust", "dev-1", ComplianceReport{State: StateCompliant}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if gotCategory != CategoryIDEExtension {
		t.Fatalf("category should default to %q, got %q", CategoryIDEExtension, gotCategory)
	}
}
