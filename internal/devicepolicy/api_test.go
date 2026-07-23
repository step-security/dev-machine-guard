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

func newFetchServer(t *testing.T, status int, body string) (*httptest.Server, *HTTPFetcher) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", got)
		}
		if got := r.URL.Query().Get("category"); got != CategoryIDEExtension {
			t.Errorf("category = %q, want %q", got, CategoryIDEExtension)
		}
		if got := r.URL.Query().Get("target"); got != TargetVSCode {
			t.Errorf("target = %q, want %q", got, TargetVSCode)
		}
		if !strings.Contains(r.URL.Path, "/developer-mdm-agent/run-config") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("device_id"); got != "dev-1" {
			t.Errorf("device_id = %q, want dev-1", got)
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
	body := `{"detection_rules":{"version":1},"policy":{"category":"ide_extension","target":"vscode","clear":false,` +
		`"policy":{"extensions.allowed":{"*":false,"ms-python.python":true}},` +
		`"hash":"sha256:abc","min_vscode_version":"1.96.0","generated_at":"2026-06-08T00:00:00Z"}}`
	_, f := newFetchServer(t, 200, body)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if ep.Clear {
		t.Fatal("clear should be false")
	}
	if ep.Target != TargetVSCode {
		t.Fatalf("target = %q, want %q", ep.Target, TargetVSCode)
	}
	if ep.Hash != "sha256:abc" {
		t.Fatalf("hash = %q", ep.Hash)
	}
	// The allowlist value in the settings map must round-trip as the bytes the backend sent.
	al, ok := ep.Policy[allowedExtensionsSettingKey]
	if !ok {
		t.Fatal("settings map missing extensions.allowed")
	}
	if got := string(al); !strings.Contains(got, `"ms-python.python":true`) {
		t.Fatalf("allowlist = %s", got)
	}
}

func TestFetchClear(t *testing.T) {
	_, f := newFetchServer(t, 200, `{"policy":{"category":"ide_extension","clear":true,"generated_at":"2026-06-08T00:00:00Z"}}`)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !ep.Clear {
		t.Fatal("clear should be true")
	}
}

func TestFetchLiftsGalleryServiceURL(t *testing.T) {
	// A settings map carrying the gallery key lifts it alongside the allowlist;
	// the hash covers the whole map (backend folds the URL in).
	body := `{"policy":{"category":"ide_extension","target":"vscode","clear":false,` +
		`"policy":{"extensions.allowed":{"*":false},"extensions.gallery.serviceUrl":"https://mkt.example/api/v1"},` +
		`"hash":"sha256:g","generated_at":"2026-07-23T00:00:00Z"}}`
	_, f := newFetchServer(t, 200, body)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	gal, ok := ep.Policy[galleryServiceURLSettingKey]
	if !ok || string(gal) != `"https://mkt.example/api/v1"` {
		t.Fatalf("gallery value = %q ok=%v, want the URL as a JSON string", string(gal), ok)
	}
}

func TestFetchAbsentGalleryServiceURLIsEmpty(t *testing.T) {
	// A settings map without the gallery key (the common allowlist-only case)
	// simply omits it; that is not an error.
	body := `{"policy":{"category":"ide_extension","clear":false,` +
		`"policy":{"extensions.allowed":{"*":false}},"hash":"sha256:h","generated_at":"2026-07-23T00:00:00Z"}}`
	_, f := newFetchServer(t, 200, body)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, ok := ep.Policy[galleryServiceURLSettingKey]; ok {
		t.Fatalf("gallery key should be absent from the settings map, got %q", string(ep.Policy[galleryServiceURLSettingKey]))
	}
}

func TestFetchAbsentPolicyReturnsEmptyNoError(t *testing.T) {
	// An omitted/null `policy` means run-config carried no directive for this
	// category. It is NOT an error and NOT a clear: Fetch returns a zero
	// EffectivePolicy (present()==false) so the reconciler no-ops.
	cases := []struct {
		name string
		body string
	}{
		{"policy omitted", `{"detection_rules":{"version":1,"rules":[]}}`},
		{"empty object", `{}`},
		{"explicit null", `{"policy":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, f := newFetchServer(t, 200, tc.body)
			ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
			if err != nil {
				t.Fatalf("absent policy must not error, got %v", err)
			}
			if ep.present() {
				t.Fatalf("absent policy must yield present()==false, got %+v", ep)
			}
			if ep.Clear || len(ep.Policy) != 0 || ep.Hash != "" {
				t.Fatalf("absent policy must yield a zero EffectivePolicy, got %+v", ep)
			}
		})
	}
}

func TestFetchIgnoresDetectionRules(t *testing.T) {
	// run-config carries BOTH detection_rules and policy. Fetch decodes only the
	// `policy` slice and ignores the rules bundle entirely (the rules fetcher
	// owns that), proving the two consumers decode independent slices.
	body := `{"detection_rules":{"version":7,"rules":[{"id":"r1"}]},` +
		`"policy":{"category":"ide_extension","clear":false,` +
		`"policy":{"extensions.allowed":{"ms-python.python":true}},"hash":"sha256:xyz","generated_at":"2026-06-08T00:00:00Z"}}`
	_, f := newFetchServer(t, 200, body)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if ep.Hash != "sha256:xyz" {
		t.Fatalf("hash = %q, want sha256:xyz", ep.Hash)
	}
	if got := string(ep.Policy[allowedExtensionsSettingKey]); !strings.Contains(got, `"ms-python.python":true`) {
		t.Fatalf("allowlist = %s", got)
	}
	// The policy object omits `target`; Fetch defaults it to the requested target.
	if ep.Target != TargetVSCode {
		t.Fatalf("target = %q, want %q (defaulted from request)", ep.Target, TargetVSCode)
	}
}

func TestFetchDefaultsRequestTargetToVSCode(t *testing.T) {
	// An empty target argument must still send target=vscode on the wire
	// (newFetchServer asserts the query param) and parse back as vscode.
	body := `{"policy":{"category":"ide_extension","clear":false,` +
		`"policy":{"extensions.allowed":{"ms-python.python":true}},"hash":"sha256:abc","generated_at":"2026-06-08T00:00:00Z"}}`
	_, f := newFetchServer(t, 200, body)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if ep.Target != TargetVSCode {
		t.Fatalf("target = %q, want %q (defaulted from empty request)", ep.Target, TargetVSCode)
	}
}

func TestFetchMalformedBodyIsError(t *testing.T) {
	_, f := newFetchServer(t, 200, `not json`)
	if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode); err == nil {
		t.Fatal("malformed body must be an error (→ reconciler no-op)")
	}
}

func TestFetchNonClearMissingPolicyIsError(t *testing.T) {
	// clear=false but no policy/hash → malformed; must not be written or mistaken
	// for a clear.
	_, f := newFetchServer(t, 200, `{"policy":{"category":"ide_extension","clear":false,"generated_at":"x"}}`)
	if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode); err == nil {
		t.Fatal("non-clear result missing policy/hash must be an error")
	}
}

func TestFetchNonObjectPolicyIsError(t *testing.T) {
	// The `policy` must decode as a JSON object (setting id → value map). A
	// string / array / scalar / null in its place is malformed: it fails the
	// decode (or yields an empty map) → error, so nothing reaches the writer.
	for _, body := range []string{
		`{"policy":{"category":"ide_extension","clear":false,"policy":"bad","hash":"sha256:x","generated_at":"x"}}`,
		`{"policy":{"category":"ide_extension","clear":false,"policy":[],"hash":"sha256:x","generated_at":"x"}}`,
		`{"policy":{"category":"ide_extension","clear":false,"policy":42,"hash":"sha256:x","generated_at":"x"}}`,
		`{"policy":{"category":"ide_extension","clear":false,"policy":null,"hash":"sha256:x","generated_at":"x"}}`,
	} {
		_, f := newFetchServer(t, 200, body)
		if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode); err == nil {
			t.Fatalf("non-object policy must be an error, body: %s", body)
		}
	}
}

func TestFetchSettingsMissingAllowlistIsError(t *testing.T) {
	// extensions.allowed is mandatory. A settings map that carries only other keys
	// (e.g. a gallery-only response) is malformed and must error — never be written
	// or read back "compliant".
	body := `{"policy":{"category":"ide_extension","clear":false,` +
		`"policy":{"extensions.gallery.serviceUrl":"https://mkt.example/api/v1"},"hash":"sha256:x","generated_at":"x"}}`
	_, f := newFetchServer(t, 200, body)
	if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode); err == nil {
		t.Fatal("settings map missing extensions.allowed must be an error")
	}
}

func TestFetchAllowlistNotObjectIsError(t *testing.T) {
	// extensions.allowed present but not an object (a string / array written
	// verbatim could even read back "compliant") → malformed.
	for _, body := range []string{
		`{"policy":{"category":"ide_extension","clear":false,"policy":{"extensions.allowed":"bad"},"hash":"sha256:x","generated_at":"x"}}`,
		`{"policy":{"category":"ide_extension","clear":false,"policy":{"extensions.allowed":[]},"hash":"sha256:x","generated_at":"x"}}`,
	} {
		_, f := newFetchServer(t, 200, body)
		if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode); err == nil {
			t.Fatalf("non-object extensions.allowed must be an error, body: %s", body)
		}
	}
}

func TestFetchNon200IsError(t *testing.T) {
	_, f := newFetchServer(t, 500, `{"error":"boom"}`)
	if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode); err == nil {
		t.Fatal("5xx should propagate as error")
	}
}

func TestFetchEmptyIDsAreErrors(t *testing.T) {
	_, f := newFetchServer(t, 200, `{"policy":{"clear":true,"generated_at":"x"}}`)
	if _, err := f.Fetch(context.Background(), "", "dev-1", CategoryIDEExtension, TargetVSCode); err == nil {
		t.Fatal("empty customer should error")
	}
	if _, err := f.Fetch(context.Background(), "cust", "", CategoryIDEExtension, TargetVSCode); err == nil {
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
	// Caller left Target empty → defaulted to vscode on the wire.
	if gotBody.Target != TargetVSCode {
		t.Fatalf("target = %q, want %q (defaulted)", gotBody.Target, TargetVSCode)
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

func TestFetchLiftsEnforcement(t *testing.T) {
	cases := []struct {
		name  string
		field string // spliced into the policy sub-object (empty → omitted)
		want  string
	}{
		{"mdm", `"enforcement":"mdm",`, "mdm"},
		{"dmg", `"enforcement":"dmg",`, "dmg"},
		{"absent (older backend)", ``, ""},
		{"whitespace trimmed", `"enforcement":"  mdm  ",`, "mdm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"policy":{"category":"ide_extension","target":"vscode","clear":false,` + tc.field +
				`"policy":{"extensions.allowed":{"*":false}},"hash":"sha256:e","generated_at":"2026-07-23T00:00:00Z"}}`
			_, f := newFetchServer(t, 200, body)
			ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if ep.Enforcement != tc.want {
				t.Fatalf("enforcement = %q, want %q", ep.Enforcement, tc.want)
			}
		})
	}
}

func TestReportSerializesObservedAndEvaluatedEnforcement(t *testing.T) {
	var body ComplianceReport
	var raw map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_ = json.Unmarshal(b, &raw)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	rep, _ := NewHTTPReporter(ingest.Config{APIEndpoint: srv.URL, APIKey: "k"}, srv.Client())

	observed := json.RawMessage(`{"extensions.allowed":{"*":false},"extensions.gallery.serviceUrl":"https://mkt.example/api/v1"}`)
	if err := rep.Report(context.Background(), "cust", "dev-1", ComplianceReport{
		Category: CategoryIDEExtension, State: StateMDMManaged, Observed: observed, EvaluatedEnforcement: "mdm",
	}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if body.EvaluatedEnforcement != "mdm" {
		t.Fatalf("evaluated_enforcement = %q, want mdm", body.EvaluatedEnforcement)
	}
	if string(body.Observed) != string(observed) {
		t.Fatalf("observed = %s, want %s", body.Observed, observed)
	}
	if _, ok := raw["observed"]; !ok {
		t.Fatal(`wire body missing "observed" key`)
	}
	if _, ok := raw["evaluated_enforcement"]; !ok {
		t.Fatal(`wire body missing "evaluated_enforcement" key`)
	}
}

func TestReportOmitsEmptyMDMFields(t *testing.T) {
	var raw map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &raw)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	rep, _ := NewHTTPReporter(ingest.Config{APIEndpoint: srv.URL, APIKey: "k"}, srv.Client())
	if err := rep.Report(context.Background(), "cust", "dev-1", ComplianceReport{State: StateCompliant}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if _, ok := raw["observed"]; ok {
		t.Fatal(`empty observed must be omitted from the wire`)
	}
	if _, ok := raw["evaluated_enforcement"]; ok {
		t.Fatal(`empty evaluated_enforcement must be omitted from the wire`)
	}
}
