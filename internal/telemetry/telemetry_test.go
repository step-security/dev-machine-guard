package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func TestGzipBytes_RoundTrip(t *testing.T) {
	original := []byte(`{"customer_id":"acme","node_projects":[{"project_path":"/x"}]}`)
	compressed, err := gzipBytes(original)
	if err != nil {
		t.Fatalf("gzipBytes failed: %v", err)
	}
	if len(compressed) < 2 || compressed[0] != 0x1f || compressed[1] != 0x8b {
		t.Fatal("expected gzip magic bytes")
	}

	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip.NewReader failed: %v", err)
	}
	defer gz.Close()
	got, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("decompression failed: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, original)
	}
}

func TestUploadToS3_SendsCompressedBodyAndIsCompressedFlag(t *testing.T) {
	var (
		mu             sync.Mutex
		uploadURLBody  []byte
		putBody        []byte
		putContentType string
		notifyBody     []byte
	)
	var confirmCalls atomic.Int32

	// Mock S3 PUT endpoint — captures the body the agent uploads.
	// Emits x-amz-request-id so the client's "real AWS response" check
	// treats this 200 as genuine and skips the confirm step.
	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		putBody = body
		putContentType = r.Header.Get("Content-Type")
		mu.Unlock()
		w.Header().Set("x-amz-request-id", "TESTREQID000000")
		w.Header().Set("x-amz-id-2", "test-id-2")
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Server.Close()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			uploadURLBody = body
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": s3Server.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/confirm-upload"):
			confirmCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"uploaded": true, "size_bytes": 4242})
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			notifyBody = body
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()

	withTestConfig(t, backendServer.URL)

	payload := &Payload{CustomerID: "test-customer", DeviceID: "dev-1"}

	const testExecutionID = "11111111-2222-4333-8444-555555555555"
	if err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo), payload, testExecutionID, nil); err != nil {
		t.Fatalf("uploadToS3 failed: %v", err)
	}

	// On a clean AWS-headered 200, the agent must NOT consult confirm-upload —
	// that endpoint exists only to disambiguate suspicious (no-AWS-header) PUT
	// responses.
	if got := confirmCalls.Load(); got != 0 {
		t.Errorf("confirm-upload must not be called on a clean AWS-headered 200, got %d call(s)", got)
	}

	mu.Lock()
	defer mu.Unlock()

	var uploadReq map[string]any
	if err := json.Unmarshal(uploadURLBody, &uploadReq); err != nil {
		t.Fatalf("failed to parse upload-URL request body: %v", err)
	}
	if uploadReq["device_id"] != "dev-1" {
		t.Errorf("expected device_id=dev-1, got %v", uploadReq["device_id"])
	}
	if uploadReq["is_compressed"] != true {
		t.Errorf("expected is_compressed=true, got %v", uploadReq["is_compressed"])
	}

	if len(putBody) < 2 || putBody[0] != 0x1f || putBody[1] != 0x8b {
		t.Fatalf("expected gzip-compressed PUT body (got %d bytes)", len(putBody))
	}
	if putContentType != "application/json" {
		t.Errorf("expected Content-Type application/json (matches presigned URL), got %q", putContentType)
	}

	gz, err := gzip.NewReader(bytes.NewReader(putBody))
	if err != nil {
		t.Fatalf("PUT body is not valid gzip: %v", err)
	}
	defer gz.Close()
	decompressed, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("failed to decompress PUT body: %v", err)
	}
	var roundTrip Payload
	if err := json.Unmarshal(decompressed, &roundTrip); err != nil {
		t.Fatalf("decompressed body is not valid JSON: %v", err)
	}
	if roundTrip.DeviceID != "dev-1" {
		t.Errorf("decompressed payload device_id mismatch: got %q", roundTrip.DeviceID)
	}

	var notify map[string]string
	if err := json.Unmarshal(notifyBody, &notify); err != nil {
		t.Fatalf("failed to parse notify body: %v", err)
	}
	if !strings.HasSuffix(notify["s3_key"], ".json.gz") {
		t.Errorf("expected s3_key with .json.gz suffix, got %q", notify["s3_key"])
	}
	if notify["execution_id"] != testExecutionID {
		t.Errorf("expected execution_id=%q in notify body, got %q", testExecutionID, notify["execution_id"])
	}
}

// TestUploadToS3_Synthetic200ConfirmedByBackend covers the case where a TLS
// proxy strips AWS response headers but the bytes still made it to S3 (e.g.
// a transparent proxy that doesn't terminate the body, just rewrites the
// response). The backend confirms the object is present, so the upload is
// accepted and notify proceeds.
func TestUploadToS3_Synthetic200ConfirmedByBackend(t *testing.T) {
	var (
		notifyCalls  atomic.Int32
		confirmCalls atomic.Int32
	)

	fakeProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fake-proxy/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeProxy.Close()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": fakeProxy.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/confirm-upload"):
			confirmCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"uploaded": true, "size_bytes": 4242})
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			notifyCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()
	withTestConfig(t, backendServer.URL)

	err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo),
		&Payload{CustomerID: "test-customer", DeviceID: "dev-1"},
		"11111111-2222-4333-8444-555555555555", nil)
	if err != nil {
		t.Fatalf("uploadToS3 must succeed when backend confirms uploaded=true, got: %v", err)
	}
	if got := confirmCalls.Load(); got != 1 {
		t.Errorf("expected exactly one confirm-upload call (triggered by missing AWS headers), got %d", got)
	}
	if got := notifyCalls.Load(); got != 1 {
		t.Errorf("notify must be called once on confirmed upload, got %d", got)
	}
}

// TestUploadToS3_Synthetic200MissingExhaustsRetries covers a hard
// TLS-interception failure: the proxy synthesizes 200s without forwarding
// bytes, and the backend definitively reports the object never landed.
// The agent must retry up to maxRetries and then fail loudly so the run
// is recorded as failed with a clear reason instead of cheerfully calling
// notify on a phantom object.
func TestUploadToS3_Synthetic200MissingExhaustsRetries(t *testing.T) {
	withFastBackoff(t)

	var (
		notifyCalls  atomic.Int32
		confirmCalls atomic.Int32
		putCalls     atomic.Int32
	)

	fakeProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		putCalls.Add(1)
		w.Header().Set("Server", "fake-proxy/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeProxy.Close()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": fakeProxy.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/confirm-upload"):
			confirmCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uploaded": false,
				"reason":   "object_not_found",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			notifyCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()
	withTestConfig(t, backendServer.URL)

	err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo),
		&Payload{CustomerID: "test-customer", DeviceID: "dev-1"},
		"11111111-2222-4333-8444-555555555555", nil)
	if err == nil {
		t.Fatal("uploadToS3 must fail when every confirm reports the object missing")
	}
	if !strings.Contains(err.Error(), "telemetry upload failed after 3 attempts") {
		t.Errorf("expected error to mention attempt exhaustion, got: %v", err)
	}
	if !strings.Contains(err.Error(), "object_not_found") {
		t.Errorf("expected error to include the backend's reason, got: %v", err)
	}
	if got := putCalls.Load(); got != 3 {
		t.Errorf("expected 3 PUT attempts, got %d", got)
	}
	if got := confirmCalls.Load(); got != 3 {
		t.Errorf("expected 3 confirm-upload calls (one per attempt), got %d", got)
	}
	if got := notifyCalls.Load(); got != 0 {
		t.Errorf("notify must not be called when the upload was never confirmed, got %d", got)
	}
}

// TestUploadToS3_Synthetic200UnsupportedBackendTrustsPUT covers an agent
// running against a backend that predates the confirm-upload endpoint.
// We have no way to verify, so the suspicion-triggered check falls back
// to trusting the original 200 — matches pre-PR behavior for compatibility.
func TestUploadToS3_Synthetic200UnsupportedBackendTrustsPUT(t *testing.T) {
	var notifyCalls atomic.Int32

	fakeProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fake-proxy/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeProxy.Close()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": fakeProxy.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/confirm-upload"):
			// Old backend — endpoint not present.
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			notifyCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()
	withTestConfig(t, backendServer.URL)

	err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo),
		&Payload{CustomerID: "test-customer", DeviceID: "dev-1"},
		"11111111-2222-4333-8444-555555555555", nil)
	if err != nil {
		t.Fatalf("uploadToS3 must succeed when confirm-upload is unsupported (404), got: %v", err)
	}
	if got := notifyCalls.Load(); got != 1 {
		t.Errorf("notify must still be called when confirm-upload returns 404, got %d", got)
	}
}

// TestUploadToS3_Synthetic200IndeterminateExhausts covers a confirm
// endpoint that returns 5xx (e.g. its S3 HEAD failed). We can't tell
// whether the object landed; since we were already suspicious, retry —
// and fail if every attempt is indeterminate.
func TestUploadToS3_Synthetic200IndeterminateExhausts(t *testing.T) {
	withFastBackoff(t)

	var (
		notifyCalls  atomic.Int32
		confirmCalls atomic.Int32
	)

	fakeProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fake-proxy/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeProxy.Close()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": fakeProxy.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/confirm-upload"):
			confirmCalls.Add(1)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"s3_check_failed"}`))
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			notifyCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()
	withTestConfig(t, backendServer.URL)

	err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo),
		&Payload{CustomerID: "test-customer", DeviceID: "dev-1"},
		"11111111-2222-4333-8444-555555555555", nil)
	if err == nil {
		t.Fatal("uploadToS3 must fail when every confirm is indeterminate")
	}
	if !strings.Contains(err.Error(), "could not verify the upload") {
		t.Errorf("expected error to mention verification failure, got: %v", err)
	}
	if got := confirmCalls.Load(); got != 3 {
		t.Errorf("expected 3 confirm-upload attempts, got %d", got)
	}
	if got := notifyCalls.Load(); got != 0 {
		t.Errorf("notify must not be called on indeterminate verification, got %d", got)
	}
}

// TestUploadToS3_Synthetic200ThenRealAWSHeaders covers a flaky proxy
// scenario: the first PUT is intercepted (no AWS headers, backend says
// missing), but the retry routes around the proxy and S3 responds for
// real. The upload succeeds without ever needing a notify-time precheck.
func TestUploadToS3_Synthetic200ThenRealAWSHeaders(t *testing.T) {
	withFastBackoff(t)

	var (
		notifyCalls  atomic.Int32
		confirmCalls atomic.Int32
		putAttempt   atomic.Int32
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := putAttempt.Add(1)
		if n == 1 {
			// First attempt: intercepted by proxy.
			w.Header().Set("Server", "fake-proxy/1.0")
			w.WriteHeader(http.StatusOK)
			return
		}
		// Subsequent attempts: real AWS response.
		w.Header().Set("x-amz-request-id", "TESTREQID000000")
		w.Header().Set("x-amz-id-2", "test-id-2")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": upstream.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/confirm-upload"):
			confirmCalls.Add(1)
			// Object hasn't landed yet (first PUT was intercepted).
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uploaded": false,
				"reason":   "object_not_found",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			notifyCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()
	withTestConfig(t, backendServer.URL)

	err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo),
		&Payload{CustomerID: "test-customer", DeviceID: "dev-1"},
		"11111111-2222-4333-8444-555555555555", nil)
	if err != nil {
		t.Fatalf("uploadToS3 must recover when a later attempt reaches real S3, got: %v", err)
	}
	if got := putAttempt.Load(); got != 2 {
		t.Errorf("expected 2 PUT attempts (1 intercepted, 1 real), got %d", got)
	}
	if got := confirmCalls.Load(); got != 1 {
		t.Errorf("expected 1 confirm-upload call (only the first attempt was suspicious), got %d", got)
	}
	if got := notifyCalls.Load(); got != 1 {
		t.Errorf("notify must be called once after successful upload, got %d", got)
	}
}

func withTestConfig(t *testing.T, endpoint string) {
	t.Helper()
	origEndpoint, origCustomer, origKey := config.APIEndpoint, config.CustomerID, config.APIKey
	config.APIEndpoint = endpoint
	config.CustomerID = "test-customer"
	config.APIKey = "test-key"
	t.Cleanup(func() {
		config.APIEndpoint, config.CustomerID, config.APIKey = origEndpoint, origCustomer, origKey
	})
}

// withFastBackoff shrinks the inter-attempt backoff so retry-exhaustion
// tests run in milliseconds instead of seconds. Production code leaves
// the unit at its default of 2s.
func withFastBackoff(t *testing.T) {
	t.Helper()
	orig := s3UploadBackoffUnit
	s3UploadBackoffUnit = 5 * time.Millisecond
	t.Cleanup(func() { s3UploadBackoffUnit = orig })
}
