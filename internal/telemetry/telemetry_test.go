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
	"testing"

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

	// Mock S3 PUT endpoint — captures the body the agent uploads.
	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		putBody = body
		putContentType = r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Server.Close()

	// Mock backend — handles upload-URL and process-uploaded calls.
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

	// Override config globals for the duration of the test.
	origEndpoint, origCustomer, origKey := config.APIEndpoint, config.CustomerID, config.APIKey
	config.APIEndpoint = backendServer.URL
	config.CustomerID = "test-customer"
	config.APIKey = "test-key"
	defer func() {
		config.APIEndpoint, config.CustomerID, config.APIKey = origEndpoint, origCustomer, origKey
	}()

	payload := &Payload{
		CustomerID: "test-customer",
		DeviceID:   "dev-1",
	}

	const testExecutionID = "11111111-2222-4333-8444-555555555555"
	if err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo), payload, testExecutionID); err != nil {
		t.Fatalf("uploadToS3 failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Upload-URL request body must include is_compressed: true.
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

	// PUT body must be gzip-compressed.
	if len(putBody) < 2 || putBody[0] != 0x1f || putBody[1] != 0x8b {
		t.Fatalf("expected gzip-compressed PUT body (got %d bytes)", len(putBody))
	}
	if putContentType != "application/json" {
		t.Errorf("expected Content-Type application/json (matches presigned URL), got %q", putContentType)
	}

	// Decompressing the PUT body should yield the original JSON payload.
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

	// Notify-backend was called with the s3_key returned from the upload-URL endpoint.
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
