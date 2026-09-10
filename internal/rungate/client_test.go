package rungate

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckinParsesDirectiveAndSendsParams(t *testing.T) {
	var gotPath, gotQuery, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"detection_rules":{"rules":[]},"scan_directive":{"mode":"skip","reason":"not_due","gating_enabled":true,"effective_interval_minutes":240,"next_eligible_at":1753164400,"checked_at":1753160800}}`))
	}))
	defer srv.Close()

	d, wsl, cred, err := Checkin(context.Background(), srv.URL, "tenant-key", "acme corp", "SER 123", 1753150000)
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if !d.ShouldSkip() || d.Reason != "not_due" || d.EffectiveIntervalMinutes != 240 || d.NextEligibleAt != 1753164400 {
		t.Fatalf("directive = %+v", d)
	}
	if cred != nil {
		t.Fatalf("credential setting = %v, want nil when the response omits it", *cred)
	}
	if gotPath != "/v1/acme%20corp/developer-mdm-agent/run-config" && gotPath != "/v1/acme corp/developer-mdm-agent/run-config" {
		t.Errorf("path = %q (customer id must be path-escaped)", gotPath)
	}
	if !strings.Contains(gotQuery, "device_id=SER+123") && !strings.Contains(gotQuery, "device_id=SER%20123") {
		t.Errorf("query = %q, want escaped device_id", gotQuery)
	}
	if !strings.Contains(gotQuery, "last_run_at=1753150000") {
		t.Errorf("query = %q, want last_run_at", gotQuery)
	}
	if gotAuth != "Bearer tenant-key" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	// This fixture carries no wsl_directive: distro scanning must read as off.
	if wsl.Enabled {
		t.Error("wsl.Enabled = true with no wsl_directive in the response; must fail closed")
	}
}

// TestCheckinParsesWSLDirective covers the sibling block: it rides the same
// run-config response as scan_directive, so enabling WSL scanning costs no
// extra request.
func TestCheckinParsesWSLDirective(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"scan_directive":{"mode":"full","reason":"due"},` +
			`"wsl_directive":{"enabled":true,"reason":"tenant_opt_in"}}`))
	}))
	defer srv.Close()

	d, wsl, _, err := Checkin(context.Background(), srv.URL, "k", "acme", "SER1", 0)
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if d.ShouldSkip() {
		t.Error("scan directive should still proceed")
	}
	if !wsl.Enabled || wsl.Reason != "tenant_opt_in" {
		t.Errorf("wsl directive = %+v, want {true tenant_opt_in}", wsl)
	}
}

// TestCheckinWSLDirectiveDisabledIsHonoured: an explicit enabled:false must be
// read as off, not as "field present so probably on".
func TestCheckinWSLDirectiveDisabledIsHonoured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"scan_directive":{"mode":"full","reason":"due"},` +
			`"wsl_directive":{"enabled":false,"reason":"tenant_opt_out"}}`))
	}))
	defer srv.Close()

	_, wsl, _, err := Checkin(context.Background(), srv.URL, "k", "acme", "SER1", 0)
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if wsl.Enabled {
		t.Error("explicit enabled:false must stay off")
	}
	if wsl.Reason != "tenant_opt_out" {
		t.Errorf("reason = %q, want tenant_opt_out", wsl.Reason)
	}
}

func TestCheckinOmitsZeroLastRunAt(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"scan_directive":{"mode":"full","reason":"gating_disabled"}}`))
	}))
	defer srv.Close()

	if _, _, _, err := Checkin(context.Background(), srv.URL, "k", "acme", "SER1", 0); err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if strings.Contains(gotQuery, "last_run_at") {
		t.Errorf("query %q must omit last_run_at when unknown", gotQuery)
	}
}

func TestCheckinErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "401", handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }},
		{name: "404 old backend", handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }},
		{name: "500", handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }},
		{name: "garbage body", handler: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>nope")) }},
		{name: "oversized body", handler: func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"scanners":{"credentials":{"enabled":false}},"pad":"`))
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxDirectiveBytes))
			_, _ = w.Write([]byte(`"}`))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			_, _, cred, err := Checkin(context.Background(), srv.URL, "k", "acme", "SER1", 0)
			if err == nil {
				t.Fatal("Checkin must error so the gate fails open")
			}
			if cred != nil {
				t.Fatalf("credential setting = %v on error, want nil so the cache is kept", *cred)
			}
		})
	}
}

// TestCheckinWithoutDirectiveIsNotAnError: a rules-only answer or one from a
// backend that predates gating yields a zero directive (cadence falls back to
// the cache) but is still a valid response; it may carry the credential
// setting, which must not be lost behind a cadence complaint.
func TestCheckinWithoutDirectiveIsNotAnError(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		want *bool
	}{
		{name: "no scan_directive", body: `{"detection_rules":{"rules":[]}}`},
		{name: "empty mode", body: `{"scan_directive":{"reason":"x"}}`},
		{name: "no scan_directive, credentials off", body: `{"scanners":{"credentials":{"enabled":false}}}`, want: boolPtr(false)},
		{name: "empty mode, credentials off", body: `{"scan_directive":{"reason":"x"},"scanners":{"credentials":{"enabled":false}}}`, want: boolPtr(false)},
		{name: "null directive, credentials off", body: `{"scan_directive":null,"scanners":{"credentials":{"enabled":false}}}`, want: boolPtr(false)},
		{name: "wrong-typed directive field, credentials off", body: `{"scan_directive":{"mode":"full","effective_interval_minutes":"invalid"},"scanners":{"credentials":{"enabled":false}}}`, want: boolPtr(false)},
		{name: "directive not an object, credentials off", body: `{"scan_directive":"full","scanners":{"credentials":{"enabled":false}}}`, want: boolPtr(false)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(tt.body)) }))
			defer srv.Close()
			d, _, cred, err := Checkin(context.Background(), srv.URL, "k", "acme", "SER1", 0)
			if err != nil {
				t.Fatalf("Checkin: %v", err)
			}
			if d.Mode != "" {
				t.Fatalf("directive = %+v, want zero", d)
			}
			if (cred == nil) != (tt.want == nil) || (cred != nil && *cred != *tt.want) {
				t.Fatalf("credential setting = %v, want %v", deref(cred), deref(tt.want))
			}
		})
	}
}

// TestCheckinCredentialScanning covers the decode rule: only an explicit
// boolean is an answer. Omission, null (object or member) and unknown siblings
// leave the setting nil so the caller keeps whatever it already knows.
func TestCheckinCredentialScanning(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		want *bool
	}{
		{name: "explicit false", body: `{"scan_directive":{"mode":"full"},"scanners":{"credentials":{"enabled":false}}}`, want: boolPtr(false)},
		{name: "explicit true", body: `{"scan_directive":{"mode":"full"},"scanners":{"credentials":{"enabled":true}}}`, want: boolPtr(true)},
		{name: "object omitted", body: `{"scan_directive":{"mode":"full"}}`},
		{name: "scanners null", body: `{"scan_directive":{"mode":"full"},"scanners":null}`},
		{name: "scanners empty", body: `{"scan_directive":{"mode":"full"},"scanners":{}}`},
		{name: "credentials null", body: `{"scan_directive":{"mode":"full"},"scanners":{"credentials":null}}`},
		{name: "credentials empty", body: `{"scan_directive":{"mode":"full"},"scanners":{"credentials":{}}}`},
		{name: "other scanner only", body: `{"scan_directive":{"mode":"full"},"scanners":{"browser":{"enabled":false}}}`},
		{name: "enabled null", body: `{"scan_directive":{"mode":"full"},"scanners":{"credentials":{"enabled":null}}}`},
		{name: "enabled not a boolean", body: `{"scan_directive":{"mode":"full"},"scanners":{"credentials":{"enabled":"false"}}}`},
		{name: "scanners not an object", body: `{"scan_directive":{"mode":"full"},"scanners":[1]}`},
		{name: "unknown sibling fields", body: `{"scan_directive":{"mode":"full"},"scanners":{"credentials":{"enabled":false,"future":{"x":1}},"browser":{"enabled":true}},"extra":[1,2]}`, want: boolPtr(false)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(tt.body)) }))
			defer srv.Close()
			d, _, cred, err := Checkin(context.Background(), srv.URL, "k", "acme", "SER1", 0)
			if err != nil {
				t.Fatalf("Checkin: %v", err)
			}
			if d.Mode != ModeFull {
				t.Fatalf("directive = %+v, want the full directive alongside the setting", d)
			}
			if (cred == nil) != (tt.want == nil) || (cred != nil && *cred != *tt.want) {
				t.Fatalf("credential setting = %v, want %v", deref(cred), deref(tt.want))
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func TestCheckinRespectsContextDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, _, err := Checkin(ctx, srv.URL, "k", "acme", "SER1", 0)
	if err == nil {
		t.Fatal("Checkin must error on deadline")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Checkin took %v; the caller's deadline must bound it", elapsed)
	}
}

func TestCheckinValidatesInputs(t *testing.T) {
	for _, tt := range []struct {
		name                                string
		endpoint, key, customerID, deviceID string
	}{
		{name: "no endpoint", endpoint: "", key: "k", customerID: "c", deviceID: "d"},
		{name: "no key", endpoint: "http://x", key: "", customerID: "c", deviceID: "d"},
		{name: "no customer", endpoint: "http://x", key: "k", customerID: " ", deviceID: "d"},
		{name: "no device", endpoint: "http://x", key: "k", customerID: "c", deviceID: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, _, err := Checkin(context.Background(), tt.endpoint, tt.key, tt.customerID, tt.deviceID, 0); err == nil {
				t.Fatal("want validation error")
			}
		})
	}
}

// TestCheckinWSLNeedsDirective: wsl_directive rides a usable scan_directive.
// Without one the response cannot enable distro scanning, while the
// credential answer in the same response is still returned.
func TestCheckinWSLNeedsDirective(t *testing.T) {
	for name, body := range map[string]string{
		"missing directive": `{"wsl_directive":{"enabled":true,"reason":"tenant"},"scanners":{"credentials":{"enabled":false}}}`,
		"null directive":    `{"scan_directive":null,"wsl_directive":{"enabled":true},"scanners":{"credentials":{"enabled":false}}}`,
		"mode-less":         `{"scan_directive":{"reason":"due"},"wsl_directive":{"enabled":true},"scanners":{"credentials":{"enabled":false}}}`,
		"wrong type":        `{"scan_directive":{"mode":7},"wsl_directive":{"enabled":true},"scanners":{"credentials":{"enabled":false}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer srv.Close()
			d, wsl, cred, err := Checkin(context.Background(), srv.URL, "k", "acme", "SER1", 0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Mode != "" || wsl.Enabled || wsl.Reason != "" {
				t.Errorf("directive = %+v wsl = %+v, want both zero", d, wsl)
			}
			if cred == nil || *cred {
				t.Errorf("cred = %v, want false", deref(cred))
			}
		})
	}
}
