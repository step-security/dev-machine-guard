package rungate

import (
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
		_, _ = w.Write([]byte(`{"directive":{"mode":"skip","reason":"not_due","gating_enabled":true,"effective_interval_minutes":240,"next_eligible_at":1753164400,"checked_at":1753160800}}`))
	}))
	defer srv.Close()

	d, err := Checkin(context.Background(), srv.URL, "tenant-key", "acme corp", "SER 123", 1753150000)
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if !d.ShouldSkip() || d.Reason != "not_due" || d.EffectiveIntervalMinutes != 240 || d.NextEligibleAt != 1753164400 {
		t.Fatalf("directive = %+v", d)
	}
	if gotPath != "/v1/acme%20corp/developer-mdm-agent/run-directive" && gotPath != "/v1/acme corp/developer-mdm-agent/run-directive" {
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
}

func TestCheckinOmitsZeroLastRunAt(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"directive":{"mode":"full","reason":"gating_disabled"}}`))
	}))
	defer srv.Close()

	if _, err := Checkin(context.Background(), srv.URL, "k", "acme", "SER1", 0); err != nil {
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
		{name: "no directive object", handler: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }},
		{name: "empty mode", handler: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"directive":{"reason":"x"}}`)) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			if _, err := Checkin(context.Background(), srv.URL, "k", "acme", "SER1", 0); err == nil {
				t.Fatal("Checkin must error so the gate fails open")
			}
		})
	}
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
	_, err := Checkin(ctx, srv.URL, "k", "acme", "SER1", 0)
	if err == nil {
		t.Fatal("Checkin must error on deadline")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Checkin took %v; the caller's deadline must bound it", elapsed)
	}
}

func TestCheckinValidatesInputs(t *testing.T) {
	for _, tt := range []struct {
		name                                 string
		endpoint, key, customerID, deviceID string
	}{
		{name: "no endpoint", endpoint: "", key: "k", customerID: "c", deviceID: "d"},
		{name: "no key", endpoint: "http://x", key: "", customerID: "c", deviceID: "d"},
		{name: "no customer", endpoint: "http://x", key: "k", customerID: " ", deviceID: "d"},
		{name: "no device", endpoint: "http://x", key: "k", customerID: "c", deviceID: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Checkin(context.Background(), tt.endpoint, tt.key, tt.customerID, tt.deviceID, 0); err == nil {
				t.Fatal("want validation error")
			}
		})
	}
}
