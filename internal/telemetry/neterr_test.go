package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestNetErrorCode(t *testing.T) {
	// Real failures from http.Client, so the classification tracks what
	// net/http actually returns rather than hand-built error values. The
	// clients bypass proxy env vars: a proxy would answer for host.invalid and
	// turn the DNS row into a proxy or HTTP result.
	direct := &http.Client{Transport: &http.Transport{}}
	directTimeout := &http.Client{Transport: &http.Transport{}, Timeout: 50 * time.Millisecond}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer slow.Close()
	drop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = conn.Close()
		}
	}))
	defer drop.Close()
	selfSigned := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer selfSigned.Close()
	// A TLS 1.3-only server answers a TLS 1.2-max client with a protocol_version
	// alert, the shape of an egress box enforcing TLS policy.
	tls13Only := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tls13Only.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	tls13Only.StartTLS()
	defer tls13Only.Close()
	tls12Client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //#nosec G402 -- test-only server with a self-signed cert.
	}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedURL := "http://" + ln.Addr().String()
	_ = ln.Close()

	tests := []struct {
		name   string
		client *http.Client
		url    string
		want   string
	}{
		{"dns", direct, "http://host.invalid", codeDNS},
		{"refused", direct, refusedURL, codeConnect},
		{"client timeout", directTimeout, slow.URL, codeTimeout},
		{"dropped connection", direct, drop.URL, codeConnDropped},
		{"untrusted certificate", direct, selfSigned.URL, codeCert},
		{"tls alert from server", tls12Client, tls13Only.URL, codeTLS},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.client.Get(tc.url)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("expected a request error")
			}
			if got := netErrorCode(err); got != tc.want {
				t.Errorf("netErrorCode(%v) = %q, want %q", err, got, tc.want)
			}
		})
	}

	if got := netErrorCode(context.DeadlineExceeded); got != codeTimeout {
		t.Errorf("netErrorCode(DeadlineExceeded) = %q, want %q", got, codeTimeout)
	}
	if got := netErrorCode(errors.New("boom")); got != codeNetOther {
		t.Errorf("netErrorCode(unknown) = %q, want %q", got, codeNetOther)
	}
}

func TestHTTPStatusCode(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{204, codeHTTPOther},
		{301, codeHTTPOther},
		{399, codeHTTPOther},
		{400, codeHTTP4xx},
		{407, codeProxy},
		{499, codeHTTP4xx},
		{500, codeHTTP5xx},
		{503, codeHTTP5xx},
	}
	for _, tc := range tests {
		if got := httpStatusCode(tc.status); got != tc.want {
			t.Errorf("httpStatusCode(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestRequestErrorCode_ProxyRejectsConnect(t *testing.T) {
	// net/http reports a non-200 CONNECT reply as a bare error holding only
	// the status text, so only the request can tell it came from a proxy.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	req, err := http.NewRequest(http.MethodPost, "https://upload.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, doErr := client.Do(req)
	if doErr == nil {
		t.Fatal("expected CONNECT to fail")
	}

	orig := proxyForRequest
	t.Cleanup(func() { proxyForRequest = orig })

	proxyForRequest = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
	if got := requestErrorCode(req, doErr); got != codeProxy {
		t.Errorf("with proxy: requestErrorCode(%v) = %q, want %q", doErr, got, codeProxy)
	}
	proxyForRequest = func(*http.Request) (*url.URL, error) { return nil, nil }
	if got := requestErrorCode(req, doErr); got != codeNetOther {
		t.Errorf("without proxy: requestErrorCode(%v) = %q, want %q", doErr, got, codeNetOther)
	}
}
