package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
)

// Stable cause codes for network failures, carried in run-status error
// messages as "[code]". The agent-api loader scripts (bash and PowerShell)
// emit the same set, so failures group by cause across the loader and the
// agent. codeBadResponse and codeHTTPOther are agent-only: the loaders report
// malformed API responses under their own error types, and curl -f only fails
// on 4xx/5xx.
const (
	codeDNS         = "net_dns"
	codeProxy       = "net_proxy"
	codeConnect     = "net_connect"
	codeTimeout     = "net_timeout"
	codeTLS         = "net_tls"
	codeCert        = "net_cert"
	codeConnDropped = "net_conn_dropped"
	codeHTTP4xx     = "http_4xx"
	codeHTTP5xx     = "http_5xx"
	codeHTTPOther   = "http_other"
	codeBadResponse = "bad_response"
	codeNetOther    = "net_other"
)

// httpStatusCode classifies an unexpected HTTP status. The S3 PUT path passes
// any non-200, so 1xx-3xx must not be reported as a client error.
func httpStatusCode(status int) string {
	switch {
	case status == http.StatusProxyAuthRequired:
		return codeProxy
	case status >= 500:
		return codeHTTP5xx
	case status >= 400:
		return codeHTTP4xx
	default:
		return codeHTTPOther
	}
}

// netErrorCode classifies an error returned by http.Client.Do.
func netErrorCode(err error) string {
	var (
		opErr     *net.OpError
		dnsErr    *net.DNSError
		verifyErr *tls.CertificateVerificationError
		authErr   x509.UnknownAuthorityError
		hostErr   x509.HostnameError
		recordErr tls.RecordHeaderError
		netErr    net.Error
	)
	switch {
	case errors.As(err, &opErr) && opErr.Op == "proxyconnect":
		return codeProxy
	case errors.As(err, &dnsErr):
		return codeDNS
	case errors.As(err, &verifyErr), errors.As(err, &authErr), errors.As(err, &hostErr):
		return codeCert
	// crypto/tls reports an alert from the server as OpError{Op: "remote error"}.
	case errors.As(err, &recordErr), errors.As(err, &opErr) && opErr.Op == "remote error":
		return codeTLS
	// Includes "TLS handshake timeout", which net/http reports as a timeout.
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return codeTimeout
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return codeConnect
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.As(err, &opErr):
		return codeConnDropped
	}
	return codeNetOther
}

// proxyForRequest is the proxy the default transport would use; a var so tests
// can stub it, since http.ProxyFromEnvironment caches the environment.
var proxyForRequest = http.ProxyFromEnvironment

// requestErrorCode is netErrorCode plus the case the error alone can't show: a
// proxy refusing CONNECT (403, 407) surfaces as a bare status-text error.
func requestErrorCode(req *http.Request, err error) string {
	code := netErrorCode(err)
	if code == codeNetOther && req.URL.Scheme == "https" {
		if proxyURL, _ := proxyForRequest(req); proxyURL != nil {
			return codeProxy
		}
	}
	return code
}
