package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/telemetry"
)

const (
	actionUninstall = "uninstall"
	formatZip       = "zip"
)

// latestResponse is latest-firewall's 200 body.
type latestResponse struct {
	Action         string     `json:"action"`
	Version        flexString `json:"version"`
	Build          flexString `json:"build"`
	Checksum       string     `json:"checksum"`
	SignedChecksum string     `json:"signed_checksum"`
	Platform       string     `json:"platform"`
	Arch           string     `json:"arch"`
	Format         string     `json:"format"`
	Asset          string     `json:"asset"`
	DownloadURL    string     `json:"download_url"`
	PackagesPath   string     `json:"packages_path"`
	PackagesURL    string     `json:"packages_url"`
}

// flexString accepts a JSON string or number (a build number sent as 42
// reads as "42", as the loader's "$($response.build)" would).
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexString(n.String())
	return nil
}

// release is a validated install answer.
type release struct {
	Version, Build, Checksum, Signed, DownloadURL, Asset, PackagesPath, PackagesURL string
}

func (r release) String() string { return fmt.Sprintf("%s (%s)", r.Version, r.Build) }

// key identifies the release in the report dedupe.
func (r release) key() string { return r.Version + "+" + r.Build }

// The loader's grammar for values that end up in paths and URLs.
var (
	versionRe      = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
	buildRe        = regexp.MustCompile(`^[0-9]{1,18}$`)
	checksumRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	assetRe        = regexp.MustCompile(`^StepSecurity(OnDevice)?Firewall-[0-9A-Za-z.-]+\.zip$`)
	packagesPathRe = regexp.MustCompile(`^on-device-firewall/[a-z]+/[0-9A-Za-z.-]+/[0-9A-Za-z.-]+$`)
	githubURLRe    = regexp.MustCompile(`^https://github\.com/\S+$`)
)

// fetchLatest asks latest-firewall what this device should run. A nil
// response comes with the outcome to return: not available (404/501, one
// line, no report) or failed (reported).
func (m *Manager) fetchLatest(ctx context.Context) (*latestResponse, Outcome) {
	q := url.Values{}
	q.Set("os", "windows")
	q.Set("arch", m.Arch)
	q.Set("format", formatZip)
	if m.LagBehind > 0 || m.CooldownHours > 0 {
		q.Set("lag_behind", fmt.Sprint(m.LagBehind))
		q.Set("cooldown_hours", fmt.Sprint(m.CooldownHours))
	}
	// The device id selects the per-device override of the removal feature;
	// without one only the tenant default applies.
	if id := m.DeviceID(); id != "" {
		q.Set("device_id", id)
	}
	endpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/latest-firewall?%s",
		strings.TrimRight(m.APIEndpoint, "/"), url.PathEscape(m.CustomerID), q.Encode())

	m.Logf("firewall: checking for the latest on-device firewall version...")
	var lastErr string
attempts:
	for attempt := 1; attempt <= apiAttempts; attempt++ {
		if attempt > 1 {
			if err := m.Sleep(ctx, time.Duration(attempt-1)*5*time.Second); err != nil {
				break
			}
		}
		body, status, err := m.get(ctx, endpoint)
		switch {
		case err != nil:
			lastErr = fmt.Sprintf("[%s] %v (attempt %d/%d)", telemetry.NetErrorCode(err), err, attempt, apiAttempts)
			continue
		case status == http.StatusNotFound || status == http.StatusNotImplemented:
			m.Logf("firewall: the on-device firewall is not available yet (latest-firewall returned HTTP %d); skipping it on this tick", status)
			return nil, OutcomeNotAvailable
		case status >= 500:
			lastErr = fmt.Sprintf("[%s] HTTP %d (attempt %d/%d)", telemetry.HTTPStatusCode(status), status, attempt, apiAttempts)
			continue
		case status != http.StatusOK:
			// Any other 4xx won't change on retry.
			lastErr = fmt.Sprintf("[%s] HTTP %d (attempt %d/%d)", telemetry.HTTPStatusCode(status), status, attempt, apiAttempts)
			break attempts
		}
		var resp latestResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			msg := fmt.Sprintf("Invalid latest-firewall response: %v", err)
			m.Logf("firewall: %s", msg)
			m.fail(ctx, CodeResponseInvalid, "", msg)
			return nil, OutcomeFailed
		}
		return &resp, ""
	}
	msg := "Failed to fetch the latest on-device firewall info from the API: " + lastErr
	m.Logf("firewall: %s", msg)
	m.fail(ctx, CodeAPIFailed, "", msg)
	return nil, OutcomeFailed
}

func (m *Manager) get(ctx context.Context, endpoint string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+m.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Version", m.AgentVersion)
	req.Header.Set("User-Agent", "dmg/"+m.AgentVersion+" (firewall)")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > apiMaxBytes {
		return nil, 0, errors.New("latest-firewall response too large")
	}
	return body, resp.StatusCode, nil
}

// validate checks an install answer the way the loader does: the version,
// build and checksum grammar, then the format, asset and packages_path
// (filled in when the server sends none).
func (m *Manager) validate(ctx context.Context, r *latestResponse) (release, bool) {
	rel := release{
		Version: string(r.Version), Build: string(r.Build), Checksum: r.Checksum,
		Signed: r.SignedChecksum, DownloadURL: r.DownloadURL, Asset: r.Asset, PackagesPath: r.PackagesPath,
		PackagesURL: strings.TrimSpace(r.PackagesURL),
	}
	if !versionRe.MatchString(rel.Version) || !buildRe.MatchString(rel.Build) || !checksumRe.MatchString(rel.Checksum) {
		msg := fmt.Sprintf("Invalid latest-firewall response (version '%s', build '%s')", rel.Version, rel.Build)
		m.Logf("firewall: %s", msg)
		m.fail(ctx, CodeResponseInvalid, "", msg)
		return release{}, false
	}
	if rel.Asset == "" {
		rel.Asset = fmt.Sprintf("StepSecurityOnDeviceFirewall-%s-%s-%s.zip", rel.Version, rel.Build, m.Arch)
	}
	if rel.PackagesPath == "" {
		rel.PackagesPath = fmt.Sprintf("on-device-firewall/win/%s/%s", rel.Version, rel.Asset)
	}
	if (r.Format != "" && r.Format != formatZip) ||
		(r.Arch != "" && r.Arch != m.Arch) ||
		!assetRe.MatchString(rel.Asset) ||
		!packagesPathRe.MatchString(rel.PackagesPath) ||
		strings.Contains(rel.PackagesPath, "..") ||
		!strings.HasSuffix(rel.PackagesPath, "/"+rel.Asset) {
		msg := fmt.Sprintf("Invalid latest-firewall response (format '%s', arch '%s', asset '%s', packages_path '%s')", r.Format, r.Arch, rel.Asset, rel.PackagesPath)
		m.Logf("firewall: %s", msg)
		m.fail(ctx, CodeResponseInvalid, rel.key(), msg)
		return release{}, false
	}
	if rel.PackagesURL != "" && !validPackagesURL(rel.PackagesURL, rel.PackagesPath) {
		msg := fmt.Sprintf("Invalid latest-firewall response (packages_url '%s')", rel.PackagesURL)
		m.Logf("firewall: %s", msg)
		m.fail(ctx, CodeResponseInvalid, rel.key(), msg)
		return release{}, false
	}
	m.Logf("firewall: latest on-device firewall: %s", rel)
	return rel, true
}

// validPackagesURL accepts packages_url, the mirror fallback, only as an
// https URL with no credentials, query or fragment whose path ends in
// "/<packages_path>" (already validated, no "..").
//
// The host is not pinned: each API environment, including dedicated
// instances, has its own packages host, and the URL comes from the API this
// agent is configured for, over TLS. What makes any download source safe is
// the verification that follows every download, whatever its source: the
// sha256 against the checksum signed with the release key, then the
// Authenticode publisher and the version the exe reports. A wrong host can
// only make the download fail.
func validPackagesURL(raw, packagesPath string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	return strings.HasSuffix(u.EscapedPath(), "/"+packagesPath) && !strings.Contains(u.EscapedPath(), "..")
}

// sendRemoved tells the API the requested removal is done (POST
// devices/<id>/firewall/lifecycle {"event":"removed"}), which marks the
// device removed in the console at once. Best effort, like the loader's
// Send-OnDeviceFirewallRemoved: 2 attempts of 3 s; 2xx and 4xx are final.
func (m *Manager) sendRemoved(ctx context.Context) {
	id := m.DeviceID()
	if id == "" {
		return
	}
	endpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/devices/%s/firewall/lifecycle",
		strings.TrimRight(m.APIEndpoint, "/"), url.PathEscape(m.CustomerID), url.PathEscape(id))
	for attempt := 1; attempt <= lifecycleAttempts; attempt++ {
		if attempt > 1 {
			if m.Sleep(ctx, residueCheckPeriod) != nil {
				return
			}
		}
		status, err := m.postLifecycle(ctx, endpoint)
		switch {
		case err == nil && status < 300:
			return
		case err == nil && status < 500:
			m.Logf("firewall: the API did not record the on-device firewall removal (HTTP %d)", status)
			return
		}
	}
	m.Logf("firewall: could not report the on-device firewall removal to the API; the console updates once its last check-in ages out")
}

func (m *Manager) postLifecycle(ctx context.Context, endpoint string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, lifecycleTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte(`{"event":"removed"}`)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+m.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Version", m.AgentVersion)
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}
