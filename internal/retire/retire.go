// Package retire tells the backend that this device is going away.
//
// It backs `uninstall --retire` (and config.json retire_on_uninstall): the
// agent's last act before removing its scheduler job is a best-effort POST to
// the agent-facing retire endpoint, so an ephemeral machine — a virtual
// desktop torn down by its host pool — leaves the dashboard and the license
// count instead of lingering as an inactive seat. Everything here is
// advisory: a failure is logged and the uninstall proceeds, and a retired
// device that reports again is restored by the backend automatically.
package retire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/heartbeat"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Reasons the agent sends as retired_reason. The management API and the
// inactivity sweep use their own values.
const (
	// ReasonUninstall: `uninstall --retire` / retire_on_uninstall.
	ReasonUninstall = "agent_uninstall"
	// ReasonIdentityChanged: a host switched to the automatic per-user identity
	// and its previous machine-identity row is being retired.
	ReasonIdentityChanged = "identity_changed"
)

const (
	// attemptTimeout bounds one HTTP attempt. Uninstall runs inside an MSI
	// custom action or a teardown script, so it must not hang on a dead
	// network.
	attemptTimeout = 2 * time.Second
	attempts       = 2
	retryBackoff   = 300 * time.Millisecond
	// TotalBudget caps the whole retire step across every identity, so a
	// machine with many per-user state dirs still uninstalls promptly.
	TotalBudget = 10 * time.Second
	// MaxIdentities caps how many ids CollectIdentities returns.
	MaxIdentities = 20
	maxErrorBody  = 4 << 10
)

// ErrNotSupported is returned for a 404: the backend predates the retire
// endpoint. Callers treat it as a warning, not a failure.
var ErrNotSupported = errors.New("retire: endpoint not available on this backend (404)")

// Statuses the backend answers with on a 2xx retire response.
const (
	// StatusRetired: the row is retired (or was already).
	StatusRetired = "retired"
	// StatusUnknownDevice: no row for the id; the backend created none.
	StatusUnknownDevice = "unknown_device"
	// StatusOutOfScope: the tenant's retirement scope (Settings, Device
	// activity) does not select this device; the row stays as it is.
	StatusOutOfScope = "out_of_scope"
)

// Post retires deviceID under customerID: POST
// {endpoint}/v1/{customer}/developer-mdm-agent/devices/{device_id}/retire with
// the telemetry key as Bearer and the given reason (Reason*). A 2xx is
// success and yields the backend's status (Status*; "" when the body carries
// none), including an unknown device, which the backend answers without
// creating a row. 5xx and transport errors retry once; any other 4xx is
// terminal. Errors are redacted (the URL embeds the customer id, the header
// the tenant key).
func Post(ctx context.Context, endpoint, apiKey, customerID, deviceID, agentVersion, platform, reason string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	apiKey = strings.TrimSpace(apiKey)
	customerID = strings.TrimSpace(customerID)
	deviceID = strings.TrimSpace(deviceID)
	if endpoint == "" || apiKey == "" || customerID == "" {
		return "", errors.New("retire: missing endpoint, api key or customer id")
	}
	if deviceID == "" || deviceID == "unknown" {
		return "", errors.New("retire: no usable device id")
	}
	target := strings.TrimRight(endpoint, "/") + "/v1/" + url.PathEscape(customerID) +
		"/developer-mdm-agent/devices/" + url.PathEscape(deviceID) + "/retire"

	// device_tag lets the backend apply the tenant's retirement scope to a
	// row that predates the tag (the serial row at the identity switch).
	body, err := json.Marshal(map[string]string{
		"agent_version": agentVersion,
		"platform":      platform,
		"reason":        reason,
		"device_tag":    config.DeviceTag,
	})
	if err != nil {
		return "", fmt.Errorf("retire: encode body: %w", err)
	}

	var last error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return "", fmt.Errorf("retire: %w", ctx.Err())
			case <-time.After(retryBackoff):
			}
		}
		status, retryable, err := post(ctx, target, apiKey, body)
		if err == nil {
			return status, nil
		}
		last = err
		if !retryable {
			return "", err
		}
	}
	return "", last
}

// post performs one attempt. retryable reports whether another attempt may
// succeed (transport error or 5xx); status is the backend's verdict on a 2xx.
func post(ctx context.Context, target, apiKey string, body []byte) (status string, retryable bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return "", false, fmt.Errorf("retire: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := (&http.Client{Timeout: attemptTimeout}).Do(req)
	if err != nil {
		return "", true, fmt.Errorf("retire: transport: %s", redact.String(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		var parsed struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(raw, &parsed) // a body without a status is a plain success
		return parsed.Status, false, nil
	case resp.StatusCode == http.StatusNotFound:
		return "", false, ErrNotSupported
	case resp.StatusCode >= 500:
		return "", true, fmt.Errorf("retire: unexpected status %d", resp.StatusCode)
	default:
		return "", false, fmt.Errorf("retire: unexpected status %d", resp.StatusCode)
	}
}

// CollectIdentities returns every device id this installation may have
// registered under: the identity resolved right now (when complete), plus the
// run-gate cache of every state file under the install dir — last-run.json at
// the top level and users/*/last-run.json for per-user identities. The latter
// is what lets an MSI uninstall, which runs as SYSTEM and therefore cannot
// complete a {user} template itself, retire each logged-in user's device.
// Deduplicated, ordered, capped at MaxIdentities.
func CollectIdentities(ctx context.Context, exec executor.Executor, log *progress.Logger) []string {
	seen := map[string]bool{}
	var ids []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || id == "unknown" || seen[id] {
			return
		}
		seen[id] = true
		ids = append(ids, id)
	}

	if id := device.ResolvedDeviceID(ctx, exec); !id.Incomplete {
		add(id.DeviceID)
	} else {
		log.Debug("retire: identity template %q is incomplete in this context; relying on cached per-user ids", id.Template)
	}

	// The install dir this process resolves is not always where the scheduled
	// runs kept their state: an MSI uninstall custom action runs as SYSTEM,
	// whose own home is the systemprofile folder, while the elevated install
	// writes everything under C:\ProgramData\StepSecurity. Search both.
	for _, id := range collectCachedIDs(ctx, stateRoots()) {
		add(id)
	}
	return capIDs(ids)
}

func capIDs(ids []string) []string {
	if len(ids) > MaxIdentities {
		return ids[:MaxIdentities]
	}
	return ids
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// stateRoots lists the directories whose last-run.json files may name this
// install's devices: the resolved install dir and, on Windows, the
// machine-wide one. Deduplicated, empty entries dropped.
func stateRoots() []string {
	var roots []string
	seen := map[string]bool{}
	for _, r := range []string{paths.Home(), config.MachineInstallDir()} {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		roots = append(roots, r)
	}
	return roots
}

// Bounds on identity collection: the users tree and the per-user caches are
// user-writable, so neither the number of files read per root nor the size
// of one may depend on what a user planted there.
const (
	maxCachedIDFiles     = 64
	maxCachedIDFileBytes = 64 * 1024
)

// collectCachedIDs reads the run-gate cache of every state file under the
// roots: last-run.json at the top level and users/*/last-run.json for
// per-user identities. Order is deterministic (roots in order, users sorted).
// Stops at the uninstall budget (ctx), reads at most maxCachedIDFiles files
// per root and skips any larger than maxCachedIDFileBytes.
func collectCachedIDs(ctx context.Context, roots []string) []string {
	var ids []string
	for _, root := range roots {
		var files []string
		if top := filepath.Join(root, heartbeat.Filename); fileExists(top) {
			files = append(files, top)
		}
		if matches, err := filepath.Glob(filepath.Join(root, "users", "*", heartbeat.Filename)); err == nil {
			sort.Strings(matches)
			files = append(files, matches...)
		}
		if len(files) > maxCachedIDFiles {
			files = files[:maxCachedIDFiles]
		}
		for _, f := range files {
			if ctx.Err() != nil {
				return ids
			}
			if st, err := os.Stat(f); err != nil || !st.Mode().IsRegular() || st.Size() > maxCachedIDFileBytes {
				continue
			}
			rec, err := heartbeat.Load(f)
			if err != nil || rec == nil || rec.RunGate == nil {
				continue
			}
			ids = append(ids, rec.RunGate.DeviceID)
		}
	}
	return ids
}
