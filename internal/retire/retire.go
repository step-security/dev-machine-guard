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
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/heartbeat"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Reason is the retired_reason the backend records for an agent-initiated
// retire. Fixed on the wire; the management API and the inactivity sweep use
// their own values.
const Reason = "agent_uninstall"

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

// Post retires deviceID under customerID: POST
// {endpoint}/v1/{customer}/developer-mdm-agent/devices/{device_id}/retire with
// the telemetry key as Bearer. 2xx is success (including an unknown device —
// the backend answers 200 without creating a row). 5xx and transport errors
// retry once; any other 4xx is terminal. Errors are redacted (the URL embeds
// the customer id, the header the tenant key).
func Post(ctx context.Context, endpoint, apiKey, customerID, deviceID, agentVersion, platform string) error {
	endpoint = strings.TrimSpace(endpoint)
	apiKey = strings.TrimSpace(apiKey)
	customerID = strings.TrimSpace(customerID)
	deviceID = strings.TrimSpace(deviceID)
	if endpoint == "" || apiKey == "" || customerID == "" {
		return errors.New("retire: missing endpoint, api key or customer id")
	}
	if deviceID == "" || deviceID == "unknown" {
		return errors.New("retire: no usable device id")
	}
	target := strings.TrimRight(endpoint, "/") + "/v1/" + url.PathEscape(customerID) +
		"/developer-mdm-agent/devices/" + url.PathEscape(deviceID) + "/retire"

	body, err := json.Marshal(map[string]string{
		"agent_version": agentVersion,
		"platform":      platform,
		"reason":        Reason,
	})
	if err != nil {
		return fmt.Errorf("retire: encode body: %w", err)
	}

	var last error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("retire: %w", ctx.Err())
			case <-time.After(retryBackoff):
			}
		}
		retryable, err := post(ctx, target, apiKey, body)
		if err == nil {
			return nil
		}
		last = err
		if !retryable {
			return err
		}
	}
	return last
}

// post performs one attempt. retryable reports whether another attempt may
// succeed (transport error or 5xx).
func post(ctx context.Context, target, apiKey string, body []byte) (retryable bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("retire: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dmg/"+buildinfo.Version)

	resp, err := (&http.Client{Timeout: attemptTimeout}).Do(req)
	if err != nil {
		return true, fmt.Errorf("retire: transport: %s", redact.String(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusNotFound:
		return false, ErrNotSupported
	case resp.StatusCode >= 500:
		return true, fmt.Errorf("retire: unexpected status %d", resp.StatusCode)
	default:
		return false, fmt.Errorf("retire: unexpected status %d", resp.StatusCode)
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

	home := paths.Home()
	if home == "" {
		return capIDs(ids)
	}
	var files []string
	if top := filepath.Join(home, heartbeat.Filename); fileExists(top) {
		files = append(files, top)
	}
	if matches, err := filepath.Glob(filepath.Join(home, "users", "*", heartbeat.Filename)); err == nil {
		sort.Strings(matches)
		files = append(files, matches...)
	}
	for _, f := range files {
		rec, err := heartbeat.Load(f)
		if err != nil || rec == nil || rec.RunGate == nil {
			continue
		}
		add(rec.RunGate.DeviceID)
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
