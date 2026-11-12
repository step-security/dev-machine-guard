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
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Reasons the agent sends as retired_reason. The management API and the
// inactivity sweep use their own values.
const (
	// ReasonUninstall: `uninstall --retire` / retire_on_uninstall.
	ReasonUninstall = "agent_uninstall"
)

const (
	// attemptTimeout bounds one HTTP attempt. Uninstall runs inside an MSI
	// custom action or a teardown script, so it must not hang on a dead
	// network.
	attemptTimeout = 2 * time.Second
	attempts       = 2
	retryBackoff   = 300 * time.Millisecond
	// TotalBudget caps collecting the identities, and is the floor of the
	// budget for retiring them (BudgetFor).
	TotalBudget = 10 * time.Second
	// perIdentityBudget is what BudgetFor adds per identity beyond the
	// first: one attempt plus its retry.
	perIdentityBudget = 2*attemptTimeout + retryBackoff
	// MaxBudget caps BudgetFor so a host with many cached ids still
	// uninstalls promptly; rows the budget leaves behind are covered by the
	// dashboard's auto-retire.
	MaxBudget = 60 * time.Second
	// MaxIdentities caps how many ids CollectIdentities returns.
	MaxIdentities = 100
	maxErrorBody  = 4 << 10
)

// BudgetFor is the time budget for retiring n identities: TotalBudget plus
// perIdentityBudget for every identity beyond the first, capped at MaxBudget.
func BudgetFor(n int) time.Duration {
	budget := TotalBudget
	if n > 1 {
		budget += time.Duration(n-1) * perIdentityBudget
	}
	if budget > MaxBudget {
		return MaxBudget
	}
	return budget
}

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
	// row that predates the tag.
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
// the top level and users/*/last-run.json for the per-session state. A
// session's record normally names the machine identity too, and the per-user
// ids an older build wrote go with it, so an MSI uninstall running as SYSTEM
// leaves no row behind. Deduplicated, ordered, capped at MaxIdentities.
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

	id := device.ResolvedDeviceID(ctx, exec)
	if !id.Incomplete {
		add(id.DeviceID)
	} else {
		log.Debug("retire: identity template %q cannot be completed in this context; relying on the cached run records", id.Template)
	}

	// The install dir this process resolves is not always where the scheduled
	// runs kept their state: an MSI uninstall custom action runs as SYSTEM,
	// whose own home is the systemprofile folder, while the elevated install
	// writes everything under C:\ProgramData\StepSecurity. Search both.
	// The resolver probes the machine identity only when the template needs
	// it; the cached records are compared against it, so resolve it here
	// (once per process, bounded by ctx).
	machineID := id.Serial
	if machineID == "" {
		machineID = device.SerialNumber(ctx, exec)
	}
	if machineID == "unknown" {
		machineID = ""
	}
	for _, cached := range collectCachedIDs(ctx, stateRoots(), machineID, log) {
		add(cached)
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

// Bounds on identity collection: the users tree and the per-session caches are
// user-writable, so neither the number of files read per root nor the size
// of one may depend on what a user planted there.
const (
	// maxCachedIDFiles covers every per-session cache a host at MaxIdentities
	// can have, plus the top-level heartbeat of the same root.
	maxCachedIDFiles     = MaxIdentities + 1
	maxCachedIDFileBytes = 64 * 1024
)

// collectCachedIDs reads the run-gate cache of every state file under the
// roots: last-run.json at the top level and users/*/last-run.json for the
// per-session state. Order is deterministic (roots in order, users sorted).
// Stops at the uninstall budget (ctx), reads at most maxCachedIDFiles files
// per root and skips any larger than maxCachedIDFileBytes. A record that
// names another machine (machineID known and different) was captured into
// the image this host was cloned from: its device belongs to that machine,
// so it is not a candidate here. Records without a machine id (older
// agents) are kept.
func collectCachedIDs(ctx context.Context, roots []string, machineID string, log *progress.Logger) []string {
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
			if m := rec.RunGate.MachineID; m != "" && machineID != "" && !strings.EqualFold(m, machineID) {
				log.Debug("retire: %s was recorded by another machine (%s); not retiring %s from here", f, m, rec.RunGate.DeviceID)
				continue
			}
			ids = append(ids, rec.RunGate.DeviceID)
		}
	}
	return ids
}

// ScanHoldBudget bounds how long an uninstall waits for running scans to
// finish before it gives up on retiring. An MSI uninstall action and an MDM
// script both tolerate it; a scan normally reports within seconds of its
// upload.
const ScanHoldBudget = 30 * time.Second

// scanHoldPoll is how often HoldScans retries the instance locks.
var scanHoldPoll = 500 * time.Millisecond

// maxScanHoldScopes bounds how many per-session scopes HoldScans inspects.
// Each is a lock held (on Windows on an OS thread of its own) while the
// retire runs, and the users\ tree they are listed from is user-creatable;
// beyond this many the set cannot be inspected safely, so the retire is
// skipped and the device stays registered.
const maxScanHoldScopes = 64

// HoldScans waits, within ctx, until no scan runs under any identity on this
// host (the machine-wide instance lock and every per-session lock can be taken)
// and returns a release func that keeps them held while the caller retires,
// so no scan starts in between. idle is false when a scan still ran at the
// deadline; the caller must then leave the device registered, because a scan
// that reports after the retire restores it. Uninstall removes the scheduler
// first, but a stop that failed or a scan already mid-flight survive that.
// A lock that cannot be taken for any other reason proves nothing about the
// rest (the acquisition stops at the first failure, so a scan may hold a
// later one), so that is not idle either; it is retried until the deadline
// in case the failure was transient.
func HoldScans(ctx context.Context, log *progress.Logger) (release func(), idle bool) {
	scopes, complete := stateScopes()
	if !complete {
		log.Warn("retire: more than %d session state directories under users\\; cannot tell whether a scan is running, so the device stays registered", maxScanHoldScopes)
		return func() {}, false
	}
	return holdScans(ctx, scopes, log)
}

// AcquireScans takes, without blocking, the machine-wide instance lock and
// the per-session lock of every session state directory, so the caller knows
// no listed scan is running; it returns an error wrapping lock.ErrHeld while
// one is. The SYSTEM updater takes it before switching versions: a
// per-session scan holds only its own lock, so the machine-wide lock alone no
// longer means no scan runs. complete is false when the users\ tree was past
// the listing bounds and only the scopes listed before them were locked;
// unlike the retire, the updater still switches then, because the tree is
// user-creatable and a full one must not hold the updates back.
func AcquireScans() (release func(), complete bool, err error) {
	scopes, complete := stateScopes()
	lk, err := lock.AcquireAll(scopes)
	if err != nil {
		return nil, complete, err
	}
	return lk.Release, complete, nil
}

func holdScans(ctx context.Context, scopes []string, log *progress.Logger) (release func(), idle bool) {
	for {
		if ctx.Err() != nil {
			return func() {}, false
		}
		lk, err := lock.AcquireAll(scopes)
		if err == nil {
			return lk.Release, true
		}
		if errors.Is(err, lock.ErrHeld) {
			log.Debug("retire: a scan is still running (%v); waiting", err)
		} else {
			log.Debug("retire: the instance locks could not be inspected (%v); not treating the host as idle", err)
		}
		select {
		case <-ctx.Done():
			return func() {}, false
		case <-time.After(scanHoldPoll):
		}
	}
}

// maxUsersDirEntries bounds how much of the user-creatable users\ tree is
// listed at all; beyond it the set of scopes cannot be known.
const maxUsersDirEntries = 4096

// stateScopes lists the per-session state scopes (users/<scope> directories)
// under the state roots, the same places CollectIdentities reads. Only
// directories count against maxScanHoldScopes (stray files do not hide a
// later directory), the listing itself stops at maxUsersDirEntries, and past
// either bound complete is false with the scopes listed before it kept: the
// tree is user-creatable, so neither its size nor the number of locks taken
// may depend on what a user put there. A name longer than MaxUserTokenLen is
// skipped: no scan uses it, and its lock name could not be created.
func stateScopes() (scopes []string, complete bool) {
	complete = true
	seen := map[string]bool{}
	for _, root := range stateRoots() {
		d, err := os.Open(filepath.Join(root, "users")) // #nosec G304 -- fixed name under the install dir
		if err != nil {
			continue
		}
		entries, _ := d.ReadDir(maxUsersDirEntries + 1)
		_ = d.Close()
		if len(entries) > maxUsersDirEntries {
			entries, complete = entries[:maxUsersDirEntries], false
		}
		for _, e := range entries {
			// A name longer than any user token is no session's scope; a
			// planted one would only make its lock name invalid.
			if !e.IsDir() || seen[e.Name()] || len(e.Name()) > device.MaxUserTokenLen {
				continue
			}
			if len(scopes) >= maxScanHoldScopes {
				complete = false
				break
			}
			seen[e.Name()] = true
			scopes = append(scopes, e.Name())
		}
	}
	sort.Strings(scopes)
	return scopes, complete
}
