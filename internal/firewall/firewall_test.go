package firewall

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/fwpath"
)

const (
	testEndpoint = "https://api.example.com"
	testDevice   = "dev 1/x"
)

// testSigned stands in for a signed checksum; verifyChecksum is faked.
var testSigned = base64.StdEncoding.EncodeToString([]byte("sig"))

// exeContent is what a fake firewall exe holds: its `version --json`
// output, plus a flag that makes its `install` fail.
func exeContent(version, build string, failInstall bool) []byte {
	b, _ := json.Marshal(map[string]any{"version": version, "build": build, "fail_install": failInstall})
	return b
}

func makeZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(content)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fakeService is SCM for one service.
type fakeService struct {
	mu                       sync.Mutex
	exists, running, stopped bool
	binPath                  string
	stuck                    bool // Stop does nothing
	deleteFails              bool
	stops, starts, deletes   int
}

func (s *fakeService) Status() (ServiceStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ServiceStatus{Exists: s.exists, Running: s.exists && s.running, Stopped: s.exists && s.stopped, BinaryPath: s.binPath}, nil
}

func (s *fakeService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stops++
	if !s.stuck {
		s.running, s.stopped = false, true
	}
	return nil
}

func (s *fakeService) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts++
	if s.exists {
		s.running, s.stopped = true, false
	}
	return nil
}

func (s *fakeService) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	if s.deleteFails {
		return errors.New("access denied")
	}
	s.exists = false
	return nil
}

// fakeAPI serves latest-firewall, the packages (any other GET path) and the
// lifecycle endpoint; a transport sends every request (any host) to it.
type fakeAPI struct {
	mu         sync.Mutex
	latest     func() (int, any)
	files      map[string][]byte // path -> body; missing = 404
	requests   []*url.URL
	hosts      []string
	latestHits int
	lifecycle  []string // device ids
}

func (a *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u := *r.URL
	a.requests = append(a.requests, &u)
	a.hosts = append(a.hosts, r.Header.Get("X-Orig-Host"))
	switch {
	case strings.HasSuffix(r.URL.Path, "/developer-mdm-agent/latest-firewall"):
		a.latestHits++
		if r.Header.Get("Authorization") != "Bearer key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		status, body := a.latest()
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	case strings.HasSuffix(r.URL.Path, "/firewall/lifecycle") && r.Method == http.MethodPost:
		parts := strings.Split(r.URL.EscapedPath(), "/")
		id, _ := url.PathUnescape(parts[len(parts)-3])
		a.lifecycle = append(a.lifecycle, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		if b, ok := a.files[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func (a *fakeAPI) assetHits() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, u := range a.requests {
		if strings.HasSuffix(u.Path, ".zip") {
			n++
		}
	}
	return n
}

// redirect sends every request to the test server, keeping the path and
// recording the host it was meant for.
type redirect struct{ target *url.URL }

func (r redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Header.Set("X-Orig-Host", req.URL.Host)
	out.URL.Scheme, out.URL.Host = r.target.Scheme, r.target.Host
	out.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(out)
}

type harness struct {
	t        *testing.T
	m        *Manager
	svc      *fakeService
	api      *fakeAPI
	reports  []string
	runs     []string
	now      time.Time
	msi      string
	busy     bool
	lockHeld bool
	elevated bool
	verified []string
	pubErr   error
	sigErr   error
	logs     []string
}

func newHarness(t *testing.T, endpoint string) *harness {
	t.Helper()
	root := t.TempDir()
	h := &harness{
		t: t, svc: &fakeService{}, api: &fakeAPI{files: map[string][]byte{}},
		now: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC), msi: FirstFirewallMSIVersion, elevated: true,
	}
	srv := httptest.NewServer(h.api)
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, "ProgramData", "StepSecurity", "config.json")
	h.m = &Manager{
		APIEndpoint: endpoint, CustomerID: "cust", APIKey: "key", AgentVersion: "1.20.0",
		HTTP:       &http.Client{Transport: redirect{target}},
		DeviceID:   func() string { return testDevice },
		Arch:       "amd64",
		ConfigPath: cfg,
		Dir:        filepath.Join(root, "Program Files", "StepSecurity", fwpath.DirName),
		DataDir:    filepath.Join(root, "ProgramData", "StepSecurity", fwpath.DirName),
		StateDir:   state,
		SelfExe:    filepath.Join(root, "agent.exe"),
		Report: func(_ context.Context, msg string) error {
			h.reports = append(h.reports, msg)
			return nil
		},
		Now: func() time.Time { return h.now },
		Sleep: func(ctx context.Context, d time.Duration) error {
			h.now = h.now.Add(d)
			return ctx.Err()
		},
		Logf: func(format string, args ...any) {
			h.logs = append(h.logs, fmt.Sprintf(format, args...))
			t.Logf(format, args...)
		},
		verifyChecksum: func(string, []byte) error {
			return h.sigErr
		},
	}
	h.m.Sys = System{
		Run:          h.run,
		Service:      h.svc,
		ImageRunning: func(string) bool { h.svc.mu.Lock(); defer h.svc.mu.Unlock(); return h.svc.running },
		MSIVersion: func() (string, error) {
			if h.msi == "" {
				return "", errors.New("not found")
			}
			return h.msi, nil
		},
		VerifyPublisher: func(c, self string) error {
			h.verified = append(h.verified, c+"|"+self)
			return h.pubErr
		},
		InstallerBusy: func() bool { return h.busy },
		Elevated:      func() bool { return h.elevated },
		Lock: func() (func(), error) {
			if h.lockHeld {
				return nil, fmt.Errorf("%w: test", ErrLockHeld)
			}
			return func() {}, nil
		},
	}
	return h
}

// run is the fake firewall exe: version --json prints its content, install
// registers and starts the service (or fails), uninstall deletes it.
func (h *harness) run(_ context.Context, _ time.Duration, name string, args ...string) (string, string, int, error) {
	h.runs = append(h.runs, filepath.Base(filepath.Dir(name))+"/"+filepath.Base(name)+" "+strings.Join(args, " "))
	b, err := os.ReadFile(name)
	if err != nil {
		return "", "", 1, err
	}
	var c struct {
		FailInstall bool `json:"fail_install"`
	}
	_ = json.Unmarshal(b, &c)
	switch args[0] {
	case "version":
		return string(b), "", 0, nil
	case "install":
		if c.FailInstall {
			return "", "service failed to start", 1, nil
		}
		h.svc.mu.Lock()
		h.svc.exists, h.svc.running, h.svc.stopped = true, true, false
		h.svc.binPath = fmt.Sprintf(`"%s" run --config "%s"`, name, args[2])
		h.svc.mu.Unlock()
		return "installed", "", 0, nil
	case "uninstall":
		h.svc.mu.Lock()
		h.svc.exists, h.svc.running = false, false
		h.svc.mu.Unlock()
		return "", "", 0, nil
	}
	return "", "unknown command", 2, nil
}

// serve publishes a release: latest-firewall answers install for it (with
// packages_url) and the packages mirror serves its zip.
func (h *harness) serve(version, build string, zipBytes []byte, signed string) {
	asset := fmt.Sprintf("StepSecurityOnDeviceFirewall-%s-%s-amd64.zip", version, build)
	pp := fmt.Sprintf("on-device-firewall/win/%s/%s", version, asset)
	h.api.files["/"+pp] = zipBytes
	h.api.latest = func() (int, any) {
		return 200, map[string]any{
			"action": "install", "version": version, "build": build, "checksum": sha(zipBytes),
			"signed_checksum": signed, "platform": "windows", "arch": "amd64", "format": "zip",
			"asset": asset, "download_url": "https://github.com/o/r/releases/download/v" + version + "-win/" + asset,
			"packages_path": pp, "packages_url": "https://packages.example.com/" + pp,
		}
	}
}

func (h *harness) serveExe(version, build string, failInstall bool) {
	h.serve(version, build, makeZip(h.t, map[string][]byte{fwpath.ExeName: exeContent(version, build, failInstall)}), testSigned)
}

// installed puts an exe (and a running service) in place, as an earlier
// install would have.
func (h *harness) installed(version, build string) {
	h.t.Helper()
	if err := os.MkdirAll(h.m.Dir, 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.m.exe(), exeContent(version, build, false), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.MkdirAll(h.m.DataDir, 0o755); err != nil {
		h.t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(h.m.DataDir, "status.json"), []byte("{}"), 0o644)
	h.svc.exists, h.svc.running, h.svc.stopped = true, true, false
	h.svc.binPath = fmt.Sprintf(`"%s" run --config "%s"`, h.m.exe(), h.m.ConfigPath)
}

func (h *harness) installedVersion() string {
	b, err := os.ReadFile(h.m.exe())
	if err != nil {
		return ""
	}
	var v exeVersion
	_ = json.Unmarshal(b, &v)
	return v.String()
}

func (h *harness) wantReports(codes ...string) {
	h.t.Helper()
	if len(h.reports) != len(codes) {
		h.t.Fatalf("reports = %q, want codes %q", h.reports, codes)
	}
	for i, c := range codes {
		if !strings.HasPrefix(h.reports[i], c+": ") {
			h.t.Errorf("report %d = %q, want code %s", i, h.reports[i], c)
		}
	}
}

func (h *harness) wantNoStaging() {
	h.t.Helper()
	ents, _ := os.ReadDir(h.m.StateDir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "fw-staging-") {
			h.t.Errorf("staging dir left behind: %s", e.Name())
		}
	}
	if _, err := os.Stat(h.m.exe() + ".next"); err == nil {
		h.t.Error(".next left behind")
	}
}

func TestReconcile_NothingWhenOffAndAbsent(t *testing.T) {
	h := newHarness(t, testEndpoint)
	if got := h.m.Reconcile(context.Background()); got != OutcomeNothing {
		t.Fatalf("Reconcile = %s", got)
	}
	if len(h.api.requests) != 0 || len(h.reports) != 0 {
		t.Fatalf("requests %v, reports %v", h.api.requests, h.reports)
	}
}

func TestReconcile_FreshInstallInt(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	// A prerelease: the tag carries -rc.5, the exe reports the plain version.
	h.serve("0.2.0-rc.5", "42", makeZip(t, map[string][]byte{fwpath.ExeName: exeContent("0.2.0", "42", false)}), testSigned)
	if got := h.m.Reconcile(context.Background()); got != OutcomeInstalled {
		t.Fatalf("Reconcile = %s, reports %q", got, h.reports)
	}
	if v := h.installedVersion(); v != "0.2.0 (42)" {
		t.Errorf("installed %q", v)
	}
	if !h.svc.running || !strings.Contains(h.svc.binPath, "--config") || !strings.Contains(h.svc.binPath, h.m.ConfigPath) {
		t.Errorf("service %+v", h.svc)
	}
	q := h.api.requests[0].Query()
	for k, want := range map[string]string{"os": "windows", "arch": "amd64", "format": "zip", "device_id": testDevice} {
		if q.Get(k) != want {
			t.Errorf("latest-firewall %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Has("lag_behind") {
		t.Error("lag_behind sent without an override")
	}
	if len(h.verified) != 1 || !strings.HasSuffix(h.verified[0], "|"+h.m.SelfExe) {
		t.Errorf("Authenticode checks %v, want one against the agent", h.verified)
	}
	// GitHub first (download_url), and it served nothing, so packages_url.
	if got := h.api.hosts[1]; got != "github.com" {
		t.Errorf("first download from %q, want github.com", got)
	}
	if got := h.api.hosts[2]; got != "packages.example.com" {
		t.Errorf("fallback download from %q", got)
	}
	h.wantReports()
	h.wantNoStaging()

	// The next tick finds it up to date and downloads nothing.
	hits := h.api.assetHits()
	if got := h.m.Reconcile(context.Background()); got != OutcomeUpToDate {
		t.Fatalf("second Reconcile = %s", got)
	}
	if h.api.assetHits() != hits {
		t.Error("an up-to-date firewall was downloaded again")
	}
}

func TestReconcile_LagAndCooldownOverride(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall, h.m.LagBehind, h.m.CooldownHours = true, 1, 0
	h.serveExe("0.2.0", "42", false)
	h.m.Reconcile(context.Background())
	q := h.api.requests[0].Query()
	if q.Get("lag_behind") != "1" || q.Get("cooldown_hours") != "0" {
		t.Errorf("query %v", q)
	}
}

func TestReconcile_GitHubDownloadPreferred(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.serveExe("0.2.0", "42", false)
	// Serve the zip at the GitHub path too.
	for p, b := range h.api.files {
		h.api.files["/o/r/releases/download/v0.2.0-win/"+filepath.Base(p)] = b
	}
	if got := h.m.Reconcile(context.Background()); got != OutcomeInstalled {
		t.Fatalf("Reconcile = %s", got)
	}
	if len(h.api.hosts) != 2 || h.api.hosts[1] != "github.com" {
		t.Fatalf("hosts %v: want one GitHub download", h.api.hosts)
	}
}

func TestReconcile_DownloadFailedWithoutPackagesURL(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.serveExe("0.2.0", "42", false)
	inner := h.api.latest
	h.api.latest = func() (int, any) {
		_, r := inner()
		delete(r.(map[string]any), "packages_url")
		return 200, r
	}
	if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
		t.Fatalf("Reconcile = %s", got)
	}
	h.wantReports(CodeDownloadFailed)
	h.wantNoStaging()
}

func TestReconcile_UpgradeReplacesAndDropsOld(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.installed("0.1.0", "41")
	h.serveExe("0.2.0", "42", false)
	if got := h.m.Reconcile(context.Background()); got != OutcomeInstalled {
		t.Fatalf("Reconcile = %s, reports %q", got, h.reports)
	}
	if v := h.installedVersion(); v != "0.2.0 (42)" {
		t.Errorf("installed %q", v)
	}
	if h.svc.stops != 1 {
		t.Errorf("service stopped %d times", h.svc.stops)
	}
	if _, err := os.Stat(h.m.exe() + ".old"); err == nil {
		t.Error(".old kept after a successful upgrade")
	}
	h.wantNoStaging()
}

func TestReconcile_ConfigPathMovedReinstalls(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.installed("0.2.0", "42")
	h.svc.binPath = fmt.Sprintf(`"%s" run --config "C:\other\config.json"`, h.m.exe())
	h.serveExe("0.2.0", "42", false)
	if got := h.m.Reconcile(context.Background()); got != OutcomeInstalled {
		t.Fatalf("Reconcile = %s", got)
	}
	if !strings.Contains(h.svc.binPath, h.m.ConfigPath) {
		t.Errorf("binpath %q", h.svc.binPath)
	}
}

func TestReconcile_ServiceInstallFailsRollsBack(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.installed("0.1.0", "41")
	h.serveExe("0.2.0", "42", true)
	if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
		t.Fatalf("Reconcile = %s", got)
	}
	if v := h.installedVersion(); v != "0.1.0 (41)" {
		t.Errorf("after rollback installed %q", v)
	}
	if !h.svc.running {
		t.Error("previous version not running again")
	}
	h.wantReports(CodeServiceInstallFailed)
	if !strings.Contains(h.reports[0], "previous version restored") {
		t.Errorf("report %q", h.reports[0])
	}
	h.wantNoStaging()
}

func TestReconcile_FirstInstallFails(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.serveExe("0.2.0", "42", true)
	if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
		t.Fatalf("Reconcile = %s", got)
	}
	h.wantReports(CodeServiceInstallFailed)
	if !strings.Contains(h.reports[0], "no previous version") {
		t.Errorf("report %q", h.reports[0])
	}
}

func TestReconcile_StopFailedLeavesOldRunning(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.installed("0.1.0", "41")
	h.svc.stuck = true
	h.serveExe("0.2.0", "42", false)
	start := h.now
	if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
		t.Fatalf("Reconcile = %s", got)
	}
	if waited := h.now.Sub(start); waited < stopTimeout {
		t.Errorf("waited %s for the stop", waited)
	}
	if v := h.installedVersion(); v != "0.1.0 (41)" {
		t.Errorf("installed %q", v)
	}
	if h.svc.starts != 1 {
		t.Errorf("Start called %d times", h.svc.starts)
	}
	h.wantReports(CodeStopFailed)
	h.wantNoStaging()
}

func TestReconcile_RemoveOnRequest(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.installed("0.1.0", "41")
	// Removal is never gated by the MSI version or the install setting.
	h.msi = "1.18.0"
	h.api.latest = func() (int, any) { return 200, map[string]any{"action": "uninstall", "platform": "windows"} }
	if got := h.m.Reconcile(context.Background()); got != OutcomeRemoved {
		t.Fatalf("Reconcile = %s, reports %q", got, h.reports)
	}
	for _, p := range []string{h.m.Dir, h.m.DataDir} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s left behind", p)
		}
	}
	if h.svc.exists {
		t.Error("service left behind")
	}
	if len(h.api.lifecycle) != 1 || h.api.lifecycle[0] != testDevice {
		t.Errorf("lifecycle posts %q", h.api.lifecycle)
	}
	h.wantReports()
}

func TestReconcile_RemoveOnRequestResidue(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.installed("0.1.0", "41")
	h.svc.stuck = true
	h.runs = nil
	h.api.latest = func() (int, any) { return 200, map[string]any{"action": "uninstall"} }
	// The firewall's own uninstall fails to stop it.
	h.m.Sys.Run = func(ctx context.Context, d time.Duration, name string, args ...string) (string, string, int, error) {
		if args[0] == "uninstall" {
			return "", "busy", 1, nil
		}
		return h.run(ctx, d, name, args...)
	}
	if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
		t.Fatalf("Reconcile = %s", got)
	}
	h.wantReports(CodeUninstallFailed)
	if !strings.Contains(h.reports[0], "service "+ServiceName) {
		t.Errorf("report %q", h.reports[0])
	}
	if !fileExists(h.m.exe()) {
		t.Error("exe removed under a running service")
	}
	if len(h.api.lifecycle) != 0 {
		t.Error("removal reported with residue")
	}
}

func TestReconcile_RemoveOnRequestAbsent(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.api.latest = func() (int, any) { return 200, map[string]any{"action": "uninstall"} }
	if got := h.m.Reconcile(context.Background()); got != OutcomeNothing {
		t.Fatalf("Reconcile = %s", got)
	}
	if len(h.api.lifecycle) != 0 || len(h.reports) != 0 {
		t.Errorf("lifecycle %v, reports %v", h.api.lifecycle, h.reports)
	}
}

func TestReconcile_PresentButOffLeavesInstallAnswer(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.installed("0.1.0", "41")
	h.serveExe("0.2.0", "42", false)
	if got := h.m.Reconcile(context.Background()); got != OutcomeNothing {
		t.Fatalf("Reconcile = %s", got)
	}
	if h.api.latestHits != 1 || h.api.assetHits() != 0 {
		t.Errorf("latest %d, downloads %d", h.api.latestHits, h.api.assetHits())
	}
	if v := h.installedVersion(); v != "0.1.0 (41)" {
		t.Errorf("installed %q", v)
	}
}

func TestReconcile_MSITooOld(t *testing.T) {
	for _, msi := range []string{"1.19.1", "", "garbage"} {
		t.Run("msi="+msi, func(t *testing.T) {
			h := newHarness(t, testEndpoint)
			h.m.WantInstall = true
			h.msi = msi
			h.serveExe("0.2.0", "42", false)
			if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
				t.Fatalf("Reconcile = %s", got)
			}
			if h.api.latestHits != 0 {
				t.Error("asked latest-firewall with nothing to remove or install")
			}
			h.wantReports(CodeMSITooOld)
			// Once a day.
			h.now = h.now.Add(time.Hour)
			h.m.Reconcile(context.Background())
			h.wantReports(CodeMSITooOld)
			h.now = h.now.Add(reportWindow)
			h.m.Reconcile(context.Background())
			h.wantReports(CodeMSITooOld, CodeMSITooOld)
		})
	}
}

func TestReconcile_MSITooOldDoesNotUpgradePresent(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.msi = "1.19.1"
	h.installed("0.1.0", "41")
	h.serveExe("0.2.0", "42", false)
	if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
		t.Fatalf("Reconcile = %s", got)
	}
	if h.api.latestHits != 1 || h.api.assetHits() != 0 {
		t.Errorf("latest %d, downloads %d", h.api.latestHits, h.api.assetHits())
	}
	h.wantReports(CodeMSITooOld)
}

func TestReconcile_NotAvailable(t *testing.T) {
	for _, status := range []int{404, 501} {
		h := newHarness(t, testEndpoint)
		h.m.WantInstall = true
		h.api.latest = func() (int, any) { return status, nil }
		if got := h.m.Reconcile(context.Background()); got != OutcomeNotAvailable {
			t.Fatalf("%d: Reconcile = %s", status, got)
		}
		if h.api.latestHits != 1 || len(h.reports) != 0 {
			t.Errorf("%d: hits %d, reports %v", status, h.api.latestHits, h.reports)
		}
	}
}

func TestReconcile_APIFailed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		hits   int
		code   string
	}{
		{"5xx retried", 503, apiAttempts, "[http_5xx]"},
		{"4xx final", 403, 1, "[http_4xx]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, testEndpoint)
			h.m.WantInstall = true
			h.api.latest = func() (int, any) { return tc.status, nil }
			if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
				t.Fatalf("Reconcile = %s", got)
			}
			if h.api.latestHits != tc.hits {
				t.Errorf("hits %d, want %d", h.api.latestHits, tc.hits)
			}
			h.wantReports(CodeAPIFailed)
			if !strings.Contains(h.reports[0], tc.code) {
				t.Errorf("report %q", h.reports[0])
			}
		})
	}
}

func TestReconcile_InvalidResponse(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{
			"action": "install", "version": "0.2.0", "build": "42", "checksum": strings.Repeat("a", 64),
			"format": "zip", "arch": "amd64", "asset": "StepSecurityOnDeviceFirewall-0.2.0-42-amd64.zip",
			"packages_path": "on-device-firewall/win/0.2.0/StepSecurityOnDeviceFirewall-0.2.0-42-amd64.zip",
		}
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"bad version", func(r map[string]any) { r["version"] = "0.2" }},
		{"bad build", func(r map[string]any) { r["build"] = "4x" }},
		{"bad checksum", func(r map[string]any) { r["checksum"] = "ABC" }},
		{"format", func(r map[string]any) { r["format"] = "msi" }},
		{"arch", func(r map[string]any) { r["arch"] = "arm64" }},
		{"asset", func(r map[string]any) { r["asset"] = "../evil.zip" }},
		{"packages_path traversal", func(r map[string]any) {
			r["packages_path"] = "on-device-firewall/win/../StepSecurityOnDeviceFirewall-0.2.0-42-amd64.zip"
		}},
		{"packages_path other asset", func(r map[string]any) { r["packages_path"] = "on-device-firewall/win/0.2.0/other.zip" }},
		{"packages_url http", func(r map[string]any) {
			r["packages_url"] = "http://packages.example.com/" + r["packages_path"].(string)
		}},
		{"packages_url other asset", func(r map[string]any) {
			r["packages_url"] = "https://packages.example.com/on-device-firewall/win/0.2.0/other.zip"
		}},
		{"packages_url credentials", func(r map[string]any) {
			r["packages_url"] = "https://u:p@packages.example.com/" + r["packages_path"].(string)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, testEndpoint)
			h.m.WantInstall = true
			r := good()
			tc.edit(r)
			h.api.latest = func() (int, any) { return 200, r }
			if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
				t.Fatalf("Reconcile = %s", got)
			}
			h.wantReports(CodeResponseInvalid)
		})
	}
}

func TestReconcile_NumericBuildAndDefaults(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	z := makeZip(t, map[string][]byte{fwpath.ExeName: exeContent("0.2.0", "42", false)})
	h.api.files["/on-device-firewall/win/0.2.0/StepSecurityOnDeviceFirewall-0.2.0-42-amd64.zip"] = z
	h.api.files["/o/r/0.2.0/StepSecurityOnDeviceFirewall-0.2.0-42-amd64.zip"] = z
	// An older server: a numeric build and no asset, packages_path or packages_url.
	h.api.latest = func() (int, any) {
		return 200, map[string]any{"action": "install", "version": "0.2.0", "build": 42, "checksum": sha(z),
			"signed_checksum": testSigned, "download_url": "https://github.com/o/r/0.2.0/StepSecurityOnDeviceFirewall-0.2.0-42-amd64.zip"}
	}
	if got := h.m.Reconcile(context.Background()); got != OutcomeInstalled {
		t.Fatalf("Reconcile = %s, reports %q", got, h.reports)
	}
}

// Every release is verified, whatever API it comes from: the signed checksum
// (a missing one fails) before the download, Authenticode before the exe runs.
func TestReconcile_AlwaysVerified(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signed string
		sigErr error
		pubErr error
		want   Outcome
		code   string
	}{
		{"no signed checksum", "", nil, nil, OutcomeFailed, CodeResponseInvalid},
		{"undecodable signature", "%%%", nil, nil, OutcomeFailed, CodeSignatureDecodeFailed},
		{"bad signature", testSigned, errors.New("bad"), nil, OutcomeFailed, CodeSignatureInvalid},
		{"wrong publisher", testSigned, nil, errors.New("signed by someone else"), OutcomeFailed, CodeAuthenticodeFailed},
		{"verified", testSigned, nil, nil, OutcomeInstalled, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, testEndpoint)
			h.m.WantInstall = true
			h.sigErr, h.pubErr = tc.sigErr, tc.pubErr
			z := makeZip(t, map[string][]byte{fwpath.ExeName: exeContent("0.2.0", "42", false)})
			h.serve("0.2.0", "42", z, tc.signed)
			if got := h.m.Reconcile(context.Background()); got != tc.want {
				t.Fatalf("Reconcile = %s, reports %q", got, h.reports)
			}
			if tc.code != "" {
				h.wantReports(tc.code)
			} else {
				h.wantReports()
				if len(h.verified) != 1 || !strings.HasSuffix(h.verified[0], "|"+h.m.SelfExe) {
					t.Errorf("Authenticode checks %v", h.verified)
				}
			}
			if tc.code == CodeSignatureInvalid || tc.code == CodeResponseInvalid || tc.code == CodeSignatureDecodeFailed {
				if h.api.assetHits() != 0 {
					t.Error("downloaded before the signature was verified")
				}
			}
			h.wantNoStaging()
		})
	}
}

// The real releasesig check is what runs by default: a signature that is
// not the release key's is rejected.
func TestReconcile_RealSignatureCheck(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.m.verifyChecksum = nil
	h.serve("0.2.0", "42", makeZip(t, map[string][]byte{fwpath.ExeName: exeContent("0.2.0", "42", false)}),
		base64.StdEncoding.EncodeToString([]byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n")))
	if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
		t.Fatalf("Reconcile = %s", got)
	}
	h.wantReports(CodeSignatureInvalid)
}

func TestReconcile_PackageChecks(t *testing.T) {
	exe := exeContent("0.2.0", "42", false)
	for _, tc := range []struct {
		name string
		zip  func(t *testing.T) []byte
		sum  string // served checksum; "" = the zip's
		code string
	}{
		{"checksum mismatch", func(t *testing.T) []byte { return makeZip(t, map[string][]byte{fwpath.ExeName: exe}) }, strings.Repeat("0", 64), CodeChecksumMismatch},
		{"extra entry", func(t *testing.T) []byte {
			return makeZip(t, map[string][]byte{fwpath.ExeName: exe, "readme.txt": []byte("x")})
		}, "", CodeUnpackFailed},
		{"in a folder", func(t *testing.T) []byte { return makeZip(t, map[string][]byte{"bin/" + fwpath.ExeName: exe}) }, "", CodeUnpackFailed},
		{"other name", func(t *testing.T) []byte { return makeZip(t, map[string][]byte{"evil.exe": exe}) }, "", CodeUnpackFailed},
		{"not a zip", func(*testing.T) []byte { return []byte("nope") }, "", CodeUnpackFailed},
		{"build mismatch", func(t *testing.T) []byte {
			return makeZip(t, map[string][]byte{fwpath.ExeName: exeContent("0.2.0", "41", false)})
		}, "", CodeBuildMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, testEndpoint)
			h.m.WantInstall = true
			z := tc.zip(t)
			h.serve("0.2.0", "42", z, testSigned)
			if tc.sum != "" {
				inner := h.api.latest
				h.api.latest = func() (int, any) {
					_, r := inner()
					r.(map[string]any)["checksum"] = tc.sum
					return 200, r
				}
			}
			if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
				t.Fatalf("Reconcile = %s", got)
			}
			h.wantReports(tc.code)
			if fileExists(h.m.exe()) {
				t.Error("an unverified exe was installed")
			}
			h.wantNoStaging()
		})
	}
}

func TestReconcile_Busy(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.busy = true
	if got := h.m.Reconcile(context.Background()); got != OutcomeBusy {
		t.Fatalf("installer busy: %s", got)
	}
	h.busy, h.lockHeld = false, true
	if got := h.m.Reconcile(context.Background()); got != OutcomeBusy {
		t.Fatalf("lock held: %s", got)
	}
	if len(h.api.requests) != 0 {
		t.Error("asked the API while busy")
	}
}

func TestReconcile_PanicIsReported(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.m.Sys.MSIVersion = func() (string, error) { panic("boom") }
	if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
		t.Fatalf("Reconcile = %s", got)
	}
	h.wantReports(CodeUnhandledError)
}

func TestReconcile_ReportsOncePerRelease(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.serveExe("0.2.0", "42", true)
	h.m.Reconcile(context.Background())
	h.now = h.now.Add(time.Hour)
	h.m.Reconcile(context.Background())
	h.wantReports(CodeServiceInstallFailed)
	// A new build reports at once.
	h.serveExe("0.2.1", "43", true)
	h.m.Reconcile(context.Background())
	h.wantReports(CodeServiceInstallFailed, CodeServiceInstallFailed)
	// A success clears the record.
	h.serveExe("0.2.1", "43", false)
	if got := h.m.Reconcile(context.Background()); got != OutcomeInstalled {
		t.Fatalf("Reconcile = %s", got)
	}
	if _, err := os.Stat(filepath.Join(h.m.StateDir, reportStateFile)); err == nil {
		t.Error("report state kept after a success")
	}
}

func TestUninstall(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.installed("0.1.0", "41")
	if left := h.m.Uninstall(context.Background()); len(left) != 0 {
		t.Fatalf("left %v", left)
	}
	if h.svc.exists || fileExists(h.m.exe()) {
		t.Error("firewall left behind")
	}
	if _, err := os.Stat(h.m.DataDir); err == nil {
		t.Error("data dir left behind")
	}
	// The agent's uninstall asks no API and posts no lifecycle event.
	if len(h.api.requests) != 0 {
		t.Errorf("requests %v", h.api.requests)
	}
	if !strings.Contains(strings.Join(h.runs, ";"), fwpath.ExeName+" uninstall") {
		t.Errorf("the firewall's own uninstall did not run: %v", h.runs)
	}
	// Nothing installed: nothing to do.
	if left := h.m.Uninstall(context.Background()); len(left) != 0 {
		t.Fatalf("second Uninstall left %v", left)
	}
	h.wantReports()
}

func TestUninstall_ServiceWithoutExe(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.svc.exists, h.svc.running = true, true
	if left := h.m.Uninstall(context.Background()); len(left) != 0 {
		t.Fatalf("left %v", left)
	}
	if h.svc.stops != 1 || h.svc.deletes != 1 {
		t.Errorf("stops %d, deletes %d", h.svc.stops, h.svc.deletes)
	}
}

func TestUninstall_Residue(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(h *harness)
		want  string
	}{
		{"not elevated", func(h *harness) { h.elevated = false }, "on-device firewall ("},
		{"lock held", func(h *harness) { h.lockHeld = true }, "another run held its lock"},
		{"delete fails", func(h *harness) {
			h.svc.deleteFails = true
			h.m.Sys.Run = func(context.Context, time.Duration, string, ...string) (string, string, int, error) {
				return "", "", 1, nil
			}
		}, "service " + ServiceName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, testEndpoint)
			h.installed("0.1.0", "41")
			tc.setup(h)
			left := h.m.Uninstall(context.Background())
			if !strings.Contains(strings.Join(left, ", "), tc.want) {
				t.Fatalf("left %v, want %q", left, tc.want)
			}
			h.wantReports(CodeUninstallFailed)
		})
	}
}

func TestValidPackagesURL(t *testing.T) {
	pp := "on-device-firewall/win/0.2.0/StepSecurityOnDeviceFirewall-0.2.0-42-amd64.zip"
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"https://packages.example.com/" + pp, true},
		{"https://cdn.example.com/mirror/" + pp, true},
		{"http://packages.example.com/" + pp, false},
		{"https://packages.example.com/other/" + pp + ".x", false},
		{"https://u:p@packages.example.com/" + pp, false},
		{"https://packages.example.com/" + pp + "?x=1", false},
		{"https://packages.example.com/" + pp + "#f", false},
		{"https:///" + pp, false},
		{"https://packages.example.com/a/../" + pp, false},
		{"", false},
	} {
		if got := validPackagesURL(tc.raw, pp); got != tc.want {
			t.Errorf("validPackagesURL(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestExeVersionMatches(t *testing.T) {
	rel := release{Version: "0.2.0-rc.5", Build: "42"}
	for _, tc := range []struct {
		v    *exeVersion
		want bool
	}{
		{&exeVersion{"0.2.0-rc.5", "42"}, true},
		{&exeVersion{"0.2.0", "42"}, true},
		{&exeVersion{"0.2.0", "41"}, false},
		{&exeVersion{"0.3.0", "42"}, false},
		{nil, false},
	} {
		if got := tc.v.matches(rel); got != tc.want {
			t.Errorf("%v.matches = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// A tick too short for a swap stops before touching the installed firewall.
func TestReconcile_NoTimeForSwapLeavesInstalled(t *testing.T) {
	h := newHarness(t, testEndpoint)
	h.m.WantInstall = true
	h.installed("0.1.0", "41")
	h.serveExe("0.2.0", "42", false)
	ctx, cancel := context.WithTimeout(context.Background(), swapBudget-time.Second)
	defer cancel()
	if got := h.m.Reconcile(ctx); got != OutcomeFailed {
		t.Fatalf("Reconcile = %s", got)
	}
	if v := h.installedVersion(); v != "0.1.0 (41)" || h.svc.stops != 0 || !h.svc.running {
		t.Errorf("installed %q, stops %d, running %v", v, h.svc.stops, h.svc.running)
	}
	h.wantNoStaging()
}
