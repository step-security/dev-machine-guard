package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeAPI is an in-process latest-binary + release download + run-status
// server.
type fakeAPI struct {
	t      testing.TB
	srv    *httptest.Server
	signer *testSigner

	mu       sync.Mutex
	target   string                       // version latest-binary returns
	releases map[string]map[string][]byte // version -> remote asset name -> body
	// fault knobs
	metaStatus     int               // non-zero: latest-binary returns this
	metaBody       string            // non-empty: raw latest-binary body
	noLinuxFields  bool              // windows response omits linux_checksum fields
	githubDown     bool              // release downloads 404
	mirrorDown     bool              // mirror downloads 404
	badSig         map[string]bool   // remote asset -> signature over wrong data
	checksumOver   map[string]string // remote asset -> served checksum override
	eventStatus    int               // non-zero: run-status returns this
	requests       []*http.Request
	events         []map[string]any
	githubHits     map[string]int
	mirrorHits     map[string]int
	latestRequests []string
}

// newFakeAPI serves over TLS (srv.Client trusts it) so the HTTPS-only mirror
// rule holds.
func newFakeAPI(t testing.TB) *fakeAPI { return startFakeAPI(t, true) }

func startFakeAPI(t testing.TB, useTLS bool) *fakeAPI {
	f := &fakeAPI{
		t: t, signer: newTestSigner(t),
		releases:     map[string]map[string][]byte{},
		badSig:       map[string]bool{},
		checksumOver: map[string]string{},
		githubHits:   map[string]int{},
		mirrorHits:   map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/cust/developer-mdm-agent/latest-binary", f.latest)
	mux.HandleFunc("/v1/cust/developer-mdm-agent/telemetry/run-status", f.runStatus)
	mux.HandleFunc("/releases/", f.download("/releases/v", &f.githubDown, f.githubHits))
	mux.HandleFunc("/mirror/", f.download("/mirror/", &f.mirrorDown, f.mirrorHits))
	if useTLS {
		f.srv = httptest.NewTLSServer(mux)
	} else {
		f.srv = httptest.NewServer(mux)
	}
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) URL() string { return f.srv.URL }

// addRelease registers the three assets of version v for arch.
func (f *fakeAPI) addRelease(v, arch string, agent, launcher, linux []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases[v] = map[string][]byte{
		fmt.Sprintf("stepsecurity-dev-machine-guard-%s-windows_%s.exe", v, arch):      agent,
		fmt.Sprintf("stepsecurity-dev-machine-guard-task-%s-windows_%s.exe", v, arch): launcher,
		fmt.Sprintf("stepsecurity-dev-machine-guard-%s-linux_%s", v, arch):            linux,
	}
}

func (f *fakeAPI) setTarget(v string) { f.mu.Lock(); f.target = v; f.mu.Unlock() }

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (f *fakeAPI) assetFields(v, remote string) (checksum, signed string) {
	body, ok := f.releases[v][remote]
	if !ok {
		return "", ""
	}
	checksum = sum(body)
	if o, ok := f.checksumOver[remote]; ok {
		checksum = o
	}
	signed = f.signer.transport(checksum)
	if f.badSig[remote] {
		signed = f.signer.transport(strings.Repeat("0", 64))
	}
	return checksum, signed
}

func (f *fakeAPI) latest(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
	f.latestRequests = append(f.latestRequests, r.URL.RawQuery)
	if f.metaStatus != 0 {
		w.WriteHeader(f.metaStatus)
		return
	}
	if f.metaBody != "" {
		_, _ = io.WriteString(w, f.metaBody)
		return
	}
	q := r.URL.Query()
	arch, v := q.Get("arch"), f.target
	resp := map[string]string{"version": v}
	switch q.Get("os") {
	case "windows":
		resp["checksum"], resp["signed_checksum"] = f.assetFields(v, fmt.Sprintf("stepsecurity-dev-machine-guard-%s-windows_%s.exe", v, arch))
		resp["launcher_checksum"], resp["signed_launcher_checksum"] = f.assetFields(v, fmt.Sprintf("stepsecurity-dev-machine-guard-task-%s-windows_%s.exe", v, arch))
		if !f.noLinuxFields {
			resp["linux_checksum"], resp["signed_linux_checksum"] = f.assetFields(v, fmt.Sprintf("stepsecurity-dev-machine-guard-%s-linux_%s", v, arch))
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeAPI) download(prefix string, down *bool, hits map[string]int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		v, remote, _ := strings.Cut(rest, "/")
		hits[remote]++
		body, ok := f.releases[v][remote]
		if *down || !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}
}

func (f *fakeAPI) runStatus(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.eventStatus != 0 {
		w.WriteHeader(f.eventStatus)
		return
	}
	f.events = append(f.events, body)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeAPI) client(arch string) *Client {
	return &Client{
		HTTP: f.srv.Client(), APIEndpoint: f.srv.URL, CustomerID: "cust", APIKey: "key",
		AgentVersion: "1.19.0", Arch: arch,
		ReleaseBaseURL: f.srv.URL + "/releases", MirrorURL: "",
		SigningKey: f.signer.pubB64,
	}
}
