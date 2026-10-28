package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

// Regression goldens for the argv parser and --help. Regenerate with
//
//	go test ./internal/cli -run Golden -update
//
// and review the diff: any change to a golden is a user-visible CLI change.
var update = flag.Bool("update", false, "rewrite the cli golden files")

// goldenArgvs covers every flag in each of its accepted spellings, its
// error paths, and the verb/flag interplay MSI, loader and scheduler
// invocations rely on.
var goldenArgvs = [][]string{
	{},
	{"install"}, {"--install"}, {"uninstall"}, {"--uninstall"},
	{"send-telemetry"}, {"--send-telemetry"},
	{"configure"}, {"configure", "show"}, {"configure", "--json"},
	{"--pretty"}, {"--json"}, {"--html", "r.html"}, {"--html"}, {"--html=r.html"},
	{"--json", "--pretty"},
	{"--enable-npm-scan"}, {"--disable-npm-scan"},
	{"--legacy-node-scan"}, {"--disk-node-scan"},
	{"--enable-brew-scan"}, {"--disable-brew-scan"},
	{"--enable-python-scan"}, {"--disable-python-scan"},
	{"--enable-runtime-scan"}, {"--disable-runtime-scan"},
	{"--legacy-python-scan"}, {"--disk-python-scan"},
	{"--enable-npm-scan", "--disable-npm-scan"},
	{"--include-bundled-plugins"},
	{"--include-tcc-protected"}, {"--no-include-tcc-protected"},
	{"--include-network-volumes"}, {"--no-include-network-volumes"},
	{"--npmrc"}, {"--pipconfig"}, {"--pnpmrc"}, {"--bunfig"}, {"--yarnrc"},
	{"--npmrc", "--json"}, {"--npmrc", "--yarnrc"},
	{"--color=auto"}, {"--color=always"}, {"--color=never"}, {"--color=rainbow"}, {"--color", "never"},
	{"--search-dirs", "/a"}, {"--search-dirs", "/a", "/b", "--json"},
	{"--search-dirs", "/a", "--search-dirs", "/b"}, {"--search-dirs"}, {"--search-dirs", "--json"},
	{"--search-dirs", "/a", "send-telemetry"},
	{"--non-interactive"}, {"--ignore-telemetry-error"},
	{"configure", "--from-file", "c.json"}, {"configure", "--from-file=c.json"}, {"configure", "--from-file"},
	{"configure", "--device-id", "d1"}, {"configure", "--device-id=d1"}, {"configure", "--device-id"}, {"configure", "--device-id="},
	{"configure", "--customer-id", "c1"}, {"configure", "--customer-id=c1"}, {"configure", "--customer-id"},
	{"configure", "--api-endpoint", "https://e"}, {"configure", "--api-endpoint=https://e"}, {"configure", "--api-endpoint"},
	{"configure", "--api-key", "k"}, {"configure", "--api-key=k"}, {"configure", "--api-key"},
	{"configure", "--scan-frequency", "4"}, {"configure", "--scan-frequency=4"}, {"configure", "--scan-frequency"},
	{"configure", "--max-execution-duration", "2h"}, {"configure", "--max-execution-duration=off"}, {"configure", "--max-execution-duration"},
	{"configure", "--update-mirror-url", "https://m"}, {"configure", "--update-mirror-url=https://m"}, {"configure", "--update-mirror-url"},
	{"configure", "--update-lag-behind", "2"}, {"configure", "--update-lag-behind=0"}, {"configure", "--update-lag-behind"},
	{"configure", "--update-lag-behind=-1"}, {"configure", "--update-lag-behind", "x"},
	{"configure", "--update-cooldown-hours", "24"}, {"configure", "--update-cooldown-hours=24"}, {"configure", "--update-cooldown-hours"},
	{"configure", "--auto-update=false"}, {"configure", "--auto-update=1"}, {"configure", "--auto-update=maybe"}, {"configure", "--auto-update"},
	{"configure", "--non-interactive", "--customer-id", "c1", "--api-endpoint", "https://e", "--api-key", "k", "--scan-frequency", "4"},
	{"--verbose"}, {"--override-gate"},
	{"--config", "c.json"}, {"--config=c.json"}, {"--config"},
	{"--wsl-host-serial", "S"}, {"--wsl-host-serial=S"}, {"--wsl-host-serial"},
	{"--wsl-distro-id", "D"}, {"--wsl-distro-id=D"}, {"--wsl-distro-id"},
	{"--force-scan"},
	{"--rules-file", "r.json"}, {"--rules-file=r.json"}, {"--rules-file"},
	{"--telemetry-out", "t.json"}, {"--telemetry-out=t.json"}, {"--telemetry-out"},
	{"--log-level=debug"}, {"--log-level=WARNING"}, {"--log-level=info"}, {"--log-level=loud"}, {"--log-level", "debug"},
	{"--install-dir", "/opt/x"}, {"--install-dir=/opt/x"}, {"--install-dir="}, {"--install-dir"},
	{"install", "--install-dir="}, {"uninstall", "--install-dir="}, {"send-telemetry", "--install-dir="},
	{"--bogus"}, {"stray"},
	{"send-telemetry", "--force-scan", "--log-level=info", "--install-dir", "/opt/x", "--search-dirs", "/a"},
}

// parseProjection is Parse's observable result as the fields that differ
// from a bare invocation, minus the configure-only fields whose
// representation is free to change (their behaviour is pinned by the
// configure tests instead).
func parseProjection(t *testing.T, args []string) any {
	t.Helper()
	cfg, err := Parse(args)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	m := configFields(t, cfg)
	if len(args) > 0 {
		base, err := Parse(nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range configFields(t, base) {
			if reflect.DeepEqual(m[k], v) {
				delete(m, k)
			}
		}
	}
	return m
}

func configFields(t *testing.T, cfg *Config) map[string]any {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for k := range m {
		if k == "ColorModeSet" || (strings.HasPrefix(k, "Config") && k != "ConfigFile" && k != "ConfigFromFile") {
			delete(m, k)
		}
	}
	return m
}

func TestParse_Golden(t *testing.T) {
	t.Setenv("STEPSECURITY_RULES_FILE", "")
	t.Setenv("STEPSECURITY_TELEMETRY_OUT", "")
	type entry struct {
		Args   []string `json:"args"`
		Result any      `json:"result"`
	}
	got := make([]entry, 0, len(goldenArgvs))
	for _, args := range goldenArgvs {
		got = append(got, entry{Args: args, Result: parseProjection(t, args)})
	}
	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "parse.golden.json", append(data, '\n'))
}

func TestHelp_Golden(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	printHelp()
	os.Stdout = stdout
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	// Pin the text, not the release it was built from.
	out = bytes.ReplaceAll(out, []byte(buildinfo.Version), []byte("VERSION"))
	out = bytes.ReplaceAll(out, []byte(buildinfo.AgentURL), []byte("AGENT_URL"))
	out = bytes.ReplaceAll(out, []byte(filepath.Base(os.Args[0])), []byte("BINARY"))
	checkGolden(t, "help.golden.txt", out)
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden; if the change is intended, rerun with -update and review the diff.\n--- got ---\n%s", path, got)
	}
}
