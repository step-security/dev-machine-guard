package devicepolicy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

const netrcExpected = "machine registry.stepsecurity.io\nlogin step-security\npassword step_acme-1_uuid::dev:DEVICE-123"

func TestNetrcMarkers_Canonical(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"DMG begin", dmgNetrcBegin, "#stepsecurity-package-config-credential-dmg-begin"},
		{"DMG end", dmgNetrcEnd, "#stepsecurity-package-config-credential-end"},
		{"MDM begin", mdmNetrcBegin, "#stepsecurity-package-config-credential-mdm-begin"},
		{"MDM end", mdmNetrcEnd, "#stepsecurity-package-config-credential-end"},
		{"DMG disabled prefix", dmgNetrcDisabledPrefix, "#stepsecurity-package-config-credential-dmg-disabled:"},
		{"MDM disabled prefix", mdmNetrcDisabledPrefix, "#stepsecurity-package-config-credential-mdm-disabled:"},
		{"MDM created", mdmNetrcCreated, "#stepsecurity-package-config-credential-mdm-created"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("marker = %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func TestNetrcWriter_CredentialOwnershipLinesAreSingleTokens(t *testing.T) {
	tests := []struct {
		name      string
		initial   string
		wantLines int
	}{
		{
			name:      "ordinary entry before managed block",
			initial:   "machine other.example login user password secret\n",
			wantLines: 2,
		},
		{
			name:      "displaced exact-host entry",
			initial:   "machine registry.stepsecurity.io login old password old-secret\nmachine other.example login user password secret\n",
			wantLines: 3,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, path := newNetrcTestWriter(t, []byte(tc.initial))
			if _, err := w.Write(netrcExpected); err != nil {
				t.Fatalf("Write: %v", err)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var ownershipLines []string
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSuffix(line, "\r")
				if strings.HasPrefix(line, "#") && strings.Contains(strings.ToLower(line), "credential") {
					ownershipLines = append(ownershipLines, line)
				}
			}
			if len(ownershipLines) != tc.wantLines {
				t.Fatalf("credential ownership lines = %q, want %d", ownershipLines, tc.wantLines)
			}
			for _, line := range ownershipLines {
				if !strings.HasPrefix(line, "#stepsecurity-package-config-credential") || strings.ContainsAny(line, " \t\r") {
					t.Errorf("credential ownership line %q is not one whitespace-free token", line)
				}
			}
		})
	}
}

func newNetrcTestWriter(t *testing.T, initial []byte) (*NetrcWriter, string) {
	t.Helper()
	t.Setenv("NETRC", "")
	home := t.TempDir()
	if initial != nil {
		if err := os.WriteFile(filepath.Join(home, ".netrc"), initial, 0o600); err != nil {
			t.Fatalf("seed .netrc: %v", err)
		}
	}
	h := newSecureTestHome(t, home)
	w, err := NewNetrcWriter(h, netrcTestPolicy(t))
	if err != nil {
		t.Fatalf("NewNetrcWriter: %v", err)
	}
	w.lookupEnv = os.Getenv
	return w, filepath.Join(home, ".netrc")
}

func netrcTestPolicy(t *testing.T) PyPIPolicy {
	t.Helper()
	policy, err := ParsePyPIPolicy(json.RawMessage(`{"ecosystem":"pypi","clients":["pip","uv"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`), "DEVICE-123")
	if err != nil {
		t.Fatalf("ParsePyPIPolicy: %v", err)
	}
	return policy
}

func TestNetrcWriter_PreservesOrdinaryGrammarAndClearRestores(t *testing.T) {
	initial := []byte("\ufeff# keep this comment\r\nmachine files.example login \"user name\" account deploy password \"secret with space\"\r\ndefault login fallback password fallback-secret\r\n")
	w, path := newNetrcTestWriter(t, initial)

	got, err := w.Write(netrcExpected)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got != netrcExpected {
		t.Fatalf("Write readback = %q, want exact managed entry", got)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(content), string(initial)) {
		t.Fatalf("unrelated netrc bytes changed:\n%s", content)
	}
	if !strings.Contains(string(content), "\r\n"+dmgNetrcBegin+"\r\n") || strings.Contains(strings.ReplaceAll(string(content), "\r\n", ""), "\n") {
		t.Fatalf("managed block did not preserve CRLF style:\n%q", content)
	}
	if converged, err := w.Converged(netrcExpected); err != nil || !converged {
		t.Fatalf("Converged = %v, %v, want true", converged, err)
	}

	changed, err := w.Clear()
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if !changed {
		t.Fatal("Clear changed = false, want true")
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(initial) {
		t.Fatalf("clear restored %q, want exact original %q", restored, initial)
	}
}

func TestNetrcWriter_MigratesOneExactHostReversibly(t *testing.T) {
	initial := []byte("# before\nmachine registry.stepsecurity.io\n  login old-user\n  account old-account\n  password old-secret\nmachine other.example login other password other-secret")
	w, path := newNetrcTestWriter(t, initial)

	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	displaced := "machine registry.stepsecurity.io\n  login old-user\n  account old-account\n  password old-secret\n"
	var encoded string
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, dmgNetrcDisabledPrefix) {
			encoded = strings.TrimPrefix(line, dmgNetrcDisabledPrefix)
			break
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		t.Fatalf("disabled ownership record is not canonical base64url: %v", err)
	}
	if string(decoded) != displaced {
		t.Fatalf("disabled ownership record decodes to %q, want exact %q", decoded, displaced)
	}
	if !strings.Contains(string(content), "machine other.example login other password other-secret") {
		t.Fatalf("unrelated host was not preserved:\n%s", content)
	}
	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatalf("idempotent Write: %v", err)
	}
	content, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(content), dmgNetrcDisabledPrefix); got != 1 {
		t.Fatalf("disabled ownership records after idempotent write = %d, want 1", got)
	}
	if changed, err := w.Clear(); err != nil || !changed {
		t.Fatalf("Clear = %v, %v, want changed", changed, err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(initial) {
		t.Fatalf("clear restored %q, want exact original %q", restored, initial)
	}
}

func TestNetrcWriter_EncodedEntryRoundTripsExactBytes(t *testing.T) {
	tests := []struct {
		name    string
		initial []byte
	}{
		{"LF one-line final newline", []byte("machine registry.stepsecurity.io login old password secret\n")},
		{"CRLF multiline", []byte("machine registry.stepsecurity.io\r\n\tlogin old\r\n\tpassword secret\r\n")},
		{"UTF-8 BOM and indentation", append([]byte{0xef, 0xbb, 0xbf}, []byte("  machine registry.stepsecurity.io login old password secret\n")...)},
		{"no final newline", []byte("machine registry.stepsecurity.io login old password secret")},
		{"surrounding entries", []byte("# before\nmachine first.example login one password one\nmachine registry.stepsecurity.io\n login old\n password secret\nmachine last.example login last password last\n# after\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, path := newNetrcTestWriter(t, tc.initial)
			if _, err := w.Write(netrcExpected); err != nil {
				t.Fatalf("Write: %v", err)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(string(content), dmgNetrcDisabledPrefix); got != 1 {
				t.Fatalf("disabled ownership records = %d, want 1", got)
			}
			if changed, err := w.Clear(); err != nil || !changed {
				t.Fatalf("Clear = %v, %v, want changed", changed, err)
			}
			restored, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(restored, tc.initial) {
				t.Fatalf("clear restored %q, want exact original %q", restored, tc.initial)
			}
		})
	}
}

func TestNetrcWriter_KeyRotationRetainsOneEncodedEntry(t *testing.T) {
	initial := []byte("machine registry.stepsecurity.io login old password secret\n")
	w, path := newNetrcTestWriter(t, initial)
	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatalf("initial Write: %v", err)
	}
	rotatedPolicy, err := ParsePyPIPolicy(json.RawMessage(`{"ecosystem":"pypi","clients":["pip","uv"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_rotated"}}`), "DEVICE-123")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewNetrcWriter(newSecureTestHome(t, filepath.Dir(path)), rotatedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	rotated.lookupEnv = os.Getenv
	rotatedExpected := renderNetrcEntry(rotatedPolicy.RegistryHost(), rotatedPolicy.DeviceToken())
	if _, err := rotated.Write(rotatedExpected); err != nil {
		t.Fatalf("rotated Write: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(content), dmgNetrcDisabledPrefix); got != 1 {
		t.Fatalf("disabled ownership records after rotation = %d, want 1", got)
	}
	if changed, err := rotated.Clear(); err != nil || !changed {
		t.Fatalf("Clear = %v, %v, want changed", changed, err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, initial) {
		t.Fatalf("clear restored %q, want exact original %q", restored, initial)
	}
}

func TestNetrcWriter_CreatesRotatesAndRemovesCredential(t *testing.T) {
	w, path := newNetrcTestWriter(t, nil)
	if w.Location() != path {
		t.Fatalf("Location = %q, want %q", w.Location(), path)
	}
	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if enforcePOSIXMetadata && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o, want 0600", info.Mode().Perm())
	}

	rotated := strings.Replace(netrcExpected, "step_acme-1_uuid", "step_acme-1_rotated", 1)
	_, writeErr := w.Write(rotated)
	if writeErr == nil {
		t.Fatal("Write accepted an entry different from the constructor policy")
	}
	if strings.Contains(writeErr.Error(), "step_acme") {
		t.Fatalf("Write error leaked credential material: %v", writeErr)
	}

	if changed, err := w.Clear(); err != nil || !changed {
		t.Fatalf("Clear = %v, %v, want changed", changed, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential-only file remains after clear: %v", err)
	}
	if backups, err := filepath.Glob(path + ".dmg-*.bak"); err != nil || len(backups) != 0 {
		t.Fatalf("backups after clear = %v, %v, want none", backups, err)
	}
	staleBackup := path + ".dmg-stale.bak"
	if err := os.WriteFile(staleBackup, []byte("stale protected credential backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.Clear(); err != nil || changed {
		t.Fatalf("absent-file Clear = %v, %v, want unchanged", changed, err)
	}
	if _, err := os.Stat(staleBackup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale credential backup remains after clear: %v", err)
	}
}

func TestParseNetrc_PreservesHashInPasswords(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"embedded hash", "pa#ss"},
		{"leading hash", "#secret"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("# comment\nmachine other.example login user password " + tc.password + "\n")
			entries, err := parseNetrc(data)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].pass != tc.password {
				t.Fatalf("entries = %+v, want password %q", entries, tc.password)
			}
		})
	}
}

func TestNetrcWriter_RejectsAmbiguousOrMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"duplicate exact host", "machine registry.stepsecurity.io login one password old\nmachine registry.stepsecurity.io login two password old"},
		{"exact host shares a line", "machine other.example login u password p machine registry.stepsecurity.io login stale password old"},
		{"macdef", "macdef init\necho unsafe\n\nmachine other.example login u password p\n"},
		{"unterminated quote", "machine other.example login \"unterminated"},
		{"missing directive value", "machine other.example login"},
		{"unknown directive", "machine other.example protocol https"},
		{"duplicate default", "default login one\ndefault login two"},
		{"duplicate begin marker", dmgNetrcBegin + "\n" + dmgNetrcBegin + "\n" + netrcExpected + "\n" + dmgNetrcEnd + "\n"},
		{"duplicate end marker", dmgNetrcBegin + "\n" + netrcExpected + "\n" + dmgNetrcEnd + "\n" + dmgNetrcEnd + "\n"},
		{"incomplete MDM marker", mdmNetrcBegin + "\n" + netrcExpected + "\n"},
		{"end before begin", dmgNetrcEnd + "\n" + dmgNetrcBegin + "\n" + netrcExpected + "\n"},
		{"lone carriage return", "machine other.example\rlogin user"},
		{"invalid utf8", string([]byte{0xff, 0xfe})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, path := newNetrcTestWriter(t, []byte(tc.body))
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(netrcExpected); err == nil {
				t.Fatal("Write error = nil, want fail-closed refusal")
			} else if strings.Contains(err.Error(), "step_acme") || strings.Contains(err.Error(), "old-secret") {
				t.Fatalf("Write error leaked credential material: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("refused write changed file: before=%q after=%q", before, after)
			}
		})
	}
}

func TestScanNetrcMarkers_RejectsDisabledRecordInsideOrAfterManagedBlock(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("machine registry.stepsecurity.io login old password old-secret\n"))
	dmgRecord := dmgNetrcDisabledPrefix + encoded
	mdmRecord := mdmNetrcDisabledPrefix + encoded
	tests := []struct {
		name string
		data string
	}{
		{"DMG record inside block", dmgNetrcBegin + "\n" + dmgRecord + "\n" + netrcExpected + "\n" + dmgNetrcEnd + "\n"},
		{"DMG record after block", dmgNetrcBegin + "\n" + netrcExpected + "\n" + dmgNetrcEnd + "\n" + dmgRecord + "\n"},
		{"MDM record inside block", mdmNetrcBegin + "\n" + mdmRecord + "\n" + netrcExpected + "\n" + mdmNetrcEnd + "\n"},
		{"MDM record after block", mdmNetrcBegin + "\n" + netrcExpected + "\n" + mdmNetrcEnd + "\n" + mdmRecord + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := scanNetrcMarkers([]byte(tc.data)); !errors.Is(err, ErrTargetUnusable) {
				t.Fatalf("scanNetrcMarkers error = %v, want ErrTargetUnusable", err)
			}
		})
	}
}

func TestNetrcWriter_RejectsInvalidEncodedOwnershipWithoutMutation(t *testing.T) {
	encode := func(data string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(data))
	}
	exact := "machine registry.stepsecurity.io login old password old-secret\n"
	valid := encode(exact)
	block := func(record string) string {
		return record + "\n" + dmgNetrcBegin + "\n" + netrcExpected + "\n" + dmgNetrcEnd + "\n"
	}
	tests := []struct {
		name    string
		initial string
	}{
		{"malformed base64url", block(dmgNetrcDisabledPrefix + "%%%")},
		{"padded base64url", block(dmgNetrcDisabledPrefix + valid + "=")},
		{"duplicate records", block(dmgNetrcDisabledPrefix + valid + "\n" + dmgNetrcDisabledPrefix + valid)},
		{"wrong-lane record", block(mdmNetrcDisabledPrefix + valid)},
		{"wrong-lane created marker", block(mdmNetrcCreated)},
		{"orphan record", dmgNetrcDisabledPrefix + valid + "\nmachine other.example login user password secret\n"},
		{"leading record whitespace", block(" " + dmgNetrcDisabledPrefix + valid)},
		{"trailing record whitespace", block(dmgNetrcDisabledPrefix + valid + " ")},
		{"leading marker whitespace", dmgNetrcDisabledPrefix + valid + "\n " + dmgNetrcBegin + "\n" + netrcExpected + "\n" + dmgNetrcEnd + "\n"},
		{"decoded invalid UTF-8", block(dmgNetrcDisabledPrefix + base64.RawURLEncoding.EncodeToString([]byte{0xff}))},
		{"decoded NUL", block(dmgNetrcDisabledPrefix + base64.RawURLEncoding.EncodeToString([]byte("machine registry.stepsecurity.io login u password p\x00")))},
		{"decoded lone carriage return", block(dmgNetrcDisabledPrefix + encode("machine registry.stepsecurity.io\rlogin u password p"))},
		{"decoded wrong host", block(dmgNetrcDisabledPrefix + encode("machine other.example login u password p\n"))},
		{"decoded default entry", block(dmgNetrcDisabledPrefix + encode("default login u password p\n"))},
		{"decoded multiple entries", block(dmgNetrcDisabledPrefix + encode("machine registry.stepsecurity.io login u password p\nmachine other.example login u password p\n"))},
		{"decoded hidden MDM ownership", block(dmgNetrcDisabledPrefix + encode(exact+mdmNetrcCreated+"\n"))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, path := newNetrcTestWriter(t, []byte(tc.initial))
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Clear(); err == nil {
				t.Fatal("Clear error = nil, want fail-closed refusal")
			} else if strings.Contains(err.Error(), "old-secret") {
				t.Fatalf("Clear error leaked displaced credential material: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatalf("refused clear changed file: before=%q after=%q", before, after)
			}
		})
	}
}

func TestDecodeNetrcEntries_RejectsOversizedDecodedContent(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString(make([]byte, secureuserfile.MaxBytes+1))
	if _, _, err := decodeNetrcEntries([]byte(dmgNetrcDisabledPrefix+payload), dmgNetrcDisabledPrefix); err == nil {
		t.Fatal("decodeNetrcEntries error = nil, want oversized refusal")
	}
}

func TestNetrcWriter_ObservationUsesExactTokenAndNETRCOverride(t *testing.T) {
	w, _ := newNetrcTestWriter(t, nil)
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenAbsent {
		t.Fatalf("absent Observation = %q, %v", status, err)
	}
	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatal(err)
	}
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMatch {
		t.Fatalf("matching Observation = %q, %v", status, err)
	}

	prefixOnly := strings.TrimSuffix(netrcExpected, "DEVICE-123")
	content, err := os.ReadFile(w.Location())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.Location(), bytes.Replace(content, []byte(netrcExpected), []byte(prefixOnly), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMismatch {
		t.Fatalf("prefix-only on-disk Observation = %q, %v, want mismatch", status, err)
	}
	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatalf("repair after prefix-only token: %v", err)
	}

	t.Setenv("NETRC", filepath.Join(t.TempDir(), "alternate.netrc"))
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMismatch {
		t.Fatalf("NETRC override Observation = %q, %v, want mismatch", status, err)
	}
	t.Setenv("NETRC", w.Location())
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMatch {
		t.Fatalf("exact NETRC Observation = %q, %v, want match", status, err)
	}
}

func TestNetrcWriter_NETRCOverrideRefusesWriteWithoutMutation(t *testing.T) {
	w, path := newNetrcTestWriter(t, nil)
	before := []byte("machine other.example login user password value\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETRC", filepath.Join(t.TempDir(), "alternate.netrc"))

	if _, err := w.Write(w.expected); err == nil {
		t.Fatal("Write succeeded with an alternate NETRC path")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("default netrc changed: %q", after)
	}
}

func TestNetrcWriter_NETRCRelativeOverrideIsUnusable(t *testing.T) {
	w, _ := newNetrcTestWriter(t, nil)
	t.Chdir(filepath.Dir(w.Location()))
	t.Setenv("NETRC", filepath.Base(w.Location()))
	if err := w.ValidateEffectivePath(); !errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("ValidateEffectivePath error = %v, want target unusable", err)
	}
}

func TestNetrcWriter_UsesResolvedPlatformForWindowsAlternateValidation(t *testing.T) {
	homeDir := t.TempDir()
	dot := filepath.Join(homeDir, ".netrc")
	underscore := filepath.Join(homeDir, "_netrc")
	if err := os.WriteFile(underscore, []byte("machine registry.stepsecurity.io login stale password old-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u.HomeDir = homeDir
	normalizeSecureTestUser(t, u)
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	home, err := secureuserfile.OpenUserHome(secureTestExecutor{Executor: mock, user: u})
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()
	w, err := NewNetrcWriter(home, netrcTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if w.Location() != dot {
		t.Fatalf("Location = %q, want %q", w.Location(), dot)
	}
	if _, err := w.Write(netrcExpected); !errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("Write error = %v, want alternate conflict", err)
	}
}

func TestNetrcWriter_SecurityRefusalsAndPermissionRepair(t *testing.T) {
	t.Run("non-regular", func(t *testing.T) {
		w, path := newNetrcTestWriter(t, nil)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(netrcExpected); !errors.Is(err, secureuserfile.ErrTargetUnusable) {
			t.Fatalf("Write error = %v, want secureuserfile.ErrTargetUnusable", err)
		}
	})

	t.Run("symlink escape", func(t *testing.T) {
		w, path := newNetrcTestWriter(t, nil)
		outside := filepath.Join(t.TempDir(), "outside.netrc")
		if err := os.WriteFile(outside, []byte("machine other.example login u password p\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		if _, err := w.Write(netrcExpected); !errors.Is(err, secureuserfile.ErrTargetUnusable) {
			t.Fatalf("Write error = %v, want secureuserfile.ErrTargetUnusable", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		w, path := newNetrcTestWriter(t, nil)
		if err := os.WriteFile(path, []byte(strings.Repeat("x", secureuserfile.MaxBytes+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(netrcExpected); !errors.Is(err, secureuserfile.ErrTargetUnusable) {
			t.Fatalf("Write error = %v, want secureuserfile.ErrTargetUnusable", err)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("loose mode repaired", func(t *testing.T) {
			w, path := newNetrcTestWriter(t, []byte("machine other.example login u password p\n"))
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if converged, err := w.Converged(netrcExpected); err != nil || converged {
				t.Fatalf("Converged before repair = %v, %v, want false", converged, err)
			}
			if _, err := w.Write(netrcExpected); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("mode after write = %#o, want 0600", info.Mode().Perm())
			}
		})
	}
}

func TestNetrcWriter_OwnershipStateNeverPersistsCredential(t *testing.T) {
	t.Setenv("NETRC", "")
	homeDir := t.TempDir()
	home := newSecureTestHome(t, homeDir)
	withTempCache(t)
	if err := WriteAppliedState(CategoryPackageConfig, TargetPyPI, AppliedTargetState{
		AppliedHash:     "sibling",
		WrittenSettings: map[string]string{"keep": "non-secret"},
	}); err != nil {
		t.Fatal(err)
	}

	run := func(raw, hash string) *NetrcWriter {
		t.Helper()
		policy, err := ParsePyPIPolicy(json.RawMessage(raw), "DEVICE-123")
		if err != nil {
			t.Fatal(err)
		}
		writer, err := NewNetrcWriter(home, policy)
		if err != nil {
			t.Fatal(err)
		}
		r := &Reconciler{
			Fetcher: &fakeFetcher{ep: EffectivePolicy{
				Category: CategoryPackageConfig,
				Target:   TargetPyPI,
				Policy:   json.RawMessage(raw),
				Hash:     hash,
			}},
			Writer:              writer,
			Category:            CategoryPackageConfig,
			Target:              TargetPyPI,
			OwnershipTarget:     PyPICredentialOwnershipTarget,
			OwnershipStateValue: PyPICredentialOwnershipValue,
			OwnershipKey:        "credential",
			OwnsByMarker:        true,
			Render: func(raw json.RawMessage) (string, error) {
				parsed, err := ParsePyPIPolicy(raw, "DEVICE-123")
				if err != nil {
					return "", err
				}
				return renderNetrcEntry(parsed.RegistryHost(), parsed.DeviceToken()), nil
			},
			Converged:       writer.Converged,
			RestoreSnapshot: writer.RestoreSnapshot,
			Probe:           func() (bool, string) { return false, "" },
			Now:             func() time.Time { return time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC) },
		}
		if err := r.Reconcile(context.Background()); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNetrcStateSecretFree(t, pypiKey, policy.DeviceToken())
		return writer
	}

	oldRaw := `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`
	writer := run(oldRaw, "sha256:OLD")
	run(oldRaw, "sha256:OLD") // idempotent convergence

	content, err := os.ReadFile(writer.Location())
	if err != nil {
		t.Fatal(err)
	}
	content = bytes.Replace(content, []byte("step_acme-1_uuid::dev:DEVICE-123"), []byte("tampered"), 1)
	if err := os.WriteFile(writer.Location(), content, 0o600); err != nil {
		t.Fatal(err)
	}
	run(oldRaw, "sha256:OLD") // same-hash drift repair

	newRaw := `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_rotated"}}`
	writer = run(newRaw, "sha256:NEW")
	assertNetrcStateSecretFree(t, "step_rotated", "step_rotated::dev:DEVICE-123")

	r := &Reconciler{
		Fetcher:             &fakeFetcher{ep: EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true}},
		Writer:              writer,
		Category:            CategoryPackageConfig,
		Target:              TargetPyPI,
		OwnershipTarget:     PyPICredentialOwnershipTarget,
		OwnershipStateValue: PyPICredentialOwnershipValue,
		OwnershipKey:        "credential",
		OwnsByMarker:        true,
		RestoreSnapshot:     writer.RestoreSnapshot,
		Probe:               func() (bool, string) { return false, "" },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("clear Reconcile: %v", err)
	}
	assertNetrcStateSecretFree(t, pypiKey, "step_rotated", "::dev:")
	if _, ok := ReadAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget); ok {
		t.Fatal("credential ownership state remains after clear")
	}
}

func assertNetrcStateSecretFree(t *testing.T, forbidden ...string) {
	t.Helper()
	state, err := os.ReadFile(CachePath())
	if err != nil {
		t.Fatalf("read complete ownership state: %v", err)
	}
	for _, value := range forbidden {
		if value != "" && bytes.Contains(state, []byte(value)) {
			t.Fatalf("ownership state contains credential material %q: %s", value, state)
		}
	}
}

func TestNetrcWriter_MDMOwnershipRequiresExactHostInsideBlock(t *testing.T) {
	tests := []struct {
		name    string
		initial string
	}{
		{"unmarked", netrcExpected + "\n"},
		{"marker around other host", mdmNetrcBegin + "\nmachine other.example login step-security password other\n" + mdmNetrcEnd + "\n" + netrcExpected + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := newNetrcTestWriter(t, []byte(tc.initial))
			owned, err := w.MDMOwned()
			if err != nil {
				t.Fatal(err)
			}
			if owned {
				t.Fatal("MDMOwned = true, want false")
			}
		})
	}
}

func TestNetrcWriter_AcceptsValidMDMEncodedOwnership(t *testing.T) {
	displaced := []byte("machine registry.stepsecurity.io login old password old-secret\n")
	encoded := base64.RawURLEncoding.EncodeToString(displaced)
	initial := []byte(mdmNetrcDisabledPrefix + encoded + "\n" + mdmNetrcBegin + "\n" + mdmNetrcCreated + "\n" + netrcExpected + "\n" + mdmNetrcEnd + "\n")
	w, _ := newNetrcTestWriter(t, initial)
	hardenSecureTestFile(t, w.file)
	if present, err := w.HasMDMMarker(); err != nil || !present {
		t.Fatalf("HasMDMMarker = %v, %v, want true", present, err)
	}
	if owned, err := w.MDMOwned(); err != nil || !owned {
		t.Fatalf("MDMOwned = %v, %v, want true", owned, err)
	}
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMatch {
		t.Fatalf("Observation = %q, %v, want match", status, err)
	}
}

func TestNetrcWriter_ReadAndMDMMarker(t *testing.T) {
	w, _ := newNetrcTestWriter(t, []byte(mdmNetrcBegin+"\n"+netrcExpected+"\n"+mdmNetrcEnd+"\n"))
	hardenSecureTestFile(t, w.file)
	if present, err := w.HasMDMMarker(); err != nil || !present {
		t.Fatalf("HasMDMMarker = %v, %v, want true", present, err)
	}
	if owned, err := w.MDMOwned(); err != nil || !owned {
		t.Fatalf("MDMOwned = %v, %v, want true", owned, err)
	}
	if _, present, err := w.Read(); err != nil || present {
		t.Fatalf("Read DMG block = present %v, %v, want absent", present, err)
	}
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMatch {
		t.Fatalf("MDM credential Observation = %q, %v, want match", status, err)
	}
}
