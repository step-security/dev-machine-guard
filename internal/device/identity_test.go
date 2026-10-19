package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// withConfigDeviceID sets the config.json template for a test and restores it.
func withConfigDeviceID(t *testing.T, v string) {
	t.Helper()
	prev := config.DeviceID
	config.DeviceID = v
	t.Cleanup(func() { config.DeviceID = prev })
}

type identityVector struct {
	Name             string `json:"name"`
	Template         string `json:"template"`
	Serial           string `json:"serial"`
	Hostname         string `json:"hostname"`
	User             string `json:"user"`
	GOOS             string `json:"goos"`
	ExpectID         string `json:"expect_id"`
	ExpectIncomplete bool   `json:"expect_incomplete"`
}

// TestResolveIdentity_TemplateVectors drives the shared vector file. The same
// file is replayed by the Windows loader's PowerShell implementation, so the
// two sides can never disagree on what a template resolves to.
func TestResolveIdentity_TemplateVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/identity_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors []identityVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			withConfigDeviceID(t, v.Template)
			mock := executor.NewMock()
			mock.SetGOOS(v.GOOS)
			id := ResolveIdentity(mock, v.Serial, v.Hostname, v.User)
			if id.Issue != "" {
				t.Fatalf("unexpected issue: %s", id.Issue)
			}
			if id.Incomplete != v.ExpectIncomplete {
				t.Fatalf("incomplete = %v, want %v (id=%q)", id.Incomplete, v.ExpectIncomplete, id.DeviceID)
			}
			if v.ExpectIncomplete {
				if id.DeviceID != "" {
					t.Fatalf("incomplete identity must carry no id, got %q", id.DeviceID)
				}
				return
			}
			if id.DeviceID != v.ExpectID {
				t.Fatalf("device id = %q, want %q", id.DeviceID, v.ExpectID)
			}
			if id.Serial != v.Serial {
				t.Fatalf("serial = %q, want the probed value %q", id.Serial, v.Serial)
			}
			if id.Source != IdentitySourceConfig {
				t.Fatalf("source = %q, want config", id.Source)
			}
			wantPerUser := strings.Contains(v.Template, "{user}")
			if id.PerUser != wantPerUser {
				t.Fatalf("per_user = %v, want %v", id.PerUser, wantPerUser)
			}
		})
	}
}

func TestResolveIdentity_DefaultSerialUnsanitized(t *testing.T) {
	withConfigDeviceID(t, "")
	mock := executor.NewMock()
	// A VMware serial carries spaces; the default path must ship it verbatim
	// so an upgraded fleet keeps its device ids.
	const serial = "VMware-56 4d 1a 2b 3c"
	id := ResolveIdentity(mock, serial, "host", "jdoe")
	if id.DeviceID != serial || id.Serial != serial {
		t.Fatalf("default identity altered the serial: %+v", id)
	}
	if id.Source != IdentitySourceSerial || id.PerUser || id.Incomplete || id.Template != "" {
		t.Fatalf("unexpected identity fields: %+v", id)
	}
	if IdentityUserScope(mock) != "" {
		t.Fatal("no template must mean no per-user scope")
	}
}

func TestResolveIdentity_EnvBeatsConfig(t *testing.T) {
	withConfigDeviceID(t, "{hostname}")
	mock := executor.NewMock()
	mock.SetEnv(EnvDeviceID, "from-env-{user}")
	id := ResolveIdentity(mock, "SER", "Host1", "jdoe")
	if id.DeviceID != "from-env-jdoe" || id.Source != IdentitySourceEnv {
		t.Fatalf("env override not applied: %+v", id)
	}
	if !id.PerUser || id.UserScope != "jdoe" {
		t.Fatalf("per-user scope not derived from the env template: %+v", id)
	}
	// IdentityUserScope reads the env template too (the mock's default user
	// is "testuser").
	if got := IdentityUserScope(mock); got != "testuser" {
		t.Fatalf("scope from the env template = %q, want testuser", got)
	}
	mock.SetUsername("CONTOSO\\JDoe")
	if got := IdentityUserScope(mock); got != "jdoe" {
		t.Fatalf("IdentityUserScope = %q, want jdoe", got)
	}
}

func TestResolveIdentity_UnknownTokenFallsBackToSerial(t *testing.T) {
	withConfigDeviceID(t, "{hostname}-{site}")
	mock := executor.NewMock()
	id := ResolveIdentity(mock, "SER", "host", "jdoe")
	if id.DeviceID != "SER" || id.Source != IdentitySourceSerial {
		t.Fatalf("unknown token must fall back to the serial: %+v", id)
	}
	if id.Issue == "" || !strings.Contains(id.Issue, "{site}") {
		t.Fatalf("issue must name the unknown token: %q", id.Issue)
	}
	if id.Incomplete {
		t.Fatal("fallback identity is complete")
	}
}

func TestResolveIdentity_EmptyAfterSanitizeFallsBackToSerial(t *testing.T) {
	// A token that expands to nothing but unsafe runes sanitizes to "", so the
	// identity falls back to the machine serial with an issue. (A literal is
	// never sanitized, so this can only happen through a token.)
	withConfigDeviceID(t, "{hostname}")
	mock := executor.NewMock()
	id := ResolveIdentity(mock, "SER", "###", "jdoe")
	if id.DeviceID != "SER" || id.Source != IdentitySourceSerial || id.Issue == "" {
		t.Fatalf("empty sanitized id must fall back with an issue: %+v", id)
	}
}

func TestResolveIdentity_ServiceAccountIsIncompleteOnlyWithUserToken(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	withConfigDeviceID(t, "{hostname}")
	if id := ResolveIdentity(mock, "SER", "h1", `NT AUTHORITY\SYSTEM`); id.Incomplete || id.DeviceID != "h1" {
		t.Fatalf("a template without {user} must not care who runs it: %+v", id)
	}
	withConfigDeviceID(t, "{hostname}-{user}")
	id := ResolveIdentity(mock, "SER", "h1", `NT AUTHORITY\SYSTEM`)
	if !id.Incomplete || id.DeviceID != "" || !id.PerUser {
		t.Fatalf("SYSTEM with {user} must be incomplete: %+v", id)
	}
	if id.Serial != "SER" || id.Template != "{hostname}-{user}" {
		t.Fatalf("incomplete identity must keep serial and template: %+v", id)
	}
}

func TestIsServiceAccount(t *testing.T) {
	win := executor.NewMock()
	win.SetGOOS("windows")
	linux := executor.NewMock()
	linux.SetGOOS("linux")
	root := executor.NewMock()
	root.SetGOOS("linux")
	root.SetIsRoot(true)
	for _, tt := range []struct {
		exec *executor.Mock
		user string
		want bool
	}{
		{win, "", true},
		{win, "unknown", true},
		{win, `NT AUTHORITY\SYSTEM`, true},
		{win, `nt authority\local service`, true},
		{win, `NT AUTHORITY\NETWORK SERVICE`, true},
		{win, `NT SERVICE\TrustedInstaller`, true},
		{win, `Window Manager\DWM-1`, true},
		{win, `Font Driver Host\UMFD-0`, true},
		{win, "SYSTEM", true},
		{win, `WORKGROUP\AVD-HOST-07$`, true},
		{win, `AVD-HOST-07\jdoe`, false},
		{win, `AzureAD\JDoe`, false},
		{win, "jdoe@example.com", false},
		{linux, "root", false}, // root by name only counts when the process is root
		{root, "root", true},
		{linux, "system", false}, // bare "system" is a Windows account name, not a Linux one
		{linux, "jdoe", false},
	} {
		if got := IsServiceAccount(tt.exec, tt.user); got != tt.want {
			t.Errorf("IsServiceAccount(%s, %q) = %v, want %v", tt.exec.GOOS(), tt.user, got, tt.want)
		}
	}
}

func TestSanitizeDeviceID_Vectors(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"###", ""},
		{"-.-", ""},
		{"avd-host-07", "avd-host-07"},
		{"AVD host 07", "AVD-host-07"},
		{"a/b#c:d?e&f=g+h,i@j%k", "a-b-c-d-e-f-g-h-i-j-k"},
		{"pool/east/{x}", "pool-east-x"},
		{"a--b___c~d.e", "a-b___c~d.e"},
		{"  --lead--trail--  ", "lead-trail"},
		{".dotted.", "dotted"},
		{"Ünïcødé", "n-c-d"},
		{`CONTOSO\jdoe`, "CONTOSO-jdoe"},
	} {
		if got := SanitizeDeviceID(tt.in); got != tt.want {
			t.Errorf("SanitizeDeviceID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSanitizeDeviceID_LongIdDeterministicHashSuffix(t *testing.T) {
	long := strings.Repeat("abcdefghij", 20) // 200 chars
	got := SanitizeDeviceID(long)
	if len(got) > maxDeviceIDLen {
		t.Fatalf("len = %d, want <= %d", len(got), maxDeviceIDLen)
	}
	sum := sha256.Sum256([]byte(long))
	want := long[:longIDPrefixLen] + "-" + hex.EncodeToString(sum[:])[:longIDHashSuffixLen]
	if got != want {
		t.Fatalf("long id = %q, want %q", got, want)
	}
	if again := SanitizeDeviceID(long); again != got {
		t.Fatal("long-id sanitization is not deterministic")
	}
	// Two long ids that share the first 115 bytes must still differ.
	other := SanitizeDeviceID(long[:190] + "zzzzzzzzzz")
	if other == got {
		t.Fatal("distinct long ids collided")
	}
	if len(SanitizeDeviceID(strings.Repeat("x", maxDeviceIDLen))) != maxDeviceIDLen {
		t.Fatal("an id exactly at the cap must not be hashed")
	}
}

func TestResolvedDeviceID_ProbesOnlyWhenNeeded(t *testing.T) {
	withConfigDeviceID(t, "")
	t.Cleanup(ResetIDCache)
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetHostname("mac")
	mock.SetUsername("jdoe")
	mock.SetCommand(`"IOPlatformSerialNumber" = "PROBED"`, "", 0, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")

	if id := ResolvedDeviceID(context.Background(), mock); id.DeviceID != "PROBED" || id.Serial != "PROBED" {
		t.Fatalf("machine identity must be the probed serial: %+v", id)
	}

	// A template without {serial} never resolves one: with the process cache
	// cleared and every probe failing, the id still resolves.
	ResetIDCache()
	withConfigDeviceID(t, "{hostname}-{user}")
	mock.SetCommand("", "", 1, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	mock.SetCommand("", "", 1, "system_profiler", "SPHardwareDataType")
	id := ResolvedDeviceID(context.Background(), mock)
	if id.DeviceID != "mac-jdoe" || id.Serial != "" {
		t.Fatalf("template without {serial} must not need one: %+v", id)
	}

	// {serial} with no probe source falls through to the generated, persisted
	// machine id (id.go) rather than an incomplete identity.
	old := userIDFile
	userIDFile = func() string { return "/tmp/dmg-identity-test/device-id" }
	t.Cleanup(func() { userIDFile = old })
	withConfigDeviceID(t, "{serial}-{user}")
	id = ResolvedDeviceID(context.Background(), mock)
	if id.Incomplete || !strings.HasSuffix(id.DeviceID, "-jdoe") || id.Serial == "" {
		t.Fatalf("{serial} must use the generated machine id: %+v", id)
	}
}

func TestIdentityUserScope(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetUsername(`CONTOSO\JDoe`)
	withConfigDeviceID(t, "{hostname}")
	if got := IdentityUserScope(mock); got != "" {
		t.Fatalf("no {user} token must yield no scope, got %q", got)
	}
	withConfigDeviceID(t, "{hostname}-{user}")
	if got := IdentityUserScope(mock); got != "jdoe" {
		t.Fatalf("scope = %q, want jdoe", got)
	}
	mock.SetEnv("USER_EMAIL", "Jane.Doe@example.com")
	if got := IdentityUserScope(mock); got != "jane.doe" {
		t.Fatalf("scope must honour the email override, got %q", got)
	}
	mock.SetEnv("USER_EMAIL", "")
	mock.SetUsername(`NT AUTHORITY\SYSTEM`)
	if got := IdentityUserScope(mock); got != "" {
		t.Fatalf("a service account has no scope, got %q", got)
	}
}
