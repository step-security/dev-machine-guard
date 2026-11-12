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
	if id.Source != IdentitySourceSerial || id.Incomplete || id.Template != "" || id.PerSession || id.SessionScope != "" {
		t.Fatalf("unexpected identity fields: %+v", id)
	}
	if id.UserToken != "jdoe-"+UserTokenFingerprint("jdoe") {
		t.Fatalf("the signed-in user's token must ride along: %+v", id)
	}
	if SessionScope(mock) != "" {
		t.Fatal("a single-user host keeps shared state")
	}
}

func TestResolveIdentity_EnvBeatsConfig(t *testing.T) {
	withConfigDeviceID(t, "{hostname}")
	mock := executor.NewMock()
	mock.SetEnv(EnvDeviceID, "{hostname}-env")
	id := ResolveIdentity(mock, "SER", "Host1", "jdoe")
	if id.DeviceID != "host1-env" || id.Source != IdentitySourceEnv || id.Template != "{hostname}-env" {
		t.Fatalf("env override not applied: %+v", id)
	}
	if got, _ := IdentityTemplate(mock); got != "{hostname}-env" {
		t.Fatalf("IdentityTemplate = %q, want the env value", got)
	}
}

func TestResolveIdentity_UnknownTokenFallsBackToSerial(t *testing.T) {
	withConfigDeviceID(t, "{hostname}-{site}")
	mock := executor.NewMock()
	id := ResolveIdentity(mock, "SER", "host", "jdoe")
	if id.DeviceID != "SER" || id.Source != IdentitySourceSerial {
		t.Fatalf("unknown token must fall back to the serial: %+v", id)
	}
	if id.Issue == "" || !strings.Contains(id.Issue, "{site}") || !strings.Contains(id.Issue, "{serial} {hostname}") {
		t.Fatalf("issue must name the unknown token and the known ones: %q", id.Issue)
	}
	if id.Incomplete {
		t.Fatal("fallback identity is complete")
	}
}

// {user} was an identity token in an unreleased build. A device is the
// machine, so a template that still carries it is reported with a specific
// message and resolves to the machine identity, like any unknown token.
func TestResolveIdentity_UserTokenTemplateIsRejected(t *testing.T) {
	mock := executor.NewMock()
	for _, template := range []string{"{hostname}-{user}", "{user}", "{USER}"} {
		withConfigDeviceID(t, template)
		id := ResolveIdentity(mock, "SER", "host", "jdoe")
		if id.DeviceID != "SER" || id.Source != IdentitySourceSerial || id.Incomplete {
			t.Fatalf("%s must fall back to the machine identity: %+v", template, id)
		}
		if !strings.Contains(id.Issue, "{user}") || !strings.Contains(id.Issue, "users are reported inside it") {
			t.Fatalf("%s: issue must explain the removed token: %q", template, id.Issue)
		}
	}
	// The run still knows which user it scans for.
	if id := ResolveIdentity(mock, "SER", "host", "jdoe"); id.UserToken != "jdoe-"+UserTokenFingerprint("jdoe") {
		t.Fatalf("user token missing after the fallback: %+v", id)
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

// The identity never depends on who runs the scan; only the user token does:
// a service account has none, a developer's names the account.
func TestResolveIdentity_UserTokenFollowsTheSession(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	withConfigDeviceID(t, "{hostname}")
	system := ResolveIdentity(mock, "SER", "h1", `NT AUTHORITY\SYSTEM`)
	if system.Incomplete || system.DeviceID != "h1" || system.UserToken != "" {
		t.Fatalf("SYSTEM resolves the machine identity with no user token: %+v", system)
	}
	user := ResolveIdentity(mock, "SER", "h1", `CONTOSO\JDoe`)
	if user.DeviceID != "h1" || user.UserToken != "jdoe-"+UserTokenFingerprint(`contoso\jdoe`) {
		t.Fatalf("a developer's run carries the user token: %+v", user)
	}
	if UserToken(mock, `CONTOSO\JDoe`) != user.UserToken || UserToken(mock, `NT AUTHORITY\SYSTEM`) != "" {
		t.Fatal("UserToken must agree with the resolved identity")
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
	withConfigDeviceID(t, "{hostname}")
	mock.SetCommand("", "", 1, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	mock.SetCommand("", "", 1, "system_profiler", "SPHardwareDataType")
	id := ResolvedDeviceID(context.Background(), mock)
	if id.DeviceID != "mac" || id.Serial != "" {
		t.Fatalf("template without {serial} must not need one: %+v", id)
	}
	if id.UserToken != "jdoe-"+UserTokenFingerprint("jdoe") {
		t.Fatalf("the user token is resolved without a probe: %+v", id)
	}

	// {serial} with no probe source falls through to the generated, persisted
	// machine id (id.go) rather than an incomplete identity.
	old := userIDFile
	userIDFile = func() string { return "/tmp/dmg-identity-test/device-id" }
	t.Cleanup(func() { userIDFile = old })
	withConfigDeviceID(t, "{serial}-vdi")
	id = ResolvedDeviceID(context.Background(), mock)
	if id.Incomplete || id.Serial == "" || id.DeviceID != id.Serial+"-vdi" {
		t.Fatalf("{serial} must use the generated machine id: %+v", id)
	}
}

// SessionScope is the per-session state directory: the user's token on a
// host that scans every signed-in session separately, nothing on a
// single-user host, nothing for a service account.
func TestSessionScope(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetUsername(`CONTOSO\JDoe`)
	withConfigDeviceID(t, "")
	if got := SessionScope(mock); got != "" {
		t.Fatalf("a single-user host keeps shared state, got scope %q", got)
	}

	withMachineStateDir(t, "EnterpriseMultiSession", false)
	if got, want := SessionScope(mock), "jdoe-"+UserTokenFingerprint(`contoso\jdoe`); got != want {
		t.Fatalf("scope on a multi-session host = %q, want %q", got, want)
	}
	mock.SetEnv("USER_EMAIL", "Jane.Doe@example.com")
	if got, want := SessionScope(mock), "jane.doe-"+UserTokenFingerprint("jane.doe@example.com"); got != want {
		t.Fatalf("scope must honour the email override, got %q, want %q", got, want)
	}
	mock.SetEnv("USER_EMAIL", "")
	mock.SetUsername(`NT AUTHORITY\SYSTEM`)
	if got := SessionScope(mock); got != "" {
		t.Fatalf("a service account has no scope, got %q", got)
	}
	// The identity reports the same facts.
	id := ResolveIdentity(mock, "SER1", "AVD-HOST-07", `NT AUTHORITY\SYSTEM`)
	if !id.PerSession || id.SessionScope != "" || id.UserToken != "" || id.DeviceID != "SER1" {
		t.Fatalf("SYSTEM on a per-session host: %+v", id)
	}
	id = ResolveIdentity(mock, "SER1", "AVD-HOST-07", `CONTOSO\JDoe`)
	if !id.PerSession || id.SessionScope != id.UserToken || id.UserToken == "" || id.DeviceID != "SER1" {
		t.Fatalf("a developer on a per-session host: %+v", id)
	}
}

// {hostname} on a host without a usable name falls back to the machine
// identity, so the serial is probed although the template has no {serial}.
func TestResolvedDeviceID_NamelessHostProbesSerial(t *testing.T) {
	withConfigDeviceID(t, "{hostname}")
	ResetIDCache()
	t.Cleanup(ResetIDCache)
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetHostname("localhost")
	mock.SetUsername("jdoe")
	mock.SetCommand(`"IOPlatformSerialNumber" = "PROBED"`, "", 0, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	id := ResolvedDeviceID(context.Background(), mock)
	if id.Incomplete || id.DeviceID != "PROBED" || id.Source != IdentitySourceConfig {
		t.Fatalf("a nameless host must resolve {hostname} through the serial: %+v", id)
	}
}

// Two principals that share a short name never share a user token (and so
// never a state scope, a lock or a user entry on the device): the token
// carries a fingerprint of the whole principal. Case differences in the
// principal do not change it.
func TestUserToken_DistinctPrincipalsNeverCollide(t *testing.T) {
	principals := []string{`CORP\alice`, `HOST\alice`, "alice@a.example", "alice@b.example", "alice"}
	seen := map[string]string{}
	for _, p := range principals {
		tok := userToken("windows", false, p)
		if !strings.HasPrefix(tok, "alice-") || len(tok) != len("alice-")+UserTokenFingerprintLen {
			t.Errorf("userToken(%q) = %q, want alice-<fingerprint>", p, tok)
		}
		if prev, dup := seen[tok]; dup {
			t.Errorf("%q and %q collide on %q", prev, p, tok)
		}
		seen[tok] = p
	}
	if userToken("windows", false, `corp\ALICE`) != userToken("windows", false, `CORP\alice`) {
		t.Error("the principal's case must not change the token")
	}
	mock := executor.NewMock()
	if UserToken(mock, `CORP\alice`) == UserToken(mock, `HOST\alice`) {
		t.Fatal("CORP\\alice and HOST\\alice must have distinct tokens")
	}
}

// A name whose readable part sanitizes away (a non-Latin display name) still
// gets a token, never an empty one that would read as a service account.
func TestUserToken_NonLatinNameKeepsAToken(t *testing.T) {
	mock := executor.NewMock()
	if got, want := UserToken(mock, `AVD\张三`), "user-"+UserTokenFingerprint(`avd\张三`); got != want {
		t.Fatalf("user token = %q, want %q", got, want)
	}
	if UserToken(mock, `AVD\李四`) == UserToken(mock, `AVD\张三`) {
		t.Fatal("two non-Latin names must not collide")
	}
}

// A user token never exceeds MaxUserTokenLen, the bound the state-scope
// listing trusts, however long the account name.
func TestUserToken_FitsMaxUserTokenLen(t *testing.T) {
	for _, user := range []string{strings.Repeat("a", 600), `CONTOSO\` + strings.Repeat("b", 300), strings.Repeat("c", 400) + "@example.com"} {
		if tok := userToken("windows", false, user); len(tok) > MaxUserTokenLen {
			t.Errorf("token for a %d-byte name is %d bytes, over %d", len(user), len(tok), MaxUserTokenLen)
		}
	}
}
