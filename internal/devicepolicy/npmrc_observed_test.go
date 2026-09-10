package devicepolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// probeNPMRCObserved — MDM verify-only observed bag (pure)
// ---------------------------------------------------------------------------

// observedStrings decodes an observed bag into plain strings so a test can assert
// values without repeating the JSON quoting at every call site.
func observedStrings(t *testing.T, observed map[string]json.RawMessage) map[string]string {
	t.Helper()
	out := make(map[string]string, len(observed))
	for k, raw := range observed {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("observed[%s] = %s is not a JSON string: %v", k, raw, err)
		}
		out[k] = s
	}
	return out
}

func TestProbeContentNPM_ObservedBag(t *testing.T) {
	// A shared tenant token carries no ::dev:<serial> suffix — the comparison is on
	// the tenant-key prefix, so it still reads match.
	const sharedToken = "ssabc123"
	const foreignToken = "ssdifferent999::dev:SERIAL123"
	const otherRegistry = "https://evil.example/javascript"

	cases := []struct {
		name    string
		content string
		present bool
		reg     string
		auth    string
	}{
		{
			name:    "marker with matching registry and device token",
			content: mdmBlock(),
			present: true, reg: stdRegistry, auth: authTokenMatch,
		},
		{
			name:    "shared tenant token without a device serial still matches",
			content: npmrcMDMMarker + "\nregistry=" + stdRegistry + "\n" + stdTokenKey + "=" + sharedToken + "\n",
			present: true, reg: stdRegistry, auth: authTokenMatch,
		},
		{
			name:    "foreign tenant key mismatches",
			content: npmrcMDMMarker + "\nregistry=" + stdRegistry + "\n" + stdTokenKey + "=" + foreignToken + "\n",
			present: true, reg: stdRegistry, auth: authTokenMismatch,
		},
		{
			name:    "no token line for the tenant registry is absent",
			content: npmrcMDMMarker + "\nregistry=" + stdRegistry + "\n",
			present: true, reg: stdRegistry, auth: authTokenAbsent,
		},
		{
			// The reported registry is what npm would USE, not what the MDM block
			// claims — a later line wins, and the backend derives drift from it.
			name:    "a later registry line is reported as the effective one",
			content: mdmBlock() + "registry=" + otherRegistry + "\n",
			present: true, reg: otherRegistry, auth: authTokenMatch,
		},
		{
			// A block pointing elsewhere carries a different _authToken key, so the
			// tenant registry has no effective token: absent, plus the registry drift.
			name:    "a drifted registry reports its own url and an absent token",
			content: npmrcMDMMarker + "\nregistry=" + otherRegistry + "\n//evil.example/javascript/:_authToken=" + stdTokenVal + "\n",
			present: true, reg: otherRegistry, auth: authTokenAbsent,
		},
		{
			name:    "no mdm marker is not applied",
			content: "registry=" + stdRegistry + "\n" + stdTokenKey + "=" + stdTokenVal + "\n",
			present: false,
		},
		{
			name:    "empty file is not applied",
			content: "",
			present: false,
		},
		{
			// Our own DMG block is not MDM management: the marker search excludes it.
			name:    "only a dmg-owned block is not mdm applied",
			content: block(stdBody),
			present: false,
		},
		{
			name:    "an mdm marker planted inside our dmg block does not count",
			content: npmrcBeginMarker + "\n" + npmrcMDMMarker + "\nregistry=" + stdRegistry + "\n" + stdTokenKey + "=" + stdTokenVal + "\n" + npmrcEndMarker + "\n",
			present: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			present, observed, err := probeNPMRCObserved(tc.content, stdBody)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if present != tc.present {
				t.Fatalf("present = %v, want %v\ncontent:\n%s", present, tc.present, tc.content)
			}
			if !tc.present {
				if observed != nil {
					t.Fatalf("a not-applied read must carry no observed bag, got %v", observed)
				}
				return
			}
			got := observedStrings(t, observed)
			if len(got) != 3 {
				t.Fatalf("observed must carry exactly 3 keys, got %v", got)
			}
			if got[observedKeyEcosystem] != "npm" {
				t.Fatalf("ecosystem = %q, want npm", got[observedKeyEcosystem])
			}
			if got[observedKeyRegistryURL] != tc.reg {
				t.Fatalf("registry_url = %q, want %q", got[observedKeyRegistryURL], tc.reg)
			}
			if got[observedKeyAuthTokenStatus] != tc.auth {
				t.Fatalf("auth_token_status = %q, want %q", got[observedKeyAuthTokenStatus], tc.auth)
			}
		})
	}
}

func TestProbeContentNPM_SettingsStatus(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{name: "match", content: boundedMDMBlock(stdSettingsBody), want: settingsMatch},
		{name: "absent from fixed block", content: mdmBlock(), want: settingsAbsent},
		{name: "partial", content: boundedMDMBlock(strings.Replace(stdSettingsBody, "engine-strict=true\n", "", 1)), want: settingsMismatch},
		{name: "wrong", content: boundedMDMBlock(strings.Replace(stdSettingsBody, "save-exact=true", "save-exact=false", 1)), want: settingsMismatch},
		{name: "later override", content: boundedMDMBlock(stdSettingsBody) + "save-exact=false\n", want: settingsMismatch},
		{name: "duplicate block", content: boundedMDMBlock(stdSettingsBody) + boundedMDMBlock(stdSettingsBody), want: settingsMismatch},
		{name: "missing end", content: npmrcMDMBeginMarker + "\n" + stdSettingsBody + "\n", want: settingsMismatch},
		{name: "bounded block without settings", content: boundedMDMBlock(stdBody), want: settingsAbsent},
		{name: "stale extra setting", content: boundedMDMBlock(stdSettingsBody + "\nstale-option=true"), want: settingsMismatch},
		{name: "registry drift keeps settings match", content: boundedMDMBlock(strings.Replace(stdSettingsBody, stdRegistry, "https://other.example/javascript", 1)), want: settingsMatch},
		{name: "credential drift keeps settings match", content: boundedMDMBlock(strings.Replace(stdSettingsBody, stdTokenVal, "other::dev:SERIAL123", 1)), want: settingsMatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			present, observed, err := probeNPMRCObserved(tc.content, stdSettingsBody)
			if err != nil {
				t.Fatalf("probeNPMRCObserved: %v", err)
			}
			if !present {
				t.Fatal("MDM ownership was not recognized")
			}
			got := observedStrings(t, observed)
			if len(got) != 4 {
				t.Fatalf("observed key count = %d, want 4", len(got))
			}
			if got[observedKeySettingsStatus] != tc.want {
				t.Fatalf("settings_status = %q, want %q", got[observedKeySettingsStatus], tc.want)
			}
			raw, err := json.Marshal(observed)
			if err != nil {
				t.Fatal(err)
			}
			for _, sensitive := range []string{"save-exact", "EXAMPLE_NPM_TOKEN", "${EXAMPLE_NPM_TOKEN}", "engine-strict"} {
				if strings.Contains(string(raw), sensitive) {
					t.Fatalf("observed evidence contains %q: %s", sensitive, raw)
				}
			}
		})
	}
}

func TestProbeContentNPM_SettingsUnsafeShapesFailClosed(t *testing.T) {
	cases := []string{
		boundedMDMBlock(stdSettingsBody) + "save-exact[]=false\n",
		"[team]\n" + boundedMDMBlock(stdSettingsBody),
		boundedMDMBlock(stdSettingsBody) + "save-exact=false\r",
	}
	for _, content := range cases {
		present, observed, err := probeNPMRCObserved(content, stdSettingsBody)
		if err == nil {
			t.Fatalf("unsafe content did not fail: present=%v observed=%v", present, observed)
		}
		if present {
			t.Fatal("unsafe content reported MDM ownership")
		}
		if observed != nil {
			t.Fatalf("unsafe content produced evidence: %v", observed)
		}
	}

	planted := block(npmrcMDMBeginMarker + "\n" + stdSettingsBody + "\n" + npmrcMDMEndMarker)
	present, observed, err := probeNPMRCObserved(planted, stdSettingsBody)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("bounded MDM marker inside a DMG block claimed ownership")
	}
	if observed != nil {
		t.Fatalf("bounded MDM marker inside a DMG block produced evidence: %v", observed)
	}
}

func TestProbeContentNPM_FailsClosedNotUnapplied(t *testing.T) {
	// Constructs we cannot reason about must return an ERROR (→ verification_failed),
	// never the clean present=false (→ policy_not_applied). Reporting "nothing is
	// managing this file" off a file whose effective config we could not establish
	// would be a confident wrong answer.
	cases := []struct {
		name    string
		content string
	}{
		{"bare CR hides a section from the line split", "[team]\r" + mdmBlock()},
		{"INI section scopes the keys below it", "[team]\n" + mdmBlock()},
		{"single-quoted array key coerces to a registry override", mdmBlock() + `'["registry"]'=https://evil/` + "\n"},
		{"marker present but no effective registry line", npmrcMDMMarker + "\n" + stdTokenKey + "=" + stdTokenVal + "\n"},
		{"two dmg blocks leave a marker range unexcluded", mdmBlock() + block(stdBody) + block(stdBody)},
		// npm folds an array-append line into the same key, so the registry we would
		// report is not the one npm resolves.
		{"array-append registry poisons the effective value", mdmBlock() + "registry[]=https://evil.example/\n"},
		{"array-append registry above the block poisons it too", "registry[]=https://evil.example/\n" + mdmBlock()},
		{"a quoted array-append key is the same override", mdmBlock() + `"registry[]"=https://evil.example/` + "\n"},
		{"array-append on the token key", mdmBlock() + stdTokenKey + "[]=ssevil\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			present, observed, err := probeNPMRCObserved(tc.content, stdBody)
			if err == nil {
				t.Fatalf("want an error (verification_failed), got present=%v observed=%v", present, observed)
			}
			if present || observed != nil {
				t.Fatalf("a failed read must report nothing, got present=%v observed=%v", present, observed)
			}
		})
	}
}

func TestProbeContentNPM_RejectsUnrenderableExpected(t *testing.T) {
	// Without a parseable desired block there is no tenant key to compare against,
	// so the auth verdict cannot be computed. Fail rather than guess.
	if _, _, err := probeNPMRCObserved(mdmBlock(), "# not a rendered block"); err == nil {
		t.Fatal("a non-rendered expected value must error")
	}
}

func TestProbeContentNPM_RefusesCredentialBearingRegistryURL(t *testing.T) {
	// The effective registry_url is read off a user-writable file and is about to be
	// transmitted. A credential smuggled into the URL, a form an INI/URL parser
	// reads differently, or a value that is not a credible registry read at all
	// (another scheme, no host, oversize) must never leave the device — even though
	// the backend rejects it too. Note http is NOT here: see the transmit test.
	for _, url := range []string{
		"https://user:pass@registry-int.stepsecurity.io/javascript",
		"ftp://registry-int.stepsecurity.io/javascript",
		"file:///etc/passwd",
		"https:opaque-no-host",
		"https:///javascript",
		"https://" + strings.Repeat("a", 2048) + ".example/javascript",
	} {
		content := npmrcMDMMarker + "\nregistry=" + url + "\n" + stdTokenKey + "=" + stdTokenVal + "\n"
		present, observed, err := probeNPMRCObserved(content, stdBody)
		if err == nil {
			t.Fatalf("registry_url %q must be refused, got present=%v observed=%v", url, present, observed)
		}
		if strings.Contains(err.Error(), "pass") {
			t.Fatalf("the error must not echo the url, got %v", err)
		}
	}
}

func TestProbeContentNPM_TransmitsAPlaintextHTTPRegistry(t *testing.T) {
	// A device resolving to a plaintext mirror is the most security-relevant drift
	// an admin can have, so it must travel as evidence and surface as a registry_url
	// diff. Discarding it as malformed would hide exactly the case the verify-only
	// channel exists to catch. (The renderer's validateRegistryURL stays https-only
	// for the POLICY side, which we compose ourselves.)
	const plaintext = "http://registry-int.stepsecurity.io/javascript"
	content := npmrcMDMMarker + "\nregistry=" + plaintext + "\n" + stdTokenKey + "=" + stdTokenVal + "\n"
	present, observed, err := probeNPMRCObserved(content, stdBody)
	if err != nil {
		t.Fatalf("a plaintext registry must be transmitted, not refused: %v", err)
	}
	if !present {
		t.Fatal("present = false, want true (drift evidence)")
	}
	if got := observedStrings(t, observed)[observedKeyRegistryURL]; got != plaintext {
		t.Fatalf("registry_url = %q, want the observed %q", got, plaintext)
	}
}

func TestProbeContentNPM_ForeignRegistryTokenArrayStillObserved(t *testing.T) {
	// npm consults one token key per registry, so an array-append on some OTHER
	// registry's credential cannot perturb the tenant registry or its token. The
	// guard is scoped to the key we manage: judging every `:_authToken[]` line would
	// turn a device with an ordinary second registry into a verification failure.
	content := mdmBlock() + "//npm.pkg.github.com/:_authToken[]=ghtoken\n"
	present, observed, err := probeNPMRCObserved(content, stdBody)
	if err != nil {
		t.Fatalf("another registry's token array must not fail the read: %v", err)
	}
	if !present {
		t.Fatal("present = false, want true")
	}
	if got := observedStrings(t, observed)[observedKeyRegistryURL]; got == "" {
		t.Fatal("registry_url must still be observed")
	}
}

func TestProbeContentNPM_ReportsAWrongButCleanRegistry(t *testing.T) {
	// The shape rules the RENDERER enforces (host grammar, no port, an exact
	// /javascript path) are deliberately NOT applied to an observed value: a merely
	// wrong registry is exactly the drift the backend exists to derive, so it must
	// be transmitted, not turned into a verification failure.
	const wrong = "https://registry.npmjs.org:8443/some/other/path"
	content := npmrcMDMMarker + "\nregistry=" + wrong + "\n" + stdTokenKey + "=" + stdTokenVal + "\n"
	present, observed, err := probeNPMRCObserved(content, stdBody)
	if err != nil || !present {
		t.Fatalf("a wrong-but-clean registry must still be observed, got present=%v err=%v", present, err)
	}
	if got := observedStrings(t, observed)[observedKeyRegistryURL]; got != wrong {
		t.Fatalf("registry_url = %q, want the observed %q", got, wrong)
	}
}

func TestProbeContentNPM_NeverLeaksTheToken(t *testing.T) {
	// The observed bag is the only thing that leaves the device, and it must carry
	// no token material — not the on-disk token, not the desired tenant key, not a
	// hash or prefix of either. Only the verdict.
	const onDiskToken = "ssabc123::dev:OTHER-SERIAL"
	content := npmrcMDMMarker + "\nregistry=" + stdRegistry + "\n" + stdTokenKey + "=" + onDiskToken + "\n"
	present, observed, err := probeNPMRCObserved(content, stdBody)
	if err != nil || !present {
		t.Fatalf("probe failed: present=%v err=%v", present, err)
	}
	raw, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"ssabc123", onDiskToken, stdTokenVal, "OTHER-SERIAL", "SERIAL123"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("observed leaks %q: %s", secret, raw)
		}
	}
	// The token key names the registry, not the credential, so its presence would be
	// a contract violation rather than a leak — the bag is exactly three keys.
	if len(observed) != 3 {
		t.Fatalf("observed must carry exactly 3 keys, got %s", raw)
	}
}

func TestTenantKeyPrefix(t *testing.T) {
	cases := map[string]string{
		"ssabc123::dev:SERIAL123": "ssabc123",
		"ssabc123":                "ssabc123",
		"ssabc123::dev:":          "ssabc123",
		"":                        "",
		// Only the FIRST separator splits, so a serial that itself contains the
		// separator cannot shorten the compared prefix.
		"ssabc123::dev:A::dev:B": "ssabc123",
	}
	for token, want := range cases {
		if got := tenantKeyPrefix(token); got != want {
			t.Fatalf("tenantKeyPrefix(%q) = %q, want %q", token, got, want)
		}
	}
}

func TestHasArrayAppendOverride(t *testing.T) {
	// npm's ini reader strips a trailing "[]" AFTER its unsafe() normalization and
	// appends into an array under the remaining key, so `registry[]=` and our
	// block's `registry=` land in ONE array — both orders leave npm resolving to a
	// comma-joined list while a scalar last-wins scan still picks our line. Verified
	// against npm 10.9.7. Only keys we manage are judged: an unrelated array config
	// must not make the file unusable.
	desired, ok := parseNPMDesired(stdBody)
	if !ok {
		t.Fatal("standard body did not parse")
	}
	flagged := []string{
		"registry[]=https://evil.example/",
		`"registry[]"=https://evil.example/`,
		stdTokenKey + "[]=ssevil",
		"registry[]=",
	}
	for _, l := range flagged {
		if !hasArrayAppendOverride([]string{l}, desired) {
			t.Errorf("hasArrayAppendOverride(%q) = false, want true", l)
		}
	}
	clean := []string{
		"registry=https://good.example/javascript",
		// npm stores this under the distinct key "registry " — it overrides nothing.
		"registry [] = https://evil.example/",
		// Array configs we do not manage are none of our business.
		"omit[]=dev",
		"//other.example/:_authToken=sstoken",
		// npm consults only the tenant registry's token key, so an array on some
		// other registry's credential cannot perturb ours — refusing over it would
		// make a file we can enforce report unenforceable.
		"//other.example/:_authToken[]=sstoken",
		"# registry[]=https://evil.example/",
		"[]=x",
		"",
	}
	for _, l := range clean {
		if hasArrayAppendOverride([]string{l}, desired) {
			t.Errorf("hasArrayAppendOverride(%q) = true, want false", l)
		}
	}
}

func TestDMGBlockLines(t *testing.T) {
	// One block → its whole range is marked; no block → nothing is marked; more
	// than one → refused (managedBlockBounds only finds the first, so a marker
	// planted in the second would otherwise read as MDM presence).
	lines := strings.Split(strings.TrimRight("cache=x\n"+block(stdBody), "\n"), "\n")
	in, err := dmgBlockLines(lines)
	if err != nil {
		t.Fatal(err)
	}
	if in[0] {
		t.Fatal("a line before the block must not be marked")
	}
	marked := 0
	for _, m := range in {
		if m {
			marked++
		}
	}
	if marked != len(lines)-1 {
		t.Fatalf("marked %d of %d lines, want every block line", marked, len(lines))
	}

	none, err := dmgBlockLines([]string{"cache=x", "registry=y"})
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range none {
		if m {
			t.Fatalf("line %d marked with no block present", i)
		}
	}

	two := strings.Split(strings.TrimRight(block(stdBody)+block(stdBody), "\n"), "\n")
	if _, err := dmgBlockLines(two); !isTargetUnusable(err) {
		t.Fatalf("two dmg blocks must fail closed with ErrTargetUnusable, got %v", err)
	}
}

// A combined block left on disk after the policy moved to settings-only keeps
// StepSecurity as the effective default registry even when every desired setting
// is present, so it must not report settings_status=match.
func TestProbeContentNPM_SettingsOnlyRejectsStaleCombinedBlock(t *testing.T) {
	settingsOnly := strings.TrimPrefix(stdSettingsBody, stdBody+"\n")
	present, observed, err := probeNPMRCObserved(boundedMDMBlock(stdSettingsBody), settingsOnly)
	if err != nil || !present {
		t.Fatalf("probeNPMRCObserved: present=%v err=%v", present, err)
	}
	if got := observedStrings(t, observed); got[observedKeySettingsStatus] != settingsMismatch {
		t.Fatalf("settings_status = %q, want %q", got[observedKeySettingsStatus], settingsMismatch)
	}
}

func TestProbeContentNPM_SettingsOnlyObserved(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{name: "match", content: boundedMDMBlock(stdSettingsOnlyBody), want: settingsMatch},
		{name: "match with unrelated user config", content: "engine-strict=true\n" + boundedMDMBlock(stdSettingsOnlyBody), want: settingsMatch},
		{name: "absent under a bare fixed marker", content: npmrcMDMMarker + "\n", want: settingsAbsent},
		{name: "fixed StepSecurity block registry mismatches", content: mdmBlock(), want: settingsMismatch},
		{name: "partial", content: boundedMDMBlock(strings.Replace(stdSettingsOnlyBody, "\nsave-exact=true", "", 1)), want: settingsMismatch},
		{name: "wrong registry", content: boundedMDMBlock(strings.Replace(stdSettingsOnlyBody, "packages.example.com/npm/\n", "other.example/\n", 1)), want: settingsMismatch},
		{name: "later registry override", content: boundedMDMBlock(stdSettingsOnlyBody) + "registry=https://later.example/\n", want: settingsMismatch},
		{name: "duplicate block", content: boundedMDMBlock(stdSettingsOnlyBody) + boundedMDMBlock(stdSettingsOnlyBody), want: settingsMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			present, observed, err := probeNPMRCObserved(tc.content, stdSettingsOnlyBody)
			if err != nil {
				t.Fatalf("probeNPMRCObserved: %v", err)
			}
			if !present {
				t.Fatal("MDM ownership was not recognized")
			}
			got := observedStrings(t, observed)
			if len(got) != 2 || got[observedKeyEcosystem] != "npm" {
				t.Fatalf("settings-only observed = %v, want ecosystem and settings_status only", got)
			}
			if got[observedKeySettingsStatus] != tc.want {
				t.Fatalf("settings_status = %q, want %q", got[observedKeySettingsStatus], tc.want)
			}
			raw, err := json.Marshal(observed)
			if err != nil {
				t.Fatal(err)
			}
			for _, sensitive := range []string{"packages.example.com", "EXAMPLE_NPM_TOKEN", "save-exact", "registry_url", "auth_token_status"} {
				if strings.Contains(string(raw), sensitive) {
					t.Fatalf("observed evidence contains %q: %s", sensitive, raw)
				}
			}
		})
	}

	for _, content := range []string{"", "registry=https://packages.example.com/npm/\n", block(stdSettingsOnlyBody)} {
		present, observed, err := probeNPMRCObserved(content, stdSettingsOnlyBody)
		if err != nil || present || observed != nil {
			t.Fatalf("content %q: present=%v observed=%v err=%v, want not applied", content, present, observed, err)
		}
	}
	if _, _, err := probeNPMRCObserved(boundedMDMBlock(stdSettingsOnlyBody)+"registry[]=https://evil.example/\n", stdSettingsOnlyBody); err == nil {
		t.Fatal("managed registry array must fail closed")
	}
}

func TestNPMCompliantObserved(t *testing.T) {
	observed, err := npmCompliantObserved(stdBody)
	if err != nil || observed != nil {
		t.Fatalf("StepSecurity-only compliant report must carry no bag, got %v err=%v", observed, err)
	}
	observed, err = npmCompliantObserved(stdSettingsBody)
	if err != nil {
		t.Fatal(err)
	}
	if got := observedStrings(t, observed); len(got) != 4 || got[observedKeyRegistryURL] != stdRegistry || got[observedKeyAuthTokenStatus] != authTokenMatch || got[observedKeySettingsStatus] != settingsMatch {
		t.Fatalf("combined compliant bag = %v", got)
	}
	observed, err = npmCompliantObserved(stdSettingsOnlyBody)
	if err != nil {
		t.Fatal(err)
	}
	if got := observedStrings(t, observed); len(got) != 2 || got[observedKeyEcosystem] != "npm" || got[observedKeySettingsStatus] != settingsMatch {
		t.Fatalf("settings-only compliant bag = %v", got)
	}
}
