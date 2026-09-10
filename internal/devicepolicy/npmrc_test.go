package devicepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Standard fixture policy + serial shared across the pure-layer tests.
const (
	stdSerial       = "SERIAL123"
	stdPolicyJSON   = `{"ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"}}`
	stdBody         = "registry=https://registry-int.stepsecurity.io/javascript\n//registry-int.stepsecurity.io/javascript/:_authToken=ssabc123::dev:SERIAL123"
	stdRegistry     = "https://registry-int.stepsecurity.io/javascript"
	stdTokenKey     = "//registry-int.stepsecurity.io/javascript/:_authToken"
	stdTokenVal     = "ssabc123::dev:SERIAL123"
	stdSettingsBody = stdBody + "\n//registry.npmjs.org/:_authToken=${EXAMPLE_NPM_TOKEN}\n@example:registry=https://registry.npmjs.org/\nengine-strict=true\nsave-exact=true"
)

func npmSettingsPolicy(t *testing.T, settings any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"ecosystem":    "npm",
		"registry_url": stdRegistry,
		"auth": map[string]any{
			"scheme":  "stepsecurity_device_token",
			"api_key": "ssabc123",
		},
		"settings": settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// block wraps a rendered body in the managed markers exactly as the writer does.
func block(body string) string {
	return npmrcBeginMarker + "\n" + body + "\n" + npmrcEndMarker + "\n"
}

// ---------------------------------------------------------------------------
// RenderNPMRCBlock — validation table
// ---------------------------------------------------------------------------

func TestRenderNPMRCBlock_Valid(t *testing.T) {
	got, err := RenderNPMRCBlock(json.RawMessage(stdPolicyJSON), stdSerial)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != stdBody {
		t.Fatalf("rendered body mismatch:\n got: %q\nwant: %q", got, stdBody)
	}
	// The rendered body is exactly two content lines, no markers, no trailing
	// newline.
	if strings.Contains(got, npmrcBeginMarker) || strings.Contains(got, npmrcEndMarker) {
		t.Fatalf("rendered body must not contain markers: %q", got)
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatalf("rendered body must not end in a newline: %q", got)
	}
	if lines := strings.Split(got, "\n"); len(lines) != 2 {
		t.Fatalf("rendered body must be two lines, got %d", len(lines))
	}
}

func TestRenderNPMRCBlock_Settings(t *testing.T) {
	settings := map[string]string{
		"save-exact":                       "true",
		"@example:registry":                "https://registry.npmjs.org/",
		"engine-strict":                    "true",
		"//registry.npmjs.org/:_authToken": "${EXAMPLE_NPM_TOKEN}",
	}
	got, err := RenderNPMRCBlock(npmSettingsPolicy(t, settings), stdSerial)
	if err != nil {
		t.Fatalf("RenderNPMRCBlock: %v", err)
	}
	if got != stdSettingsBody {
		t.Fatalf("rendered body = %q, want %q", got, stdSettingsBody)
	}
	if !strings.Contains(got, "${EXAMPLE_NPM_TOKEN}") {
		t.Fatal("environment reference was not preserved literally")
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatal("rendered body must not end in a newline")
	}

	first := json.RawMessage(`{"ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"},"settings":{"z":"last","a":"first"}}`)
	second := json.RawMessage(`{"settings":{"a":"first","z":"last"},"auth":{"api_key":"ssabc123","scheme":"stepsecurity_device_token"},"registry_url":"https://registry-int.stepsecurity.io/javascript","ecosystem":"npm"}`)
	one, err := RenderNPMRCBlock(first, stdSerial)
	if err != nil {
		t.Fatal(err)
	}
	two, err := RenderNPMRCBlock(second, stdSerial)
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatalf("map order changed rendering: %q != %q", one, two)
	}

	advanced, err := RenderNPMRCBlock(npmSettingsPolicy(t, map[string]string{
		"@private:registry":                       "https://packages.example:8443/npm/",
		"//packages.example:8443/npm/:_authToken": "${PRIVATE_TOKEN}",
		"empty-option":                            "",
		"value-with-equals":                       "left=right",
		"literal-dollar":                          "$HOME",
	}), stdSerial)
	if err != nil {
		t.Fatalf("valid port/path settings: %v", err)
	}
	for _, line := range []string{
		"//packages.example:8443/npm/:_authToken=${PRIVATE_TOKEN}",
		"@private:registry=https://packages.example:8443/npm/",
		"empty-option=",
		"literal-dollar=$HOME",
		"value-with-equals=left=right",
	} {
		if !strings.Contains(advanced, "\n"+line) {
			t.Fatalf("rendered body missing %q: %q", line, advanced)
		}
	}
}

func TestRenderNPMRCBlock_SettingsRejections(t *testing.T) {
	tooMany := make(map[string]string, npmrcMaxSettings+1)
	for i := 0; i <= npmrcMaxSettings; i++ {
		tooMany[fmt.Sprintf("setting-%02d", i)] = "x"
	}
	productTokenKey := stdTokenKey
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{name: "null", raw: npmSettingsPolicy(t, nil)},
		{name: "empty", raw: npmSettingsPolicy(t, map[string]string{})},
		{name: "wrong type", raw: npmSettingsPolicy(t, []string{"x"})},
		{name: "non-string value", raw: npmSettingsPolicy(t, map[string]any{"save-exact": true})},
		{name: "null member value", raw: npmSettingsPolicy(t, map[string]any{"save-exact": nil})},
		{name: "too many", raw: npmSettingsPolicy(t, tooMany)},
		{name: "unknown top-level field", raw: json.RawMessage(`{"ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"},"extra":true}`)},
		{name: "unknown auth field", raw: json.RawMessage(`{"ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123","extra":true}}`)},
		{name: "trailing JSON", raw: json.RawMessage(stdPolicyJSON + ` {}`)},
		{name: "duplicate top-level member", raw: json.RawMessage(`{"ecosystem":"npm","ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"}}`)},
		{name: "duplicate setting member", raw: json.RawMessage(`{"ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"},"settings":{"save-exact":"true","save-exact":"false"}}`)},
		{name: "key whitespace", raw: npmSettingsPolicy(t, map[string]string{" save-exact": "true"})},
		{name: "value whitespace", raw: npmSettingsPolicy(t, map[string]string{"save-exact": " true"})},
		{name: "empty key", raw: npmSettingsPolicy(t, map[string]string{"": "true"})},
		{name: "oversize key", raw: npmSettingsPolicy(t, map[string]string{strings.Repeat("k", npmrcMaxSettingKeyBytes+1): "x"})},
		{name: "oversize value", raw: npmSettingsPolicy(t, map[string]string{"x": strings.Repeat("v", npmrcMaxSettingValueBytes+1)})},
		{name: "array key", raw: npmSettingsPolicy(t, map[string]string{"omit[]": "dev"})},
		{name: "section key", raw: npmSettingsPolicy(t, map[string]string{"[team]": "x"})},
		{name: "comment in value", raw: npmSettingsPolicy(t, map[string]string{"x": "value#comment"})},
		{name: "reserved registry", raw: npmSettingsPolicy(t, map[string]string{"ReGiStRy": "https://registry.npmjs.org/"})},
		{name: "reserved auth", raw: npmSettingsPolicy(t, map[string]string{"_AUTHTOKEN": "${TOKEN}"})},
		{name: "product token collision", raw: npmSettingsPolicy(t, map[string]string{productTokenKey: "${TOKEN}"})},
		{name: "literal scoped token", raw: npmSettingsPolicy(t, map[string]string{"@example:registry": "https://registry.npmjs.org/", "//registry.npmjs.org/:_authToken": "secret-token"})},
		{name: "unpaired scoped token", raw: npmSettingsPolicy(t, map[string]string{"//registry.npmjs.org/:_authToken": "${TOKEN}"})},
		{name: "unsupported scoped credential", raw: npmSettingsPolicy(t, map[string]string{"//registry.npmjs.org/:username": "user"})},
		{name: "malformed environment reference", raw: npmSettingsPolicy(t, map[string]string{"x": "${BAD-NAME}"})},
		{name: "invalid scope", raw: npmSettingsPolicy(t, map[string]string{"@Bad:registry": "https://registry.npmjs.org/"})},
		{name: "non-canonical registry suffix", raw: npmSettingsPolicy(t, map[string]string{"@example:REGISTRY": "https://registry.npmjs.org/"})},
		{name: "http scoped registry", raw: npmSettingsPolicy(t, map[string]string{"@example:registry": "http://registry.npmjs.org/"})},
		{name: "scoped registry userinfo", raw: npmSettingsPolicy(t, map[string]string{"@example:registry": "https://user:pass@registry.npmjs.org/"})},
		{name: "scoped registry query", raw: npmSettingsPolicy(t, map[string]string{"@example:registry": "https://registry.npmjs.org/?x=1"})},
		{name: "scoped registry bad port", raw: npmSettingsPolicy(t, map[string]string{"@example:registry": "https://registry.npmjs.org:70000/"})},
		{name: "scoped registry empty port", raw: npmSettingsPolicy(t, map[string]string{"@example:registry": "https://registry.npmjs.org:/"})},
		{name: "scoped registry missing host", raw: npmSettingsPolicy(t, map[string]string{"@example:registry": "https:///packages/"})},
		{name: "non-canonical host", raw: npmSettingsPolicy(t, map[string]string{"@example:registry": "https://Registry.NPMJS.org/"})},
		{name: "non-canonical trailing slash", raw: npmSettingsPolicy(t, map[string]string{"@example:registry": "https://registry.npmjs.org/path"})},
		{name: "ordinary URL userinfo", raw: npmSettingsPolicy(t, map[string]string{"proxy": "https://user:pass@proxy.example/"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RenderNPMRCBlock(tc.raw, stdSerial); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}

	invalidUTF8 := append([]byte(`{"ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"},"settings":{"x":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"}}`)...)
	if _, err := RenderNPMRCBlock(invalidUTF8, stdSerial); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestRenderNPMRCBlock_RejectsNormalizedKeyCollisions(t *testing.T) {
	body, err := RenderNPMRCBlock(npmSettingsPolicy(t, map[string]string{
		`foo\bar`:  "first",
		`foo\\bar`: "second",
	}), stdSerial)
	if err == nil || body != "" {
		t.Fatal("expected normalized key collision to return an error and no rendered body")
	}
}

func TestRenderNPMRCBlock_SettingsErrorsDoNotLeakValues(t *testing.T) {
	const literalSecret = "literal-private-token"
	const envName = "CUSTOMER_PRIVATE_TOKEN"
	raw := npmSettingsPolicy(t, map[string]string{
		"@example:registry":                "https://registry.npmjs.org/",
		"//registry.npmjs.org/:_authToken": literalSecret + "-${" + envName + "}",
	})
	_, err := RenderNPMRCBlock(raw, stdSerial)
	if err == nil {
		t.Fatal("unsafe credential value was accepted")
	}
	for _, sensitive := range []string{literalSecret, envName, "ssabc123", stdTokenVal} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error contains %q: %v", sensitive, err)
		}
	}
}

func TestRenderNPMRCBlock_SettingsSizeBoundary(t *testing.T) {
	prefix, err := RenderNPMRCBlock(json.RawMessage(stdPolicyJSON), stdSerial)
	if err != nil {
		t.Fatal(err)
	}
	key := "x"
	atLimit := strings.Repeat("v", npmrcMaxRenderedBytes-len(prefix)-len(key)-2)
	body, err := RenderNPMRCBlock(npmSettingsPolicy(t, map[string]string{key: atLimit}), stdSerial)
	if err != nil {
		t.Fatalf("body at limit: %v", err)
	}
	if len(body) != npmrcMaxRenderedBytes {
		t.Fatalf("rendered length = %d, want %d", len(body), npmrcMaxRenderedBytes)
	}
	if _, err := RenderNPMRCBlock(npmSettingsPolicy(t, map[string]string{key: atLimit + "v"}), stdSerial); err == nil {
		t.Fatal("body above limit was accepted")
	}
}

func TestRenderNPMRCBlock_Rejections(t *testing.T) {
	base := func(mut func(m map[string]any)) json.RawMessage {
		m := map[string]any{
			"ecosystem":    "npm",
			"registry_url": stdRegistry,
			"auth": map[string]any{
				"scheme":  "stepsecurity_device_token",
				"api_key": "ssabc123",
			},
		}
		if mut != nil {
			mut(m)
		}
		b, _ := json.Marshal(m)
		return b
	}
	setAuth := func(m map[string]any, k string, v any) {
		m["auth"].(map[string]any)[k] = v
	}

	cases := []struct {
		name   string
		policy json.RawMessage
		serial string
	}{
		{"not-an-object", json.RawMessage(`["nope"]`), stdSerial},
		{"wrong-ecosystem", base(func(m map[string]any) { m["ecosystem"] = "pip" }), stdSerial},
		{"wrong-scheme", base(func(m map[string]any) { setAuth(m, "scheme", "basic") }), stdSerial},
		{"empty-key", base(func(m map[string]any) { setAuth(m, "api_key", "") }), stdSerial},
		{"oversize-key", base(func(m map[string]any) { setAuth(m, "api_key", strings.Repeat("a", 257)) }), stdSerial},
		{"unsafe-key-space", base(func(m map[string]any) { setAuth(m, "api_key", "ab cd") }), stdSerial},
		{"unsafe-key-hash", base(func(m map[string]any) { setAuth(m, "api_key", "ab#cd") }), stdSerial},
		{"unsafe-key-dollar", base(func(m map[string]any) { setAuth(m, "api_key", "${X}") }), stdSerial},
		{"unsafe-key-newline", base(func(m map[string]any) { setAuth(m, "api_key", "ab\ncd") }), stdSerial},
		{"empty-serial", base(nil), ""},
		{"oversize-serial", base(nil), strings.Repeat("s", 129)},
		{"unsafe-serial", base(nil), "ser ial"},
		{"empty-url", base(func(m map[string]any) { m["registry_url"] = "" }), stdSerial},
		{"http-url", base(func(m map[string]any) { m["registry_url"] = "http://registry-int.stepsecurity.io/javascript" }), stdSerial},
		{"url-with-userinfo", base(func(m map[string]any) { m["registry_url"] = "https://user:pw@registry-int.stepsecurity.io/javascript" }), stdSerial},
		{"url-with-query", base(func(m map[string]any) { m["registry_url"] = "https://registry-int.stepsecurity.io/javascript?x=1" }), stdSerial},
		{"url-with-fragment", base(func(m map[string]any) { m["registry_url"] = "https://registry-int.stepsecurity.io/javascript#f" }), stdSerial},
		{"url-bare-fragment", base(func(m map[string]any) { m["registry_url"] = "https://registry-int.stepsecurity.io/javascript#" }), stdSerial},
		{"url-bare-query", base(func(m map[string]any) { m["registry_url"] = "https://registry-int.stepsecurity.io/javascript?" }), stdSerial},
		{"url-control-byte", base(func(m map[string]any) { m["registry_url"] = "https://registry-int.stepsecurity.io/java\x00script" }), stdSerial},
		{"url-with-port", base(func(m map[string]any) { m["registry_url"] = "https://registry-int.stepsecurity.io:8443/javascript" }), stdSerial},
		{"url-wrong-path", base(func(m map[string]any) { m["registry_url"] = "https://registry-int.stepsecurity.io/py" }), stdSerial},
		{"url-trailing-slash-path", base(func(m map[string]any) { m["registry_url"] = "https://registry-int.stepsecurity.io/javascript/" }), stdSerial},
		{"url-uppercase-host", base(func(m map[string]any) { m["registry_url"] = "https://Registry-Int.StepSecurity.io/javascript" }), stdSerial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RenderNPMRCBlock(tc.policy, tc.serial)
			if err == nil {
				t.Fatalf("expected rejection, got nil error")
			}
			// Error messages never echo the key material.
			if strings.Contains(err.Error(), "ssabc123") || strings.Contains(err.Error(), "${X}") {
				t.Fatalf("error message leaked key material: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// rewriteContent — the §3 rewrite algorithm (pure []byte -> []byte)
// ---------------------------------------------------------------------------

func rewrite(t *testing.T, current string) string {
	t.Helper()
	w := &NPMRCWriter{}
	out, err := w.rewriteContent([]byte(current), stdBody)
	if err != nil {
		t.Fatalf("rewriteContent(%q): %v", current, err)
	}
	return string(out)
}

func TestRewrite_Table(t *testing.T) {
	cases := []struct {
		name    string
		current string
		want    string
	}{
		{
			name:    "empty file creates block only", // edge 1 (content)
			current: "",
			want:    block(stdBody),
		},
		{
			name:    "no registry lines appends block", // edge 2
			current: "cache=/tmp/x\n",
			want:    "cache=/tmp/x\n" + block(stdBody),
		},
		{
			name:    "bare registry commented out", // edge 3
			current: "registry=https://registry.npmjs.org/\n",
			want:    "# [stepsecurity-dmg] registry=https://registry.npmjs.org/\n" + block(stdBody),
		},
		{
			name:    "scoped registry / token / cooldown preserved", // edge 4
			current: "@acme:registry=https://acme.jfrog.io/\n//acme.jfrog.io/:_authToken=xyz\nmin-release-age=7\n",
			want:    "@acme:registry=https://acme.jfrog.io/\n//acme.jfrog.io/:_authToken=xyz\nmin-release-age=7\n" + block(stdBody),
		},
		{
			name:    "already prefixed line not double prefixed", // edge 5
			current: "# [stepsecurity-dmg] registry=https://registry.npmjs.org/\n",
			want:    "# [stepsecurity-dmg] registry=https://registry.npmjs.org/\n" + block(stdBody),
		},
		{
			name:    "registry appended below block is re-commented, block stays last", // edge 6
			current: block(stdBody) + "registry=https://evil/\n",
			want:    "# [stepsecurity-dmg] registry=https://evil/\n" + block(stdBody),
		},
		{
			name:    "missing END stripped to EOF", // edge 10
			current: "foo\n" + npmrcBeginMarker + "\nregistry=stale\n",
			want:    "foo\n" + block(stdBody),
		},
		{
			name:    "env-ref token line preserved", // edge 13
			current: "//host/:_authToken=${NPM_TOKEN}\n",
			want:    "//host/:_authToken=${NPM_TOKEN}\n" + block(stdBody),
		},
		{
			name:    "no trailing newline gets one before block", // edge 34
			current: "foo",
			want:    "foo\n" + block(stdBody),
		},
		{
			name:    "pre-existing blank lines preserved", // edge 34
			current: "foo\n\n\n",
			want:    "foo\n\n\n" + block(stdBody),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rewrite(t, tc.current); got != tc.want {
				t.Fatalf("rewrite mismatch:\n current: %q\n     got: %q\n    want: %q", tc.current, got, tc.want)
			}
		})
	}
}

func TestRewrite_CRLFPreserved(t *testing.T) { // edge 11
	current := "cache=x\r\nregistry=y\r\n"
	got := rewrite(t, current)
	want := "cache=x\r\n# [stepsecurity-dmg] registry=y\r\n" + block(stdBody)
	if got != want {
		t.Fatalf("CRLF rewrite mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestRewrite_BOMPreserved(t *testing.T) { // edge 38
	current := "\ufeff" + "registry=x\n"
	got := rewrite(t, current)
	if !strings.HasPrefix(got, "\ufeff") {
		t.Fatalf("BOM not preserved at start: %q", got)
	}
	if !strings.Contains(got, "# [stepsecurity-dmg] registry=x\n") {
		t.Fatalf("BOM file registry not commented (BOM must not glue to key): %q", got)
	}
	if strings.Count(got, "\ufeff") != 1 {
		t.Fatalf("BOM should appear exactly once: %q", got)
	}
}

func TestRewrite_SectionFailsClosed(t *testing.T) { // edge 37
	w := &NPMRCWriter{}
	_, err := w.rewriteContent([]byte("[global]\nregistry=x\n"), stdBody)
	if err == nil {
		t.Fatal("expected a section header to fail closed")
	}
	if !isTargetUnusable(err) {
		t.Fatalf("section rewrite error should be ErrTargetUnusable, got %v", err)
	}
}

func TestStripManagedBlock_RemovesAllDuplicates(t *testing.T) {
	// Two complete managed blocks (a user copy, or a partial prior write) must both
	// be stripped — the pure guarantee behind offboarding revoking EVERY token and
	// a rewrite never oscillating between one block and two.
	two := block(stdBody) + block(stdBody)
	lines := strings.Split(strings.TrimRight(two, "\n"), "\n")
	out, toEOF := stripManagedBlock(lines)
	if toEOF {
		t.Fatal("two well-formed blocks must not report a truncated (EOF) strip")
	}
	for _, l := range out {
		if isMarkerLine(l, npmrcBeginMarker) || isMarkerLine(l, npmrcEndMarker) {
			t.Fatalf("a managed marker survived stripping all blocks: %q", out)
		}
	}
}

func TestRewrite_CollapsesDuplicateBlocks(t *testing.T) {
	// A file carrying two managed blocks rewrites to exactly one clean block —
	// otherwise Converged's single-block requirement would loop forever.
	got := rewrite(t, block(stdBody)+block(stdBody))
	if n := strings.Count(got, npmrcBeginMarker); n != 1 {
		t.Fatalf("expected exactly one block after rewrite, got %d:\n%s", n, got)
	}
	if got != block(stdBody) {
		t.Fatalf("rewrite of duplicate blocks = %q, want a single clean block %q", got, block(stdBody))
	}
}

func TestRewrite_Idempotent(t *testing.T) { // edge 15 (content)
	fixtures := []string{
		"",
		"registry=https://registry.npmjs.org/\n",
		"@acme:registry=https://acme.jfrog.io/\nmin-release-age=7\n",
		"foo",
		"foo\n\n\n",
		"\ufeffregistry=x\n",
		"cache=x\r\nregistry=y\r\n",
	}
	for _, f := range fixtures {
		first := rewrite(t, f)
		second := rewrite(t, first)
		if first != second {
			t.Fatalf("not idempotent for %q:\nfirst:  %q\nsecond: %q", f, first, second)
		}
	}
}

func TestRewrite_SettingsLifecycleAndPrecedence(t *testing.T) {
	initial := "\ufeffsave-exact=false\r\n@example:registry=https://old.example/\r\n"
	w := &NPMRCWriter{}
	applied, err := w.rewriteContent([]byte(initial), stdSettingsBody)
	if err != nil {
		t.Fatalf("initial rewrite: %v", err)
	}
	if !strings.HasPrefix(string(applied), initial) {
		t.Fatalf("existing scalar assignments changed: %q", applied)
	}
	if !strings.HasSuffix(string(applied), block(stdSettingsBody)) {
		t.Fatalf("managed settings block was not appended last: %q", applied)
	}
	cleared, err := w.clearContent(applied)
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if string(cleared) != initial {
		t.Fatalf("clear = %q, want exact original %q", cleared, initial)
	}

	drifted := append(append([]byte(nil), applied...), []byte("save-exact=false\n")...)
	lines := strings.Split(string(drifted), "\n")
	if blockIsLastEffective(lines, stdSettingsBody) {
		t.Fatal("later setting override must defeat convergence")
	}
	repaired, err := w.rewriteContent(drifted, stdSettingsBody)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if !strings.Contains(string(repaired), "save-exact=false\n") {
		t.Fatal("repair removed the user override")
	}
	if !strings.HasSuffix(string(repaired), block(stdSettingsBody)) {
		t.Fatal("repair did not move the managed block last")
	}

	changed := strings.Replace(stdSettingsBody, "save-exact=true", "save-exact=false", 1)
	changed = strings.Replace(changed, "engine-strict=true\n", "", 1)
	updated, err := w.rewriteContent(repaired, changed)
	if err != nil {
		t.Fatalf("policy update: %v", err)
	}
	if strings.Contains(extractBodyForTest(t, updated), "engine-strict=") {
		t.Fatal("removed setting remained in the managed block")
	}
	baseOnly, err := w.rewriteContent(updated, stdBody)
	if err != nil {
		t.Fatalf("return to base-only: %v", err)
	}
	if got := extractBodyForTest(t, baseOnly); got != stdBody {
		t.Fatalf("base-only body = %q, want %q", got, stdBody)
	}
}

func TestRewrite_BackslashSettingUsesNPMSemantics(t *testing.T) {
	body, err := RenderNPMRCBlock(npmSettingsPolicy(t, map[string]string{"cache": `\\server\share`}), stdSerial)
	if err != nil {
		t.Fatal(err)
	}
	w := &NPMRCWriter{}
	first, err := w.rewriteContent(nil, body)
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.rewriteContent(first, body)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(first) {
		t.Fatalf("repeated rewrite changed bytes: %q != %q", second, first)
	}
	lines := strings.Split(string(first), "\n")
	if !blockIsLastEffective(lines, body) {
		t.Fatal("unchanged backslash setting did not converge")
	}
	managed, _ := probeNPMRCContent(boundedMDMBlock(body), body)
	if !managed {
		t.Fatal("matching bounded MDM block with a backslash setting was not managed")
	}
	present, observed, err := probeNPMRCObserved(boundedMDMBlock(body), body)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatal("matching bounded MDM block was not observed")
	}
	got := observedStrings(t, observed)
	if got[observedKeySettingsStatus] != settingsMatch {
		t.Fatalf("settings_status = %q, want %q", got[observedKeySettingsStatus], settingsMatch)
	}
}

func extractBodyForTest(t *testing.T, content []byte) string {
	t.Helper()
	body, present := extractManagedBody(string(content))
	if !present {
		t.Fatal("managed block missing")
	}
	return body
}

func TestRewrite_SettingsArrayConflict(t *testing.T) {
	desired, ok := parseNPMDesired(stdSettingsBody)
	if !ok {
		t.Fatal("standard settings body did not parse")
	}
	if !hasArrayAppendOverride([]string{"save-exact[]=false"}, desired) {
		t.Fatal("managed setting array was not detected")
	}
	w := &NPMRCWriter{}
	if _, err := w.rewriteContent([]byte("save-exact[]=false\n"), stdSettingsBody); !errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("managed setting array error = %v, want target unusable", err)
	}
	out, err := w.rewriteContent([]byte("omit[]=dev\n"), stdSettingsBody)
	if err != nil {
		t.Fatalf("unrelated array rewrite: %v", err)
	}
	if !strings.HasPrefix(string(out), "omit[]=dev\n") {
		t.Fatalf("unrelated array changed: %q", out)
	}
}

// ---------------------------------------------------------------------------
// clearContent — the clear transform (pure bytes in, bytes out)
// ---------------------------------------------------------------------------

func clearOf(t *testing.T, current string) string {
	t.Helper()
	w := &NPMRCWriter{}
	out, err := w.clearContent([]byte(current))
	if err != nil {
		t.Fatalf("clearContent: %v", err)
	}
	return string(out)
}

func TestClear_RestoresAndPreserves(t *testing.T) { // edge 9
	// A file the writer previously converged: original registry commented, MDM
	// line present, our block at the bottom.
	current := "# [stepsecurity-dmg] registry=https://registry.npmjs.org/\n" +
		"# [stepsecurity] registry=https://mdm/\n" +
		block(stdBody)
	got := clearOf(t, current)
	want := "registry=https://registry.npmjs.org/\n# [stepsecurity] registry=https://mdm/\n"
	if got != want {
		t.Fatalf("clear mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestClear_ShellOnlyBlockRemoved(t *testing.T) { // edge 24
	current := npmrcBeginMarker + "\n" + npmrcEndMarker + "\n"
	if got := clearOf(t, current); got != "" {
		t.Fatalf("shell-only block should clear to empty, got %q", got)
	}
}

func TestClear_NeverUnprefixesMDM(t *testing.T) {
	current := "# [stepsecurity] registry=https://mdm/\n" + block(stdBody)
	got := clearOf(t, current)
	if !strings.Contains(got, "# [stepsecurity] registry=https://mdm/\n") {
		t.Fatalf("clear must not un-comment the MDM lane's prefix: %q", got)
	}
}

func TestClear_MissingFinalNewlineNotRestored(t *testing.T) { // edge 34 (clear)
	// Enforce turned "foo" (no trailing newline) into "foo\n<block>". Clearing
	// keeps the "\n" enforce added — the one permitted byte deviation.
	enforced := rewrite(t, "foo")
	got := clearOf(t, enforced)
	if got != "foo\n" {
		t.Fatalf("clear should leave %q, got %q", "foo\n", got)
	}
}

// ---------------------------------------------------------------------------
// INI classifier + shared-consumer behavior
// ---------------------------------------------------------------------------

func TestActiveKV(t *testing.T) {
	cases := []struct {
		line string
		key  string
		val  string
		ok   bool
	}{
		{"registry=https://x/", "registry", "https://x/", true},
		{"registry = https://x/", "registry", "https://x/", true}, // spaced
		{"registry\t=\tx", "registry", "x", true},                 // tabbed
		{"@acme:registry=https://y/", "@acme:registry", "https://y/", true},
		{`always-auth="true"`, "always-auth", "true", true}, // quoted value
		// npm parity: npm's unsafe() strips an unescaped inline ';'/'#' comment and
		// unquotes a fully quoted token on BOTH key and value, so each of these is an
		// active `registry` assignment to npm — and must be to us, or a disguised
		// override slips past last-wins.
		{"registry#ignored=https://evil/", "registry", "https://evil/", true},
		{`"registry"=https://evil/`, "registry", "https://evil/", true},
		{`'registry'=https://evil/`, "registry", "https://evil/", true},
		{`"a\qb"=v`, `"a\qb"`, "v", true},                                    // invalid JSON escape → npm keeps the quoted form
		{"registry ; note=https://evil/", "registry", "https://evil/", true}, // comment in key portion
		{"registry=https://evil/ # trailing", "registry", "https://evil/", true},
		{`registry\#x=v`, "registry#x", "v", true}, // escaped '#' is literal, not a comment
		{"# registry=commented", "", "", false},
		{"; registry=commented", "", "", false},
		{"  # indented comment", "", "", false},
		{"[section]", "", "", false},
		{"", "", "", false},
		{"noequalsline", "", "", false},
		{"=noKey", "", "", false},
	}
	for _, tc := range cases {
		key, val, ok := activeKV(tc.line)
		if ok != tc.ok || key != tc.key || val != tc.val {
			t.Fatalf("activeKV(%q) = (%q,%q,%v), want (%q,%q,%v)", tc.line, key, val, ok, tc.key, tc.val, tc.ok)
		}
	}
}

func TestActiveKV_DoubleQuotedJSONEscapeDecodes(t *testing.T) {
	// npm's ini unsafe() runs JSON.parse on a double-quoted token, so a \uXXXX
	// escape resolves: the on-disk key `"registry"` (i = 'i') is the key
	// `registry` to npm. Our classifier must JSON-decode it too, or the override is
	// missed and Converged/probe report a false compliant/managed. The escape is
	// assembled from a literal backslash so the on-disk bytes are unambiguous.
	bs := "\\" // one backslash
	line := `"reg` + bs + `u0069stry"=https://evil/`
	if !strings.Contains(line, "u0069") { // guard: prove it is the ESCAPED form, not plain "registry"
		t.Fatalf("test did not build the escaped form: %q", line)
	}
	key, val, ok := activeKV(line)
	if !ok || key != "registry" || val != "https://evil/" {
		t.Fatalf("activeKV(%q) = (%q,%q,%v), want (registry, https://evil/, true)", line, key, val, ok)
	}
	// The effectiveness + precedence consumers must treat it as a real override.
	blk := strings.Split(strings.TrimRight(block(stdBody)+line+"\n", "\n"), "\n")
	if blockIsLastEffective(blk, stdBody) {
		t.Fatal("a \\u-escaped registry override must defeat blockIsLastEffective")
	}
	if managed, _ := probeNPMRCContent(mdmBlock()+line+"\n", stdBody); managed {
		t.Fatal("a \\u-escaped registry override must prevent a managed probe")
	}
}

// TestSharedClassifier_SpacedForms proves one INI classifier backs the
// consumers that must see npm's whitespace-tolerant key matching: comment-out
// (rewrite), precedence (probe), and round-trip restore (clear).
func TestSharedClassifier_SpacedForms(t *testing.T) {
	for _, spaced := range []string{"registry = https://evil/", "registry\t=\thttps://evil/"} {
		// rewrite comments out the spaced active registry line.
		out := rewrite(t, spaced+"\n")
		if !strings.Contains(out, npmrcDMGPrefix+spaced+"\n") {
			t.Fatalf("spaced registry %q was not commented out:\n%s", spaced, out)
		}
		// clear restores it exactly (literal prefix strip, spacing intact).
		if got := clearOf(t, out); got != spaced+"\n" {
			t.Fatalf("clear did not restore spaced form: got %q want %q", got, spaced+"\n")
		}
		// probe precedence: the same spaced line below an MDM block defeats
		// effectiveness (a later bare registry overrides).
		content := npmrcMDMMarker + "\nregistry=" + stdRegistry + "\n" + stdTokenKey + "=" + stdTokenVal + "\n" + spaced + "\n"
		if managed, _ := probeNPMRCContent(content, stdBody); managed {
			t.Fatalf("probe must not report managed when a spaced registry override follows: %q", spaced)
		}
		// Converged's effectiveness check (the 4th consumer) sees the spaced form
		// too: a spaced registry override after our block defeats last-wins.
		blk := strings.Split(strings.TrimRight(block(stdBody)+spaced+"\n", "\n"), "\n")
		if blockIsLastEffective(blk, stdBody) {
			t.Fatalf("blockIsLastEffective must be false when a spaced registry override follows: %q", spaced)
		}
	}
}

// TestClassifier_NpmDisguisedOverrideCaught proves the npm-faithful key parsing
// catches an override npm honors but a naive first-'=' split would miss: an
// inline comment or quotes on the key both resolve to `registry` for npm. Both
// the convergence effectiveness check and the MDM precedence probe must treat
// each as a real override and refuse to report the block effective/managed.
func TestClassifier_NpmDisguisedOverrideCaught(t *testing.T) {
	for _, override := range []string{
		"registry#ignored=https://evil/",
		`"registry"=https://evil/`,
		`'registry'=https://evil/`,
		"registry = https://evil/ # trailing",
	} {
		blk := strings.Split(strings.TrimRight(block(stdBody)+override+"\n", "\n"), "\n")
		if blockIsLastEffective(blk, stdBody) {
			t.Fatalf("blockIsLastEffective must be false when an npm-parsed override follows: %q", override)
		}
		if managed, _ := probeNPMRCContent(mdmBlock()+override+"\n", stdBody); managed {
			t.Fatalf("probe must not report managed when an npm-parsed override follows: %q", override)
		}
	}
}

func TestRewrite_LoneCRFailsClosed(t *testing.T) {
	// A bare CR (old-Mac line break, or an injected one) is a line separator to npm
	// but not to our '\n' split; a section or override hidden behind it must fail
	// closed, never be silently mis-parsed.
	w := &NPMRCWriter{}
	for _, in := range []string{
		"[global]\rregistry=x\n",            // section hidden behind a bare CR
		"cache=x\rregistry=https://evil/\n", // override hidden behind a bare CR
		"foo\r",                             // trailing bare CR
	} {
		if _, err := w.rewriteContent([]byte(in), stdBody); !isTargetUnusable(err) {
			t.Fatalf("rewriteContent(%q) must fail closed with ErrTargetUnusable, got %v", in, err)
		}
	}
	// CRLF is NOT a lone CR and must still round-trip.
	if _, err := w.rewriteContent([]byte("cache=x\r\nregistry=y\r\n"), stdBody); err != nil {
		t.Fatalf("CRLF must not be rejected as a bare CR: %v", err)
	}
}

func TestRewrite_CoercibleQuotedKeyFailsClosed(t *testing.T) {
	// npm strips single quotes and JSON-parses the inner, coercing a non-string
	// (an array) to a string key: `'["registry"]'` becomes the key `registry`. We
	// can't cheaply mirror that coercion, so any single-quoted non-string JSON key
	// fails closed rather than being silently mis-parsed and missed.
	w := &NPMRCWriter{}
	for _, in := range []string{
		`'["registry"]'=https://evil/` + "\n",
		`'["//registry-int.stepsecurity.io/javascript/:_authToken"]'=evil::dev:X` + "\n",
		`'[["registry"]]'=https://evil/` + "\n",
	} {
		if _, err := w.rewriteContent([]byte(in), stdBody); !isTargetUnusable(err) {
			t.Fatalf("rewriteContent(%q) must fail closed with ErrTargetUnusable, got %v", in, err)
		}
	}
	// A single-quoted STRING key is NOT coercible-non-string: npm reads it as the
	// plain key, and so do we — it is recognized and commented out, not refused.
	for _, in := range []string{`'registry'=https://evil/` + "\n", `'"registry"'=https://evil/` + "\n"} {
		out, err := w.rewriteContent([]byte(in), stdBody)
		if err != nil {
			t.Fatalf("rewriteContent(%q) must not fail closed, got %v", in, err)
		}
		if !strings.Contains(string(out), npmrcDMGPrefix) {
			t.Fatalf("a single-quoted registry key should be commented out, got %q", string(out))
		}
	}
}

func TestRewrite_ArrayAppendOverrideFailsClosed(t *testing.T) {
	// npm's ini reader folds `registry[]=` and our block's own `registry=` into ONE
	// array, so the effective registry becomes a comma-joined list containing the
	// injected value while a last-wins scalar scan still sees our line as the
	// winner. Verified against npm 10.9.7: `registry=<ours>` + `registry[]=<theirs>`
	// yields "<ours>,<theirs>", and the reverse order yields "<theirs>,<ours>".
	// Commenting the line out is not enough (npm arrays are order-independent), so
	// the transform refuses the file.
	w := &NPMRCWriter{}
	for _, in := range []string{
		"registry[]=https://evil.example/\n",
		`"registry[]"=https://evil.example/` + "\n",
		"//registry-int.stepsecurity.io/javascript/:_authToken[]=ssevil\n",
	} {
		if _, err := w.rewriteContent([]byte(in), stdBody); !isTargetUnusable(err) {
			t.Fatalf("rewriteContent(%q) must fail closed with ErrTargetUnusable, got %v", in, err)
		}
	}
	// Array syntax on a key we do NOT manage is npm-legal config and must not make
	// the file unusable — including another registry's token, which npm never
	// consults for ours. Nor must the spaced form, which npm stores under the
	// distinct key "registry " and which overrides nothing.
	for _, in := range []string{
		"omit[]=dev\n",
		"//npm.pkg.github.com/:_authToken[]=ghtoken\n",
		"registry [] = https://evil.example/\n",
	} {
		if _, err := w.rewriteContent([]byte(in), stdBody); err != nil {
			t.Fatalf("rewriteContent(%q) must not fail closed, got %v", in, err)
		}
	}
}

func TestProbeContent_ArrayAppendOverrideNotManaged(t *testing.T) {
	// The MDM probe shares the guard: a marker plus matching lines is not proof the
	// MDM lane governs npm when an array-append line folds into the same key.
	for _, in := range []string{
		mdmBlock() + "registry[]=https://evil.example/\n",
		"registry[]=https://evil.example/\n" + mdmBlock(),
	} {
		if managed, _ := probeNPMRCContent(in, stdBody); managed {
			t.Fatalf("probe must fail closed on array-append syntax, got managed for %q", in)
		}
	}
}

func TestClear_LoneCRFailsClosed(t *testing.T) {
	// A CR-delimited file collapses to one line under the '\n' split, so no marker
	// matches and the block is never FOUND. Without this guard clearContent returned
	// its input unchanged, Clear reported the nothing-to-do success, and the
	// reconciler dropped ownership state while the token stayed on disk — an
	// offboarding that silently revoked nothing.
	w := &NPMRCWriter{}
	crFile := strings.ReplaceAll("cache=x\n"+block(stdBody), "\n", "\r")
	out, err := w.clearContent([]byte(crFile))
	if !isTargetUnusable(err) {
		t.Fatalf("clearContent on a CR-delimited block must fail closed with ErrTargetUnusable, got err=%v out=%q", err, string(out))
	}
	if out != nil {
		t.Fatalf("a refused clear must return no bytes, got %q", string(out))
	}
	// CRLF is not a lone CR: a real block still clears.
	crlf := strings.ReplaceAll(block(stdBody), "\n", "\r\n")
	got, err := w.clearContent([]byte(crlf))
	if err != nil {
		t.Fatalf("CRLF must not be refused as a bare CR: %v", err)
	}
	if strings.Contains(string(got), stdTokenVal) {
		t.Fatalf("the token must be gone after a CRLF clear, got %q", string(got))
	}
}

func TestProbeContent_LoneCRNotManaged(t *testing.T) {
	// A bare CR that hides a section from our split must not let a probe report
	// managed off a marker plus matching lines npm would actually scope out.
	if managed, _ := probeNPMRCContent("[team]\r"+mdmBlock(), stdBody); managed {
		t.Fatal("probe must fail closed on a bare CR")
	}
}

func TestExtractManagedBody(t *testing.T) {
	body, present := extractManagedBody(block(stdBody))
	if !present || body != stdBody {
		t.Fatalf("extractManagedBody = (%q,%v), want (%q,true)", body, present, stdBody)
	}
	// A BEGIN with no END is not a well-formed block.
	if _, present := extractManagedBody(npmrcBeginMarker + "\nregistry=x\n"); present {
		t.Fatal("a block with no END marker must report not present")
	}
	if _, present := extractManagedBody("registry=x\n"); present {
		t.Fatal("no markers means not present")
	}
}

// ---------------------------------------------------------------------------
// probeNPMRCContent — MDM ownership logic (pure)
// ---------------------------------------------------------------------------

func mdmBlock() string {
	return npmrcMDMMarker + "\nregistry=" + stdRegistry + "\n" + stdTokenKey + "=" + stdTokenVal + "\n"
}

func boundedMDMBlock(body string) string {
	return npmrcMDMBeginMarker + "\n" + body + "\n" + npmrcMDMEndMarker + "\n"
}

func TestProbeContent(t *testing.T) {
	cases := []struct {
		name    string
		content string
		managed bool
	}{
		{"managed and effective", mdmBlock(), true},                                       // edge 8
		{"mdm absorbed our lines, our empty shell present", mdmBlock() + block(""), true}, // edge 16
		{"our shell only, mdm removed", block(""), false},                                 // edge 17
		{"no mdm marker", "registry=" + stdRegistry + "\n" + stdTokenKey + "=" + stdTokenVal + "\n", false},
		{"planted marker without valid content", npmrcMDMMarker + "\nregistry=https://wrong/\n", false},                            // edge 20
		{"stale token under marker", npmrcMDMMarker + "\nregistry=" + stdRegistry + "\n" + stdTokenKey + "=stale::dev:X\n", false}, // edge 21
		{"later bare registry override defeats precedence", mdmBlock() + "registry=https://evil/\n", false},
		{"later token override defeats precedence", mdmBlock() + stdTokenKey + "=evil::dev:X\n", false},
		{"section scopes keys → not managed", "[team]\n" + mdmBlock(), false},
		{"single-quoted array key coerces to a registry override", mdmBlock() + `'["registry"]'=https://evil/` + "\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			managed, _ := probeNPMRCContent(tc.content, stdBody)
			if managed != tc.managed {
				t.Fatalf("probeNPMRCContent managed=%v, want %v\ncontent:\n%s", managed, tc.managed, tc.content)
			}
		})
	}
}

func TestProbeContent_SettingsBoundedMDMBlock(t *testing.T) {
	cases := []struct {
		name    string
		content string
		managed bool
	}{
		{name: "exact bounded block", content: boundedMDMBlock(stdSettingsBody), managed: true},
		{name: "exact bounded CRLF block", content: strings.ReplaceAll(boundedMDMBlock(stdSettingsBody), "\n", "\r\n"), managed: true},
		{name: "fixed base-only block", content: mdmBlock()},
		{name: "wrong setting", content: boundedMDMBlock(strings.Replace(stdSettingsBody, "save-exact=true", "save-exact=false", 1))},
		{name: "partial block", content: boundedMDMBlock(strings.Replace(stdSettingsBody, "engine-strict=true\n", "", 1))},
		{name: "later setting override", content: boundedMDMBlock(stdSettingsBody) + "save-exact=false\n"},
		{name: "duplicate bounded block", content: boundedMDMBlock(stdSettingsBody) + boundedMDMBlock(stdSettingsBody)},
		{name: "missing end", content: npmrcMDMBeginMarker + "\n" + stdSettingsBody + "\n"},
		{name: "managed array", content: boundedMDMBlock(stdSettingsBody) + "save-exact[]=false\n"},
		{name: "section", content: "[team]\n" + boundedMDMBlock(stdSettingsBody)},
		{name: "marker planted in dmg block", content: block(npmrcMDMBeginMarker + "\n" + stdSettingsBody + "\n" + npmrcMDMEndMarker)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			managed, _ := probeNPMRCContent(tc.content, stdSettingsBody)
			if managed != tc.managed {
				t.Fatalf("managed = %v, want %v", managed, tc.managed)
			}
		})
	}

	if managed, _ := probeNPMRCContent(boundedMDMBlock(stdSettingsBody), stdBody); managed {
		t.Fatal("bounded settings block must not satisfy a base-only policy")
	}
	present, observed, err := probeNPMRCObserved(boundedMDMBlock(stdSettingsBody), stdBody)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("bounded settings block must not claim base-only MDM ownership")
	}
	if observed != nil {
		t.Fatalf("bounded settings block produced base-only evidence: %v", observed)
	}
}

func TestProbeContent_MarkerInsideOurBlockIgnored(t *testing.T) {
	// A user cannot force mdm_managed by planting the MDM marker inside our own
	// block — condition 1 searches only outside it.
	content := npmrcBeginMarker + "\n" + npmrcMDMMarker + "\nregistry=" + stdRegistry + "\n" + stdTokenKey + "=" + stdTokenVal + "\n" + npmrcEndMarker + "\n"
	if managed, _ := probeNPMRCContent(content, stdBody); managed {
		t.Fatal("MDM marker inside our block must not count as MDM-managed")
	}
}

// ---------------------------------------------------------------------------
// resolver predicates (pure)
// ---------------------------------------------------------------------------

func TestSymlinkTargetPredicates(t *testing.T) {
	absCases := []string{"/etc/passwd", "/home/u/.npmrc"}
	for _, c := range absCases {
		if !isAbsSymlinkTarget(c) {
			t.Fatalf("isAbsSymlinkTarget(%q) = false, want true", c)
		}
	}
	for _, c := range []string{"dotfiles/npmrc", "../up", "npmrc"} {
		if isAbsSymlinkTarget(c) {
			t.Fatalf("isAbsSymlinkTarget(%q) = true, want false", c)
		}
	}
	// The GO-2026-4970 trigger: a directory-shaped raw target.
	for _, c := range []string{"file/", "dir/.", "."} {
		if !endsInSeparatorOrDot(c) {
			t.Fatalf("endsInSeparatorOrDot(%q) = false, want true", c)
		}
	}
	for _, c := range []string{"file", "dotfiles/npmrc"} {
		if endsInSeparatorOrDot(c) {
			t.Fatalf("endsInSeparatorOrDot(%q) = true, want false", c)
		}
	}
}

// isTargetUnusable mirrors the reconciler's future structural-error
// classification.
func isTargetUnusable(err error) bool {
	return errors.Is(err, ErrTargetUnusable)
}

// ---------------------------------------------------------------------------
// settings-only policy (no StepSecurity registry_url/auth pair)
// ---------------------------------------------------------------------------

const stdSettingsOnlyBody = "//packages.example.com/npm/:_authToken=${EXAMPLE_NPM_TOKEN}\nregistry=https://packages.example.com/npm/\nsave-exact=true"

func npmSettingsOnlyPolicy(t *testing.T, settings any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"ecosystem": "npm", "settings": settings})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func stdSettingsOnlySettings() map[string]string {
	return map[string]string{
		"save-exact":                             "true",
		"registry":                               "https://packages.example.com/npm/",
		"//packages.example.com/npm/:_authToken": "${EXAMPLE_NPM_TOKEN}",
	}
}

func TestRenderNPMRCBlock_SettingsOnly(t *testing.T) {
	got, err := RenderNPMRCBlock(npmSettingsOnlyPolicy(t, stdSettingsOnlySettings()), stdSerial)
	if err != nil {
		t.Fatalf("RenderNPMRCBlock: %v", err)
	}
	if got != stdSettingsOnlyBody {
		t.Fatalf("rendered body = %q, want %q", got, stdSettingsOnlyBody)
	}
	if strings.Contains(got, "stepsecurity") || strings.Contains(got, "::dev:") {
		t.Fatalf("settings-only body carries StepSecurity lines: %q", got)
	}

	reordered, err := RenderNPMRCBlock(json.RawMessage(`{"settings":{"save-exact":"true","//packages.example.com/npm/:_authToken":"${EXAMPLE_NPM_TOKEN}","registry":"https://packages.example.com/npm/"},"ecosystem":"npm"}`), stdSerial)
	if err != nil {
		t.Fatal(err)
	}
	if reordered != got {
		t.Fatalf("map order changed rendering: %q != %q", reordered, got)
	}

	scopedOnly, err := RenderNPMRCBlock(npmSettingsOnlyPolicy(t, map[string]string{
		"@example:registry":                "https://registry.npmjs.org/",
		"//registry.npmjs.org/:_authToken": "${EXAMPLE_NPM_TOKEN}",
	}), stdSerial)
	if err != nil {
		t.Fatalf("scoped-registry-only policy: %v", err)
	}
	if scopedOnly != "//registry.npmjs.org/:_authToken=${EXAMPLE_NPM_TOKEN}\n@example:registry=https://registry.npmjs.org/" {
		t.Fatalf("scoped-only body = %q", scopedOnly)
	}

	desired, ok := parseNPMDesired(got)
	if !ok {
		t.Fatal("settings-only body did not parse")
	}
	if desired.stepSecurity() || desired.registry != "" || desired.tokenKey != "" {
		t.Fatalf("settings-only body parsed as StepSecurity-backed: %+v", desired)
	}
	if len(desired.settings) != 3 || desired.values["registry"] != "https://packages.example.com/npm/" {
		t.Fatalf("settings-only registry is not an ordinary setting: %+v", desired)
	}
	withPair, ok := parseNPMDesired(stdSettingsBody)
	if !ok || !withPair.stepSecurity() || withPair.registry != stdRegistry || withPair.tokenKey != stdTokenKey || len(withPair.settings) != 4 {
		t.Fatalf("StepSecurity pair not recognized: %+v", withPair)
	}
}

func TestRenderNPMRCBlock_SettingsOnlyRejections(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{name: "neither registry nor settings", raw: json.RawMessage(`{"ecosystem":"npm"}`)},
		{name: "registry_url without auth", raw: json.RawMessage(`{"ecosystem":"npm","registry_url":"` + stdRegistry + `","settings":{"save-exact":"true"}}`)},
		{name: "auth without registry_url", raw: json.RawMessage(`{"ecosystem":"npm","auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"},"settings":{"save-exact":"true"}}`)},
		{name: "null registry_url and auth", raw: json.RawMessage(`{"ecosystem":"npm","registry_url":null,"auth":null,"settings":{"registry":"https://packages.example.com/npm/"}}`)},
		{name: "non-string registry_url", raw: json.RawMessage(`{"ecosystem":"npm","registry_url":1,"auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"}}`)},
		{name: "ordinary settings without a registry", raw: npmSettingsOnlyPolicy(t, map[string]string{"save-exact": "true"})},
		{name: "case-variant registry is not a registry", raw: npmSettingsOnlyPolicy(t, map[string]string{"Registry": "https://packages.example.com/npm/"})},
		{name: "non-canonical default registry", raw: npmSettingsOnlyPolicy(t, map[string]string{"registry": "https://packages.example.com/npm"})},
		{name: "http default registry", raw: npmSettingsOnlyPolicy(t, map[string]string{"registry": "http://packages.example.com/npm/"})},
		{name: "token unpaired with the default registry", raw: npmSettingsOnlyPolicy(t, map[string]string{"registry": "https://packages.example.com/npm/", "//other.example/:_authToken": "${TOKEN}"})},
		{name: "literal default registry token", raw: npmSettingsOnlyPolicy(t, map[string]string{"registry": "https://packages.example.com/npm/", "//packages.example.com/npm/:_authToken": "literal"})},
		{name: "empty settings", raw: npmSettingsOnlyPolicy(t, map[string]string{})},
		{name: "null settings", raw: npmSettingsOnlyPolicy(t, nil)},
		{name: "settings.registry with StepSecurity registry", raw: npmSettingsPolicy(t, map[string]string{"registry": "https://packages.example.com/npm/"})},
		{name: "scoped registry targeting the StepSecurity registry", raw: npmSettingsPolicy(t, map[string]string{"@team:registry": stdRegistry + "/"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RenderNPMRCBlock(tc.raw, stdSerial); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	if _, err := RenderNPMRCBlock(npmSettingsOnlyPolicy(t, stdSettingsOnlySettings()), ""); err == nil {
		t.Fatal("settings-only policy accepted an empty device serial")
	}
}

func TestRenderNPMRCBlock_SettingsOnlySizeBoundary(t *testing.T) {
	const registry = "registry=https://packages.example.com/npm/\n"
	key := "x"
	atLimit := strings.Repeat("v", npmrcMaxRenderedBytes-len(registry)-len(key)-1)
	settings := map[string]string{"registry": "https://packages.example.com/npm/", key: atLimit}
	body, err := RenderNPMRCBlock(npmSettingsOnlyPolicy(t, settings), stdSerial)
	if err != nil {
		t.Fatalf("body at limit: %v", err)
	}
	if len(body) != npmrcMaxRenderedBytes {
		t.Fatalf("rendered length = %d, want %d", len(body), npmrcMaxRenderedBytes)
	}
	settings[key] = atLimit + "v"
	if _, err := RenderNPMRCBlock(npmSettingsOnlyPolicy(t, settings), stdSerial); err == nil {
		t.Fatal("body above limit was accepted")
	}
}

func TestRewrite_SettingsOnlyRegistryIsAnOrdinarySetting(t *testing.T) {
	initial := "registry=https://old.example/\nsave-exact=false\n"
	w := &NPMRCWriter{}
	applied, err := w.rewriteContent([]byte(initial), stdSettingsOnlyBody)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if string(applied) != initial+block(stdSettingsOnlyBody) {
		t.Fatalf("settings-only rewrite = %q, want user lines untouched and block appended", applied)
	}
	if !blockIsLastEffective(strings.Split(string(applied), "\n"), stdSettingsOnlyBody) {
		t.Fatal("appended settings-only block was not last-effective")
	}
	again, err := w.rewriteContent(applied, stdSettingsOnlyBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(applied) {
		t.Fatalf("repeated rewrite changed bytes: %q", again)
	}

	overridden := append(append([]byte(nil), applied...), []byte("registry=https://later.example/\n")...)
	if blockIsLastEffective(strings.Split(string(overridden), "\n"), stdSettingsOnlyBody) {
		t.Fatal("later registry override must defeat convergence")
	}
	repaired, err := w.rewriteContent(overridden, stdSettingsOnlyBody)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(repaired), "\nregistry=https://later.example/\n") || strings.Contains(string(repaired), npmrcDMGPrefix) {
		t.Fatalf("settings-only repair must keep the user registry line unprefixed: %q", repaired)
	}
	if !strings.HasSuffix(string(repaired), block(stdSettingsOnlyBody)) {
		t.Fatal("repair did not move the managed block last")
	}

	if _, err := w.rewriteContent([]byte("registry[]=https://evil.example/\n"), stdSettingsOnlyBody); !errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("settings-only registry array error = %v, want target unusable", err)
	}

	cleared, err := w.clearContent(applied)
	if err != nil {
		t.Fatal(err)
	}
	if string(cleared) != initial {
		t.Fatalf("clear = %q, want %q", cleared, initial)
	}
}

func TestRewrite_StepSecurityToSettingsOnlyTransition(t *testing.T) {
	initial := "registry=https://old.example/\n"
	w := &NPMRCWriter{}
	stepSecurity, err := w.rewriteContent([]byte(initial), stdSettingsBody)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(stepSecurity), npmrcDMGPrefix+"registry=https://old.example/\n") {
		t.Fatalf("StepSecurity shape did not prefix the bare registry: %q", stepSecurity)
	}

	settingsOnly, err := w.rewriteContent(stepSecurity, stdSettingsOnlyBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(settingsOnly) != initial+block(stdSettingsOnlyBody) {
		t.Fatalf("transition to settings-only = %q, want restored registry line then block", settingsOnly)
	}

	back, err := w.rewriteContent(settingsOnly, stdBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != npmrcDMGPrefix+initial+block(stdBody) {
		t.Fatalf("transition back to StepSecurity = %q, want re-prefixed registry then block", back)
	}
	restored, err := w.clearContent(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != initial {
		t.Fatalf("clear after round trip = %q, want %q", restored, initial)
	}
}

func TestProbeContent_SettingsOnlyBoundedMDMBlock(t *testing.T) {
	cases := []struct {
		name    string
		content string
		managed bool
	}{
		{name: "exact bounded block", content: boundedMDMBlock(stdSettingsOnlyBody), managed: true},
		{name: "exact block after unrelated user config", content: "save-exact=false\n" + boundedMDMBlock(stdSettingsOnlyBody), managed: true},
		{name: "fixed StepSecurity block", content: mdmBlock()},
		{name: "wrong registry", content: boundedMDMBlock(strings.Replace(stdSettingsOnlyBody, "packages.example.com/npm/\n", "other.example/\n", 1))},
		{name: "partial block", content: boundedMDMBlock(strings.Replace(stdSettingsOnlyBody, "\nsave-exact=true", "", 1))},
		{name: "later registry override", content: boundedMDMBlock(stdSettingsOnlyBody) + "registry=https://later.example/\n"},
		{name: "registry array", content: boundedMDMBlock(stdSettingsOnlyBody) + "registry[]=https://later.example/\n"},
		{name: "duplicate bounded block", content: boundedMDMBlock(stdSettingsOnlyBody) + boundedMDMBlock(stdSettingsOnlyBody)},
		{name: "section", content: "[team]\n" + boundedMDMBlock(stdSettingsOnlyBody)},
		{name: "marker planted in dmg block", content: block(npmrcMDMBeginMarker + "\n" + stdSettingsOnlyBody + "\n" + npmrcMDMEndMarker)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			managed, _ := probeNPMRCContent(tc.content, stdSettingsOnlyBody)
			if managed != tc.managed {
				t.Fatalf("managed = %v, want %v", managed, tc.managed)
			}
		})
	}
	if managed, _ := probeNPMRCContent(boundedMDMBlock(stdSettingsOnlyBody), stdBody); managed {
		t.Fatal("settings-only bounded block must not satisfy a StepSecurity-only policy")
	}
}
