package devicepolicy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Standard fixture policy + serial shared across the pure-layer tests.
const (
	stdSerial     = "SERIAL123"
	stdPolicyJSON = `{"ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"}}`
	stdBody       = "registry=https://registry-int.stepsecurity.io/javascript\n//registry-int.stepsecurity.io/javascript/:_authToken=ssabc123::dev:SERIAL123"
	stdRegistry   = "https://registry-int.stepsecurity.io/javascript"
	stdTokenKey   = "//registry-int.stepsecurity.io/javascript/:_authToken"
	stdTokenVal   = "ssabc123::dev:SERIAL123"
)

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

// ---------------------------------------------------------------------------
// clearContent — the §3 clear algorithm (pure []byte -> []byte)
// ---------------------------------------------------------------------------

func clearOf(current string) string {
	w := &NPMRCWriter{}
	return string(w.clearContent([]byte(current)))
}

func TestClear_RestoresAndPreserves(t *testing.T) { // edge 9
	// A file the writer previously converged: original registry commented, MDM
	// line present, our block at the bottom.
	current := "# [stepsecurity-dmg] registry=https://registry.npmjs.org/\n" +
		"# [stepsecurity] registry=https://mdm/\n" +
		block(stdBody)
	got := clearOf(current)
	want := "registry=https://registry.npmjs.org/\n# [stepsecurity] registry=https://mdm/\n"
	if got != want {
		t.Fatalf("clear mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestClear_ShellOnlyBlockRemoved(t *testing.T) { // edge 24
	current := npmrcBeginMarker + "\n" + npmrcEndMarker + "\n"
	if got := clearOf(current); got != "" {
		t.Fatalf("shell-only block should clear to empty, got %q", got)
	}
}

func TestClear_NeverUnprefixesMDM(t *testing.T) {
	current := "# [stepsecurity] registry=https://mdm/\n" + block(stdBody)
	got := clearOf(current)
	if !strings.Contains(got, "# [stepsecurity] registry=https://mdm/\n") {
		t.Fatalf("clear must not un-comment the MDM lane's prefix: %q", got)
	}
}

func TestClear_MissingFinalNewlineNotRestored(t *testing.T) { // edge 34 (clear)
	// Enforce turned "foo" (no trailing newline) into "foo\n<block>". Clearing
	// keeps the "\n" enforce added — the one permitted byte deviation.
	enforced := rewrite(t, "foo")
	got := clearOf(enforced)
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
		if got := clearOf(out); got != spaced+"\n" {
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

func TestProbeContent_MarkerInsideOurBlockIgnored(t *testing.T) {
	// A user cannot force mdm_managed by planting the MDM marker inside our own
	// block — condition 1 searches only outside it.
	content := npmrcBeginMarker + "\n" + npmrcMDMMarker + "\nregistry=" + stdRegistry + "\n" + stdTokenKey + "=" + stdTokenVal + "\n" + npmrcEndMarker + "\n"
	if managed, _ := probeNPMRCContent(content, stdBody); managed {
		t.Fatal("MDM marker inside our block must not count as MDM-managed")
	}
}

func TestParseExpected(t *testing.T) {
	reg, tokKey, tokVal, ok := parseExpected(stdBody)
	if !ok || reg != stdRegistry || tokKey != stdTokenKey || tokVal != stdTokenVal {
		t.Fatalf("parseExpected = (%q,%q,%q,%v)", reg, tokKey, tokVal, ok)
	}
	if _, _, _, ok := parseExpected("registry=only-one-line"); ok {
		t.Fatal("a single-line body must not parse")
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
