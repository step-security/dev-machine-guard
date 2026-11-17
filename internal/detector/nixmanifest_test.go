package detector

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

const (
	nixHello    = "/nix/store/jppkr0h8aap5z7m4xy4vg5yrwlly9h2v-hello-2.12.1"
	nixZlib     = "/nix/store/mrmm3hc3s1f6wnszxnwqfxvxhbchqbbi-zlib-1.3.1"
	nixZlibDev  = "/nix/store/kkgnjmnpshqw9xbw8x39g1pl1a3h15xx-zlib-1.3.1-dev"
	nixNixStore = "/nix/store/3351s56n7qxjdvpckhbkyg9ihyspfv8k-nix-2.28.5"
)

// nixRecord renders the fields a reader keys on, so expectations stay short.
func nixRecord(p model.SystemPackage) string {
	active := "nil"
	if p.Active != nil {
		active = fmt.Sprint(*p.Active)
	}
	var outs []string
	for _, o := range p.Outputs {
		outs = append(outs, o.Name+"="+o.Path)
	}
	element := p.Element
	if strings.HasPrefix(element, "paths:") {
		element = "paths:"
	}
	return fmt.Sprintf("%s %s element=%s active=%s install=%s outputs=%s", p.Name, p.Version, element, active, p.InstallPath, strings.Join(outs, ","))
}

// Expected names and versions come from the native `nix profile list` and
// `nix-env -q --json` captures taken with each fixture.
func TestParseNixManifest_NativeFixtures(t *testing.T) {
	tests := []struct {
		file string
		want []string
	}{
		{"modern-installed-manifest.json", []string{"hello 2.12.1 element=hello active=true install=" + nixHello + " outputs==" + nixHello}},
		{"multi-manifest.json", []string{"zlib 1.3.1 element=zlib active=true install=" + nixZlib + " outputs=dev=" + nixZlibDev + ",out=" + nixZlib}},
		{"direct-manifest.json", []string{"nix 2.28.5 element=nix active=true install=" + nixNixStore + " outputs==" + nixNixStore}},
		{"hm-profile-manifest.json", []string{"home-manager-path unknown element=home-manager-path active=true install=/nix/store/h1crmzbbn7mv1j6x3ki2kc72l1qwvwjs-home-manager-path outputs==/nix/store/h1crmzbbn7mv1j6x3ki2kc72l1qwvwjs-home-manager-path"}},
		{"modern-removed-manifest.json", nil},
		{"legacy-hello-manifest.nix", []string{"hello 2.12.1 element=paths: active=true install=" + nixHello + " outputs=out=" + nixHello}},
		{"legacy-inactive-manifest.nix", []string{"hello 2.12.1 element=paths: active=false install=" + nixHello + " outputs=out=" + nixHello}},
		{"legacy-manifest.nix", []string{"nix 2.28.5 element=paths: active=true install=" + nixNixStore + " outputs=out=" + nixNixStore}},
		{"legacy-full-meta-manifest.nix", []string{"hello 2.12.1 element=paths: active=true install=" + nixHello + " outputs=out=" + nixHello}},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile("testdata/nix/" + tc.file)
			if err != nil {
				t.Fatal(err)
			}
			parse := parseNixManifestJSON
			if strings.HasSuffix(tc.file, ".nix") {
				parse = parseNixManifestLegacy
			}
			pkgs, incomplete, err := parse(data)
			if err != nil || incomplete {
				t.Fatalf("err %v incomplete %v", err, incomplete)
			}
			var got []string
			for _, p := range pkgs {
				got = append(got, nixRecord(p))
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("records:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

// Versions 1 and 2 are written from the Nix source history, not captured from
// a producing release; they support the parser, not a support claim.
func TestParseNixManifest_Cases(t *testing.T) {
	tests := []struct {
		name, json, legacy string
		want               string
		incomplete         bool
		err                error
	}{
		{name: "source-derived v1", json: `{"version":1,"elements":[{"active":true,"uri":"x","storePaths":["` + nixHello + `"]}]}`,
			want: "hello 2.12.1 element=paths: active=true install=" + nixHello + " outputs==" + nixHello},
		{name: "source-derived v2 with outputs", json: `{"version":2,"elements":[{"active":false,"url":"x","outputs":["out","dev"],"storePaths":["` + nixZlibDev + `","` + nixZlib + `"]}]}`,
			want: "zlib 1.3.1 element=paths: active=false install=" + nixZlib + " outputs=dev=" + nixZlibDev + ",out=" + nixZlib},
		{name: "outputs that do not name the paths stay unknown", json: `{"version":3,"elements":{"z":{"outputs":["bin","lib"],"storePaths":["` + nixZlibDev + `","` + nixZlib + `"]}}}`,
			want: "z unknown element=z active=nil install=" + nixZlibDev + " outputs==" + nixZlibDev + ",=" + nixZlib},
		{name: "element without store paths is incomplete", json: `{"version":3,"elements":{"a":{"active":true},"b":{"storePaths":["` + nixHello + `"]}}}`,
			want: "hello 2.12.1 element=b active=nil install=" + nixHello + " outputs==" + nixHello, incomplete: true},
		{name: "null or mistyped active stays unknown", json: `{"version":3,"elements":{"a":{"active":null,"storePaths":["` + nixHello + `"]},"b":{"active":"yes","storePaths":["` + nixZlib + `"]}}}`,
			want: "hello 2.12.1 element=a active=nil install=" + nixHello + " outputs==" + nixHello + "\n" +
				"zlib 1.3.1 element=b active=nil install=" + nixZlib + " outputs==" + nixZlib},
		{name: "empty elements are an empty profile", json: `{"version":3,"elements":{}}`},
		{name: "empty v2 elements are an empty profile", json: `{"version":2,"elements":[]}`},
		{name: "null elements are unparsed", json: `{"version":3,"elements":null}`, err: errNixUnparsed},
		{name: "null v2 elements are unparsed", json: `{"version":2,"elements":null}`, err: errNixUnparsed},
		{name: "path outside the store is incomplete", json: `{"version":3,"elements":{"a":{"storePaths":["/tmp/x"]}}}`, incomplete: true},
		{name: "unknown version", json: `{"version":4,"elements":{}}`, err: errNixUnsupportedVersion},
		{name: "trailing data", json: `{"version":3,"elements":{}} {}`, err: errNixUnparsed},
		{name: "depth inside a skipped field", json: `{"version":3,"elements":{},"x":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`, err: errNixUnparsed},
		{name: "legacy string false is inactive", legacy: `[ { meta = { active = "false"; }; name = "hello-2.12.1"; outPath = "` + nixHello + `"; } ]`,
			want: "hello 2.12.1 element=paths: active=false install=" + nixHello + " outputs=out=" + nixHello},
		{name: "legacy interpolation is never evaluated", legacy: `[ { name = "x-${y}"; outPath = "` + nixHello + `"; } ]`, err: errNixUnparsed},
		{name: "legacy function call", legacy: `[ (import ./x.nix) ]`, err: errNixUnparsed},
		{name: "legacy variable", legacy: `[ { name = pkgs.hello; } ]`, err: errNixUnparsed},
		{name: "legacy depth bomb in metadata", legacy: `[ { meta = ` + strings.Repeat("[ ", 40) + strings.Repeat("] ", 40) + `; } ]`, err: errNixUnparsed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var pkgs []model.SystemPackage
			var incomplete bool
			var err error
			if tc.legacy != "" {
				pkgs, incomplete, err = parseNixManifestLegacy([]byte(tc.legacy))
			} else {
				pkgs, incomplete, err = parseNixManifestJSON([]byte(tc.json))
			}
			if !errors.Is(err, tc.err) || (tc.err == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			var got []string
			for _, p := range pkgs {
				got = append(got, nixRecord(p))
			}
			if strings.Join(got, "\n") != tc.want || incomplete != tc.incomplete {
				t.Errorf("records %q incomplete %v, want %q incomplete %v", got, incomplete, tc.want, tc.incomplete)
			}
		})
	}
}

// The derived key is order-independent and framed, so path sets that join to
// the same string do not collide.
func TestNixPathsKey(t *testing.T) {
	a := legacyKey(t, nixZlib, nixZlibDev)
	if b := legacyKey(t, nixZlibDev, nixZlib); a != b {
		t.Errorf("key depends on order: %s vs %s", a, b)
	}
	if nixPathsKey([]string{"ab", "c"}) == nixPathsKey([]string{"a", "bc"}) {
		t.Error("framing does not separate paths")
	}
}

func legacyKey(t *testing.T, out, dev string) string {
	t.Helper()
	pkgs, _, err := parseNixManifestLegacy([]byte(`[ { name = "zlib-1.3.1"; outputs = [ "out" "dev" ]; out = { outPath = "` + out + `"; }; dev = { outPath = "` + dev + `"; }; } ]`))
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("parse: %v", err)
	}
	return pkgs[0].Element
}
