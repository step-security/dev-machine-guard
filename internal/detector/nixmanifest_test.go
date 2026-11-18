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

func nixRecords(pkgs []model.SystemPackage) string {
	var out []string
	for _, p := range pkgs {
		out = append(out, fmt.Sprintf("%s %s %s", p.Name, p.Version, p.InstallPath))
	}
	return strings.Join(out, "\n")
}

// Expected names and versions come from the native `nix profile list` and
// `nix-env -q --json` captures taken with each fixture.
func TestParseNixManifest_NativeFixtures(t *testing.T) {
	tests := []struct {
		file string
		want string
	}{
		{"modern-installed-manifest.json", "hello 2.12.1 " + nixHello},
		{"multi-manifest.json", "zlib 1.3.1 " + nixZlib},
		{"direct-manifest.json", "nix 2.28.5 " + nixNixStore},
		{"hm-profile-manifest.json", "home-manager-path unknown /nix/store/h1crmzbbn7mv1j6x3ki2kc72l1qwvwjs-home-manager-path"},
		{"modern-removed-manifest.json", ""},
		{"legacy-hello-manifest.nix", "hello 2.12.1 " + nixHello},
		{"legacy-inactive-manifest.nix", "hello 2.12.1 " + nixHello},
		{"legacy-manifest.nix", "nix 2.28.5 " + nixNixStore},
		{"legacy-full-meta-manifest.nix", "hello 2.12.1 " + nixHello},
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
			if got := nixRecords(pkgs); got != tc.want {
				t.Errorf("records:\n%s\nwant:\n%s", got, tc.want)
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
			want: "hello 2.12.1 " + nixHello},
		{name: "source-derived v2 with outputs", json: `{"version":2,"elements":[{"active":false,"url":"x","outputs":["out","dev"],"storePaths":["` + nixZlibDev + `","` + nixZlib + `"]}]}`,
			want: "zlib 1.3.1 " + nixZlib},
		{name: "outputs that do not name the paths fall back to the first path", json: `{"version":3,"elements":{"z":{"outputs":["bin","lib"],"storePaths":["` + nixZlibDev + `","` + nixZlib + `"]}}}`,
			want: "zlib 1.3.1-dev " + nixZlibDev},
		{name: "element without store paths is incomplete", json: `{"version":3,"elements":{"a":{"active":true},"b":{"storePaths":["` + nixHello + `"]}}}`,
			want: "hello 2.12.1 " + nixHello, incomplete: true},
		{name: "empty elements are an empty profile", json: `{"version":3,"elements":{}}`},
		{name: "empty v2 elements are an empty profile", json: `{"version":2,"elements":[]}`},
		{name: "null elements are unparsed", json: `{"version":3,"elements":null}`, err: errNixUnparsed},
		{name: "null v2 elements are unparsed", json: `{"version":2,"elements":null}`, err: errNixUnparsed},
		{name: "path outside the store is incomplete", json: `{"version":3,"elements":{"a":{"storePaths":["/tmp/x"]}}}`, incomplete: true},
		{name: "unknown version", json: `{"version":4,"elements":{}}`, err: errNixUnparsed},
		{name: "trailing data", json: `{"version":3,"elements":{}} {}`, err: errNixUnparsed},
		{name: "depth inside a skipped field", json: `{"version":3,"elements":{},"x":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`, err: errNixUnparsed},
		{name: "legacy multi-output element", legacy: `[ { name = "zlib-1.3.1"; outputs = [ "dev" "out" ]; dev = { outPath = "` + nixZlibDev + `"; }; out = { outPath = "` + nixZlib + `"; }; } ]`,
			want: "zlib 1.3.1 " + nixZlib},
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
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if got := nixRecords(pkgs); got != tc.want || incomplete != tc.incomplete {
				t.Errorf("records %q incomplete %v, want %q incomplete %v", got, incomplete, tc.want, tc.incomplete)
			}
		})
	}
}
