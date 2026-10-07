package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposerMetadataEvidence(t *testing.T) {
	m, err := parseComposerManifest([]byte(`{"name":"example/app","require":{"example/lib":"dev-main as 1.0.x-dev","php":"^8.2","ext-json":"*","composer-runtime-api":"^2"},"require-dev":{"example/tool":"^2@dev"},"suggest":{"example/optional":"no"},"provide":{"virtual/pkg":"*"},"scripts":{"post-install-cmd":"NEVER_RUN"}}`))
	if err != nil || m.partial || len(m.packages) != 2 {
		t.Fatalf("manifest: %+v %v", m, err)
	}
	if p := m.packages[0]; p.PackageName != "example/lib" || p.VersionStatus != "unknown" || p.Version != "" || p.RequestedVersion != "dev-main as 1.0.x-dev" || p.DependencyRelation != "direct" {
		t.Fatalf("declaration: %+v", p)
	}
	for _, tc := range []struct {
		name, body  string
		installed   bool
		kinds       []string
		installPath string
	}{
		{"lock", `{"packages":[{"name":"example/lib","version":"dev-main"},{"name":"example/transitive","version":"1.2.3"}],"packages-dev":[{"name":"example/tool","version":"2.1.0"}],"aliases":[{"package":"example/lib","alias":"1.0.x-dev"}]}`, false, []string{"require", "require", "require_dev"}, ""},
		{"current", `{"packages":[{"name":"example/lib","version":"1.2.3","require-dev":{"vendor/dev":"*"}}],"dev":false,"dev-package-names":[]}`, true, []string{"require"}, ""},
		{"mixed dev", `{"packages":[{"name":"example/lib","version":"1"},{"name":"example/tool","version":"2"}],"dev-package-names":["example/tool"]}`, true, []string{"require", "require_dev"}, ""},
		{"no-dev", `{"packages":[{"name":"example/lib","version":"1"}],"dev":false,"dev-package-names":["example/tool"]}`, true, []string{"require"}, ""},
		{"custom installer", `{"packages":[{"name":"example/wp-plugin","version":"1","type":"wordpress-plugin","install-path":"../../wp-content/plugins/wp-plugin"}]}`, true, []string{"unknown"}, "../../wp-content/plugins/wp-plugin"},
		{"empty legacy", `[]`, true, []string{}, ""},
		{"empty current", `{"packages":[]}`, true, []string{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, partial, err := parseComposerPackages([]byte(tc.body), tc.installed)
			if err != nil || partial || len(entries) != len(tc.kinds) {
				t.Fatalf("entries=%+v partial=%v err=%v", entries, partial, err)
			}
			for i, e := range entries {
				if e.pkg.DependencyKind != tc.kinds[i] || e.installPath != tc.installPath {
					t.Fatalf("entry %d: %+v", i, e)
				}
			}
		})
	}
}
func TestComposerMetadataMalformedNeighborsAndBounds(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"packages":null}`, `{"packages":{}}`, `{"packages":[`, `false`} {
		if _, _, err := parseComposerPackages([]byte(body), true); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
	entries, partial, err := parseComposerPackages([]byte(`{"packages":[null,{"name":"../evil","version":"1"},{"name":"example/good","version":"dev-main","version_normalized":"dev-main"},{"name":"example/missing"}]}`), true)
	if err != nil || !partial || len(entries) != 1 || entries[0].pkg.PackageName != "example/good" {
		t.Fatalf("neighbors %+v %v %v", entries, partial, err)
	}
	old := maxComposerMetadataBytes
	t.Cleanup(func() { maxComposerMetadataBytes = old })
	maxComposerMetadataBytes = 8
	if _, _, err := parseComposerPackages([]byte(`{"packages":[]}`), true); err == nil {
		t.Fatal("accepted oversized metadata")
	}
}
func TestComposerMetadataChecksumAndURLs(t *testing.T) {
	for _, tc := range []struct {
		hash, status string
		count        int
	}{{"", "absent", 0}, {strings.Repeat("AB", 20), "recorded", 1}, {"SECRET_CANARY", "partial", 0}, {strings.Repeat("f", 39), "partial", 0}} {
		body := `{"packages":[{"name":"example/lib","version":"1.0.0","source":{"type":"git","url":"https://alice:SECRET_CANARY@code.example.invalid/lib?secret=SECRET_CANARY#SECRET_CANARY","reference":"branch/release"},"dist":{"type":"zip","url":"https://dist.example.invalid/lib.zip?token=SECRET_CANARY","reference":"branch/release","shasum":"` + tc.hash + `"}}]}`
		entries, partial, err := parseComposerPackages([]byte(body), false)
		if err != nil || partial || len(entries) != 1 {
			t.Fatalf("parse %+v %v %v", entries, partial, err)
		}
		p := entries[0].pkg
		if p.ChecksumStatus != tc.status || len(p.RecordedChecksums) != tc.count {
			t.Fatalf("checksum %+v", p)
		}
		encoded, _ := json.Marshal(p)
		if strings.Contains(string(encoded), "SECRET_CANARY") {
			t.Fatal("secret survived")
		}
		if p.Source.Type != "git" || p.Source.URL != "https://code.example.invalid/lib" || p.Source.Reference != "branch/release" || p.Dist.Type != "zip" || p.Dist.URL != "https://dist.example.invalid/lib.zip" || p.Dist.Reference != "branch/release" {
			t.Fatalf("descriptors %+v %+v", p.Source, p.Dist)
		}
		if tc.count > 0 && (p.RecordedChecksums[0].Value != strings.Repeat("ab", 20) || p.RecordedChecksums[0].Verification != "not_verified") {
			t.Fatal("checksum normalization")
		}
	}
}

// Sanitized receipts from the research archive dated 2026-10-04, including
// Composer 1.10.28 and 2.2.30. Only parser-allowlisted package fields remain.
// These format tests do not substitute for the product VM acceptance run.
func TestComposerNativeMetadataFixtures(t *testing.T) {
	for _, tc := range []struct{ name, kind, installPath string }{
		{"composer1", "unknown", ""},
		{"composer22", "require", "../example/contracts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "composer", tc.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			entries, partial, err := parseComposerPackages(data, true)
			if err != nil || partial || len(entries) != 1 {
				t.Fatalf("native metadata %d %v %v", len(entries), partial, err)
			}
			e := entries[0]
			if e.pkg.PackageName != "example/contracts" || e.pkg.Version != "1.0.0" || e.pkg.VersionNormalized != "1.0.0.0" || e.pkg.DependencyKind != tc.kind || e.installPath != tc.installPath || e.pathProvided != (tc.installPath != "") {
				t.Fatalf("native entry %+v", e)
			}
		})
	}
}
func TestComposerAlternateLockNames(t *testing.T) {
	for input, want := range map[string]string{"composer.json": "composer.lock", "backend.json": "backend.lock", "deps.manifest": "deps.manifest.lock"} {
		if got := composerLockPath(input); got != want {
			t.Errorf("%s -> %s", input, got)
		}
	}
}

func TestComposerMetadataMalformedMetapackagePath(t *testing.T) {
	entries, partial, err := parseComposerPackages([]byte(`{"packages":[{"name":"example/meta","version":"1","type":"metapackage","install-path":"../bad"}]}`), true)
	if err != nil || !partial || len(entries) != 1 || entries[0].installPath != "" {
		t.Fatal("malformed metapackage path could invalidate the whole inventory")
	}
}

func TestComposerManifestPlatformNamesAndVendorNamespaces(t *testing.T) {
	m, err := parseComposerManifest([]byte(`{"require":{"php":"^8","php-64bit":"^8","php-ipv6":"^8","php-zts":"^8","php-debug":"^8","composer":"^2","composer-plugin-api":"^2","composer-runtime-api":"^2","ext-json":"*","lib-curl":"*","ext-example/lib":"^1","lib-example/lib":"^1","php-example/lib":"^1","composer-example/lib":"^1"}}`))
	if err != nil || m.partial || len(m.packages) != 4 {
		t.Fatalf("platform requirements affected package enumeration: %+v, %v", m, err)
	}
	for _, p := range m.packages {
		if !strings.Contains(p.PackageName, "/") {
			t.Fatal("platform emitted as package")
		}
	}
}
