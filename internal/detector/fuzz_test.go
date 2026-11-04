package detector

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func FuzzNodeLockfiles(f *testing.F) {
	for _, seed := range []string{
		`{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0"},"node_modules/@scope/y":{"version":"2.0.0"}}}`,
		`{"dependencies":{"x":{"version":"1","dependencies":{"y":{"version":"2"}}}}}`,
		"packages:\n  x@1.0.0:\n    resolution: {integrity: sha512-test}\n",
		"x@^1.0.0:\n  version \"1.0.0\"\n",
		`{"packages":{"x":["x@1.0.0","",{},"sha512-test"]}}`,
		"", "{", "\xff\x00",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16*1024 {
			t.Skip()
		}
		d := NewNodeDistDetector(executor.NewMock())
		direct := map[string]struct{}{"x": {}, "@scope/y": {}}
		for _, parse := range []lockfileParser{d.parsePackageLock, d.parsePnpmLock, d.parseYarnLock, d.parseBunLock} {
			before := bytes.Clone(data)
			a := dedupSortPackages(parse(data, direct))
			b := dedupSortPackages(parse(data, direct))
			if !bytes.Equal(data, before) {
				t.Fatal("parser mutated input")
			}
			if !slices.Equal(a, b) {
				t.Fatal("inventory depends on map iteration or prior invocation")
			}
			// Nil and empty slices represent the same normalized package set.
			if !slices.Equal(a, dedupSortPackages(a)) {
				t.Fatal("normalization is not idempotent")
			}
			for i, p := range a {
				if p.Name == "" || p.Version == "" {
					t.Fatal("empty package identity")
				}
				_, want := direct[p.Name]
				if p.IsDirect != want {
					t.Fatalf("directness for %q=%v, want %v", p.Name, p.IsDirect, want)
				}
				if i > 0 && (a[i-1].Name > p.Name || (a[i-1].Name == p.Name && a[i-1].Version >= p.Version)) {
					t.Fatal("inventory is not sorted and unique")
				}
			}
		}
	})
}

func FuzzPythonMetadata(f *testing.F) {
	for _, s := range []string{"Name: example\nVersion: 1.0\n\nName: ignored", "Name: x\r\nVersion: 2\r\n", "Name:\n continuation\n", "", "\xff\x00"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16*1024 {
			t.Skip()
		}
		name, version := parseRFC822NameVersion(data)
		if name != strings.TrimSpace(name) || version != strings.TrimSpace(version) {
			t.Fatal("untrimmed package identity")
		}
		// A known header followed by the fuzzed body must keep the header identity.
		for _, sep := range []string{"\n", "\r\n"} {
			b := append([]byte("Name: fuzz-package"+sep+"Version: 1.2.3"+sep+sep), data...)
			n, v := parseRFC822NameVersion(b)
			if n != "fuzz-package" || v != "1.2.3" {
				t.Fatal("body overrode metadata headers")
			}
		}
		// Once a blank line terminates arbitrary headers, appended fields are body.
		b := append(bytes.Clone(data), '\n', '\n')
		n, v := parseRFC822NameVersion(b)
		b = append(b, []byte("Name: injected\nVersion: 999\n")...)
		n2, v2 := parseRFC822NameVersion(b)
		if n != n2 || v != v2 {
			t.Fatal("body fields changed parsed identity")
		}
	})
}

// FuzzRubyMetadata feeds one input to every Ruby parser: each must be
// deterministic, leave its input untouched, and admit only valid identities.
func FuzzRubyMetadata(f *testing.F) {
	for _, s := range []string{
		"source \"https://rubygems.org\"\ngem \"rack\", \"~> 3.0\", group: :test\n",
		"Gem::Specification.new do |s|\n  s.name = \"x\"\n  s.version = \"1.0\"\n  s.add_dependency \"y\"\nend\n",
		"GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.8)\n\nDEPENDENCIES\n  rack!\n\nCHECKSUMS\n  rack (3.0.8) sha256=bad\n",
		rubyStubHeader, "gem \"x\" if ENV[\"X\"]\n", "", "\xff\x00",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16*1024 {
			t.Skip()
		}
		before := bytes.Clone(data)
		for _, parse := range []func([]byte) (*rubyManifest, error){parseRubyGemfile, parseRubyGemspec} {
			m, err := parse(data)
			m2, err2 := parse(data)
			if !reflect.DeepEqual(m, m2) || (err == nil) != (err2 == nil) {
				t.Fatal("manifest parse is not deterministic")
			}
			if err == nil && m != nil {
				for _, d := range m.declarations {
					if !configaudit.RubyGemName(d.name) {
						t.Fatalf("invalid declared name %q", d.name)
					}
				}
			}
		}
		entries, reasons, err := parseRubyLock(data)
		entries2, reasons2, err2 := parseRubyLock(data)
		if !reflect.DeepEqual(entries, entries2) || !slices.Equal(reasons, reasons2) || (err == nil) != (err2 == nil) {
			t.Fatal("lock parse is not deterministic")
		}
		for _, e := range entries {
			if !configaudit.RubyGemName(e.pkg.PackageName) || e.pkg.Version == "" {
				t.Fatalf("invalid locked identity %q %q", e.pkg.PackageName, e.pkg.Version)
			}
		}
		if name, _, _, err := parseRubyStub(data); err == nil && !configaudit.RubyGemName(name) {
			t.Fatalf("invalid stub name %q", name)
		}
		n, v, p, reason := parseRubyArchive(data)
		if n2, v2, p2, reason2 := parseRubyArchive(data); n != n2 || v != v2 || p != p2 || reason != reason2 {
			t.Fatal("archive parse is not deterministic")
		}
		if reason == "" && !configaudit.RubyGemName(n) {
			t.Fatalf("invalid archive name %q", n)
		}
		if !bytes.Equal(data, before) {
			t.Fatal("parser mutated input")
		}
	})
}

// FuzzCondaMetadata feeds one input to every Conda parser: each must be
// deterministic, leave its input untouched, admit only valid identities and
// never pass a credential, token or query through to output.
func FuzzCondaMetadata(f *testing.F) {
	for _, s := range []string{
		condaZlibReceipt,
		`{"name":"x","version":"1","build":"0","channel":"https://u:p@h/t/tok/c/noarch","url":"https://u:p@h/t/tok/c/noarch/x-1-0.conda","requested_specs":["c::x","https://u:p@h/x"]}`,
		"name: a\nchannels:\n  - conda-forge\ndependencies:\n  - python=3.12\n  - conda-forge::numpy>=1.26\n  - pip:\n    - requests\n  - sel(win): m2\n",
		`{"channels":["conda-forge"],"dependencies":["python"]}`,
		"# platform: linux-64\n@EXPLICIT\nhttps://conda.anaconda.org/conda-forge/linux-64/bzip2-1.0.8-h4bc722e_7.conda#" + condaMD5A + "\nfile:///c/noarch/x-1-0.tar.bz2\n",
		"version: 1\npackage:\n- manager: conda\n  name: x\n  version: '1'\n  platform: linux-64\n  url: https://c/linux-64/x-1-0.conda\n  hash:\n    md5: " + condaMD5A + "\n",
		"version: 6\nenvironments:\n  default:\n    packages:\n      linux-64:\n        - conda: https://c/linux-64/x-1-0.conda\npackages:\n  - conda: https://c/linux-64/x-1-0.conda\n    sha256: " + condaSHA_A + "\n",
		"version: 7\nplatforms:\n  - name: linux-64\nenvironments: {}\npackages: []\n",
		"", "{", "\xff\x00", "a: &x [1]\nb: *x\n",
	} {
		f.Add([]byte(s))
	}
	leak := func(s string) bool {
		// A token lives in a URL path; a host named "t" or a local
		// directory named "t" is not one.
		path := ""
		if i := strings.Index(s, "://"); i >= 0 {
			path = strings.TrimLeft(s[i+3:], "/")
			if j := strings.IndexByte(path, '/'); j >= 0 {
				path = path[j:]
			} else {
				path = ""
			}
		}
		return strings.ContainsAny(s, "@?#") || strings.Contains(path, "/t/") || strings.Contains(s, "%2F") || strings.Contains(s, "%2f")
	}
	check := func(t *testing.T, pkgs []model.CondaPackage) {
		t.Helper()
		for _, p := range pkgs {
			if _, ok := condaName(p.PackageName); !ok || condaVirtual(p.PackageName) {
				t.Fatalf("invalid package name %q", p.PackageName)
			}
			if len(p.RequestedSpecs) > maxCondaRequestedSpecs {
				t.Fatalf("%d requested specs", len(p.RequestedSpecs))
			}
			for _, s := range append([]string{p.ArtifactURL, p.Origin.URL}, p.RequestedSpecs...) {
				if s != condaRedacted && leak(s) {
					t.Fatalf("credential text survived: %q", s)
				}
			}
			for _, h := range p.RecordedChecksums {
				if !condaChecksum(h.Algorithm, h.Value) {
					t.Fatalf("invalid checksum %+v", h)
				}
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16*1024 {
			t.Skip()
		}
		before := bytes.Clone(data)
		r, err := parseCondaRecord(data)
		if r2, err2 := parseCondaRecord(data); !reflect.DeepEqual(r, r2) || (err == nil) != (err2 == nil) {
			t.Fatal("record parse is not deterministic")
		}
		if err == nil {
			check(t, []model.CondaPackage{condaFact(r)})
		}
		m, err := parseCondaEnvironment(data)
		if m2, err2 := parseCondaEnvironment(data); !reflect.DeepEqual(m, m2) || (err == nil) != (err2 == nil) {
			t.Fatal("manifest parse is not deterministic")
		}
		if err == nil {
			for _, d := range m.declarations {
				if _, ok := condaName(d.name); !ok || condaVirtual(d.name) || d.spec != condaRedacted && leak(d.spec) || d.channel != condaRedacted && leak(d.channel) {
					t.Fatalf("invalid declaration %+v", d)
				}
			}
		}
		for _, parse := range []func([]byte) ([]condaLockEntry, []string, error){parseCondaExplicit, parseCondaLockYAML} {
			entries, reasons, err := parse(data)
			entries2, reasons2, err2 := parse(data)
			if !reflect.DeepEqual(entries, entries2) || !slices.Equal(reasons, reasons2) || (err == nil) != (err2 == nil) {
				t.Fatal("lock parse is not deterministic")
			}
			pkgs := []model.CondaPackage{}
			for _, e := range entries {
				if e.pkg.VersionStatus != "known" || e.pkg.Version == "" {
					t.Fatalf("locked row without a version %+v", e.pkg)
				}
				pkgs = append(pkgs, e.pkg)
			}
			check(t, pkgs)
		}
		if !bytes.Equal(data, before) {
			t.Fatal("parser mutated input")
		}
	})
}

func FuzzMavenMetadata(f *testing.F) {
	for _, s := range []string{
		mavenTestPOM("org.example", "app", "1.0"),
		`<project><parent><groupId>g</groupId><artifactId>p</artifactId><version>1</version></parent><artifactId>a</artifactId>` +
			`<dependencies><dependency><groupId>g</groupId><artifactId>d</artifactId><version>https://u:p@h/x</version><classifier/></dependency></dependencies>` +
			`<build><plugins><plugin><artifactId>m</artifactId><dependencies><dependency><groupId>g</groupId><artifactId>pd</artifactId></dependency></dependencies></plugin></plugins></build>` +
			`<profiles><profile><id>ci</id><dependencies><dependency><groupId>${g}</groupId><artifactId>x</artifactId></dependency></dependencies></profile></profiles></project>`,
		"org.example:a:1.0=compileClasspath,runtimeClasspath\nempty=annotationProcessor\n",
		"[versions]\nv = { strictly = \"[1,2)\" }\n[libraries]\na = { module = \"g:a\", version.ref = \"v\" }\nb = \"g:b:1\"\n",
		`<verification-metadata><configuration><verify-metadata>true</verify-metadata></configuration><components><component group="g" name="a" version="1">` +
			`<artifact name="a-1.jar"><sha256 value="` + mavenSHA256A + `"><also-trust value="` + mavenSHA256B + `"/></sha256></artifact></component></components></verification-metadata>`,
		`<ivy-module version="2.0"><info organisation="g" module="a" revision="1"/></ivy-module>`,
		"distributionUrl=https\\://u\\:p@h/x.zip\nwrapperSha256Sum=\\u0041\n",
		"", "<", "\xff\x00", `<!DOCTYPE x [<!ENTITY a "b">]><project/>`,
	} {
		f.Add([]byte(s))
	}
	check := func(t *testing.T, ds []mavenDeclaration) {
		t.Helper()
		for _, d := range ds {
			if mavenCoordinate(d.group) != "" || mavenCoordinate(d.artifact) != "" {
				t.Fatalf("invalid declaration identity %+v", d)
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16*1024 {
			t.Skip()
		}
		before := bytes.Clone(data)
		pom, err := parseMavenPOM(data)
		if pom2, err2 := parseMavenPOM(data); !reflect.DeepEqual(pom, pom2) || (err == nil) != (err2 == nil) {
			t.Fatal("POM parse is not deterministic")
		}
		if err == nil {
			check(t, pom.declarations)
		}
		catalog, err := parseGradleCatalog(data)
		if catalog2, err2 := parseGradleCatalog(data); !reflect.DeepEqual(catalog, catalog2) || (err == nil) != (err2 == nil) {
			t.Fatal("catalog parse is not deterministic")
		}
		if err == nil {
			check(t, catalog.declarations)
		}
		for _, legacy := range []string{"", "compileClasspath"} {
			if lock, err := parseGradleLock(data, legacy); err == nil {
				for _, e := range lock.entries {
					if mavenCoordinate(e.group) != "" || mavenCoordinate(e.artifact) != "" || !mavenVersion(e.version) {
						t.Fatalf("invalid lock entry %+v", e)
					}
				}
			}
		}
		if refs, _, _, err := parseGradleVerification(data); err == nil {
			for _, r := range refs {
				if len(r.checksums) > maxMavenChecksums {
					t.Fatalf("%d checksums", len(r.checksums))
				}
				for _, h := range r.checksums {
					if len(h.value) != mavenHexLengths[h.algorithm] || strings.Trim(h.value, "0123456789abcdef") != "" {
						t.Fatalf("invalid checksum %+v", h)
					}
				}
			}
		}
		mavenIvyMatches(data, "g", "a", "1")
		_, _, _, _ = mavenPOMIdentity(data)
		props, _ := configaudit.ParseJavaProperties(data)
		if len(props) > 4096 {
			t.Fatalf("%d properties", len(props))
		}
		if !bytes.Equal(data, before) {
			t.Fatal("parser mutated input")
		}
	})
}
