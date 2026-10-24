package detector

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/executor"
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
