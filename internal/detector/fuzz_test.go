package detector

import (
	"bytes"
	"slices"
	"strings"
	"testing"

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
