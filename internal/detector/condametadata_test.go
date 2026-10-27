package detector

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

const (
	condaMD5A  = "f77c7d05dc47868e181135af65cb6e26"
	condaSHA_A = "adfa71f158cbd872a36394c56c3568e6034aa55c623634b37a4836bd036e6b91"
)

func TestCondaNameAndDist(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		ok       bool
		want     string
	}{
		{"lowercased", "NumPy", true, "numpy"},
		{"dots and dashes", "ca-certificates", true, "ca-certificates"},
		{"underscore start", "_libgcc_mutex", true, "_libgcc_mutex"},
		{"virtual rejected", "__glibc", false, ""},
		{"empty", "", false, ""},
		{"space", "a b", false, ""},
		{"slash", "a/b", false, ""},
	} {
		got, ok := condaName(tc.in)
		if ok != tc.ok || ok && got != tc.want {
			t.Errorf("%s: condaName(%q) = %q %v", tc.name, tc.in, got, ok)
		}
	}
	for _, tc := range []struct {
		fn                   string
		name, version, build string
		ok                   bool
	}{
		{"zlib-1.2.11-hf3cbc9b_2.tar.bz2", "zlib", "1.2.11", "hf3cbc9b_2", true},
		{"python-3.13.0-hbbac1ca_101_cp313.conda", "python", "3.13.0", "hbbac1ca_101_cp313", true},
		{"_openmp_mutex-4.5-1_gnu", "_openmp_mutex", "4.5", "1_gnu", true},
		{"ansi2html-1.9.5-py3_none_any_0", "ansi2html", "1.9.5", "py3_none_any_0", true},
		{"zlib-1.2.11", "", "", "", false},
		{"-1.0-0", "", "", "", false},
		{"a--0", "", "", "", false},
	} {
		name, version, build, ok := condaDist(tc.fn)
		if ok != tc.ok || name != tc.name || version != tc.version || build != tc.build {
			t.Errorf("condaDist(%q) = %q %q %q %v", tc.fn, name, version, build, ok)
		}
	}
}

func TestCondaArtifactURL(t *testing.T) {
	for _, tc := range []struct {
		name, in    string
		display     string
		channel     string
		subdir      string
		local       bool
		wheel       bool
		ok          bool
		md5, sha256 string
		invalid     bool
		unresolved  bool
	}{
		{name: "channel artifact with md5 fragment", in: "https://conda.anaconda.org/conda-forge/osx-arm64/bzip2-1.0.8-h93a5062_5.conda#" + condaMD5A,
			display: "https://conda.anaconda.org/conda-forge/osx-arm64/bzip2-1.0.8-h93a5062_5.conda", channel: "https://conda.anaconda.org/conda-forge", subdir: "osx-arm64", ok: true, md5: condaMD5A},
		{name: "sha256 fragment with prefix", in: "https://prefix.dev/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda#sha256:" + condaSHA_A,
			display: "https://prefix.dev/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda", channel: "https://prefix.dev/conda-forge", subdir: "noarch", ok: true, sha256: condaSHA_A},
		{name: "bad fragment", in: "https://conda.anaconda.org/conda-forge/linux-64/zlib-1.2.11-h166bdaf_0.tar.bz2#CANARY",
			display: "https://conda.anaconda.org/conda-forge/linux-64/zlib-1.2.11-h166bdaf_0.tar.bz2", channel: "https://conda.anaconda.org/conda-forge", subdir: "linux-64", ok: true, invalid: true},
		{name: "token path removed", in: "https://conda.anaconda.org/t/CANARY-TOKEN/private/linux-64/zlib-1.2.11-h166bdaf_0.conda",
			display: "https://conda.anaconda.org/private/linux-64/zlib-1.2.11-h166bdaf_0.conda", channel: "https://conda.anaconda.org/private", subdir: "linux-64", ok: true},
		{name: "userinfo removed", in: "https://CANARY_USER:CANARY_PASS@repo.example.invalid/ch/linux-64/zlib-1.2.11-h166bdaf_0.conda",
			display: "https://repo.example.invalid/ch/linux-64/zlib-1.2.11-h166bdaf_0.conda", channel: "https://repo.example.invalid/ch", subdir: "linux-64", ok: true},
		{name: "encoded token redacts whole url", in: "https://conda.anaconda.org%2Ft%2FCANARY/linux-64/zlib-1.2.11-h166bdaf_0.conda", display: condaRedacted},
		{name: "wheel", in: "https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl", display: "https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl", wheel: true},
		{name: "file url", in: "file:///opt/channel/linux-64/zlib-1.2.11-h166bdaf_0.conda", display: "/opt/channel/linux-64/zlib-1.2.11-h166bdaf_0.conda", channel: "/opt/channel", subdir: "linux-64", local: true, ok: true},
		{name: "absolute path", in: "/opt/channel/noarch/tzdata-2024b-hc8b5060_0.conda", display: "/opt/channel/noarch/tzdata-2024b-hc8b5060_0.conda", channel: "/opt/channel", subdir: "noarch", local: true, ok: true},
		{name: "windows path", in: `C:\channel\win-64\zlib-1.2.11-h8ffe710_4.conda`, display: `C:\channel\win-64\zlib-1.2.11-h8ffe710_4.conda`, channel: `C:\channel`, subdir: "win-64", local: true, ok: true},
		{name: "relative path unresolved", in: "pkgs/zlib-1.2.11-h166bdaf_0.conda", display: "pkgs/zlib-1.2.11-h166bdaf_0.conda", local: true, ok: true, unresolved: true},
		{name: "host directly above file has no channel", in: "https://host.example.invalid/zlib-1.2.11-h166bdaf_0.conda", display: "https://host.example.invalid/zlib-1.2.11-h166bdaf_0.conda", ok: true},
		{name: "not an artifact", in: "https://conda.anaconda.org/conda-forge/linux-64/zlib", display: "https://conda.anaconda.org/conda-forge/linux-64/zlib"},
		{name: "unsafe text", in: "https://x/\x00", display: condaRedacted},
	} {
		a := parseCondaArtifactURL(tc.in)
		if a.display != tc.display || a.channel != tc.channel || a.subdir != tc.subdir || a.local != tc.local || a.wheel != tc.wheel || a.ok != tc.ok ||
			a.md5 != tc.md5 || a.sha256 != tc.sha256 || a.checksumInvalid != tc.invalid || a.unresolvable != tc.unresolved {
			t.Errorf("%s: %+v", tc.name, a)
		}
		if strings.Contains(a.display+a.channel, "CANARY") {
			t.Errorf("%s: credential survived in %+v", tc.name, a)
		}
	}
}

func TestCondaOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, channel, url, subdir string
		want                       model.CondaOrigin
		reason                     string
	}{
		{"channel url with subdir", "https://repo.anaconda.com/pkgs/main/osx-64", "", "osx-64", model.CondaOrigin{Kind: "channel", URL: "https://repo.anaconda.com/pkgs/main"}, ""},
		{"label resolved through artifact", "conda-forge", "https://conda.anaconda.org/conda-forge/linux-64/zlib-1.2.11-h166bdaf_0.conda", "linux-64", model.CondaOrigin{Kind: "channel", URL: "https://conda.anaconda.org/conda-forge"}, ""},
		{"label with mismatched artifact subdir", "conda-forge", "https://conda.anaconda.org/conda-forge/noarch/zlib-1.2.11-h166bdaf_0.conda", "linux-64", model.CondaOrigin{Kind: "unknown"}, ""},
		{"wheel host never a channel", "conda-pypi", "https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl", "noarch", model.CondaOrigin{Kind: "unknown"}, ""},
		{"local file channel", "file:///opt/channel/linux-64", "", "linux-64", model.CondaOrigin{Kind: "local", Path: "/opt/channel"}, ""},
		{"credential channel", "https://CANARY:CANARY@repo.example.invalid/t/CANARY/ch/noarch", "", "noarch", model.CondaOrigin{Kind: "channel", URL: "https://repo.example.invalid/ch"}, ""},
		{"unknown placeholder", "<unknown>", "", "", model.CondaOrigin{Kind: "unknown"}, ""},
		{"redacted channel", condaRedacted, "", "", model.CondaOrigin{Kind: "unknown"}, "origin_unresolved"},
		{"empty", "", "", "", model.CondaOrigin{Kind: "unknown"}, ""},
	} {
		got, reason := condaOrigin(tc.channel, tc.url, tc.subdir)
		if got != tc.want || reason != tc.reason {
			t.Errorf("%s: condaOrigin = %+v %q", tc.name, got, reason)
		}
	}
}

func TestCondaMatchSpec(t *testing.T) {
	for _, tc := range []struct {
		in, status, name, spec, channel string
		redacted                        bool
	}{
		{"numpy>=1.26", "ok", "numpy", "numpy>=1.26", "", false},
		{"Python=3.12", "ok", "python", "Python=3.12", "", false},
		{"conda-forge::numpy>=1.26", "ok", "numpy", "conda-forge::numpy>=1.26", "conda-forge", false},
		{"https://CANARY:x@repo.example.invalid/ch::pkg 1.0", "ok", "pkg", "https://repo.example.invalid/ch::pkg 1.0", "https://repo.example.invalid/ch", false},
		{"bad channel!::pkg", "ok", "pkg", condaRedacted + "::pkg", condaRedacted, true},
		{"pkg 1.0 py38*", "ok", "pkg", "pkg 1.0 py38*", "", false},
		{"numpy[version='>=1.26']", "unsupported", "", "", "", false},
		{"numpy*", "unsupported", "", "", "", false},
		{"ns:conda-forge::pkg", "unsupported", "", "", "", false},
		{"pkg:1.0", "unsupported", "", "", "", false},
		{"__glibc>=2.17", "virtual", "", "", "", false},
		{"", "invalid", "", "", "", false},
		{"=1.0", "invalid", "", "", "", false},
	} {
		d, status := parseCondaMatchSpec(tc.in)
		if status != tc.status || d.name != tc.name || d.spec != tc.spec || d.channel != tc.channel || d.channelRedacted != tc.redacted {
			t.Errorf("parseCondaMatchSpec(%q) = %+v %q", tc.in, d, status)
		}
		if strings.Contains(d.spec+d.channel, "CANARY") {
			t.Errorf("credential survived in %+v", d)
		}
	}
}

// condaZlibReceipt mirrors a historical upstream prefix record; the file
// lists Conda writes beside these fields are never read.
const condaZlibReceipt = `{
  "build": "hf3cbc9b_2",
  "build_number": 2,
  "channel": "https://repo.anaconda.com/pkgs/main/osx-64",
  "constrains": [],
  "depends": [],
  "extracted_package_dir": "/Users/CANARY_HOME/pkgs/zlib-1.2.11-hf3cbc9b_2",
  "features": "",
  "files": ["lib/libz.1.2.11.dylib"],
  "fn": "zlib-1.2.11-hf3cbc9b_2.tar.bz2",
  "license": "zlib",
  "link": {"source": "/Users/CANARY_HOME/pkgs/zlib-1.2.11-hf3cbc9b_2", "type": 1},
  "md5": "` + condaMD5A + `",
  "name": "zlib",
  "package_tarball_full_path": "/Users/CANARY_HOME/pkgs/zlib-1.2.11-hf3cbc9b_2.tar.bz2",
  "paths_data": {"paths": [], "paths_version": 1},
  "requested_spec": "None",
  "size": 103233,
  "subdir": "osx-64",
  "timestamp": 1510092154915,
  "url": "https://repo.continuum.io/pkgs/main/osx-64/zlib-1.2.11-hf3cbc9b_2.tar.bz2",
  "version": "1.2.11"
}`

var condaManySpecs = func() string {
	parts := []string{}
	for i := range 40 {
		parts = append(parts, `"spec`+string(rune('a'+i%26))+strings.Repeat("x", i/26)+`"`)
	}
	return strings.Join(parts, ",")
}()

func TestCondaRecord(t *testing.T) {
	r, err := parseCondaRecord([]byte(condaZlibReceipt))
	if err != nil {
		t.Fatal(err)
	}
	if r.name != "zlib" || r.version != "1.2.11" || r.build != "hf3cbc9b_2" || r.subdir != "osx-64" || r.buildNumber == nil || *r.buildNumber != 2 || r.md5 != condaMD5A || len(r.requested) != 0 || len(r.reasons) != 0 {
		t.Errorf("historical receipt %+v", r)
	}
	p := condaFact(r)
	if p.DependencyRelation != "unknown" || p.Origin != (model.CondaOrigin{Kind: "channel", URL: "https://repo.anaconda.com/pkgs/main"}) || p.ArtifactURL != "https://repo.continuum.io/pkgs/main/osx-64/zlib-1.2.11-hf3cbc9b_2.tar.bz2" ||
		p.ChecksumStatus != "recorded" || len(p.RecordedChecksums) != 1 || p.RecordedChecksums[0].Algorithm != "md5" {
		t.Errorf("historical fact %+v", p)
	}

	modern := `{"name":"NumPy","version":"1.26.4","build":"py312h8813227_0","build_number":0,"subdir":"osx-arm64","channel":"conda-forge",
		"url":"https://conda.anaconda.org/conda-forge/osx-arm64/numpy-1.26.4-py312h8813227_0.conda","md5":"` + condaMD5A + `","sha256":"` + strings.ToUpper(condaSHA_A) + `",
		"requested_specs":["numpy>=1.26","https://CANARY:x@repo.example.invalid/t/CANARY/ch::numpy","numpy>=1.26","./numpy.conda#CANARY_FRAGMENT","ch::numpy?CANARY_QUERY"],"requested_spec":"ignored","package_type":"noarch_python"}`
	r, err = parseCondaRecord([]byte(modern))
	if err != nil {
		t.Fatal(err)
	}
	p = condaFact(r)
	if p.PackageName != "numpy" || p.DependencyRelation != "direct" || !slices.Equal(p.RequestedSpecs, []string{"numpy>=1.26", "https://repo.example.invalid/ch::numpy", "[redacted]"}) || p.BuildNumber == nil || *p.BuildNumber != 0 ||
		p.Origin != (model.CondaOrigin{Kind: "channel", URL: "https://conda.anaconda.org/conda-forge"}) || len(p.RecordedChecksums) != 2 || p.RecordedChecksums[0].Algorithm != "sha256" || p.RecordedChecksums[0].Value != condaSHA_A {
		t.Errorf("modern fact %+v", p)
	}

	// A wheel installed through conda-pypi: the channel is a label and the
	// download host is not a channel.
	wheel := `{"name":"ansi2html","version":"1.9.5","build":"py3_none_any_0","build_number":0,"subdir":"noarch","channel":"conda-pypi","noarch":"python",
		"url":"https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl","sha256":"` + condaSHA_A + `","requested_spec":"conda-pypi::ansi2html"}`
	r, err = parseCondaRecord([]byte(wheel))
	if err != nil {
		t.Fatal(err)
	}
	p = condaFact(r)
	if p.Origin.Kind != "unknown" || p.ArtifactURL != "https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl" || p.DependencyRelation != "direct" || p.ChecksumStatus != "recorded" || len(p.Reasons) != 0 {
		t.Errorf("wheel fact %+v", p)
	}

	for _, tc := range []struct {
		name, in string
		reasons  []string
		invalid  bool
		err      error
	}{
		{"virtual package type", `{"name":"__glibc","version":"2.17","build":"0","package_type":"virtual_system"}`, nil, false, errCondaUnsupportedFormat},
		{"virtual name", `{"name":"__glibc","version":"2.17","build":"0"}`, nil, false, errors.New("")},
		{"missing build", `{"name":"zlib","version":"1.2.11"}`, nil, false, errors.New("")},
		{"build_string alias", `{"name":"zlib","version":"1.2.11","build_string":"h0"}`, []string{}, false, nil},
		{"bad subdir and build number", `{"name":"zlib","version":"1.2.11","build":"h0","subdir":"Linux 64","build_number":-1}`, []string{"parse_error", "parse_error"}, false, nil},
		{"bad checksum", `{"name":"zlib","version":"1.2.11","build":"h0","md5":"xyz"}`, []string{}, true, nil},
		{"too many requests", `{"name":"zlib","version":"1.2.11","build":"h0","requested_specs":[` + condaManySpecs + `]}`, []string{"entry_limit"}, false, nil},
		{"not an object", `[]`, nil, false, errors.New("")},
	} {
		r, err := parseCondaRecord([]byte(tc.in))
		switch {
		case tc.err != nil && err == nil, tc.err == nil && err != nil:
			t.Errorf("%s: err = %v", tc.name, err)
		case tc.err == errCondaUnsupportedFormat && !errors.Is(err, errCondaUnsupportedFormat):
			t.Errorf("%s: err = %v", tc.name, err)
		case err == nil && (!slices.Equal(r.reasons, tc.reasons) || r.checksumInvalid != tc.invalid):
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
	if r, _ := parseCondaRecord([]byte(`{"name":"zlib","version":"1.2.11","build":"h0","requested_specs":[` + strings.Repeat(`"a",`, 40) + `"b"]}`)); !slices.Equal(r.requested, []string{"a", "b"}) || len(r.reasons) != 0 {
		t.Errorf("duplicate requests %+v", r)
	}
	if r, _ := parseCondaRecord([]byte(`{"name":"zlib","version":"1.2.11","build":"h0","requested_specs":[` + condaManySpecs + `]}`)); len(r.requested) != maxCondaRequestedSpecs {
		t.Errorf("request cap kept %d", len(r.requested))
	}
}

func TestCondaEnvironment(t *testing.T) {
	m, err := parseCondaEnvironment([]byte(`name: app
channels:
  - conda-forge
  - http://mirror.example.invalid/ch
  - https://user:CANARY@repo.example.invalid/t/CANARY/private
  - nodefaults
dependencies:
  - python=3.12
  - conda-forge::numpy>=1.26
  - pip
  - __glibc>=2.17
  - numpy*
  - pip:
      - requests
  - m2-base  # [win]
variables:
  CANARY_VAR: CANARY_VALUE
prefix: /home/CANARY/envs/app
`))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.channels, []string{"conda-forge", "http://mirror.example.invalid/ch", "https://user:CANARY@repo.example.invalid/t/CANARY/private", "nodefaults"}) {
		t.Errorf("channels %v", m.channels)
	}
	names := []string{}
	for _, d := range m.declarations {
		names = append(names, d.name)
	}
	if !slices.Equal(names, []string{"python", "numpy", "pip"}) || !m.unsupported || m.invalid {
		t.Errorf("manifest %+v", m)
	}
	if m.declarations[1].channel != "conda-forge" || m.declarations[0].spec != "python=3.12" {
		t.Errorf("declarations %+v", m.declarations)
	}

	m, err = parseCondaEnvironment([]byte(`{"name": "app", "channels": ["conda-forge"], "dependencies": ["zlib=1.2.11", {"pip": ["x"]}], "prefix": "/opt/x"}`))
	if err != nil || len(m.declarations) != 1 || m.unsupported || m.invalid || !slices.Equal(m.channels, []string{"conda-forge"}) {
		t.Errorf("json export %+v %v", m, err)
	}

	for _, tc := range []struct {
		name, in             string
		unsupported, invalid bool
		err                  bool
	}{
		{"root merge", "<<: {dependencies: [numpy]}\n", true, false, false},
		{"tagged key", "!custom dependencies: [numpy]\n", true, false, false},
		{"sel form", "dependencies:\n  - sel(win): m2-base\n", true, false, false},
		{"duplicate dependencies key", "dependencies:\n  - a\ndependencies:\n  - b\n", true, false, false},
		{"anchor", "channels: &c\n  - conda-forge\ndependencies: *c\n", true, false, false},
		{"scalar dependencies", "dependencies: numpy\n", false, true, false},
		{"null channel entry", "channels:\n  - \n", false, true, false},
		{"empty", "", false, false, false},
		{"sequence root", "- a\n", false, false, true},
		{"not yaml", "a: [\n", false, false, true},
		{"not utf8", "\xff", false, false, true},
	} {
		m, err := parseCondaEnvironment([]byte(tc.in))
		if (err != nil) != tc.err || err == nil && (m.unsupported != tc.unsupported || m.invalid != tc.invalid) {
			t.Errorf("%s: %+v %v", tc.name, m, err)
		}
	}
}

func TestCondaExplicit(t *testing.T) {
	data := []byte(`# This file may be used to create an environment using:
# $ conda create --name <env> --file <this file>
# platform: osx-arm64
@EXPLICIT
https://conda.anaconda.org/conda-forge/osx-arm64/bzip2-1.0.8-h93a5062_5.conda#` + condaMD5A + `
https://conda.anaconda.org/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda#sha256:` + condaSHA_A + `
https://conda.anaconda.org/t/CANARY-TOKEN/private/osx-arm64/zlib-1.2.13-h53f4e23_5.conda
https://conda.anaconda.org/conda-forge/osx-arm64/libffi-3.4.2-h3422bc3_5.tar.bz2#CANARY
file:///opt/channel/osx-arm64/local-1.0-0.conda
pkgs/relative-1.0-0.conda
https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl
https://conda.anaconda.org/conda-forge/osx-arm64/README
`)
	if !condaIsExplicit(data) || condaIsExplicit([]byte("# platform: x\nnumpy\n")) || condaIsExplicit(nil) {
		t.Fatal("explicit header detection")
	}
	entries, reasons, err := parseCondaExplicit(data)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(reasons, []string{"checksum_invalid", "path_unresolved", "unsupported_format", "parse_error"}) {
		t.Errorf("reasons %v", reasons)
	}
	if len(entries) != 6 {
		t.Fatalf("rows %d", len(entries))
	}
	rows := map[string]model.CondaPackage{}
	for _, e := range entries {
		rows[e.pkg.PackageName] = e.pkg
		if e.pkg.TargetPlatform != "osx-arm64" || e.pkg.VersionStatus != "known" || e.pkg.DependencyRelation != "unknown" || strings.Contains(e.pkg.ArtifactURL, "CANARY") {
			t.Errorf("row %+v", e.pkg)
		}
	}
	if p := rows["bzip2"]; p.ChecksumStatus != "recorded" || p.RecordedChecksums[0].Value != condaMD5A || p.Origin != (model.CondaOrigin{Kind: "channel", URL: "https://conda.anaconda.org/conda-forge"}) || p.Build != "h93a5062_5" || p.Subdir != "osx-arm64" {
		t.Errorf("bzip2 %+v", p)
	}
	if p := rows["tzdata"]; p.RecordedChecksums[0].Algorithm != "sha256" || p.Subdir != "noarch" {
		t.Errorf("tzdata %+v", p)
	}
	if p := rows["zlib"]; p.Origin.URL != "https://conda.anaconda.org/private" || p.ArtifactURL != "https://conda.anaconda.org/private/osx-arm64/zlib-1.2.13-h53f4e23_5.conda" {
		t.Errorf("zlib %+v", p)
	}
	if p := rows["libffi"]; p.ChecksumStatus != "partial" || !slices.Equal(p.Reasons, []string{"checksum_invalid"}) {
		t.Errorf("libffi %+v", p)
	}
	if p := rows["local"]; p.Origin != (model.CondaOrigin{Kind: "local", Path: "/opt/channel"}) || p.ArtifactURL != "/opt/channel/osx-arm64/local-1.0-0.conda" {
		t.Errorf("local %+v", p)
	}
	if p := rows["relative"]; p.Origin.Kind != "unknown" || p.ArtifactURL != "" || !slices.Equal(p.Reasons, []string{"path_unresolved"}) {
		t.Errorf("relative %+v", p)
	}
	for _, in := range []string{"numpy\nzlib\n", "# platform: linux-64\n", "", "\xff@EXPLICIT\n"} {
		if _, _, err := parseCondaExplicit([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestCondaLockYAML(t *testing.T) {
	v1 := `# This lock file was generated by conda-lock. DO NOT EDIT!
metadata:
  channels:
  - conda-forge
  platforms:
  - linux-64
  - osx-arm64
package:
- category: main
  dependencies: {}
  hash:
    md5: ` + condaMD5A + `
  manager: conda
  name: _libgcc_mutex
  optional: false
  platform: linux-64
  url: https://conda.anaconda.org/conda-forge/linux-64/_libgcc_mutex-0.1-conda_forge.tar.bz2
  version: '0.1'
- category: main
  dependencies: {}
  hash:
    sha256: ` + condaSHA_A + `
  manager: conda
  name: tzdata
  optional: false
  platform: linux-64
  url: https://conda.anaconda.org/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda
  version: 2024b
- category: main
  dependencies: {}
  hash:
    sha256: ` + condaSHA_A + `
  manager: conda
  name: tzdata
  optional: false
  platform: osx-arm64
  url: https://conda.anaconda.org/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda
  version: 2024b
- category: main
  dependencies: {}
  hash:
    sha256: ` + condaSHA_A + `
  manager: pip
  name: requests
  optional: false
  platform: linux-64
  url: https://files.pythonhosted.org/packages/ab/cd/requests-2.32.3-py3-none-any.whl
  version: 2.32.3
- category: main
  dependencies: {}
  hash:
    md5: bad
  manager: conda
  name: renamed
  optional: false
  platform: linux-64
  url: https://user:CANARY@conda.anaconda.org/conda-forge/linux-64/other-1.0-0.conda
  version: '1.0'
version: 1
`
	entries, reasons, err := parseCondaLockYAML([]byte(v1))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 || !slices.Equal(reasons, []string{"identity_mismatch", "checksum_invalid"}) {
		t.Fatalf("v1 rows %d reasons %v", len(entries), reasons)
	}
	if p := entries[0].pkg; p.PackageName != "_libgcc_mutex" || p.Version != "0.1" || p.Build != "conda_forge" || p.Subdir != "linux-64" || p.TargetPlatform != "linux-64" ||
		p.Origin != (model.CondaOrigin{Kind: "channel", URL: "https://conda.anaconda.org/conda-forge"}) || p.ChecksumStatus != "recorded" {
		t.Errorf("v1 row %+v", p)
	}
	if a, b := entries[1].pkg, entries[2].pkg; a.TargetPlatform != "linux-64" || b.TargetPlatform != "osx-arm64" || a.ArtifactURL != b.ArtifactURL {
		t.Errorf("two targets sharing a noarch artifact %+v %+v", a, b)
	}
	if p := entries[3].pkg; p.PackageName != "renamed" || p.ArtifactURL != "" || p.Origin.Kind != "unknown" || !slices.Equal(p.Reasons, []string{"identity_mismatch", "checksum_invalid"}) || p.ChecksumStatus != "partial" {
		t.Errorf("v1 mismatched row %+v", p)
	}

	v6 := `version: 6
environments:
  default:
    channels:
      - url: https://prefix.dev/conda-forge/
    packages:
      osx-arm64:
        - conda: https://prefix.dev/conda-forge/osx-arm64/bzip2-1.0.8-h99b78c6_7.conda
        - conda: https://prefix.dev/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda
        - conda: https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl
        - pypi: https://files.pythonhosted.org/packages/ab/cd/numpy-2.2.1-cp313-cp313-macosx_11_0_arm64.whl
      linux-64:
        - conda: https://prefix.dev/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda
        - conda: ../minimal-project
          build: second
        - conda: https://prefix.dev/conda-forge/linux-64/missing-1.0-0.conda
  second:
    channels:
      - url: https://prefix.dev/conda-forge/
    packages:
      win-64:
        - conda: ../minimal-project
          build: first
        - conda: ../minimal-project
packages:
  - conda: https://prefix.dev/conda-forge/osx-arm64/bzip2-1.0.8-h99b78c6_7.conda
    sha256: ` + condaSHA_A + `
    md5: ` + condaMD5A + `
    depends:
      - __osx >=11.0
    license: bzip2-1.0.6
    purls: []
    size: 122909
    timestamp: 1720974522888
  - conda: https://prefix.dev/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda
    sha256: ` + condaSHA_A + `
    md5: ` + condaMD5A + `
    license: LicenseRef-Public-Domain
    size: 122354
  - conda: https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl
    build_number: 0
    sha256: ` + condaSHA_A + `
  - pypi: https://files.pythonhosted.org/packages/ab/cd/numpy-2.2.1-cp313-cp313-macosx_11_0_arm64.whl
    name: numpy
    version: 2.2.1
    sha256: ` + condaSHA_A + `
  - conda: ../minimal-project
    name: minimal-project
    version: "0.1"
    subdir: win-64
    build: first
  - conda: ../minimal-project
    name: minimal-project
    version: "0.1"
    build: second
    subdir: win-64
`
	entries, reasons, err = parseCondaLockYAML([]byte(v6))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(reasons, []string{"unsupported_format", "path_unresolved", "parse_error"}) {
		t.Errorf("v6 reasons %v", reasons)
	}
	type key struct{ name, env, platform string }
	got := map[key]model.CondaPackage{}
	for _, e := range entries {
		got[key{e.pkg.PackageName, e.pkg.LockEnvironment, e.pkg.TargetPlatform}] = e.pkg
	}
	if len(got) != 5 || len(entries) != 5 {
		t.Fatalf("v6 rows %+v", entries)
	}
	if p := got[key{"bzip2", "default", "osx-arm64"}]; p.Version != "1.0.8" || p.Build != "h99b78c6_7" || p.Subdir != "osx-arm64" || p.Origin.URL != "https://prefix.dev/conda-forge" || len(p.RecordedChecksums) != 2 {
		t.Errorf("v6 bzip2 %+v", p)
	}
	if _, ok := got[key{"tzdata", "default", "linux-64"}]; !ok {
		t.Error("v6 noarch artifact referenced by two targets")
	}
	if p := got[key{"minimal-project", "default", "linux-64"}]; p.Build != "second" || p.Subdir != "win-64" || !slices.Equal(p.Reasons, []string{"path_unresolved"}) || p.ArtifactURL != "" {
		t.Errorf("v6 source variant %+v", p)
	}
	if p := got[key{"minimal-project", "second", "win-64"}]; p.Build != "first" {
		t.Errorf("v6 source variant by build %+v", p)
	}
	for _, in := range []string{"version: 1\n<<: {package: [{manager: conda, name: numpy, version: '1.0'}]}\n", "version: 2\npackage: []\n", "version: 6\n", "version: 6\npackages: []\nenvironments: []\n", "version: 1\npackage: {}\n", "", "\xff", "version: 6\npackages: &p []\nenvironments: *p\n"} {
		if _, _, err := parseCondaLockYAML([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
	if _, _, err := parseCondaLockYAML([]byte("version: 2\npackage: []\n")); !errors.Is(err, errCondaUnsupportedFormat) {
		t.Errorf("version 2 = %v", err)
	}
	if entries, _, err := parseCondaLockYAML([]byte(strings.Replace(v6, "version: 6", "version: 7\nplatforms:\n  - name: osx-arm64\n", 1))); err != nil || len(entries) != 5 {
		t.Errorf("version 7 = %d rows %v", len(entries), err)
	}
}
