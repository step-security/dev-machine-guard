package detector

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// rubyStubHeader is the generated header of a native RubyGems spec
// (macOS system Ruby 2.6 default gem forwardable-1.2.0.gemspec).
const rubyStubHeader = "# -*- encoding: utf-8 -*-\n# stub: forwardable 1.2.0 ruby lib\n\nGem::Specification.new do |s|\n  s.name = \"forwardable\".freeze\nend\n"

// rubyNativeMetadata is the head of a native .gem's metadata.gz
// (did_you_mean-1.3.0.gem), with Ruby object tags left in place.
const rubyNativeMetadata = `--- !ruby/object:Gem::Specification
name: did_you_mean
version: !ruby/object:Gem::Version
  version: 1.3.0
platform: ruby
authors:
- Yuki Nishijima
autorequire:
bindir: bin
cert_chain: []
dependencies:
- !ruby/object:Gem::Dependency
  name: bundler
  requirement: !ruby/object:Gem::Requirement
    requirements:
    - - ">="
      - !ruby/object:Gem::Version
        version: '0'
  type: :development
`

const rubyHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func rubyMetadataGz(t *testing.T, metadata string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(metadata))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// rubyGemArchive builds a .gem tar from name/body pairs in order.
func rubyGemArchive(t *testing.T, members ...string) string {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for i := 0; i+1 < len(members); i += 2 {
		if err := w.WriteHeader(&tar.Header{Name: members[i], Mode: 0o444, Size: int64(len(members[i+1])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(members[i+1]))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func rubyDeclarationText(m *rubyManifest) []string {
	out := []string{}
	for _, d := range m.declarations {
		out = append(out, fmt.Sprintf("%s %s %q %v %v %s %s %s", d.name, d.kind, d.requirements, d.groups, d.platforms, d.origin, d.url, d.path))
	}
	return out
}

func TestRubyGemfileParser(t *testing.T) {
	m, err := parseRubyGemfile([]byte(`# frozen_string_literal: true
# gem "commented"
source "https://rubygems.org"
ruby "3.3.0"
gemspec path: "lib", name: "mylib"
eval_gemfile "Gemfile.shared"
lockfile "Custom.lock"

gem "rails", "~> 7.1", ">= 7.1.2"
gem 'rack', require: false
gem 'rack', require: false
gem("puma",
  "~> 6.0")
group :development, :test, optional: true do
  gem "rspec", groups: [:ci]
end
platforms :mri do
  gem "byebug", platform: :windows
end
source "https://gems.example.invalid", cooldown: 3 do
  gem "private-gem"
end
git "https://github.com/org/repo.git", branch: "main" do
  gem "forked"
end
gem "local", path: "../local"
gem "tool", git: "git@github.com:org/tool.git", tag: "v1"
gem "pinned", :source => "https://other.example.invalid"
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`rails unknown ["~> 7.1" ">= 7.1.2"] [] []   `,
		`rack unknown [] [] []   `,
		`puma unknown ["~> 6.0"] [] []   `,
		`rspec unknown [] [ci development test] []   `,
		`byebug unknown [] [] [mri windows]   `,
		`private-gem unknown [] [] [] registry https://gems.example.invalid `,
		`forked unknown [] [] [] git https://github.com/org/repo.git `,
		`local unknown [] [] [] path  ../local`,
		`tool unknown [] [] [] git git@github.com:org/tool.git `,
		`pinned unknown [] [] [] registry https://other.example.invalid `,
	}
	if got := rubyDeclarationText(m); !slices.Equal(got, want) {
		t.Fatalf("declarations\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !slices.Equal(m.globals, []string{"https://rubygems.org"}) || !slices.Equal(m.evals, []string{"Gemfile.shared"}) || m.lockfile != "Custom.lock" || !m.lockfileSet || m.noLockfile ||
		!slices.Equal(m.gemspecs, []rubyGemspecRef{{"lib", "mylib"}}) || m.partial {
		t.Fatalf("manifest %+v", m)
	}
	wantSources := []configaudit.RubyManifestSource{{Type: "registry", URL: "https://rubygems.org"}, {Type: "registry", URL: "https://gems.example.invalid", Cooldown: "3"},
		{Type: "git", URL: "https://github.com/org/repo.git"}, {Type: "git", URL: "git@github.com:org/tool.git"}, {Type: "registry", URL: "https://other.example.invalid"}}
	if !slices.Equal(m.sources, wantSources) {
		t.Fatalf("sources %+v", m.sources)
	}
	if m, err := parseRubyGemfile([]byte("lockfile false\n")); err != nil || !m.noLockfile || !m.lockfileSet {
		t.Fatalf("lockfile false: %+v %v", m, err)
	}

	// Anything outside the literal subset rejects the whole file; no partial
	// declaration set is ever returned.
	for _, tc := range []struct{ name, src string }{
		{"heredoc", "gem \"x\", <<~EOS\n1\nEOS\n"},
		{"interpolation", "gem \"x#{1}\"\n"},
		{"modifier", "gem \"x\" if ENV[\"Y\"]\n"},
		{"conditional block", "if true\n  gem \"x\"\nend\n"},
		{"backtick", "gem `cat name`\n"},
		{"percent literal", "gem %w[x].first\n"},
		{"receiver call", "ENV.fetch(\"X\")\n"},
		{"constant value", "gem \"x\", MyGem::VERSION\n"},
		{"global variable", "gem $name\n"},
		{"brace block", "gem(\"x\") { }\n"},
		{"embedded doc", "=begin\ngem \"x\"\n=end\n"},
		{"data section", "gem \"x\"\n__END__\n"},
		{"plugin source", "source \"https://x.example.invalid\", type: \"plugin\"\n"},
		{"conflicting duplicate", "gem \"x\", \"1\"\ngem \"x\", \"2\"\n"},
		{"two origins", "gem \"x\", git: \"a\", path: \"b\"\n"},
		{"nested gemspec", "group :test do\n  gemspec\nend\n"},
		{"unknown option", "gem \"x\", install_if: true\n"},
		{"unterminated block", "group :test do\n  gem \"x\"\n"},
		{"invalid utf8", "gem \"\xff\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if m, err := parseRubyGemfile([]byte(tc.src)); err == nil {
				t.Fatalf("accepted %q: %+v", tc.src, m)
			}
		})
	}
}

func TestRubyGemspecParser(t *testing.T) {
	m, err := parseRubyGemspec([]byte(`# frozen_string_literal: true
Gem::Specification.new do |spec|
  spec.name = "mylib"
  spec.version = "1.2.3"
  spec.summary = "CANARY summary"
  spec.authors = ["CANARY author"]
  spec.files = ["lib/mylib.rb"]
  spec.metadata = { "source_code_uri" => "https://example.invalid" }
  spec.add_dependency "rack", ">= 2", "< 4"
  spec.add_runtime_dependency "json"
  spec.add_development_dependency "rspec", "~> 3.0"
end
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`rack runtime [">= 2" "< 4"] [] []   `, `json runtime [] [] []   `, `rspec development ["~> 3.0"] [] []   `}
	if got := rubyDeclarationText(m); m.name != "mylib" || m.version != "1.2.3" || !slices.Equal(got, want) {
		t.Fatalf("gemspec %s %s %v", m.name, m.version, got)
	}
	// Generated library gemspecs stay unsupported until built or locked.
	for _, src := range []string{
		"Gem::Specification.new do |s|\n  s.version = MyLib::VERSION\nend\n",
		"Gem::Specification.new do |s|\n  s.files = `git ls-files`.split\nend\n",
		"Gem::Specification.new do |s|\n  s.files = Dir[\"lib/**\"]\nend\n",
		"require_relative \"lib/version\"\nGem::Specification.new do |s|\nend\n",
		"Gem::Specification.new do |s|\n  t.name = \"other\"\nend\n",
		"Gem::Specification.new do |s|\n  s.unknown = \"x\"\nend\n",
		"Gem::Specification.new do |s|\nend\nputs 1\n",
	} {
		if _, err := parseRubyGemspec([]byte(src)); !errors.Is(err, errRubyUnsupportedFormat) {
			t.Errorf("accepted generated gemspec %q: %v", src, err)
		}
	}
}

func TestRubyLockParser(t *testing.T) {
	lock := `GIT
  remote: https://github.com/org/forked.git
  revision: 0123456789abcdef0123456789abcdef01234567
  branch: main
  specs:
    forked (0.1.0)
      rack (>= 2)

PATH
  remote: ../local
  specs:
    local (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.0-arm64-darwin)
      racc (~> 1.4)
    nokogiri (1.16.0-x86_64-linux)
      racc (~> 1.4)
    racc (1.7.3)
    rack (3.0.8)

PLATFORMS
  arm64-darwin
  x86_64-linux

DEPENDENCIES
  forked!
  local!
  nokogiri
  rack (>= 2)

CHECKSUMS
  nokogiri (1.16.0-arm64-darwin) sha256=` + rubyHashA + `
  nokogiri (1.16.0-x86_64-linux) sha256=bad
  rack (3.0.8)

BUNDLED WITH
   2.5.3
`
	for _, eol := range []string{"\n", "\r\n"} {
		entries, reasons, err := parseRubyLock([]byte(strings.ReplaceAll(lock, "\n", eol)))
		if err != nil || !slices.Equal(reasons, []string{"checksum_invalid"}) {
			t.Fatalf("lock: %v %v", reasons, err)
		}
		got := []string{}
		for _, e := range entries {
			p := e.pkg
			got = append(got, fmt.Sprintf("%s %s %s %s %s %s %s %s %d %s", p.PackageName, p.Version, p.Platform, p.DependencyRelation, p.Origin.Kind, p.Origin.URL, e.local, p.ChecksumStatus, len(p.RecordedChecksums), p.Revision))
		}
		want := []string{
			"forked 0.1.0 ruby direct git https://github.com/org/forked.git  absent 0 0123456789abcdef0123456789abcdef01234567",
			"local 1.0.0 ruby direct path  ../local absent 0 ",
			"nokogiri 1.16.0 arm64-darwin direct registry https://rubygems.org/  recorded 1 ",
			"nokogiri 1.16.0 x86_64-linux direct registry https://rubygems.org/  partial 0 ",
			"racc 1.7.3 ruby transitive registry https://rubygems.org/  absent 0 ",
			"rack 3.0.8 ruby direct registry https://rubygems.org/  absent 0 ",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("entries\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}

	for _, tc := range []struct {
		name, lock string
		reasons    []string
		origin     string
		relation   string
	}{
		{"missing dependencies", "GEM\n  remote: https://rubygems.org/\n  specs:\n    x (1.0)\n", []string{"parse_error"}, "registry", "unknown"},
		{"unknown section", "GEM\n  remote: https://rubygems.org/\n  specs:\n    x (1.0)\n\nFUTURE\n  y\n\nDEPENDENCIES\n  x\n", []string{"unsupported_format"}, "registry", "direct"},
		{"plugin source", "PLUGIN SOURCE\n  remote: https://plugin.example.invalid\n  type: custom\n  specs:\n    x (1.0)\n\nDEPENDENCIES\n  x!\n", []string{"unsupported_format"}, "unknown", "direct"},
		{"several remotes", "GEM\n  remote: https://a.example.invalid/\n  remote: https://b.example.invalid/\n  specs:\n    x (1.0)\n\nDEPENDENCIES\n  x\n", []string{}, "unknown", "direct"},
		{"credential remote", "GEM\n  remote: https://CANARY_TOKEN@gems.example.invalid/\n  specs:\n    x (1.0)\n\nDEPENDENCIES\n  x\n", []string{}, "registry", "direct"},
		{"bad revision", "GIT\n  remote: https://github.com/org/x.git\n  revision: main\n  specs:\n    x (1.0)\n\nDEPENDENCIES\n  x!\n", []string{"parse_error"}, "git", "direct"},
		{"invalid spec keeps neighbors", "GEM\n  remote: https://rubygems.org/\n  specs:\n    -bad (1.0)\n    x (1.0)\n\nDEPENDENCIES\n  x\n", []string{"parse_error"}, "registry", "direct"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, reasons, err := parseRubyLock([]byte(tc.lock))
			if err != nil || !slices.Equal(reasons, tc.reasons) || len(entries) != 1 {
				t.Fatalf("entries %+v reasons %v err %v", entries, reasons, err)
			}
			p := entries[0].pkg
			if p.PackageName != "x" || p.Origin.Kind != tc.origin || p.DependencyRelation != tc.relation || p.Revision != "" || strings.Contains(p.Origin.URL, "CANARY") {
				t.Fatalf("entry %+v", p)
			}
		})
	}
	for _, bad := range []string{"", "  indented only\n", "\xff"} {
		if _, _, err := parseRubyLock([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRubyStubAndArchiveIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, data             string
		gem, version, platform string
		unsupported            bool
	}{
		{"native default", rubyStubHeader, "forwardable", "1.2.0", "ruby", false},
		{"native platform", "# -*- encoding: utf-8 -*-\r\n# stub: nokogiri 1.16.0 arm64-darwin lib\r\n", "nokogiri", "1.16.0", "arm64-darwin", false},
		{"no stub header", "Gem::Specification.new do |s|\nend\n", "", "", "", true},
		{"filename is never identity", "# -*- encoding: utf-8 -*-\nGem::Specification.new do |s|\nend\n", "", "", "", true},
		{"invalid identity", "#\n# stub: -bad 1.0 ruby lib\n", "", "", "", false},
		{"invalid version", "#\n# stub: x v1 ruby lib\n", "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, version, platform, err := parseRubyStub([]byte(tc.data))
			if name != tc.gem || version != tc.version || platform != tc.platform || (err == nil) != (tc.gem != "") || errors.Is(err, errRubyUnsupportedFormat) != tc.unsupported {
				t.Fatalf("stub = %q %q %q %v", name, version, platform, err)
			}
		})
	}

	native := rubyMetadataGz(t, rubyNativeMetadata)
	for _, tc := range []struct {
		name, archive, reason string
	}{
		{"native gz", rubyGemArchive(t, "metadata.gz", native, "data.tar.gz", "never decompressed", "checksums.yaml.gz", ""), ""},
		{"plain metadata", rubyGemArchive(t, "metadata", rubyNativeMetadata), ""},
		{"irrelevant alias", rubyGemArchive(t, "metadata", "a: &x [1]\nb: *x\n"+rubyNativeMetadata[strings.Index(rubyNativeMetadata, "name:"):]), ""},
		{"both variants", rubyGemArchive(t, "metadata.gz", native, "metadata", rubyNativeMetadata), "parse_error"},
		{"duplicate member", rubyGemArchive(t, "metadata.gz", native, "data.tar.gz", "", "metadata.gz", native), "parse_error"},
		{"no metadata", rubyGemArchive(t, "data.tar.gz", ""), "unsupported_format"},
		{"aliased identity", rubyGemArchive(t, "metadata", "x: &n did_you_mean\nname: *n\nversion: 1.0\nplatform: ruby\n"), "parse_error"},
		{"duplicate identity key", rubyGemArchive(t, "metadata", "name: a\nname: b\nversion: 1.0\nplatform: ruby\n"), "parse_error"},
		{"tagged identity", rubyGemArchive(t, "metadata", "name: !ruby/sym x\nversion: 1.0\nplatform: ruby\n"), "parse_error"},
		{"missing platform", rubyGemArchive(t, "metadata", "name: x\nversion: 1.0\n"), "parse_error"},
		{"not tar", "not a tar archive", "parse_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, version, platform, reason := parseRubyArchive([]byte(tc.archive))
			if reason != tc.reason || tc.reason == "" && (name != "did_you_mean" || version != "1.3.0" || platform != "ruby") || tc.reason != "" && name != "" {
				t.Fatalf("archive = %q %q %q %q", name, version, platform, reason)
			}
		})
	}

	// The bound applies to the expanded member, so a small gzip cannot inflate.
	old := maxRubyMetadataBytes
	maxRubyMetadataBytes = 1024
	t.Cleanup(func() { maxRubyMetadataBytes = old })
	bomb := rubyMetadataGz(t, rubyNativeMetadata+"padding: "+strings.Repeat("x", 4096)+"\n")
	if _, _, _, reason := parseRubyArchive([]byte(rubyGemArchive(t, "metadata.gz", bomb))); reason != "size_limit" {
		t.Fatalf("expanded metadata bound = %q", reason)
	}
	if _, _, _, reason := parseRubyArchive([]byte(rubyGemArchive(t, "metadata", strings.Repeat("x", 2048)))); reason != "size_limit" {
		t.Fatalf("plain metadata bound = %q", reason)
	}
}

func TestRubyLockOriginLocalGit(t *testing.T) {
	origin, local, reason := rubyLockOrigin(&rubyLockSource{section: "GIT", remotes: []string{"/srv/repos/x"}})
	if origin != (model.RubyOrigin{Kind: "path"}) || local != "/srv/repos/x" || reason != "" {
		t.Fatalf("local git = %+v %q %q", origin, local, reason)
	}
	origin, _, reason = rubyLockOrigin(&rubyLockSource{section: "GIT", remotes: []string{"git@github.com:org/x.git"}})
	if origin.URL != "[redacted]" || reason != "origin_unresolved" {
		t.Fatalf("scp git = %+v %q", origin, reason)
	}
}
