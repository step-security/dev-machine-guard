package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// rubyTrap confines the scan to the test's temporary tree, so shared roots
// on the host (/usr, /Library, Homebrew, C:\Ruby*) read as absent, counts
// filesystem calls, and fails on any read of a RubyGems credentials file.
type rubyTrap struct {
	*composerTrap
	sandbox string
	calls   *int
}

func (x *rubyTrap) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	return &rubyTrap{composerTrap: x.composerTrap.GuardedFiles(roots, guard, max).(*composerTrap), sandbox: x.sandbox, calls: x.calls}
}
func (x *rubyTrap) outside(method, path string) bool {
	*x.calls++
	path = filepath.Clean(path)
	if path == x.sandbox || strings.HasPrefix(path, x.sandbox+string(filepath.Separator)) {
		return false
	}
	x.unguarded(method)
	return true
}
func (x *rubyTrap) Stat(path string) (os.FileInfo, error) {
	if x.outside("Stat", path) {
		return nil, fs.ErrNotExist
	}
	return x.composerTrap.Stat(path)
}
func (x *rubyTrap) ReadDirLimit(path string, max int) ([]os.DirEntry, bool, error) {
	if x.outside("ReadDirLimit", path) {
		return nil, false, fs.ErrNotExist
	}
	return x.composerTrap.ReadDirLimit(path, max)
}
func (x *rubyTrap) EvalSymlinks(path string) (string, error) {
	if x.outside("EvalSymlinks", path) {
		return "", fs.ErrNotExist
	}
	return x.composerTrap.EvalSymlinks(path)
}
func (x *rubyTrap) ReadFile(path string) ([]byte, error) {
	if filepath.Base(path) == "credentials" {
		x.t.Fatalf("read credential file %s", path)
	}
	if x.outside("ReadFile", path) {
		return nil, fs.ErrNotExist
	}
	return x.composerTrap.ReadFile(path)
}

func rubyTestScanner(t *testing.T, home string) (*RubyScanner, *rubyTrap) {
	t.Helper()
	x := &rubyTrap{composerTrap: &composerTrap{goTrap: &goTrap{Executor: executor.NewReal(), t: t, current: goTestTarget(home)}, env: map[string]string{}, denied: map[string]error{}, reads: map[string]int{}, readErrors: map[string]error{}},
		sandbox: filepath.Dir(home), calls: new(int)}
	s := NewRubyScanner(x, progress.NewNoop())
	s.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(string) string { return "" }, func(string) bool { return false }
	}
	return s, x
}

func TestRubyScanCredentialReferences(t *testing.T) {
	for _, kind := range []string{"direct", "alias", "credential-alias", "xdg", "default-xdg", "config"} {
		t.Run(kind, func(t *testing.T) {
			home := goTestHome(t)
			root := filepath.Join(home, "projects")
			scanner, x := rubyTestScanner(t, home)
			credential := filepath.Join(home, ".gem", "credentials")
			switch kind {
			case "xdg":
				x.env["XDG_DATA_HOME"] = filepath.Join(home, "data")
				credential = filepath.Join(home, "data", "gem", "credentials")
			case "default-xdg":
				credential = filepath.Join(home, ".local", "share", "gem", "credentials")
			}
			goWrite(t, credential, "---\n:rubygems_api_key: CANARY_RUBY_CREDENTIAL\n", 0o600)
			reference := credential
			if kind == "alias" || kind == "credential-alias" {
				alias := filepath.Join(home, "Gemfile.shared")
				from, to := credential, alias
				if kind == "credential-alias" {
					if err := os.Rename(credential, alias); err != nil {
						t.Fatal(err)
					}
					from, to = alias, credential
				}
				if err := os.Symlink(from, to); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				reference = alias
			}
			manifest := filepath.Join(root, "Gemfile")
			if kind == "config" {
				x.env["BUNDLE_USER_CONFIG"] = credential
				goWrite(t, manifest, "source \"https://rubygems.org\"\n", 0o600)
			} else {
				goWrite(t, manifest, "eval_gemfile \""+filepath.ToSlash(reference)+"\"\n", 0o600)
			}
			inv, audit := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
			if x.reads[reference] != 0 || x.reads[credential] != 0 {
				t.Fatal("credential contents were read")
			}
			if kind == "config" {
				if !slices.Contains(audit.Reasons, "skipped_protected") {
					t.Fatalf("audit reasons: %v", audit.Reasons)
				}
			} else if !slices.Contains(inv.Reasons, "skipped_protected") {
				t.Fatalf("inventory reasons: %v", inv.Reasons)
			}
			found := false
			for _, f := range audit.CredentialFiles {
				if f.Path == credential && f.Presence == "present" {
					found = true
				}
			}
			if !found {
				t.Fatal("credential existence was lost")
			}
		})
	}
}

func rubyStub(name, version, platform string) string {
	return "# -*- encoding: utf-8 -*-\n# stub: " + name + " " + version + " " + platform + " lib\n\nGem::Specification.new do |s|\nend\n"
}

func rubyGemFile(t *testing.T, name, version string) string {
	t.Helper()
	metadata := strings.Replace(strings.Replace(rubyNativeMetadata, "did_you_mean", name, 1), "1.3.0", version, 1)
	return rubyGemArchive(t, "metadata.gz", rubyMetadataGz(t, metadata), "data.tar.gz", "")
}

// rubyWriteFixture lays out every evidence kind: a gems.rb project with an
// evaluated Gemfile, project gemspec, lock, configured project gem home,
// Git checkouts and vendor cache; an unsupported manifest whose lock
// survives; a lock-only directory; an unselected lock; a standalone gemspec;
// a walk-found gem home; runtime-manager, user and Bundler cache roots; and
// RubyGems/Bundler config. Secrets are canaries that must never appear.
func rubyWriteFixture(t *testing.T, home, root string) {
	t.Helper()
	app := filepath.Join(root, "app")
	goWrite(t, filepath.Join(app, "gems.rb"), `source "https://rubygems.org"
gemspec
eval_gemfile "../shared/Gemfile.shared"
gem "rails", "~> 7.1"
gem "local", path: "../local"
gem "forked", git: "https://github.com/org/forked.git"
group :test do
  gem "rspec"
end
`, 0o600)
	goWrite(t, filepath.Join(app, "Gemfile"), "raise \"gems.rb takes precedence\"\n", 0o600)
	goWrite(t, filepath.Join(app, "app.gemspec"), `Gem::Specification.new do |spec|
  spec.name = "app"
  spec.version = "1.0.0"
  spec.summary = "CANARY_SUMMARY"
  spec.add_development_dependency "rubocop", "~> 1.60"
end
`, 0o600)
	goWrite(t, filepath.Join(app, "gems.locked"), `GIT
  remote: https://github.com/org/forked.git
  revision: 0123456789abcdef0123456789abcdef01234567
  specs:
    forked (0.1.0)

PATH
  remote: ../local
  specs:
    local (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.0-arm64-darwin)
    nokogiri (1.16.0-x86_64-linux)
    rack (3.0.8)
    rails (7.1.3)
      rack (>= 2)

PLATFORMS
  arm64-darwin
  x86_64-linux

DEPENDENCIES
  forked!
  local!
  rails (~> 7.1)
  rspec

CHECKSUMS
  nokogiri (1.16.0-arm64-darwin) sha256=`+rubyHashA+`
  nokogiri (1.16.0-x86_64-linux) sha256=bad
  rack (3.0.8) sha256=`+rubyHashA+`

BUNDLED WITH
   2.5.3
`, 0o600)
	goWrite(t, filepath.Join(app, ".bundle", "config"), "---\nBUNDLE_PATH: \"vendor/bundle\"\n", 0o600)
	gems := filepath.Join(app, "vendor", "bundle", "ruby", "3.3.0")
	goWrite(t, filepath.Join(gems, "specifications", "rack-3.0.8.gemspec"), rubyStub("rack", "3.0.8", "ruby"), 0o600)
	goMkdir(t, filepath.Join(gems, "gems", "rack-3.0.8"))
	// A receipt whose package directory is gone changes presence only.
	goWrite(t, filepath.Join(gems, "specifications", "nokogiri-1.16.0-arm64-darwin.gemspec"), rubyStub("nokogiri", "1.16.0", "arm64-darwin"), 0o600)
	checkout := filepath.Join(gems, "bundler", "gems", "forked-0123456789ab")
	goWrite(t, filepath.Join(checkout, "forked.gemspec"), rubyStub("forked", "0.1.0", "ruby"), 0o600)
	goWrite(t, filepath.Join(checkout, "lib-a", "lib-a.gemspec"), rubyStub("lib-a", "0.1.0", "ruby"), 0o600)
	goWrite(t, filepath.Join(app, "vendor", "cache", "rack-3.0.8.gem"), rubyGemFile(t, "rack", "3.0.8"), 0o600)
	goWrite(t, filepath.Join(app, "vendor", "cache", "forked-0123456789ab", "forked.gemspec"), rubyStub("forked", "0.1.0", "ruby"), 0o600)
	goWrite(t, filepath.Join(root, "shared", "Gemfile.shared"), "gem \"shared-dep\"\n", 0o600)
	goWrite(t, filepath.Join(root, "local", "local.gemspec"), "Gem::Specification.new do |s|\n  s.name = \"local\"\n  s.version = \"1.0.0\"\n  s.add_dependency \"thor\"\nend\n", 0o600)
	// Executable Ruby: declarations are unproven, the lock still counts.
	goWrite(t, filepath.Join(root, "legacy", "Gemfile"), "gem \"rack\" if ENV[\"CANARY_ENV\"]\n", 0o600)
	goWrite(t, filepath.Join(root, "legacy", "Gemfile.lock"), "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n\nDEPENDENCIES\n  rack\n", 0o600)
	goWrite(t, filepath.Join(root, "lockonly", "Gemfile.lock"), "GEM\n  remote: https://rubygems.org/\n  specs:\n    json (2.7.1)\n\nDEPENDENCIES\n  json\n", 0o600)
	// Gemfile selects Gemfile.lock; the gems.locked beside it is independent.
	goWrite(t, filepath.Join(root, "pair", "Gemfile"), "source \"https://rubygems.org\"\ngem \"rake\"\n", 0o600)
	goWrite(t, filepath.Join(root, "pair", "gems.locked"), "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.1.0)\n\nDEPENDENCIES\n  rake\n", 0o600)
	goWrite(t, filepath.Join(root, "tools", "vendored", "specifications", "thor-1.3.0.gemspec"), rubyStub("thor", "1.3.0", "ruby"), 0o600)
	goMkdir(t, filepath.Join(root, "tools", "vendored", "gems", "thor-1.3.0"))

	prefix := filepath.Join(home, ".rbenv", "versions", "3.3.0")
	shared := filepath.Join(prefix, "lib", "ruby", "gems", "3.3.0")
	goWrite(t, filepath.Join(shared, "specifications", "default", "forwardable-1.2.0.gemspec"), rubyStubHeader, 0o600)
	goWrite(t, filepath.Join(shared, "specifications", "json-2.7.1.gemspec"), rubyStub("json", "2.7.1", "ruby"), 0o600)
	goMkdir(t, filepath.Join(shared, "gems", "json-2.7.1"))
	goWrite(t, filepath.Join(shared, "cache", "json-2.7.1.gem"), rubyGemFile(t, "json", "2.7.1"), 0o600)
	goWrite(t, filepath.Join(prefix, "etc", "gemrc"), ":ssl_verify_mode: 0\n", 0o600)
	goWrite(t, filepath.Join(home, ".gem", "ruby", "3.3.0", "specifications", "bundler-2.5.3.gemspec"), rubyStub("bundler", "2.5.3", "ruby"), 0o600)
	goWrite(t, filepath.Join(home, ".gem", "credentials"), "---\n:rubygems_api_key: CANARY_API_KEY\n", 0o600)
	goWrite(t, filepath.Join(home, ".bundle", "cache", "gems", "rubygems.org.443.0123456789abcdef", "rack-3.0.8.gem"), rubyGemFile(t, "rack", "3.0.8"), 0o600)
	goWrite(t, filepath.Join(home, ".bundle", "cache", "compact_index", "rubygems.org.443.0123456789abcdef", "versions"), "CANARY_INDEX\n", 0o600)
	goWrite(t, filepath.Join(home, ".gemrc"), "---\n:sources:\n- http://gems.example.invalid/\n- https://rubygems.org/\n:http_proxy: http://CANARY_USER:CANARY_PASS@proxy.example.invalid:8080\ngem: --CANARY_OPTION\n", 0o600)
	goWrite(t, filepath.Join(home, ".bundle", "config"), "---\nBUNDLE_DISABLE_CHECKSUM_VALIDATION: \"true\"\nBUNDLE_GEMS__EXAMPLE__COM: \"CANARY_USER:CANARY_PASS\"\nBUNDLE_JOBS: \"4\"\n", 0o600)
}

func rubyFixtureEnv(x *rubyTrap) {
	x.env["HTTPS_PROXY"] = "https://user:CANARY_PASSWORD@proxy.example.invalid:8443/?CANARY_QUERY"
	x.env["GEM_HOST_API_KEY"] = "CANARY_HOST_KEY"
	x.env["BUNDLE_GEMS__EXAMPLE__COM"] = "CANARY_USER:CANARY_PASS"
	x.env["BUNDLE_CANARY_SETTING"] = "CANARY_VALUE"
}

func rubyAssertRefs(t *testing.T, inv *model.RubyInventory, audit *model.RubyConfigAudit) {
	t.Helper()
	ids := map[string]bool{}
	for _, s := range inv.Sources {
		if ids[s.SourceID] {
			t.Error("duplicate source")
		}
		ids[s.SourceID] = true
	}
	ref := func(id string) {
		if !ids[id] {
			t.Errorf("dangling inventory source %s", id)
		}
	}
	for _, s := range inv.Sources {
		if s.ParentSourceID != "" {
			ref(s.ParentSourceID)
		}
		for _, id := range s.DiscoveredSources {
			ref(id)
		}
	}
	for _, p := range inv.Packages {
		ref(p.SourceID)
		for _, hash := range p.RecordedChecksums {
			ref(hash.SourceID)
		}
	}
	for _, p := range inv.Projects {
		ref(p.ManifestSourceID)
	}
	files := map[string]bool{}
	for _, f := range audit.Files {
		files[f.SourceID] = true
	}
	for _, c := range audit.Contexts {
		for _, id := range c.ConfigSourceIDs {
			if !files[id] {
				t.Error("dangling config context")
			}
		}
	}
	for _, f := range audit.Findings {
		if !files[f.SourceID] {
			t.Error("dangling finding")
		}
	}
	for _, v := range []any{inv, audit} {
		data, _ := json.Marshal(v)
		if bytes.Contains(data, []byte(":null")) {
			t.Fatal("null array")
		}
		if bytes.Contains(data, []byte("CANARY_")) {
			t.Fatal("output contains a credential canary")
		}
	}
}

func rubySource(t *testing.T, inv *model.RubyInventory, kind, path string) model.RubySource {
	t.Helper()
	for _, src := range inv.Sources {
		if src.Kind == kind && src.Path == path {
			return src
		}
	}
	t.Fatalf("no %s source for %s", kind, path)
	return model.RubySource{}
}

func rubyPackages(inv *model.RubyInventory, evidence, name string) []model.RubyPackage {
	var out []model.RubyPackage
	for _, p := range inv.Packages {
		if p.Evidence == evidence && (name == "" || p.PackageName == name) {
			out = append(out, p)
		}
	}
	return out
}

func rubyProject(t *testing.T, inv *model.RubyInventory, manifest string) model.RubyProject {
	t.Helper()
	for _, p := range inv.Projects {
		if p.ManifestPath == manifest {
			return p
		}
	}
	t.Fatalf("no project for %s", manifest)
	return model.RubyProject{}
}

func rubyOwned(inv *model.RubyInventory) map[string]int {
	owned := map[string]int{}
	for _, p := range inv.Packages {
		owned[p.SourceID]++
	}
	return owned
}

// rubyAssertComplete checks the retirement contract: a source a bounded scan
// leaves complete must still hold everything it holds unbounded.
func rubyAssertComplete(t *testing.T, budget int, owned map[string]int, inv *model.RubyInventory) {
	t.Helper()
	got := rubyOwned(inv)
	for _, src := range inv.Sources {
		if src.Status == "complete" && got[src.SourceID] != owned[src.SourceID] {
			t.Fatalf("budget %d: complete %s %s holds %d of %d packages", budget, src.Kind, src.Path, got[src.SourceID], owned[src.SourceID])
		}
	}
}

func TestRubyScanFixtureEvidence(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	app := filepath.Join(root, "app")
	rubyWriteFixture(t, home, root)
	scanner, x := rubyTestScanner(t, home)
	rubyFixtureEnv(x)
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	rubyAssertRefs(t, inv, audit)
	if inv.Status != "partial" || !slices.Equal(inv.Reasons, []string{"checksum_invalid", "unsupported_format"}) {
		t.Fatalf("inventory %s %v", inv.Status, inv.Reasons)
	}
	if x.reads[filepath.Join(app, "Gemfile")] != 0 {
		t.Error("read Gemfile beside gems.rb")
	}

	if p := rubyProject(t, inv, filepath.Join(app, "gems.rb")); p.SelectionStatus != "observed" || !slices.Equal(p.LockfilePaths, []string{filepath.Join(app, "gems.locked")}) || p.PackageName != "app" || p.PackageVersion != "1.0.0" {
		t.Errorf("app project %+v", p)
	}
	if p := rubyProject(t, inv, filepath.Join(root, "legacy", "Gemfile")); p.SelectionStatus != "partial" || len(p.LockfilePaths) != 1 {
		t.Errorf("unsupported manifest project %+v", p)
	}
	if p := rubyProject(t, inv, filepath.Join(root, "pair", "Gemfile")); p.SelectionStatus != "partial" || len(p.LockfilePaths) != 0 {
		t.Errorf("project beside an unselected lock %+v", p)
	}
	if p := rubyProject(t, inv, filepath.Join(root, "local", "local.gemspec")); p.SelectionStatus != "observed" || p.PackageName != "local" {
		t.Errorf("standalone gemspec %+v", p)
	}
	if len(inv.Projects) != 4 {
		t.Errorf("projects %+v", inv.Projects)
	}
	if src := rubySource(t, inv, "manifest", filepath.Join(root, "legacy", "Gemfile")); src.Status != "partial" || !slices.Equal(src.Reasons, []string{"unsupported_format"}) {
		t.Errorf("unsupported manifest %+v", src)
	}

	type want struct {
		evidence, name, sourcePath, project, scope string
		check                                      func(model.RubyPackage) bool
	}
	gems := filepath.Join(app, "vendor", "bundle", "ruby", "3.3.0")
	checkout := filepath.Join(gems, "bundler", "gems", "forked-0123456789ab")
	shared := filepath.Join(home, ".rbenv", "versions", "3.3.0", "lib", "ruby", "gems", "3.3.0")
	local := filepath.Join(root, "local")
	installed := func(path, presence string) func(model.RubyPackage) bool {
		return func(p model.RubyPackage) bool {
			return p.Installation != nil && p.Installation.Path == path && p.Installation.Presence == presence && !p.Installation.DefaultGem && p.Origin.Kind == "unknown"
		}
	}
	for _, w := range []want{
		{"declared_requirement", "rails", filepath.Join(app, "gems.rb"), app, "project", func(p model.RubyPackage) bool {
			return p.Origin == model.RubyOrigin{Kind: "registry", URL: "https://rubygems.org"} && p.RequestedVersions != nil && slices.Equal(*p.RequestedVersions, []string{"~> 7.1"}) &&
				p.DependencyKind == "unknown" && p.VersionStatus == "unknown"
		}},
		{"declared_requirement", "rspec", filepath.Join(app, "gems.rb"), app, "project", func(p model.RubyPackage) bool { return slices.Equal(p.Groups, []string{"test"}) }},
		{"declared_requirement", "local", filepath.Join(app, "gems.rb"), app, "project", func(p model.RubyPackage) bool { return p.Origin == model.RubyOrigin{Kind: "path", Path: local} }},
		{"declared_requirement", "forked", filepath.Join(app, "gems.rb"), app, "project", func(p model.RubyPackage) bool { return p.Origin.Kind == "git" }},
		{"declared_requirement", "shared-dep", filepath.Join(root, "shared", "Gemfile.shared"), app, "project", func(p model.RubyPackage) bool { return p.Origin.Kind == "registry" }},
		{"declared_requirement", "rubocop", filepath.Join(app, "app.gemspec"), app, "project", func(p model.RubyPackage) bool { return p.DependencyKind == "development" }},
		{"declared_requirement", "thor", filepath.Join(local, "local.gemspec"), local, "project", func(p model.RubyPackage) bool { return p.Origin.Kind == "unknown" && p.DependencyKind == "runtime" }},
		{"locked_package", "forked", filepath.Join(app, "gems.locked"), app, "project", func(p model.RubyPackage) bool {
			return p.Revision == "0123456789abcdef0123456789abcdef01234567" && p.DependencyRelation == "direct"
		}},
		{"locked_package", "local", filepath.Join(app, "gems.locked"), app, "project", func(p model.RubyPackage) bool { return p.Origin == model.RubyOrigin{Kind: "path", Path: local} }},
		{"locked_package", "rack", filepath.Join(app, "gems.locked"), app, "project", func(p model.RubyPackage) bool {
			return p.ChecksumStatus == "recorded" && p.DependencyRelation == "transitive" && p.RecordedChecksums[0].SourceKind == "lockfile"
		}},
		{"locked_package", "rack", filepath.Join(root, "legacy", "Gemfile.lock"), filepath.Join(root, "legacy"), "project", func(p model.RubyPackage) bool { return p.Version == "2.2.8" }},
		{"locked_package", "json", filepath.Join(root, "lockonly", "Gemfile.lock"), filepath.Join(root, "lockonly"), "project", func(p model.RubyPackage) bool { return true }},
		{"locked_package", "rake", filepath.Join(root, "pair", "gems.locked"), filepath.Join(root, "pair"), "project", func(p model.RubyPackage) bool { return true }},
		{"installed_package", "rack", filepath.Join(gems, "specifications", "rack-3.0.8.gemspec"), app, "project", installed(filepath.Join(gems, "gems", "rack-3.0.8"), "present")},
		{"installed_package", "nokogiri", filepath.Join(gems, "specifications", "nokogiri-1.16.0-arm64-darwin.gemspec"), app, "project", installed(filepath.Join(gems, "gems", "nokogiri-1.16.0-arm64-darwin"), "absent")},
		{"installed_package", "forked", filepath.Join(checkout, "forked.gemspec"), app, "project", installed(checkout, "present")},
		{"installed_package", "lib-a", filepath.Join(checkout, "lib-a", "lib-a.gemspec"), app, "project", installed(filepath.Join(checkout, "lib-a"), "present")},
		{"installed_package", "forwardable", filepath.Join(shared, "specifications", "default", "forwardable-1.2.0.gemspec"), "", "user", func(p model.RubyPackage) bool {
			return *p.Installation == model.RubyInstallation{PathStatus: "not_applicable", Presence: "not_applicable", DefaultGem: true}
		}},
		{"installed_package", "json", filepath.Join(shared, "specifications", "json-2.7.1.gemspec"), "", "user", installed(filepath.Join(shared, "gems", "json-2.7.1"), "present")},
		{"installed_package", "bundler", filepath.Join(home, ".gem", "ruby", "3.3.0", "specifications", "bundler-2.5.3.gemspec"), "", "user", installed(filepath.Join(home, ".gem", "ruby", "3.3.0", "gems", "bundler-2.5.3"), "absent")},
		{"installed_package", "thor", filepath.Join(root, "tools", "vendored", "specifications", "thor-1.3.0.gemspec"), "", "user", installed(filepath.Join(root, "tools", "vendored", "gems", "thor-1.3.0"), "present")},
		{"cached_package", "rack", filepath.Join(app, "vendor", "cache", "rack-3.0.8.gem"), app, "project", func(p model.RubyPackage) bool { return p.Installation == nil }},
		{"cached_package", "forked", filepath.Join(app, "vendor", "cache", "forked-0123456789ab", "forked.gemspec"), app, "project", func(p model.RubyPackage) bool { return p.Installation == nil }},
		{"cached_package", "json", filepath.Join(shared, "cache", "json-2.7.1.gem"), "", "user", func(p model.RubyPackage) bool { return p.Version == "2.7.1" }},
		{"cached_package", "rack", filepath.Join(home, ".bundle", "cache", "gems", "rubygems.org.443.0123456789abcdef", "rack-3.0.8.gem"), "", "user", func(p model.RubyPackage) bool { return p.Origin.Kind == "unknown" }},
	} {
		found := false
		for _, p := range rubyPackages(inv, w.evidence, w.name) {
			if p.SourcePath == w.sourcePath {
				found = true
				if p.ProjectPath != w.project || p.Scope != w.scope || !w.check(p) {
					t.Errorf("%s %s from %s = %+v", w.evidence, w.name, w.sourcePath, p)
				}
			}
		}
		if !found {
			t.Errorf("missing %s %s from %s", w.evidence, w.name, w.sourcePath)
		}
	}
	if n := len(rubyPackages(inv, "locked_package", "nokogiri")); n != 2 {
		t.Errorf("multi-platform lock rows = %d", n)
	}
	if src := rubySource(t, inv, "lockfile", filepath.Join(app, "gems.locked")); src.Status != "partial" || !slices.Equal(src.Reasons, []string{"checksum_invalid"}) {
		t.Errorf("lock with an invalid checksum %+v", src)
	}
	if src := rubySource(t, inv, "gem_home", filepath.Join(root, "tools", "vendored")); src.ParentSourceID != rubySource(t, inv, "project_search_root", root).SourceID {
		t.Errorf("walk-found gem home %+v", src)
	}
	for _, src := range inv.Sources {
		if strings.Contains(src.Path, "compact_index") || src.Path == filepath.Join(app, "Gemfile") {
			t.Errorf("unexpected source %+v", src)
		}
	}

	if len(audit.CredentialFiles) != 1 || audit.CredentialFiles[0].Presence != "present" || audit.CredentialFiles[0].Path != filepath.Join(home, ".gem", "credentials") {
		t.Errorf("credential files %+v", audit.CredentialFiles)
	}
	codes := map[string]bool{}
	for _, f := range audit.Findings {
		codes[f.Code] = true
	}
	if len(codes) != 4 {
		t.Errorf("findings %+v", audit.Findings)
	}
	contexts := map[string]int{}
	for _, c := range audit.Contexts {
		contexts[c.Manager]++
	}
	// One ambient RubyGems and Bundler context, plus one per Bundler project.
	if contexts["rubygems"] != 1 || contexts["bundler"] != 4 {
		t.Errorf("contexts %+v", audit.Contexts)
	}
}

func TestRubyScanUnknownProcessAndDeveloper(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	rubyWriteFixture(t, home, root)
	scanner, x := rubyTestScanner(t, home)
	x.current.Uid = "1001"
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	rubyAssertRefs(t, inv, audit)
	for _, f := range audit.Files {
		if f.Scope == "process" && (f.Status != "unsupported" || !slices.Contains(f.Reasons, "user_unresolved")) {
			t.Errorf("process file = %+v", f)
		}
	}
	for _, c := range audit.Contexts {
		if c.SelectionStatus != "partial" {
			t.Errorf("unverified process left %s context complete: %+v", c.Manager, c)
		}
	}
	// Default roots do not depend on the process environment.
	rubySource(t, inv, "gem_home", filepath.Join(home, ".rbenv", "versions", "3.3.0", "lib", "ruby", "gems", "3.3.0"))

	scanner, x = rubyTestScanner(t, home)
	target := goTestTarget(home)
	target.Uid = "0"
	if x.GOOS() == model.PlatformWindows {
		target.Uid = "S-1-5-18"
	}
	x.current = target
	inv, audit = scanner.Scan(context.Background(), target, []string{root}, nil)
	if inv.Status != "partial" || !slices.Equal(inv.Reasons, []string{"user_unresolved"}) || len(inv.Sources) != 0 || audit.Status != "partial" {
		t.Fatalf("service identity scanned: %+v", inv)
	}
}

func TestRubyScanLimitsDeadlineAndGuards(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	app := filepath.Join(root, "app")
	legacyLock := filepath.Join(root, "legacy", "Gemfile.lock")
	rubyWriteFixture(t, home, root)
	scanner, x := rubyTestScanner(t, home)
	rubyFixtureEnv(x)
	full, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	total := len(full.Sources) + len(full.Projects) + len(full.Packages)
	owned := rubyOwned(full)
	old := maxRubyRecords
	t.Cleanup(func() { maxRubyRecords = old })
	for budget := 1; budget < total; budget++ {
		maxRubyRecords = budget
		inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		if inv.Status != "partial" || !slices.Contains(inv.Reasons, "record_limit") || len(inv.Sources)+len(inv.Projects)+len(inv.Packages) > budget {
			t.Fatalf("budget %d: status %s reasons %v", budget, inv.Status, inv.Reasons)
		}
		rubyAssertComplete(t, budget, owned, inv)
		rubyAssertRefs(t, inv, audit)
	}
	maxRubyRecords = old

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	*x.calls = 0
	inv, audit := scanner.Scan(ctx, goTestTarget(home), []string{root}, nil)
	rubyAssertRefs(t, inv, audit)
	if inv.Status != "partial" || !slices.Contains(inv.Reasons, "deadline_exceeded") || len(inv.Packages) != 0 || *x.calls != 0 {
		t.Fatalf("cancelled scan = %s %v %d packages after %d filesystem calls", inv.Status, inv.Reasons, len(inv.Packages), *x.calls)
	}
	// Cancellation mid-project stops later reads and leaves the shared
	// evaluated Gemfile unproven.
	ctx, cancel = context.WithCancel(context.Background())
	x.reads, x.afterRead = map[string]int{}, func(path string) {
		if path == filepath.Join(app, "gems.locked") {
			cancel()
		}
	}
	inv, audit = scanner.Scan(ctx, goTestTarget(home), []string{root}, nil)
	x.afterRead = nil
	rubyAssertRefs(t, inv, audit)
	if !slices.Contains(inv.Reasons, "deadline_exceeded") || x.reads[legacyLock] != 0 {
		t.Fatalf("cancelled scan kept reading: reasons %v", inv.Reasons)
	}
	if src := rubySource(t, inv, "manifest", filepath.Join(root, "shared", "Gemfile.shared")); src.Status != "partial" {
		t.Errorf("shared manifest left complete after cancellation: %+v", src)
	}

	// Cancelling right after a manifest naming `gemspec` is read stops
	// discovery: no candidate listing or any other filesystem call follows.
	ctx, cancel = context.WithCancel(context.Background())
	after := -1
	x.afterRead = func(path string) {
		if path == filepath.Join(app, "gems.rb") {
			cancel()
			after = *x.calls
		}
	}
	inv, audit = scanner.Scan(ctx, goTestTarget(home), []string{root}, nil)
	x.afterRead = nil
	rubyAssertRefs(t, inv, audit)
	if after < 0 || *x.calls != after {
		t.Fatalf("filesystem calls after cancellation: %d then %d", after, *x.calls)
	}

	// Permission denied is never absence.
	x.readErrors[filepath.Join(app, "gems.locked")] = os.ErrPermission
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	rubyAssertRefs(t, inv, audit)
	if src := rubySource(t, inv, "lockfile", filepath.Join(app, "gems.locked")); src.Presence != "unknown" || !slices.Contains(src.Reasons, "permission_denied") {
		t.Errorf("unreadable lock = %+v", src)
	}
	if p := rubyProject(t, inv, filepath.Join(app, "gems.rb")); len(p.LockfilePaths) != 1 {
		t.Errorf("unreadable selected lock dropped from project: %+v", p)
	}
	delete(x.readErrors, filepath.Join(app, "gems.locked"))

	scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(p string) string {
			if strings.HasPrefix(p, filepath.Join(root, "legacy")) {
				return "skipped_protected"
			}
			return ""
		}, func(string) bool { return false }
	}
	x.reads = map[string]int{}
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	rubyAssertRefs(t, inv, audit)
	if src := rubySource(t, inv, "project_search_root", root); !slices.Contains(src.Reasons, "skipped_protected") || x.reads[legacyLock] != 0 {
		t.Errorf("protected directory not reported: %+v", src)
	}

	// A blocked interpreter may hide its etc/gemrc: the audit is partial so
	// earlier history is kept, and files that were read keep their settings.
	prefix := filepath.Join(home, ".rbenv", "versions", "3.3.0")
	scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(p string) string {
			if p == prefix || strings.HasPrefix(p, prefix+string(filepath.Separator)) {
				return "skipped_protected"
			}
			return ""
		}, func(string) bool { return false }
	}
	_, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	if audit.Status != "partial" || !slices.Contains(audit.Reasons, "skipped_protected") {
		t.Errorf("blocked interpreter left audit %s %v", audit.Status, audit.Reasons)
	}
	for _, c := range audit.Contexts {
		if c.Manager == "rubygems" && c.SelectionStatus != "partial" {
			t.Errorf("blocked interpreter left RubyGems context %+v", c)
		}
	}
	for _, f := range audit.Files {
		if f.Path == filepath.Join(home, ".gemrc") && (f.Status != "present" || len(f.Settings) == 0) {
			t.Errorf("readable gemrc lost its settings: %+v", f)
		}
	}
	scanner, x = rubyTestScanner(t, home)
	rubyFixtureEnv(x)

	t.Run("truncated interpreter listing", func(t *testing.T) {
		home := goTestHome(t)
		root := filepath.Join(home, "projects")
		versions := filepath.Join(home, ".rbenv", "versions")
		for i := range maxRubyListEntries + 1 {
			goWrite(t, filepath.Join(versions, strconv.Itoa(i)), "", 0o600)
		}
		scanner, _ := rubyTestScanner(t, home)
		inv, audit := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
		if !slices.Contains(inv.Reasons, "entry_limit") || !slices.Contains(audit.Reasons, "entry_limit") {
			t.Fatalf("truncated listing: inventory %v, audit %v", inv.Reasons, audit.Reasons)
		}
	})

	// Every output budget keeps admitted records and leaves only fully
	// collected sources complete.
	oldOut := maxRubyOutputBytes
	t.Cleanup(func() { maxRubyOutputBytes = oldOut })
	empty := emptyRubyInventory()
	base, step := goJSONSize(&empty)+(256<<10), goJSONSize(full)/40
	for limit := base; ; limit += step {
		if limit > base+4*goJSONSize(full) {
			t.Fatal("output budget never admitted the full inventory")
		}
		maxRubyOutputBytes = limit
		inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		if !slices.Contains(inv.Reasons, "output_size_limit") {
			break
		}
		if inv.Status != "partial" || goJSONSize(inv)+goJSONSize(audit) > limit {
			t.Fatalf("limit %d: status %s size %d", limit, inv.Status, goJSONSize(inv)+goJSONSize(audit))
		}
		rubyAssertComplete(t, limit, owned, inv)
		rubyAssertRefs(t, inv, audit)
	}
}

func TestRubyScanRootsAndTargetedGemfile(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	rubyWriteFixture(t, home, root)
	scanner, x := rubyTestScanner(t, home)
	first, firstAudit := scanner.Scan(context.Background(), goTestTarget(home), []string{root, root, filepath.Join(root, "app")}, nil)
	second, secondAudit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	a, _ := json.Marshal([]any{first, firstAudit})
	b, _ := json.Marshal([]any{second, secondAudit})
	if !bytes.Equal(a, b) {
		t.Fatal("nested or repeated roots changed the inventory")
	}

	// BUNDLE_GEMFILE selects a project outside every search root; a missing
	// targeted manifest is absent, never a walk.
	elsewhere := filepath.Join(home, "elsewhere")
	goWrite(t, filepath.Join(elsewhere, "Gemfile"), "source \"https://rubygems.org\"\ngem \"sinatra\"\n", 0o600)
	goWrite(t, filepath.Join(elsewhere, "Gemfile.lock"), "GEM\n  remote: https://rubygems.org/\n  specs:\n    sinatra (4.0.0)\n\nDEPENDENCIES\n  sinatra\n", 0o600)
	x.env["BUNDLE_GEMFILE"] = filepath.Join(elsewhere, "Gemfile")
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	rubyAssertRefs(t, inv, audit)
	if p := rubyProject(t, inv, filepath.Join(elsewhere, "Gemfile")); p.SelectionStatus != "observed" || len(p.LockfilePaths) != 1 {
		t.Errorf("targeted project %+v", p)
	}
	if len(rubyPackages(inv, "locked_package", "sinatra")) != 1 || len(rubyPackages(inv, "declared_requirement", "sinatra")) != 1 {
		t.Error("targeted project evidence missing")
	}
	x.env["BUNDLE_GEMFILE"] = filepath.Join(home, "missing", "Gemfile")
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	rubyAssertRefs(t, inv, audit)
	if src := rubySource(t, inv, "manifest", filepath.Join(home, "missing", "Gemfile")); src.Presence != "absent" || src.Status != "complete" {
		t.Errorf("missing targeted manifest %+v", src)
	}

	// An existing alternate Gemfile replaces its directory's default manifest;
	// the lock it does not select stays independent evidence.
	pair := filepath.Join(root, "pair")
	goWrite(t, filepath.Join(pair, "Gemfile.ci"), "source \"https://rubygems.org\"\ngem \"ci-only\"\n", 0o600)
	x.env["BUNDLE_GEMFILE"] = filepath.Join(pair, "Gemfile.ci")
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	rubyAssertRefs(t, inv, audit)
	if p := rubyProject(t, inv, filepath.Join(pair, "Gemfile.ci")); p.SelectionStatus != "partial" || len(p.LockfilePaths) != 0 {
		t.Errorf("selected alternate Gemfile %+v", p)
	}
	for _, p := range inv.Projects {
		if p.ManifestPath == filepath.Join(pair, "Gemfile") {
			t.Error("default Gemfile scanned beside the selected Gemfile.ci")
		}
	}
	if len(rubyPackages(inv, "declared_requirement", "ci-only")) != 1 || len(rubyPackages(inv, "declared_requirement", "rake")) != 0 || len(rubyPackages(inv, "locked_package", "rake")) != 1 {
		t.Error("alternate Gemfile selection changed evidence")
	}

	// Two spellings of one gem home emit its facts once.
	link := filepath.Join(home, "gems-link")
	if err := os.Symlink(filepath.Join(home, ".rbenv", "versions", "3.3.0", "lib", "ruby", "gems", "3.3.0"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	delete(x.env, "BUNDLE_GEMFILE")
	x.env["GEM_PATH"] = link
	inv, _ = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	if n := len(rubyPackages(inv, "installed_package", "json")); n != 1 {
		t.Fatalf("aliased gem home duplicated facts: %d", n)
	}

	// A runtime alias must not turn missing optional directories into refusals.
	prefix := filepath.Join(home, ".rbenv", "versions", "3.3.0")
	physical := filepath.Join(home, "ruby-keg")
	if err := os.Rename(prefix, physical); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(physical, prefix); err != nil {
		t.Fatal(err)
	}
	inv, audit = scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
	gemHome := filepath.Join(physical, "lib", "ruby", "gems", "3.3.0")
	if src := rubySource(t, inv, "gem_home", gemHome); src.Status != "complete" {
		t.Errorf("aliased runtime gem home = %+v", src)
	}
	for _, f := range audit.Files {
		if slices.Contains(f.Reasons, "outside_approved_roots") {
			t.Errorf("aliased runtime config = %+v", f)
		}
	}
}

// A shared evaluated Gemfile is complete only when every consumer that could
// use it was read; otherwise backend retirement of its occurrences is unsafe.
func TestRubyScanSharedManifestCoverage(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	shared := filepath.Join(root, "shared.rb")
	goWrite(t, shared, "gem \"rack\"\n", 0o600)
	for _, name := range []string{"a", "b"} {
		goWrite(t, filepath.Join(root, name, "Gemfile"), "source \"https://rubygems.org\"\neval_gemfile \"../shared.rb\"\n", 0o600)
	}
	consumer := filepath.Join(root, "b")
	for _, tc := range []struct {
		name, reason  string
		deny, protect bool
		uses          int
	}{
		{name: "every consumer read", uses: 2},
		{name: "unreadable consumer", reason: "permission_denied", deny: true, uses: 1},
		{name: "protected consumer", reason: "skipped_protected", protect: true, uses: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner, x := rubyTestScanner(t, home)
			if tc.deny {
				x.readErrors[filepath.Join(consumer, "Gemfile")] = os.ErrPermission
			}
			if tc.protect {
				scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
					return func(p string) string {
						if p == consumer || strings.HasPrefix(p, consumer+string(filepath.Separator)) {
							return "skipped_protected"
						}
						return ""
					}, func(string) bool { return false }
				}
			}
			inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
			rubyAssertRefs(t, inv, audit)
			if n := len(rubyPackages(inv, "declared_requirement", "rack")); n != tc.uses {
				t.Errorf("shared declarations = %d, want %d", n, tc.uses)
			}
			src := rubySource(t, inv, "manifest", shared)
			if tc.reason == "" && src.Status != "complete" || tc.reason != "" && (src.Status != "partial" || !slices.Contains(src.Reasons, tc.reason)) {
				t.Errorf("shared manifest %+v", src)
			}
		})
	}
}
