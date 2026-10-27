package detector

import (
	"bytes"
	"context"
	"encoding/json"
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

// condaTrap adds the Conda-specific never-read files: credential stores,
// download URL lists, index caches and Python requirement files.
type condaTrap struct{ *rubyTrap }

func (x *condaTrap) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	return &condaTrap{x.rubyTrap.GuardedFiles(roots, guard, max).(*rubyTrap)}
}
func (x *condaTrap) ReadFile(path string) ([]byte, error) {
	name := filepath.Base(path)
	if slices.Contains([]string{".netrc", "_netrc", "tokens", "urls.txt", "requirements.txt", "repodata.json"}, name) ||
		strings.Contains(path, "binstar") || strings.Contains(filepath.ToSlash(path), "/pkgs/cache/") {
		x.t.Fatalf("read forbidden file %s", path)
	}
	return x.rubyTrap.ReadFile(path)
}

func condaTestScanner(t *testing.T, home string) (*CondaScanner, *condaTrap) {
	t.Helper()
	_, inner := rubyTestScanner(t, home)
	x := &condaTrap{inner}
	s := NewCondaScanner(x, progress.NewNoop())
	s.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(string) string { return "" }, func(string) bool { return false }
	}
	return s, x
}

// condaReceipt is a conda-meta record in the shape Conda writes: identity,
// channel, download URL and checksums, with the never-read link data trimmed.
func condaReceipt(name, version, build, subdir, channel, url, md5, sha256, requested string) string {
	return `{"name":"` + name + `","version":"` + version + `","build":"` + build + `","build_number":0,"subdir":"` + subdir + `","channel":"` + channel + `","url":"` + url + `",` +
		`"md5":"` + md5 + `","sha256":"` + sha256 + `","fn":"` + name + `-` + version + `-` + build + `.conda","depends":[],"constrains":[],"files":["lib/x"],"paths_data":{"paths":[],"paths_version":1},` +
		`"link":{"source":"/Users/CANARY_HOME/pkgs/` + name + `","type":1},"extracted_package_dir":"/Users/CANARY_HOME/pkgs/` + name + `","requested_specs":[` + requested + `]}` + "\n"
}

const condaTzdata = `{"name":"tzdata","version":"2024b","build":"hc8b5060_0","build_number":0,"subdir":"noarch","noarch":"generic","channel":"https://conda.anaconda.org/conda-forge/noarch",` +
	`"url":"https://conda.anaconda.org/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda","sha256":"` + condaSHA_A + `","md5":"` + condaMD5A + `","requested_spec":"None","license":"LicenseRef-Public-Domain"}` + "\n"

func condaWriteFixture(t *testing.T, home, root string) {
	t.Helper()
	history := "==> 2024-09-01 10:00:00 <==\n# cmd: conda create -n app packaging\n+conda-forge::packaging-24.1-pyhd8ed1ab_0\n"
	base := filepath.Join(home, "miniforge3")
	meta := filepath.Join(base, "conda-meta")
	goWrite(t, filepath.Join(meta, "history"), history, 0o600)
	// A Windows launcher package has files but no path data.
	goWrite(t, filepath.Join(meta, "conda-launchers-1.0.0-h57928b3_0.json"), `{"name":"conda-launchers","version":"1.0.0","build":"h57928b3_0","build_number":0,"subdir":"win-64",`+
		`"channel":"https://conda.anaconda.org/conda-forge/win-64","url":"https://conda.anaconda.org/conda-forge/win-64/conda-launchers-1.0.0-h57928b3_0.conda","md5":"`+condaMD5A+`",`+
		`"files":["Scripts/a.exe","Scripts/b.exe","Scripts/c.exe","Scripts/d.exe","Scripts/e.exe","Scripts/f.exe"],"paths_data":{"paths":[],"paths_version":1},"requested_spec":"None"}`+"\n", 0o600)
	goWrite(t, filepath.Join(meta, "_openmp_mutex-4.5-2_gnu.json"), `{"name":"_openmp_mutex","version":"4.5","build":"2_gnu","build_number":2,"subdir":"linux-64","channel":"https://conda.anaconda.org/conda-forge/linux-64",`+
		`"url":"https://conda.anaconda.org/conda-forge/linux-64/_openmp_mutex-4.5-2_gnu.tar.bz2","md5":"`+condaMD5A+`","sha256":"`+condaSHA_A+`","requested_specs":["_openmp_mutex=4.5=2_gnu"]}`+"\n", 0o600)
	goWrite(t, filepath.Join(meta, "broken-1.0-0.json"), `{"name":"broken",`, 0o600)
	goWrite(t, filepath.Join(meta, "renamed-1.0-0.json"), `{"name":"other","version":"1.0","build":"0"}`, 0o600)
	goWrite(t, filepath.Join(meta, "._tmp-1.0-0.json"), `{"name":"tmp","version":"1.0","build":"0"}`, 0o600)
	goWrite(t, filepath.Join(meta, "state"), `{"env_vars":{"CONDA_SSL_VERIFY":"false","CONDA_CHANNELS":"***unset***","HTTPS_PROXY":"https://u:CANARY_STATE@proxy.example.invalid:8443"}}`, 0o600)
	goWrite(t, filepath.Join(base, ".condarc"), "channels:\n  - https://user:CANARY_RC@private.example.invalid/ch\n  - conda-forge\nssl_verify: false\nsafety_checks: disabled\n", 0o600)

	app := filepath.Join(base, "envs", "app")
	appMeta := filepath.Join(app, "conda-meta")
	goWrite(t, filepath.Join(appMeta, "history"), history, 0o600)
	goWrite(t, filepath.Join(appMeta, "packaging-24.1-pyhd8ed1ab_0.json"), condaReceipt("packaging", "24.1", "pyhd8ed1ab_0", "noarch", "https://conda.anaconda.org/conda-forge/noarch",
		"https://conda.anaconda.org/conda-forge/noarch/packaging-24.1-pyhd8ed1ab_0.conda", condaMD5A, condaSHA_A, `"packaging"`), 0o600)
	// Mamba records a bare channel label beside the full download URL.
	goWrite(t, filepath.Join(appMeta, "zlib-1.3.1-h4e2bd7c_1.json"), condaReceipt("zlib", "1.3.1", "h4e2bd7c_1", "osx-arm64", "conda-forge",
		"https://conda.anaconda.org/conda-forge/osx-arm64/zlib-1.3.1-h4e2bd7c_1.conda", condaMD5A, condaSHA_A, ""), 0o600)
	goWrite(t, filepath.Join(appMeta, "ansi2html-1.9.5-py3_none_any_0.json"), `{"name":"ansi2html","version":"1.9.5","build":"py3_none_any_0","build_number":0,"subdir":"noarch","noarch":"python","channel":"conda-pypi",`+
		`"url":"https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl","sha256":"`+condaSHA_A+`","requested_spec":"conda-pypi::ansi2html"}`+"\n", 0o600)
	goWrite(t, filepath.Join(appMeta, "secret-1.0-0.json"), condaReceipt("secret", "1.0", "0", "osx-arm64", "https://user:CANARY_PASS@private.example.invalid/t/CANARY_TOKEN/ch/osx-arm64",
		"https://user:CANARY_PASS@private.example.invalid/t/CANARY_TOKEN/ch/osx-arm64/secret-1.0-0.conda", condaMD5A, condaSHA_A,
		`"https://user:CANARY_PASS@private.example.invalid/t/CANARY_TOKEN/ch::secret","CANARY_USER@private.example.invalid:secret"`), 0o600)
	goWrite(t, filepath.Join(appMeta, "badsum-1.0-0.json"), `{"name":"badsum","version":"1.0","build":"0","channel":"conda-forge","md5":"xyz"}`, 0o600)
	goWrite(t, filepath.Join(base, "envs", "empty", "conda-meta", "history"), history, 0o600)
	goWrite(t, filepath.Join(base, "envs", "nohistory", "conda-meta", "tzdata-2024b-hc8b5060_0.json"), condaTzdata, 0o600)

	pkgs := filepath.Join(base, "pkgs")
	goWrite(t, filepath.Join(pkgs, "packaging-24.1-pyhd8ed1ab_0", "info", "index.json"), `{"name":"packaging","version":"24.1","build":"pyhd8ed1ab_0","build_number":0,"subdir":"noarch","depends":["python >=3.8"]}`, 0o600)
	goWrite(t, filepath.Join(pkgs, "packaging-24.1-pyhd8ed1ab_0", "info", "repodata_record.json"), condaReceipt("packaging", "24.1", "pyhd8ed1ab_0", "noarch", "https://conda.anaconda.org/conda-forge/noarch",
		"https://conda.anaconda.org/conda-forge/noarch/packaging-24.1-pyhd8ed1ab_0.conda", condaMD5A, condaSHA_A, ""), 0o600)
	goWrite(t, filepath.Join(pkgs, "packaging-24.1-pyhd8ed1ab_0.conda"), "CANARY_ARCHIVE", 0o600)
	goWrite(t, filepath.Join(pkgs, "zlib-1.3.1-h4e2bd7c_1", "info", "index.json"), `{"name":"zlib","version":"1.3.1","build":"h4e2bd7c_1","build_number":1,"subdir":"osx-arm64"}`, 0o600)
	goWrite(t, filepath.Join(pkgs, "broken-1.0-0", "info", "index.json"), `{"name":"broken","version":"1.0","build":"0","subdir":"noarch"}`, 0o600)
	goWrite(t, filepath.Join(pkgs, "broken-1.0-0", "info", "repodata_record.json"), `{"name":"broken",`, 0o600)
	goWrite(t, filepath.Join(pkgs, "orphan-1.0-0.tar.bz2"), "CANARY_ARCHIVE", 0o600)
	goWrite(t, filepath.Join(pkgs, "cache", "repodata.json"), `{"CANARY_INDEX":1}`, 0o600)
	goWrite(t, filepath.Join(pkgs, "urls.txt"), "https://user:CANARY_URLS@x.example.invalid/a.conda\n", 0o600)
	goMkdir(t, filepath.Join(pkgs, "locks"))

	mm := filepath.Join(home, "micromamba")
	goWrite(t, filepath.Join(mm, "pkgs", "https", "conda.anaconda.org", "conda-forge", "noarch", "tzdata-2024b-hc8b5060_0", "info", "index.json"), `{"name":"tzdata","version":"2024b","build":"hc8b5060_0","build_number":0,"subdir":"noarch","noarch":"generic"}`, 0o600)
	goWrite(t, filepath.Join(mm, "envs", "mm", "conda-meta", "history"), history, 0o600)
	goWrite(t, filepath.Join(mm, "envs", "mm", "conda-meta", "tzdata-2024b-hc8b5060_0.json"), condaTzdata, 0o600)

	goWrite(t, filepath.Join(home, ".conda", "envs", "old", "conda-meta", "history"), history, 0o600)
	goWrite(t, filepath.Join(home, ".conda", "pkgs", "urls.txt"), "CANARY_URLS\n", 0o600)
	elsewhere := filepath.Join(home, "elsewhere", "env")
	goWrite(t, filepath.Join(elsewhere, "conda-meta", "history"), history, 0o600)
	goWrite(t, filepath.Join(elsewhere, "conda-meta", "tzdata-2024b-hc8b5060_0.json"), condaTzdata, 0o600)
	goWrite(t, filepath.Join(home, ".conda", "environments.txt"), base+"\n"+elsewhere+"\r\n"+filepath.Join(home, "stale-env")+"\nrelative/junk\n\n", 0o600)

	lead := filepath.Join(home, "extra-envs", "lead")
	goWrite(t, filepath.Join(lead, "conda-meta", "history"), history, 0o600)
	goWrite(t, filepath.Join(lead, "conda-meta", "tzdata-2024b-hc8b5060_0.json"), condaTzdata, 0o600)
	goWrite(t, filepath.Join(home, "extra-pkgs", "bzip2-1.0.8-h99b78c6_7", "info", "index.json"), `{"name":"bzip2","version":"1.0.8","build":"h99b78c6_7","build_number":7,"subdir":"osx-arm64"}`, 0o600)
	goWrite(t, filepath.Join(home, ".netrc"), "machine x login CANARY_NETRC password CANARY_NETRC\n", 0o600)

	proj := filepath.Join(root, "proj")
	goWrite(t, filepath.Join(proj, "environment.yml"), `name: proj
channels:
  - nodefaults
  - http://mirror.example.invalid/conda
  - https://conda.anaconda.org/t/CANARY_TOKEN/private
  - conda-forge
dependencies:
  - python=3.12
  - conda-forge::numpy>=1.26
  - numpy*
  - __glibc>=2.17
  - pip
  - requests  # [win]
  - pip:
      - ansi2html==1.9.5
variables:
  SECRET: CANARY_VARIABLE
prefix: /Users/CANARY_HOME/miniforge3/envs/proj
`, 0o600)
	goWrite(t, filepath.Join(proj, "environment.json"), `{"name": "proj", "channels": ["conda-forge"], "dependencies": ["python=3.12"], "prefix": "/Users/CANARY_HOME/miniforge3/envs/proj"}`, 0o600)
	goWrite(t, filepath.Join(proj, ".conda", "conda-meta", "history"), history, 0o600)
	goWrite(t, filepath.Join(proj, ".conda", "conda-meta", "tzdata-2024b-hc8b5060_0.json"), condaTzdata, 0o600)
	goWrite(t, filepath.Join(proj, "explicit.txt"), `# This file may be used to create an environment using:
# $ conda create --name <env> --file <this file>
# platform: osx-arm64
@EXPLICIT
https://conda.anaconda.org/conda-forge/osx-arm64/bzip2-1.0.8-h93a5062_5.conda#`+condaMD5A+`
https://conda.anaconda.org/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda#sha256:`+condaSHA_A+`
https://conda.anaconda.org/t/CANARY_TOKEN/private/osx-arm64/zlib-1.2.13-h53f4e23_5.conda
https://conda.anaconda.org/conda-forge/osx-arm64/libffi-3.4.2-h3422bc3_5.tar.bz2#CANARY_FRAGMENT
file:///opt/channel/osx-arm64/local-1.0-0.conda
pkgs/relative-1.0-0.conda
https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl
`, 0o600)
	goWrite(t, filepath.Join(proj, "conda-lock.yml"), `# This lock file was generated by conda-lock. DO NOT EDIT!
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
    md5: `+condaMD5A+`
  manager: conda
  name: _libgcc_mutex
  optional: false
  platform: linux-64
  url: https://conda.anaconda.org/conda-forge/linux-64/_libgcc_mutex-0.1-conda_forge.tar.bz2
  version: '0.1'
- category: main
  dependencies: {}
  hash:
    sha256: `+condaSHA_A+`
  manager: conda
  name: tzdata
  optional: false
  platform: linux-64
  url: https://conda.anaconda.org/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda
  version: 2024b
- category: main
  dependencies: {}
  hash:
    sha256: `+condaSHA_A+`
  manager: conda
  name: tzdata
  optional: false
  platform: osx-arm64
  url: https://conda.anaconda.org/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda
  version: 2024b
- category: main
  dependencies: {}
  hash:
    sha256: `+condaSHA_A+`
  manager: pip
  name: requests
  optional: false
  platform: linux-64
  url: https://files.pythonhosted.org/packages/ab/cd/requests-2.32.3-py3-none-any.whl
  version: 2.32.3
- category: main
  dependencies: {}
  hash:
    md5: `+condaMD5A+`
  manager: conda
  name: private
  optional: false
  platform: linux-64
  url: https://user:CANARY_LOCK@conda.anaconda.org/private/linux-64/private-1.0-0.conda
  version: '1.0'
version: 1
`, 0o600)
	goWrite(t, filepath.Join(proj, "pixi.lock"), `version: 6
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
        - conda: https://prefix.dev/conda-forge/linux-64/missing-1.0-0.conda
packages:
  - conda: https://prefix.dev/conda-forge/osx-arm64/bzip2-1.0.8-h99b78c6_7.conda
    sha256: `+condaSHA_A+`
    md5: `+condaMD5A+`
    depends:
      - __osx >=11.0
    license: bzip2-1.0.6
    purls: []
    size: 122909
    timestamp: 1720974522888
  - conda: https://prefix.dev/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda
    sha256: `+condaSHA_A+`
    md5: `+condaMD5A+`
    license: LicenseRef-Public-Domain
    size: 122354
  - conda: https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl
    build_number: 0
    sha256: `+condaSHA_A+`
  - pypi: https://files.pythonhosted.org/packages/ab/cd/numpy-2.2.1-cp313-cp313-macosx_11_0_arm64.whl
    name: numpy
    version: 2.2.1
    sha256: `+condaSHA_A+`
  - conda: ../minimal-project
    name: minimal-project
    version: "0.1"
    subdir: linux-64
    build: hbf21a9e_0
`, 0o600)
	pixiMeta := filepath.Join(proj, ".pixi", "envs", "default", "conda-meta")
	goWrite(t, filepath.Join(pixiMeta, "pixi"), `{"manifest_path":"`+filepath.ToSlash(filepath.Join(proj, "pixi.toml"))+`","environment_name":"default","pixi_version":"0.40.0"}`, 0o600)
	goWrite(t, filepath.Join(pixiMeta, "bzip2-1.0.8-h99b78c6_7.json"), condaReceipt("bzip2", "1.0.8", "h99b78c6_7", "osx-arm64", "https://prefix.dev/conda-forge/osx-arm64",
		"https://prefix.dev/conda-forge/osx-arm64/bzip2-1.0.8-h99b78c6_7.conda", condaMD5A, condaSHA_A, ""), 0o600)
	goWrite(t, filepath.Join(proj, "conda-dev.lock"), "# platform: linux-64\n@EXPLICIT\nhttps://conda.anaconda.org/conda-forge/linux-64/_libgcc_mutex-0.1-conda_forge.tar.bz2#"+condaMD5A+"\n", 0o600)
	goWrite(t, filepath.Join(proj, "conda-notes.lock"), "notes about CANARY_NOTES\n", 0o600)
	goWrite(t, filepath.Join(proj, "requirements.txt"), "https://user:CANARY_PIP@pypi.example.invalid/simple\n", 0o600)
	goWrite(t, filepath.Join(root, "legacy", "environment.yaml"), "channels:\n  - conda-forge\ndependencies:\n  - python\n  - sel(win): m2-base\n", 0o600)
	goWrite(t, filepath.Join(root, "lockonly", "conda-lock.yaml"), "version: 2\npackage: []\n", 0o600)
	goWrite(t, filepath.Join(root, "node_modules", "dep", "environment.yml"), "dependencies:\n  - CANARY_SKIPPED\n", 0o600)
}

func condaFixtureEnv(x *condaTrap, home string) {
	x.env["HTTPS_PROXY"] = "https://user:CANARY_PASSWORD@proxy.example.invalid:8443/?CANARY_QUERY"
	x.env["CONDA_ENVS_DIRS"] = filepath.Join(home, "extra-envs")
	x.env["CONDA_PKGS_DIRS"] = filepath.Join(home, "extra-pkgs")
	x.env["CONDA_PREFIX"] = filepath.Join(home, "miniforge3", "envs", "app")
	x.env["CONDA_CHANNEL_ALIAS"] = "https://conda.example.invalid/t/CANARY_ALIAS"
}

func condaAssertRefs(t *testing.T, inv *model.CondaInventory, audit *model.CondaConfigAudit) {
	t.Helper()
	ids := map[string]bool{}
	for _, s := range inv.Sources {
		if ids[s.SourceID] {
			t.Error("duplicate source")
		}
		ids[s.SourceID] = true
		if s.Status == "complete" && s.Presence == "unknown" {
			t.Errorf("complete source with unknown presence: %+v", s)
		}
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
		if _, ok := condaName(p.PackageName); !ok || condaVirtual(p.PackageName) {
			t.Errorf("invalid package name %q", p.PackageName)
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
		if bytes.Contains(data, []byte("CANARY")) {
			t.Fatalf("output contains a canary: %s", data)
		}
	}
}

func condaSource(t *testing.T, inv *model.CondaInventory, kind, path string) model.CondaSource {
	t.Helper()
	for _, src := range inv.Sources {
		if src.Kind == kind && src.Path == path {
			return src
		}
	}
	t.Fatalf("no %s source for %s", kind, path)
	return model.CondaSource{}
}

func condaPackages(inv *model.CondaInventory, evidence, name string) []model.CondaPackage {
	var out []model.CondaPackage
	for _, p := range inv.Packages {
		if p.Evidence == evidence && (name == "" || p.PackageName == name) {
			out = append(out, p)
		}
	}
	return out
}

func condaProject(t *testing.T, inv *model.CondaInventory, manifest string) model.CondaProject {
	t.Helper()
	for _, p := range inv.Projects {
		if p.ManifestPath == manifest {
			return p
		}
	}
	t.Fatalf("no project for %s", manifest)
	return model.CondaProject{}
}

func condaOwned(inv *model.CondaInventory) map[string]int {
	owned := map[string]int{}
	for _, p := range inv.Packages {
		owned[p.SourceID]++
	}
	return owned
}

// condaAssertComplete checks the retirement contract: a source a bounded scan
// leaves complete must still hold everything it holds unbounded.
func condaAssertComplete(t *testing.T, budget int, owned map[string]int, inv *model.CondaInventory) {
	t.Helper()
	got := condaOwned(inv)
	for _, src := range inv.Sources {
		if src.Status == "complete" && got[src.SourceID] != owned[src.SourceID] {
			t.Fatalf("budget %d: complete %s %s holds %d of %d packages", budget, src.Kind, src.Path, got[src.SourceID], owned[src.SourceID])
		}
	}
}

func TestCondaScanFixtureEvidence(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	condaWriteFixture(t, home, root)
	scanner, x := condaTestScanner(t, home)
	condaFixtureEnv(x, home)
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	condaAssertRefs(t, inv, audit)
	base := filepath.Join(home, "miniforge3")
	app := filepath.Join(base, "envs", "app")
	proj := filepath.Join(root, "proj")

	type want struct{ evidence, name, source, project, scope string }
	wants := []want{
		{"installed_package", "conda-launchers", filepath.Join(base, "conda-meta", "conda-launchers-1.0.0-h57928b3_0.json"), "", "user"},
		{"installed_package", "_openmp_mutex", filepath.Join(base, "conda-meta", "_openmp_mutex-4.5-2_gnu.json"), "", "user"},
		{"installed_package", "packaging", filepath.Join(app, "conda-meta", "packaging-24.1-pyhd8ed1ab_0.json"), "", "user"},
		{"installed_package", "zlib", filepath.Join(app, "conda-meta", "zlib-1.3.1-h4e2bd7c_1.json"), "", "user"},
		{"installed_package", "ansi2html", filepath.Join(app, "conda-meta", "ansi2html-1.9.5-py3_none_any_0.json"), "", "user"},
		{"installed_package", "secret", filepath.Join(app, "conda-meta", "secret-1.0-0.json"), "", "user"},
		{"installed_package", "badsum", filepath.Join(app, "conda-meta", "badsum-1.0-0.json"), "", "user"},
		{"installed_package", "tzdata", filepath.Join(base, "envs", "nohistory", "conda-meta", "tzdata-2024b-hc8b5060_0.json"), "", "user"},
		{"installed_package", "tzdata", filepath.Join(home, "micromamba", "envs", "mm", "conda-meta", "tzdata-2024b-hc8b5060_0.json"), "", "user"},
		{"installed_package", "tzdata", filepath.Join(home, "elsewhere", "env", "conda-meta", "tzdata-2024b-hc8b5060_0.json"), "", "user"},
		{"installed_package", "tzdata", filepath.Join(home, "extra-envs", "lead", "conda-meta", "tzdata-2024b-hc8b5060_0.json"), "", "user"},
		{"installed_package", "tzdata", filepath.Join(proj, ".conda", "conda-meta", "tzdata-2024b-hc8b5060_0.json"), proj, "project"},
		{"installed_package", "bzip2", filepath.Join(proj, ".pixi", "envs", "default", "conda-meta", "bzip2-1.0.8-h99b78c6_7.json"), proj, "project"},
		{"cached_package", "packaging", filepath.Join(base, "pkgs", "packaging-24.1-pyhd8ed1ab_0", "info"), "", "user"},
		{"cached_package", "zlib", filepath.Join(base, "pkgs", "zlib-1.3.1-h4e2bd7c_1", "info"), "", "user"},
		{"cached_package", "broken", filepath.Join(base, "pkgs", "broken-1.0-0", "info"), "", "user"},
		{"cached_package", "tzdata", filepath.Join(home, "micromamba", "pkgs", "https", "conda.anaconda.org", "conda-forge", "noarch", "tzdata-2024b-hc8b5060_0", "info"), "", "user"},
		{"cached_package", "bzip2", filepath.Join(home, "extra-pkgs", "bzip2-1.0.8-h99b78c6_7", "info"), "", "user"},
		{"declared_requirement", "python", filepath.Join(proj, "environment.yml"), proj, "project"},
		{"declared_requirement", "numpy", filepath.Join(proj, "environment.yml"), proj, "project"},
		{"declared_requirement", "pip", filepath.Join(proj, "environment.yml"), proj, "project"},
		{"declared_requirement", "python", filepath.Join(proj, "environment.json"), proj, "project"},
		{"declared_requirement", "python", filepath.Join(root, "legacy", "environment.yaml"), filepath.Join(root, "legacy"), "project"},
		{"locked_package", "bzip2", filepath.Join(proj, "explicit.txt"), proj, "project"},
		{"locked_package", "tzdata", filepath.Join(proj, "explicit.txt"), proj, "project"},
		{"locked_package", "zlib", filepath.Join(proj, "explicit.txt"), proj, "project"},
		{"locked_package", "libffi", filepath.Join(proj, "explicit.txt"), proj, "project"},
		{"locked_package", "local", filepath.Join(proj, "explicit.txt"), proj, "project"},
		{"locked_package", "relative", filepath.Join(proj, "explicit.txt"), proj, "project"},
		{"locked_package", "_libgcc_mutex", filepath.Join(proj, "conda-lock.yml"), proj, "project"},
		{"locked_package", "tzdata", filepath.Join(proj, "conda-lock.yml"), proj, "project"},
		{"locked_package", "tzdata", filepath.Join(proj, "conda-lock.yml"), proj, "project"},
		{"locked_package", "private", filepath.Join(proj, "conda-lock.yml"), proj, "project"},
		{"locked_package", "bzip2", filepath.Join(proj, "pixi.lock"), proj, "project"},
		{"locked_package", "tzdata", filepath.Join(proj, "pixi.lock"), proj, "project"},
		{"locked_package", "tzdata", filepath.Join(proj, "pixi.lock"), proj, "project"},
		{"locked_package", "minimal-project", filepath.Join(proj, "pixi.lock"), proj, "project"},
		{"locked_package", "_libgcc_mutex", filepath.Join(proj, "conda-dev.lock"), proj, "project"},
	}
	got := []want{}
	for _, p := range inv.Packages {
		got = append(got, want{p.Evidence, p.PackageName, p.SourcePath, p.ProjectPath, p.Scope})
	}
	key := func(w want) string {
		return strings.Join([]string{w.evidence, w.name, w.source, w.project, w.scope}, "\x00")
	}
	slices.SortFunc(wants, func(a, b want) int { return strings.Compare(key(a), key(b)) })
	slices.SortFunc(got, func(a, b want) int { return strings.Compare(key(a), key(b)) })
	if !slices.Equal(got, wants) {
		t.Errorf("package rows:\n got %+v\nwant %+v", got, wants)
	}

	installed := func(name, source string) model.CondaPackage {
		for _, p := range condaPackages(inv, "installed_package", name) {
			if strings.HasPrefix(p.SourcePath, source) {
				return p
			}
		}
		t.Fatalf("no installed %s under %s", name, source)
		return model.CondaPackage{}
	}
	if p := installed("packaging", app); p.Version != "24.1" || p.Build != "pyhd8ed1ab_0" || p.Subdir != "noarch" || p.BuildNumber == nil || *p.BuildNumber != 0 || p.VersionStatus != "known" ||
		p.DependencyRelation != "direct" || !slices.Equal(p.RequestedSpecs, []string{"packaging"}) || p.Origin != (model.CondaOrigin{Kind: "channel", URL: "https://conda.anaconda.org/conda-forge"}) ||
		p.ArtifactURL != "https://conda.anaconda.org/conda-forge/noarch/packaging-24.1-pyhd8ed1ab_0.conda" || p.ChecksumStatus != "recorded" || len(p.RecordedChecksums) != 2 ||
		p.EnvironmentPath != app || p.Installation == nil || p.Installation.Path != app || p.Installation.Presence != "present" || len(p.Reasons) != 0 {
		t.Errorf("installed packaging %+v", p)
	}
	if p := installed("zlib", app); p.Origin != (model.CondaOrigin{Kind: "channel", URL: "https://conda.anaconda.org/conda-forge"}) || p.DependencyRelation != "unknown" || len(p.RequestedSpecs) != 0 {
		t.Errorf("mamba bare label %+v", p)
	}
	if p := installed("ansi2html", app); p.Origin.Kind != "unknown" || p.ArtifactURL != "https://files.pythonhosted.org/packages/ab/cd/ansi2html-1.9.5-py3-none-any.whl" || !slices.Equal(p.RequestedSpecs, []string{"conda-pypi::ansi2html"}) {
		t.Errorf("wheel receipt %+v", p)
	}
	if p := installed("secret", app); p.Origin != (model.CondaOrigin{Kind: "channel", URL: "https://private.example.invalid/ch"}) || p.ArtifactURL != "https://private.example.invalid/ch/osx-arm64/secret-1.0-0.conda" ||
		!slices.Equal(p.RequestedSpecs, []string{"https://private.example.invalid/ch::secret", condaRedacted}) {
		t.Errorf("credential receipt %+v", p)
	}
	if p := installed("badsum", app); p.ChecksumStatus != "partial" || !slices.Equal(p.Reasons, []string{"checksum_invalid"}) || p.Origin.Kind != "unknown" {
		t.Errorf("bad checksum %+v", p)
	}
	if p := installed("_openmp_mutex", base); p.BuildNumber == nil || *p.BuildNumber != 2 || p.DependencyRelation != "direct" {
		t.Errorf("openmp %+v", p)
	}
	if p := installed("conda-launchers", base); p.ChecksumStatus != "recorded" || len(p.RecordedChecksums) != 1 || p.Subdir != "win-64" {
		t.Errorf("launchers %+v", p)
	}
	for _, p := range condaPackages(inv, "cached_package", "") {
		if p.EnvironmentPath != "" || p.Installation != nil || p.DependencyRelation != "unknown" || len(p.RequestedSpecs) != 0 {
			t.Errorf("cached row %+v", p)
		}
		switch p.PackageName {
		case "packaging":
			if p.Origin.Kind != "channel" || p.ChecksumStatus != "recorded" {
				t.Errorf("cached download record %+v", p)
			}
		default:
			if p.Origin.Kind != "unknown" || p.ChecksumStatus != "absent" || p.ArtifactURL != "" {
				t.Errorf("cached index fallback %+v", p)
			}
		}
	}
	for _, p := range condaPackages(inv, "declared_requirement", "") {
		if p.VersionStatus != "unknown" || p.DependencyRelation != "direct" || len(p.RequestedSpecs) != 1 || p.ChecksumStatus != "absent" || p.EnvironmentPath != "" {
			t.Errorf("declared row %+v", p)
		}
	}
	if p := condaPackages(inv, "declared_requirement", "numpy"); p[0].RequestedSpecs[0] != "conda-forge::numpy>=1.26" || p[0].Origin.Kind != "unknown" {
		t.Errorf("qualified declaration %+v", p[0])
	}
	locked := func(name, lock, platform string) model.CondaPackage {
		for _, p := range condaPackages(inv, "locked_package", name) {
			if p.SourcePath == filepath.Join(proj, lock) && (platform == "" || p.TargetPlatform == platform) {
				return p
			}
		}
		t.Fatalf("no locked %s in %s", name, lock)
		return model.CondaPackage{}
	}
	if p := locked("zlib", "explicit.txt", ""); p.ArtifactURL != "https://conda.anaconda.org/private/osx-arm64/zlib-1.2.13-h53f4e23_5.conda" || p.Origin.URL != "https://conda.anaconda.org/private" || p.TargetPlatform != "osx-arm64" {
		t.Errorf("token lock row %+v", p)
	}
	if p := locked("libffi", "explicit.txt", ""); p.ChecksumStatus != "partial" || !slices.Equal(p.Reasons, []string{"checksum_invalid"}) {
		t.Errorf("bad fragment row %+v", p)
	}
	if p := locked("local", "explicit.txt", ""); p.Origin != (model.CondaOrigin{Kind: "local", Path: "/opt/channel"}) {
		t.Errorf("local channel row %+v", p)
	}
	if p := locked("relative", "explicit.txt", ""); !slices.Equal(p.Reasons, []string{"path_unresolved"}) || p.Origin.Kind != "unknown" {
		t.Errorf("relative row %+v", p)
	}
	if p := locked("private", "conda-lock.yml", ""); p.ArtifactURL != "https://conda.anaconda.org/private/linux-64/private-1.0-0.conda" || p.Origin.URL != "https://conda.anaconda.org/private" {
		t.Errorf("credential lock row %+v", p)
	}
	if p := locked("bzip2", "pixi.lock", "osx-arm64"); p.LockEnvironment != "default" || len(p.RecordedChecksums) != 2 || p.Build != "h99b78c6_7" {
		t.Errorf("pixi row %+v", p)
	}
	if p := locked("minimal-project", "pixi.lock", "linux-64"); p.VersionStatus != "known" || p.Version != "0.1" || !slices.Equal(p.Reasons, []string{"path_unresolved"}) {
		t.Errorf("pixi source row %+v", p)
	}

	type srcWant struct {
		kind, path, status, presence string
		reasons                      []string
	}
	for _, w := range []srcWant{
		{"project_search_root", root, "partial", "present", []string{"checksum_invalid", "parse_error", "path_unresolved", "unsupported_format"}},
		{"environment_root", base, "partial", "present", []string{"checksum_invalid", "extraction_incomplete", "identity_mismatch", "parse_error", "unsupported_format"}},
		{"environment", base, "partial", "present", []string{"identity_mismatch", "parse_error"}},
		{"installed_metadata", filepath.Join(base, "conda-meta", "broken-1.0-0.json"), "partial", "present", []string{"parse_error"}},
		{"installed_metadata", filepath.Join(base, "conda-meta", "renamed-1.0-0.json"), "partial", "present", []string{"identity_mismatch"}},
		{"installed_metadata", filepath.Join(base, "conda-meta", "conda-launchers-1.0.0-h57928b3_0.json"), "complete", "present", []string{}},
		{"environment", app, "partial", "present", []string{"checksum_invalid"}},
		{"installed_metadata", filepath.Join(app, "conda-meta", "badsum-1.0-0.json"), "partial", "present", []string{"checksum_invalid"}},
		{"installed_metadata", filepath.Join(app, "conda-meta", "secret-1.0-0.json"), "complete", "present", []string{}},
		{"environment", filepath.Join(base, "envs", "empty"), "complete", "present", []string{}},
		{"environment", filepath.Join(base, "envs", "nohistory"), "partial", "present", []string{"extraction_incomplete"}},
		{"cache_root", filepath.Join(base, "pkgs"), "partial", "present", []string{"parse_error", "unsupported_format"}},
		{"cached_metadata", filepath.Join(base, "pkgs", "broken-1.0-0", "info"), "partial", "present", []string{"parse_error"}},
		{"cached_metadata", filepath.Join(base, "pkgs", "zlib-1.3.1-h4e2bd7c_1", "info"), "complete", "present", []string{}},
		{"environment_root", filepath.Join(home, "micromamba"), "complete", "present", []string{}},
		{"cache_root", filepath.Join(home, "micromamba", "pkgs"), "complete", "present", []string{}},
		{"environment_root", filepath.Join(home, ".conda"), "complete", "present", []string{}},
		{"environment", filepath.Join(home, ".conda", "envs", "old"), "complete", "present", []string{}},
		{"environment", filepath.Join(home, "elsewhere", "env"), "complete", "present", []string{}},
		{"environment", filepath.Join(home, "extra-envs", "lead"), "complete", "present", []string{}},
		{"cache_root", filepath.Join(home, "extra-pkgs"), "complete", "present", []string{}},
		{"environment", filepath.Join(proj, ".conda"), "complete", "present", []string{}},
		{"environment", filepath.Join(proj, ".pixi", "envs", "default"), "complete", "present", []string{}},
		{"manifest", filepath.Join(proj, "environment.yml"), "partial", "present", []string{"unsupported_format"}},
		{"manifest", filepath.Join(proj, "environment.json"), "complete", "present", []string{}},
		{"manifest", filepath.Join(root, "legacy", "environment.yaml"), "partial", "present", []string{"unsupported_format"}},
		{"lockfile", filepath.Join(proj, "explicit.txt"), "partial", "present", []string{"checksum_invalid", "path_unresolved", "unsupported_format"}},
		{"lockfile", filepath.Join(proj, "conda-lock.yml"), "complete", "present", []string{}},
		{"lockfile", filepath.Join(proj, "pixi.lock"), "partial", "present", []string{"parse_error", "path_unresolved", "unsupported_format"}},
		{"lockfile", filepath.Join(proj, "conda-dev.lock"), "complete", "present", []string{}},
		{"lockfile", filepath.Join(root, "lockonly", "conda-lock.yaml"), "partial", "present", []string{"unsupported_format"}},
	} {
		src := condaSource(t, inv, w.kind, w.path)
		if src.Status != w.status || src.Presence != w.presence || !slices.Equal(src.Reasons, w.reasons) {
			t.Errorf("%s %s = %s/%s %v, want %s/%s %v", w.kind, w.path, src.Status, src.Presence, src.Reasons, w.status, w.presence, w.reasons)
		}
	}
	for _, src := range inv.Sources {
		switch {
		case strings.Contains(src.Path, "conda-notes.lock"), strings.Contains(src.Path, "node_modules"), strings.Contains(src.Path, "stale-env"), strings.Contains(src.Path, "._tmp"):
			t.Errorf("unexpected source %+v", src)
		}
	}
	if inv.Status != "partial" || !slices.Equal(inv.Reasons, []string{"checksum_invalid", "extraction_incomplete", "identity_mismatch", "parse_error", "path_unresolved", "unsupported_format"}) {
		t.Errorf("inventory %s %v", inv.Status, inv.Reasons)
	}
	if p := condaProject(t, inv, filepath.Join(proj, "environment.yml")); p.SelectionStatus != "partial" || p.ProjectPath != proj ||
		!slices.Equal(p.LockfilePaths, []string{filepath.Join(proj, "conda-dev.lock"), filepath.Join(proj, "conda-lock.yml"), filepath.Join(proj, "explicit.txt"), filepath.Join(proj, "pixi.lock")}) {
		t.Errorf("project %+v", p)
	}
	if p := condaProject(t, inv, filepath.Join(proj, "environment.json")); p.SelectionStatus != "observed" || len(p.LockfilePaths) != 4 {
		t.Errorf("json project %+v", p)
	}
	if len(inv.Projects) != 3 {
		t.Errorf("projects %+v", inv.Projects)
	}
	// Caches, prefixes and environment roots are never walked for projects.
	if x.reads[filepath.Join(base, "pkgs", "urls.txt")] != 0 || x.reads[filepath.Join(proj, "requirements.txt")] != 0 || x.reads[filepath.Join(proj, "conda-notes.lock")] != 1 {
		t.Errorf("reads %v", x.reads)
	}

	// Configuration: the root file, saved state and manifest channels are
	// observed; findings carry no credential text.
	findings := map[string]bool{}
	for _, f := range audit.Findings {
		for _, file := range audit.Files {
			if file.SourceID == f.SourceID {
				findings[f.Code+" "+file.Scope+" "+filepath.Base(file.Path)+" "+f.Key] = true
			}
		}
	}
	for _, want := range []string{
		"conda-002 system .condarc ssl_verify", "conda-003 system .condarc auth_configured",
		"conda-002 environment state ssl_verify", "conda-003 environment state auth_configured",
		"conda-001 project environment.yml channels.1.url", "conda-003 project environment.yml auth_configured",
	} {
		if !findings[want] {
			t.Errorf("missing finding %s in %v", want, findings)
		}
	}
	// Two manifests share one project path; a partial one marks the project.
	contexts := map[string]string{}
	for _, c := range audit.Contexts {
		if key := c.EnvironmentPath + "|" + c.ProjectPath; contexts[key] != "partial" {
			contexts[key] = c.SelectionStatus
		}
	}
	for _, key := range []string{"|", app + "|", base + "|", filepath.Join(proj, ".conda") + "|", "|" + proj, "|" + filepath.Join(root, "legacy")} {
		if contexts[key] == "" {
			t.Errorf("missing context %q in %v", key, contexts)
		}
	}
	if contexts[filepath.Join(base, "envs", "empty")+"|"] != "observed" || contexts["|"+proj] != "partial" || contexts["|"] != "observed" {
		t.Errorf("context selection %v", contexts)
	}
	if audit.Status != "partial" || !slices.Contains(audit.Reasons, "unsupported_format") {
		t.Errorf("audit %s %v", audit.Status, audit.Reasons)
	}
	present := 0
	for _, c := range audit.CredentialFiles {
		if c.Presence == "present" {
			present++
		}
	}
	if present != 1 {
		t.Errorf("credential files %+v", audit.CredentialFiles)
	}
}

func TestCondaScanUnknownProcessAndDeveloper(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	condaWriteFixture(t, home, root)
	scanner, x := condaTestScanner(t, home)
	x.current.Uid = "1001"
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	condaAssertRefs(t, inv, audit)
	for _, f := range audit.Files {
		if f.Scope == "process" && (f.Status != "unsupported" || !slices.Contains(f.Reasons, "user_unresolved")) {
			t.Errorf("process file = %+v", f)
		}
	}
	for _, c := range audit.Contexts {
		if c.SelectionStatus != "partial" {
			t.Errorf("unverified process left context complete: %+v", c)
		}
	}
	// Default roots and the registry do not depend on the process environment.
	condaSource(t, inv, "environment_root", filepath.Join(home, "miniforge3"))
	condaSource(t, inv, "environment", filepath.Join(home, "elsewhere", "env"))
	for _, src := range inv.Sources {
		if strings.HasPrefix(src.Path, filepath.Join(home, "extra-")) {
			t.Errorf("process lead followed without a verified process: %+v", src)
		}
	}

	scanner, x = condaTestScanner(t, home)
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

func TestCondaScanLimitsDeadlineAndGuards(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	base := filepath.Join(home, "miniforge3")
	app := filepath.Join(base, "envs", "app")
	proj := filepath.Join(root, "proj")
	condaWriteFixture(t, home, root)
	scanner, x := condaTestScanner(t, home)
	condaFixtureEnv(x, home)
	full, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	total := len(full.Sources) + len(full.Projects) + len(full.Packages)
	owned := condaOwned(full)
	old := maxCondaRecords
	t.Cleanup(func() { maxCondaRecords = old })
	for budget := 1; budget < total; budget++ {
		maxCondaRecords = budget
		inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		if inv.Status != "partial" || !slices.Contains(inv.Reasons, "record_limit") || len(inv.Sources)+len(inv.Projects)+len(inv.Packages) > budget {
			t.Fatalf("budget %d: status %s reasons %v", budget, inv.Status, inv.Reasons)
		}
		condaAssertComplete(t, budget, owned, inv)
		condaAssertRefs(t, inv, audit)
	}
	maxCondaRecords = old

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	*x.calls = 0
	inv, audit := scanner.Scan(ctx, goTestTarget(home), []string{root}, nil)
	condaAssertRefs(t, inv, audit)
	if inv.Status != "partial" || !slices.Contains(inv.Reasons, "deadline_exceeded") || len(inv.Packages) != 0 || *x.calls != 0 {
		t.Fatalf("cancelled scan = %s %v %d packages after %d filesystem calls", inv.Status, inv.Reasons, len(inv.Packages), *x.calls)
	}
	// Cancellation mid-environment keeps admitted receipts, leaves the
	// environment partial and stops every later read.
	ctx, cancel = context.WithCancel(context.Background())
	after := -1
	x.reads, x.afterRead = map[string]int{}, func(path string) {
		if path == filepath.Join(app, "conda-meta", "packaging-24.1-pyhd8ed1ab_0.json") {
			cancel()
			after = *x.calls
		}
	}
	inv, audit = scanner.Scan(ctx, goTestTarget(home), []string{root}, nil)
	x.afterRead = nil
	condaAssertRefs(t, inv, audit)
	if after < 0 || *x.calls != after || !slices.Contains(inv.Reasons, "deadline_exceeded") || x.reads[filepath.Join(proj, "environment.yml")] != 0 {
		t.Fatalf("cancelled scan kept reading: reasons %v, %d then %d calls", inv.Reasons, after, *x.calls)
	}
	if src := condaSource(t, inv, "environment", app); src.Status != "partial" || !slices.Contains(src.Reasons, "deadline_exceeded") {
		t.Errorf("environment left complete after cancellation: %+v", src)
	}
	if len(condaPackages(inv, "installed_package", "packaging")) != 1 {
		t.Error("admitted receipt dropped after cancellation")
	}

	// Cancellation during a project walk or a cache listing stops the lock
	// header probe and the next cache entry too.
	for _, trigger := range []string{filepath.Join(proj, "environment.yml"), filepath.Join(base, "pkgs", "packaging-24.1-pyhd8ed1ab_0", "info", "repodata_record.json")} {
		ctx, cancel = context.WithCancel(context.Background())
		after = -1
		x.afterRead = func(path string) {
			if path == trigger {
				cancel()
				after = *x.calls
			}
		}
		inv, audit = scanner.Scan(ctx, goTestTarget(home), []string{root}, nil)
		x.afterRead = nil
		condaAssertRefs(t, inv, audit)
		if after < 0 || *x.calls != after {
			t.Errorf("cancellation after %s kept reading: %d then %d calls", trigger, after, *x.calls)
		}
	}

	// An unreadable platform lock is reported, never read as removed.
	platformLock := filepath.Join(proj, "conda-linux-64.lock")
	goWrite(t, platformLock, "@EXPLICIT\nhttps://conda.anaconda.org/conda-forge/noarch/tzdata-2024b-hc8b5060_0.conda\n", 0o600)
	x.readErrors[platformLock] = os.ErrPermission
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	condaAssertRefs(t, inv, audit)
	if src := condaSource(t, inv, "lockfile", platformLock); src.Presence != "unknown" || !slices.Contains(src.Reasons, "permission_denied") {
		t.Errorf("unreadable platform lock = %+v", src)
	}
	if src := condaSource(t, inv, "project_search_root", root); !slices.Contains(src.Reasons, "permission_denied") {
		t.Errorf("search root with unreadable lock = %+v", src)
	}
	delete(x.readErrors, platformLock)
	if err := os.Remove(platformLock); err != nil {
		t.Fatal(err)
	}

	// Permission denied is never absence.
	denied := filepath.Join(app, "conda-meta", "zlib-1.3.1-h4e2bd7c_1.json")
	x.readErrors[denied] = os.ErrPermission
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	condaAssertRefs(t, inv, audit)
	if src := condaSource(t, inv, "installed_metadata", denied); src.Presence != "unknown" || !slices.Contains(src.Reasons, "permission_denied") {
		t.Errorf("unreadable receipt = %+v", src)
	}
	if src := condaSource(t, inv, "environment", app); src.Status != "partial" || !slices.Contains(src.Reasons, "permission_denied") {
		t.Errorf("environment with unreadable receipt = %+v", src)
	}
	delete(x.readErrors, denied)
	x.readErrors[filepath.Join(home, ".conda", "environments.txt")] = os.ErrPermission
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	condaAssertRefs(t, inv, audit)
	if !slices.Contains(inv.Reasons, "permission_denied") {
		t.Errorf("unreadable registry = %v", inv.Reasons)
	}
	condaSource(t, inv, "environment_root", base)
	delete(x.readErrors, filepath.Join(home, ".conda", "environments.txt"))

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
	condaAssertRefs(t, inv, audit)
	if src := condaSource(t, inv, "project_search_root", root); !slices.Contains(src.Reasons, "skipped_protected") || x.reads[filepath.Join(root, "legacy", "environment.yaml")] != 0 {
		t.Errorf("protected directory not reported: %+v", src)
	}

	// A blocked installation root is reported, never assumed absent, and its
	// configuration contexts stay partial so earlier history is kept.
	scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(p string) string {
			if p == base || strings.HasPrefix(p, base+string(filepath.Separator)) {
				return "skipped_protected"
			}
			return ""
		}, func(string) bool { return false }
	}
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	condaAssertRefs(t, inv, audit)
	if src := condaSource(t, inv, "environment_root", base); src.Presence != "unknown" || !slices.Contains(src.Reasons, "skipped_protected") {
		t.Errorf("blocked root = %+v", src)
	}
	if len(condaPackages(inv, "installed_package", "packaging")) != 0 {
		t.Error("blocked root still yielded receipts")
	}
	for _, c := range audit.Contexts {
		if c.SelectionStatus != "partial" {
			t.Errorf("blocked root left context %+v", c)
		}
	}
	scanner, x = condaTestScanner(t, home)
	condaFixtureEnv(x, home)

	t.Run("truncated environments listing", func(t *testing.T) {
		home := goTestHome(t)
		root := filepath.Join(home, "projects")
		envs := filepath.Join(home, "miniconda3", "envs")
		goWrite(t, filepath.Join(home, "miniconda3", "conda-meta", "history"), "", 0o600)
		for i := range maxCondaListEntries + 1 {
			goWrite(t, filepath.Join(envs, strconv.Itoa(i)), "", 0o600)
		}
		scanner, _ := condaTestScanner(t, home)
		inv, audit := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
		condaAssertRefs(t, inv, audit)
		if src := condaSource(t, inv, "environment_root", filepath.Join(home, "miniconda3")); !slices.Contains(src.Reasons, "entry_limit") || !slices.Contains(inv.Reasons, "entry_limit") {
			t.Fatalf("truncated listing: %+v %v", src, inv.Reasons)
		}
	})

	// Every output budget keeps admitted records and leaves only fully
	// collected sources complete.
	oldOut := maxCondaOutputBytes
	t.Cleanup(func() { maxCondaOutputBytes = oldOut })
	empty := emptyCondaInventory()
	basis, step := goJSONSize(&empty)+(256<<10), goJSONSize(full)/40
	for limit := basis; ; limit += step {
		if limit > basis+4*goJSONSize(full) {
			t.Fatal("output budget never admitted the full inventory")
		}
		maxCondaOutputBytes = limit
		inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		if !slices.Contains(inv.Reasons, "output_size_limit") {
			break
		}
		if inv.Status != "partial" || goJSONSize(inv)+goJSONSize(audit) > limit {
			t.Fatalf("limit %d: status %s size %d", limit, inv.Status, goJSONSize(inv)+goJSONSize(audit))
		}
		condaAssertComplete(t, limit, owned, inv)
		condaAssertRefs(t, inv, audit)
	}
}

func TestCondaScanRootsAndLeads(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	base := filepath.Join(home, "miniforge3")
	condaWriteFixture(t, home, root)
	scanner, x := condaTestScanner(t, home)
	condaFixtureEnv(x, home)
	// A registered prefix inside a search root is owned by that root, so a
	// later scan of the root can prove its removal.
	reg := filepath.Join(root, "regapp", ".conda")
	goWrite(t, filepath.Join(reg, "conda-meta", "history"), "", 0o600)
	goWrite(t, filepath.Join(reg, "conda-meta", "tzdata-2024b-hc8b5060_0.json"), condaTzdata, 0o600)
	registry := filepath.Join(home, ".conda", "environments.txt")
	registered, _ := os.ReadFile(registry)
	goWrite(t, registry, string(registered)+reg+"\n", 0o600)
	first, firstAudit := scanner.Scan(context.Background(), goTestTarget(home), []string{root, root, filepath.Join(root, "proj")}, nil)
	second, secondAudit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	a, _ := json.Marshal([]any{first, firstAudit})
	b, _ := json.Marshal([]any{second, secondAudit})
	if !bytes.Equal(a, b) {
		t.Fatal("nested or repeated roots changed the inventory")
	}
	if owner, src := condaSource(t, second, "project_search_root", root), condaSource(t, second, "environment", reg); src.ParentSourceID != owner.SourceID || !slices.Contains(owner.DiscoveredSources, src.SourceID) {
		t.Errorf("registered prefix not owned by its search root: %+v", src)
	}
	// A cache reached as a lead and under its root is one source; a prefix
	// reached as a lead, from the registry and under its root is one source.
	x.env["CONDA_PKGS_DIRS"] = filepath.Join(base, "pkgs")
	x.env["CONDA_PREFIX"] = base
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	condaAssertRefs(t, inv, audit)
	if n := len(condaPackages(inv, "cached_package", "packaging")); n != 1 {
		t.Errorf("cache reached twice emitted %d facts", n)
	}
	if n := len(condaPackages(inv, "installed_package", "_openmp_mutex")); n != 1 {
		t.Errorf("root prefix reached three ways emitted %d facts", n)
	}
	roots := 0
	for _, src := range inv.Sources {
		if src.Kind == "environment_root" && src.Path == base {
			roots++
		}
	}
	if roots != 1 {
		t.Errorf("environment root recorded %d times", roots)
	}
	// A search root inside an installation root is still the prefix, never a
	// project walk through its receipts and cache.
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root, base}, nil)
	condaAssertRefs(t, inv, audit)
	if src, prefix := condaSource(t, inv, "project_search_root", base), condaSource(t, inv, "environment_root", base); !slices.Equal(src.DiscoveredSources, []string{prefix.SourceID}) || !slices.Equal(src.Reasons, prefix.Reasons) {
		t.Errorf("search root at a prefix = %+v", src)
	}
	if x.reads[filepath.Join(base, "pkgs", "urls.txt")] != 0 {
		t.Error("search root walked into the package cache")
	}
	// A standard root and a lead cache under a search root are owned by it,
	// so removing them leaves a surviving ancestor that proves the removal.
	condaFixtureEnv(x, home)
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{home}, nil)
	condaAssertRefs(t, inv, audit)
	owner := condaSource(t, inv, "project_search_root", home)
	for _, src := range []model.CondaSource{condaSource(t, inv, "environment_root", base), condaSource(t, inv, "cache_root", filepath.Join(home, "extra-pkgs"))} {
		if src.ParentSourceID != owner.SourceID || !slices.Contains(owner.DiscoveredSources, src.SourceID) {
			t.Errorf("%s not owned by the search root: %+v", src.Kind, src)
		}
	}
	if err := os.RemoveAll(base); err != nil {
		t.Fatal(err)
	}
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{home}, nil)
	condaAssertRefs(t, inv, audit)
	if src := condaSource(t, inv, "project_search_root", home); src.Presence != "present" {
		t.Errorf("search root after removal = %+v", src)
	}
	for _, src := range inv.Sources {
		if src.Path == base || goPathWithin(src.Path, base) {
			t.Errorf("removed installation still observed: %+v", src)
		}
	}
	if n := len(condaPackages(inv, "installed_package", "_openmp_mutex")); n != 0 {
		t.Errorf("removed installation still has %d facts", n)
	}
	condaWriteFixture(t, home, root)
	condaFixtureEnv(x, home)

	// Two spellings of one prefix emit its facts once.
	link := filepath.Join(home, "app-link")
	if err := os.Symlink(filepath.Join(base, "envs", "app"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	x.env["CONDA_PREFIX"] = link
	delete(x.env, "CONDA_PKGS_DIRS")
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	condaAssertRefs(t, inv, audit)
	if n := len(condaPackages(inv, "installed_package", "packaging")); n != 1 {
		t.Fatalf("aliased prefix duplicated facts: %d", n)
	}
	// A relocated root reached through a symlink keeps its facts under the
	// spelling it was found by.
	physical := filepath.Join(home, "forge-keg")
	if err := os.Rename(base, physical); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(physical, base); err != nil {
		t.Fatal(err)
	}
	inv, audit = scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
	condaAssertRefs(t, inv, audit)
	if src := condaSource(t, inv, "environment_root", base); src.Status != "partial" || src.Presence != "present" {
		t.Errorf("aliased root = %+v", src)
	}
	if n := len(condaPackages(inv, "installed_package", "packaging")); n != 1 {
		t.Fatalf("aliased root duplicated facts: %d", n)
	}
}

func TestCondaScanDiscoveryCoverage(t *testing.T) {
	t.Run("truncated installation", func(t *testing.T) {
		home := goTestHome(t)
		base := filepath.Join(home, "miniforge3")
		goMkdir(t, filepath.Join(base, "aaa"))
		goMkdir(t, filepath.Join(base, "envs"))
		goMkdir(t, filepath.Join(base, "pkgs"))
		goWrite(t, filepath.Join(base, "conda-meta", "history"), "history", 0o600)
		goWrite(t, filepath.Join(base, "conda-meta", "tzdata-2024b-hc8b5060_0.json"), condaTzdata, 0o600)
		old := maxCondaListEntries
		maxCondaListEntries = 2
		t.Cleanup(func() { maxCondaListEntries = old })
		s, _ := condaTestScanner(t, home)
		inv, _ := s.Scan(t.Context(), goTestTarget(home), nil, nil)
		if !slices.Contains(inv.Reasons, "entry_limit") {
			t.Fatalf("truncated root reported %s, %v", inv.Status, inv.Reasons)
		}
	})
	t.Run("custom root ownership", func(t *testing.T) {
		home := goTestHome(t)
		base := filepath.Join(home, "custom-forge")
		env := filepath.Join(base, "envs", "app")
		cache := filepath.Join(base, "pkgs")
		goWrite(t, filepath.Join(env, "conda-meta", "history"), "history", 0o600)
		goMkdir(t, cache)
		s, x := condaTestScanner(t, home)
		x.env["CONDA_ROOT"] = base
		x.env["CONDA_ENVS_PATH"] = filepath.Join(base, "envs")
		x.env["CONDA_PKGS_DIRS"] = cache
		inv, _ := s.Scan(t.Context(), goTestTarget(home), nil, nil)
		owner := condaSource(t, inv, "environment_root", base)
		for _, kindPath := range [][2]string{{"environment", env}, {"cache_root", cache}} {
			child := condaSource(t, inv, kindPath[0], kindPath[1])
			if child.ParentSourceID != owner.SourceID {
				t.Errorf("%s remains parentless: %q", kindPath[0], child.ParentSourceID)
			}
		}
	})
	t.Run("deferred lock owners", func(t *testing.T) {
		home := goTestHome(t)
		roots := []string{}
		for _, name := range []string{"a", "b", "c"} {
			p := filepath.Join(home, name)
			roots = append(roots, p)
			goWrite(t, filepath.Join(p, "explicit.txt"), "@EXPLICIT\nhttps://example.invalid/ch/noarch/tzdata-2024b-hc8b5060_0.conda\n", 0o600)
		}
		old := maxCondaRecords
		maxCondaRecords = 5
		t.Cleanup(func() { maxCondaRecords = old })
		s, _ := condaTestScanner(t, home)
		inv, _ := s.Scan(t.Context(), goTestTarget(home), roots, nil)
		if src := condaSource(t, inv, "project_search_root", roots[2]); src.Status == "complete" {
			t.Fatal("third root complete despite uncollected lock")
		}
	})
	t.Run("cache breadth", func(t *testing.T) {
		home := goTestHome(t)
		cache := filepath.Join(home, "cache-probe")
		for i := range 3 {
			for j := range 5 {
				goWrite(t, filepath.Join(cache, strconv.Itoa(i), strconv.Itoa(j)), "incomplete extraction", 0o600)
			}
		}
		old := maxCondaWalkEntries
		maxCondaWalkEntries = 10
		t.Cleanup(func() { maxCondaWalkEntries = old })
		s, x := condaTestScanner(t, home)
		x.env["CONDA_PKGS_DIRS"] = cache
		inv, _ := s.Scan(t.Context(), goTestTarget(home), nil, nil)
		if src := condaSource(t, inv, "cache_root", cache); !slices.Contains(src.Reasons, "entry_limit") {
			t.Fatalf("cache exceeded total entry budget: %s %v", src.Status, src.Reasons)
		}
	})
}
