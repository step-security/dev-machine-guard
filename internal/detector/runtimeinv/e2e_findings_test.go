package runtimeinv

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Regressions from the Fedora E2E run (ledger-e2e-linux.md F1–F6).

func TestE2ELauncherAndCacheSkips(t *testing.T) {
	f := newFixture(t)
	home := f.path("home/dev")
	// F4: volta's node is a link to volta-shim; pyenv/rbenv shims are scripts.
	f.file("home/dev/.volta/bin/volta-shim", "\x7fELF", true)
	f.symlink("home/dev/.volta/bin/node", "volta-shim")
	f.file("home/dev/.volta/tools/image/node/20.18.0/bin/node", "\x7fELF", true)
	f.file("home/dev/.pyenv/shims/python3", "#!/usr/bin/env bash\nexec pyenv exec python3 \"$@\"\n", true)
	f.file("home/dev/.rbenv/shims/ruby", "#!/usr/bin/env bash\n", true)
	// F5: conda's pkgs/ cache is skipped; its environments are not.
	f.file("home/dev/miniconda3/conda-meta/history", "", false)
	f.file("home/dev/miniconda3/bin/python3.12", "\x7fELF", true)
	f.file("home/dev/miniconda3/pkgs/python-3.12.4-h1/bin/python3.12", "\x7fELF", true)

	out := f.scan("linux", home, walkRoot{home, 7, nil, 0})
	var paths []string
	for _, r := range out {
		paths = append(paths, r.ExecutablePath+" ("+r.Source+")")
	}
	if len(out) != 2 {
		t.Fatalf("want volta image node + conda python only, got %v", paths)
	}
	for _, r := range out {
		switch r.Runtime {
		case "node":
			if r.Source != "volta" || r.Version != "20.18.0" { // F1: ~/.volta attribution
				t.Errorf("volta node = %+v", r)
			}
		case "python":
			if r.Source != "conda" || r.Version != "3.12" { // versioned exe name
				t.Errorf("conda python = %+v", r)
			}
		default:
			t.Errorf("unexpected %+v", r)
		}
	}
}

func TestRubyVersionFromConfigParts(t *testing.T) {
	data := []byte(`  CONFIG["MAJOR"] = "3"
  CONFIG["MINOR"] = "3"
  CONFIG["TEENY"] = "9"
  CONFIG["RUBY_PROGRAM_VERSION"] = "$(MAJOR).$(MINOR).$(TEENY)"
`)
	if got := rubyVersionFromConfig(data); got != "3.3.9" { // F3
		t.Fatalf("got %q", got)
	}
	if got := rubyVersionFromConfig([]byte(`CONFIG["RUBY_PROGRAM_VERSION"] = "2.6.10"`)); got != "2.6.10" {
		t.Fatalf("literal: got %q", got)
	}
}

func TestPkgOwnerVersion(t *testing.T) { // F2
	rpm := executor.NewMock()
	rpm.SetGOOS("linux")
	rpm.SetCommand("22.11.0", "", 0, "rpm", "-qf", "--queryformat", "%{VERSION}", "/usr/bin/node")
	if r, ok := pkgOwnerVersion(context.Background(), rpm, "/usr/bin/node", "/usr"); !ok || r.version != "22.11.0" || r.source != "pkg" {
		t.Errorf("rpm: %+v %v", r, ok)
	}

	deb := executor.NewMock()
	deb.SetGOOS("linux")
	deb.SetCommandError(context.DeadlineExceeded, "rpm", "-qf", "--queryformat", "%{VERSION}", "/usr/bin/python3.12")
	deb.SetCommand("python3.12-minimal: /usr/bin/python3.12\n", "", 0, "dpkg-query", "-S", "/usr/bin/python3.12")
	deb.SetCommand("1:3.12.3-1ubuntu0.1", "", 0, "dpkg-query", "-W", "-f=${Version}", "python3.12-minimal")
	if r, ok := pkgOwnerVersion(context.Background(), deb, "/usr/bin/python3.12", "/usr"); !ok || r.version != "3.12.3" {
		t.Errorf("dpkg: %+v %v", r, ok)
	}

	// Not consulted outside system locations or off Linux.
	if _, ok := pkgOwnerVersion(context.Background(), rpm, "/home/a/.nvm/versions/node/v18.0.0/bin/node", ""); ok {
		t.Error("non-system path consulted the package db")
	}
	mac := executor.NewMock()
	mac.SetGOOS("darwin")
	if _, ok := pkgOwnerVersion(context.Background(), mac, "/usr/bin/ruby", "/usr"); ok {
		t.Error("darwin consulted the package db")
	}
}

func TestSnapBundlerAndNewSources(t *testing.T) { // F5, F6
	if got := snapBundler("python", "/snap/core18/2846/usr/bin/python3.6"); got != "core18" {
		t.Errorf("core18 python bundled_by = %q", got)
	}
	if got := snapBundler("python", "/var/lib/snapd/snap/core/17292/usr/bin/python3.5"); got != "core" {
		t.Errorf("fedora snap mount bundled_by = %q", got)
	}
	if got := snapBundler("node", "/snap/node/9000/bin/node"); got != "" {
		t.Errorf("node snap is standalone, got %q", got)
	}
	for path, want := range map[string]string{
		"/home/a/sdk/go1.22.12/bin/go":                     "go-dl",
		"/home/a/.dotnet/dotnet":                           "dotnet-install",
		"/home/a/.volta/tools/image/node/20.18.0/bin/node": "volta",
	} {
		if got := attributeSource(path, ""); got != want {
			t.Errorf("attributeSource(%s) = %q, want %q", path, got, want)
		}
	}
}

// Fedora: node is a link to the versioned node-22 binary; ruby is a wrapper
// script around ruby-mri. Both installs are reported once, via the real binary.
func TestE2EFedoraVersionedSystemBinaries(t *testing.T) {
	f := newFixture(t)
	f.file("usr/bin/node-22", "\x7fELF", true)
	f.symlink("usr/bin/node", "node-22")
	f.file("usr/bin/ruby", "#!/usr/bin/bash\nexec /usr/bin/ruby-mri \"$@\"\n", true)
	f.file("usr/bin/ruby-mri", "\x7fELF", true)
	out := f.scan("linux", "", walkRoot{f.path("usr/bin"), 0, nil, 0})
	got := map[string]string{}
	for _, r := range out {
		got[r.Runtime] = r.ExecutablePath
	}
	if len(out) != 2 || got["node"] != f.path("usr/bin/node-22") || got["ruby"] != f.path("usr/bin/ruby-mri") {
		t.Fatalf("got %+v", out)
	}
}

// Regressions from the Windows E2E run (ledger-e2e-windows.md F2–F4, F6).
func TestE2EWindowsLaunchersTemplatesBundled(t *testing.T) {
	f := newFixture(t)
	orig := peVersion
	t.Cleanup(func() { peVersion = orig })
	peVersion = func(string) string { return "" }

	f.file("Program Files/Volta/node.exe", "MZ", false) // volta shim copy
	f.file("Program Files/Volta/volta-shim.exe", "MZ", false)
	f.file("Users/dev/scoop/shims/php.exe", "MZ", false) // scoop shim
	f.file("Users/dev/scoop/shims/php.shim", "path = x", false)
	f.file("Python312/python.exe", "MZ", false)                     // real install
	f.file("Python312/Lib/venv/scripts/nt/python.exe", "MZ", false) // stdlib template
	f.file("Users/dev/AppData/Local/Programs/cursor/resources/app/resources/helpers/node.exe", "MZ", false)
	f.file("Users/dev/AppData/Local/Microsoft/WinGet/Packages/Eclipse/eclipse/plugins/org.eclipse.justj.openjdk.hotspot.jre.full.win32.x86_64_21.0.5/jre/bin/java.exe", "MZ", false)

	out := f.scan("windows", f.path("Users/dev"),
		walkRoot{f.path("Program Files"), 5, nil, 0},
		walkRoot{f.path("Users/dev"), 12, nil, 0},
		walkRoot{f.path("Python312"), 6, nil, 0},
	)
	got := map[string]string{}
	for _, r := range out {
		got[r.ExecutablePath] = r.BundledBy
	}
	want := map[string]string{
		f.path("Python312/python.exe"): "",
		f.path("Users/dev/AppData/Local/Programs/cursor/resources/app/resources/helpers/node.exe"):                                                                          "cursor",
		f.path("Users/dev/AppData/Local/Microsoft/WinGet/Packages/Eclipse/eclipse/plugins/org.eclipse.justj.openjdk.hotspot.jre.full.win32.x86_64_21.0.5/jre/bin/java.exe"): "Eclipse",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for p, b := range want {
		if gb, ok := got[p]; !ok || gb != b {
			t.Errorf("%s: bundled_by=%q present=%v, want %q", p, gb, ok, b)
		}
	}
}
