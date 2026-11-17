package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// sysPkgFake reports unregistered paths as absent, as the real filesystem
// does; the mock's own misses are not fs.ErrNotExist.
type sysPkgFake struct {
	*executor.Mock
	denied map[string]bool
}

func (f *sysPkgFake) Stat(p string) (os.FileInfo, error) {
	if f.denied[p] {
		return nil, fs.ErrPermission
	}
	if info, err := f.Mock.Stat(p); err == nil {
		return info, nil
	}
	return nil, fs.ErrNotExist
}

func (f *sysPkgFake) ReadFile(p string) ([]byte, error) {
	if data, err := f.Mock.ReadFile(p); err == nil {
		return data, nil
	}
	return nil, fs.ErrNotExist
}

func (f *sysPkgFake) GuardedFiles([]string, func(string) string, int64) executor.Executor { return f }

func newSysPkgFake() *sysPkgFake {
	m := executor.NewMock()
	m.SetGOOS(model.PlatformLinux)
	m.SetHomeDir("/home/alice")
	return &sysPkgFake{Mock: m, denied: map[string]bool{}}
}

const (
	rpmFormat = "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\t%{SOURCERPM}\t" +
		"%{VENDOR}\t%{PACKAGER}\t%{URL}\t%{LICENSE}\t%{BUILDTIME}\t%{SIZE}\t" +
		"%{SIGPGP:pgpsig}\t%{RSAHEADER:pgpsig}\t%{EPOCH}\n"
	dpkgFormat = "${Package}\t${Version}\t${Architecture}\t${source:Package}\t" +
		"${Maintainer}\t${Origin}\t${Section}\t${Installed-Size}\t" +
		"${db-fsys:Last-Modified}\t${db:Status-Status}\n"
)

func rpmLine(name, epoch string) string {
	return name + "\t1.0-1.fc40\tx86_64\t1700000000\t" + name + "-1.0-1.fc40.src.rpm\tFedora Project\tFedora Project\thttps://example.org\tMIT\t1690000000\t1024\t(none)\tRSA/SHA256\t" + epoch
}

func dpkgLine(name, status string) string {
	return name + "\t1:2.0-1\tamd64\t" + name + "\tDebian Developers\tDebian\tutils\t4\t1700000000\t" + status
}

func (f *sysPkgFake) rpm(stdout string, exit int) {
	f.SetPath("rpm", "/usr/bin/rpm")
	f.SetCommand(stdout, "", exit, "rpm", "-qa", "--queryformat", rpmFormat)
}

func (f *sysPkgFake) dpkg(stdout string, exit int) {
	f.SetPath("dpkg-query", "/usr/bin/dpkg-query")
	f.SetCommand(stdout, "", exit, "dpkg-query", "-W", "-f", dpkgFormat)
}

type scanView struct {
	status, err string
	names       []string
}

func viewScans(scans []model.SystemPackageScanResult) map[string]scanView {
	out := map[string]scanView{}
	for _, s := range scans {
		v := scanView{status: s.Status, err: s.Error}
		for _, p := range s.Packages {
			v.names = append(v.names, p.Name)
		}
		out[s.ScanType+" "+s.SourceID] = v
	}
	return out
}

func rootSet(roots []model.SystemPackageDiscoveryRoot) map[string]bool {
	out := map[string]bool{}
	for _, r := range roots {
		out[r.ScanType+" "+r.Scope+" "+r.Path] = true
	}
	return out
}

func TestSystemPkgDetector_ScanPrimary(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(f *sysPkgFake)
		want     map[string]scanView
		roots    []string // primary roots expected listed
		unlisted []string // primary roots expected absent
		check    func(t *testing.T, pkgs []model.SystemPackage)
	}{
		{
			name: "empty rpm database does not hide dpkg",
			setup: func(f *sysPkgFake) {
				f.rpm("", 0)
				f.dpkg(strings.Join([]string{dpkgLine("bash", "installed"), dpkgLine("old", "config-files"),
					dpkgLine("gone", "not-installed"), dpkgLine("half", "half-configured"), dpkgLine("new", "unpacked")}, "\n"), 0)
			},
			want: map[string]scanView{
				"rpm machine-default":  {status: "complete"},
				"dpkg machine-default": {status: "complete", names: []string{"bash", "half", "new"}},
			},
			roots: []string{"rpm", "dpkg", "pacman", "apk"},
		},
		{
			name: "failed rpm query is failed, dpkg still complete",
			setup: func(f *sysPkgFake) {
				f.rpm("", 1)
				f.dpkg(dpkgLine("bash", "installed"), 0)
			},
			want: map[string]scanView{
				"rpm machine-default":  {status: "failed", err: "query failed (exit 1)"},
				"dpkg machine-default": {status: "complete", names: []string{"bash"}},
			},
			roots: []string{"rpm", "dpkg"},
		},
		{
			name:     "unreadable marker leaves presence unknown",
			setup:    func(f *sysPkgFake) { f.denied["/var/lib/pacman/local"] = true },
			want:     map[string]scanView{},
			roots:    []string{"rpm", "dpkg", "apk"},
			unlisted: []string{"pacman"},
		},
		{
			name: "rpm epoch is reported",
			setup: func(f *sysPkgFake) {
				f.rpm(rpmLine("none", "(none)")+"\n"+rpmLine("zero", "0")+"\n"+rpmLine("two", "2"), 0)
			},
			want:  map[string]scanView{"rpm machine-default": {status: "complete", names: []string{"none", "two", "zero"}}},
			roots: []string{"rpm"},
			check: func(t *testing.T, pkgs []model.SystemPackage) {
				for _, p := range pkgs {
					if want := map[string]int{"two": 2}[p.Name]; p.Epoch != want {
						t.Errorf("%s epoch = %d, want %d", p.Name, p.Epoch, want)
					}
				}
			},
		},
		{
			name:  "unparsed record keeps rows and is partial",
			setup: func(f *sysPkgFake) { f.rpm(rpmLine("ok", "1")+"\n"+rpmLine("bad", "x")+"\nshort\tline", 0) },
			want: map[string]scanView{
				"rpm machine-default": {status: "partial", err: "unparsed output", names: []string{"ok"}},
			},
			roots: []string{"rpm"},
		},
		{
			name: "pacman runs under the C locale",
			setup: func(f *sysPkgFake) {
				f.SetPath("pacman", "/usr/bin/pacman")
				f.SetCommand("Name            : bash\nVersion         : 5.2-1\nInstall Date    : Sat Apr 26 22:30:00 2025\n", "", 0,
					"env", "LC_ALL=C", "pacman", "-Qi")
			},
			want:  map[string]scanView{"pacman machine-default": {status: "complete", names: []string{"bash"}}},
			roots: []string{"pacman"},
			check: func(t *testing.T, pkgs []model.SystemPackage) {
				if pkgs[0].InstallTimeUnix == 0 {
					t.Error("C-locale install date not parsed")
				}
			},
		},
		{
			name:  "empty apk database is complete without the command",
			setup: func(f *sysPkgFake) { f.SetPath("apk", "/sbin/apk"); f.SetFile("/lib/apk/db/installed", []byte{}) },
			want:  map[string]scanView{"apk machine-default": {status: "complete"}},
			roots: []string{"apk"},
		},
		{
			name: "binary apk database falls back to the command",
			setup: func(f *sysPkgFake) {
				f.SetPath("apk", "/sbin/apk")
				f.SetFile("/lib/apk/db/installed", []byte("P:x\x00"))
				f.SetCommand("curl-8.9.1-r2 x86_64 {curl} (MIT)", "", 0, "apk", "list", "--installed")
			},
			want:  map[string]scanView{"apk machine-default": {status: "complete", names: []string{"curl"}}},
			roots: []string{"apk"},
		},
		{
			name: "failed apk fallback is failed",
			setup: func(f *sysPkgFake) {
				f.SetPath("apk", "/sbin/apk")
				f.SetFile("/lib/apk/db/installed", []byte("P:x\x00"))
				f.SetCommand("", "", 2, "apk", "list", "--installed")
			},
			want:  map[string]scanView{"apk machine-default": {status: "failed", err: "query failed (exit 2)"}},
			roots: []string{"apk"},
		},
		{
			name: "failed snap list is failed",
			setup: func(f *sysPkgFake) {
				f.SetPath("snap", "/usr/bin/snap")
				f.SetCommand("", "", 1, "snap", "list")
			},
			want:  map[string]scanView{"snap machine-default": {status: "failed", err: "query failed (exit 1)"}},
			roots: []string{"snap"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newSysPkgFake()
			tc.setup(f)
			r := newSysPkgRun()
			NewSystemPkgDetector(f, nil).scan(context.Background(), r)
			got := viewScans(r.scans)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("scans = %v, want %v", got, tc.want)
			}
			listed := rootSet(r.roots)
			for _, r := range tc.roots {
				if !listed[r+" machine machine-default"] {
					t.Errorf("root %s not listed: %v", r, listed)
				}
			}
			for _, r := range tc.unlisted {
				if listed[r+" machine machine-default"] {
					t.Errorf("root %s listed with unknown presence", r)
				}
			}
			for _, s := range r.scans {
				for _, p := range s.Packages {
					if p.Scope != s.Scope {
						t.Errorf("package scope %q, scan scope %q", p.Scope, s.Scope)
					}
				}
			}
			if tc.check != nil {
				tc.check(t, r.scans[0].Packages)
			}
		})
	}
}

// The record budget is shared: at the limit everything is complete, one past
// it the cut source is partial and no later root is listed.
func TestSystemPkgDetector_RecordBudget(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprint("over by ", extra), func(t *testing.T) {
			f := newSysPkgFake()
			lines := make([]string, maxSystemPackageRecords+extra)
			for i := range lines {
				lines[i] = rpmLine(fmt.Sprint("p", i), "(none)")
			}
			f.rpm(strings.Join(lines, "\n"), 0)
			f.dpkg(dpkgLine("bash", "installed"), 0)
			r := newSysPkgRun()
			NewSystemPkgDetector(f, nil).scan(context.Background(), r)
			got := viewScans(r.scans)
			listed := rootSet(r.roots)
			if extra == 0 {
				if s := got["rpm machine-default"]; s.status != "complete" || len(s.names) != maxSystemPackageRecords {
					t.Fatalf("rpm = %s with %d rows", s.status, len(s.names))
				}
				if s := got["dpkg machine-default"]; s.status != "partial" || s.err != "record limit reached" || len(s.names) != 0 {
					t.Errorf("dpkg past the budget = %+v", s)
				}
				if !listed["rpm machine machine-default"] || listed["dpkg machine machine-default"] {
					t.Errorf("roots = %v", listed)
				}
				return
			}
			if s := got["rpm machine-default"]; s.status != "partial" || len(s.names) != maxSystemPackageRecords {
				t.Fatalf("rpm = %s with %d rows", s.status, len(s.names))
			}
			if _, ok := got["dpkg machine-default"]; ok || len(r.roots) != 0 {
				t.Errorf("after the cut: scans %v roots %v", got, listed)
			}
		})
	}
}

const flatpakInfoUser = "/root/.local/share/flatpak/app/org.example.InventoryProbe/aarch64/stable/229b8db313f976fa786ffbb0f2816a5739c8b196f64cc0296286fc3d4d3c38d5"

// Rows from the retained native fixture, with the installation column.
const flatpakFixtureRows = "org.example.InventoryProbe\tInventoryProbe\t\taarch64\tbeta\tfixture-repo\t022b70a6d320\t022b70a6d320\t\tuser\n" +
	"org.example.InventoryProbe\tInventoryProbe\t\taarch64\tstable\tfixture-repo\t229b8db313f9\t229b8db313f9\t\tsystem\n" +
	"org.example.InventoryProbe\tInventoryProbe\t\taarch64\tstable\tfixture-repo\t229b8db313f9\t229b8db313f9\t\tuser\n"

func (f *sysPkgFake) flatpak(stdout string, exit int, selector ...string) {
	f.SetPath("flatpak", "/usr/bin/flatpak")
	f.SetCommand(stdout, "", exit, "/bin/sh", flatpakListArgs(selector...)...)
}

func (f *sysPkgFake) flatpakInfo(selector, branch, out string, exit int) {
	f.SetCommand(out, "", exit, "flatpak", "info", selector, "--show-location", "--arch=aarch64", "org.example.InventoryProbe", branch)
}

func TestSystemPkgDetector_Flatpak(t *testing.T) {
	const user, system = "flatpak /root/.local/share/flatpak", "flatpak /var/lib/flatpak"
	systemInfo := strings.Replace(flatpakInfoUser, "/root/.local/share/flatpak", "/var/lib/flatpak", 1)
	tests := []struct {
		name         string
		setup        func(f *sysPkgFake)
		want         map[string]scanView
		userRoot     bool
		systemRoot   bool
		extraSources int
	}{
		{
			name:     "no apps emits no scan and lists both roots",
			setup:    func(f *sysPkgFake) { f.flatpak("", 0) },
			want:     map[string]scanView{},
			userRoot: true, systemRoot: true,
		},
		{
			name: "a skipped deployment's warning withholds both roots",
			setup: func(f *sysPkgFake) {
				f.flatpak(flatpakFixtureRows+"F: Unable to load details of app/org.example.Other/x86_64/stable: secret detail\n", 0)
				f.flatpakInfo("--system", "stable", systemInfo, 0)
			},
			want: map[string]scanView{
				user:   {status: "partial", err: "unparsed output", names: []string{"org.example.InventoryProbe", "org.example.InventoryProbe"}},
				system: {status: "partial", err: "unparsed output", names: []string{"org.example.InventoryProbe"}},
			},
		},
		{
			name: "configured installation is selected by its id",
			setup: func(f *sysPkgFake) {
				f.flatpak(strings.Replace(flatpakFixtureRows, "\tsystem\n", "\tsystem (extra)\n", 1), 0)
				f.flatpakInfo("--installation=extra", "stable", strings.Replace(systemInfo, "/var/lib/flatpak", "/srv/flatpak", 1), 0)
			},
			want: map[string]scanView{
				user:                   {status: "complete", names: []string{"org.example.InventoryProbe", "org.example.InventoryProbe"}},
				"flatpak /srv/flatpak": {status: "complete", names: []string{"org.example.InventoryProbe"}},
			},
			userRoot: true, systemRoot: true,
		},
		{
			name: "unmapped installation is not emitted and withholds the system root",
			setup: func(f *sysPkgFake) {
				f.flatpak(flatpakFixtureRows, 0)
				f.flatpakInfo("--system", "stable", "", 1)
			},
			want: map[string]scanView{
				user: {status: "complete", names: []string{"org.example.InventoryProbe", "org.example.InventoryProbe"}},
			},
			userRoot: true,
		},
		{
			name: "failed global list falls back per installation",
			setup: func(f *sysPkgFake) {
				f.flatpak("", 1)
				f.flatpak("", 1, "--user")
				f.flatpak(strings.Split(flatpakFixtureRows, "\n")[1]+"\n", 0, "--system")
				f.flatpakInfo("--system", "stable", systemInfo, 0)
			},
			want: map[string]scanView{
				user:   {status: "failed", err: "query failed (exit 1)"},
				system: {status: "complete", names: []string{"org.example.InventoryProbe"}},
			},
		},
		{
			name: "installations past the source bound withhold the system root",
			setup: func(f *sysPkgFake) {
				var rows strings.Builder
				for i := range maxFlatpakSources + 1 {
					id := fmt.Sprintf("i%03d", i)
					rows.WriteString("org.example.InventoryProbe\tInventoryProbe\t\taarch64\tstable\tfixture-repo\tc\tc\t\tsystem (" + id + ")\n")
					f.flatpakInfo("--installation="+id, "stable", "/srv/"+id+"/app/org.example.InventoryProbe/aarch64/stable/c0ffee", 0)
				}
				f.flatpak(rows.String(), 0)
			},
			userRoot:     true,
			extraSources: maxFlatpakSources,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newSysPkgFake()
			f.SetHomeDir("/root")
			tc.setup(f)
			r := newSysPkgRun()
			NewSystemPkgDetector(f, nil).scan(context.Background(), r)
			scans := r.scans
			got := map[string]scanView{}
			for k, v := range viewScans(scans) {
				if strings.HasPrefix(k, "flatpak ") {
					got[k] = v
				}
			}
			if tc.extraSources > 0 {
				if len(got) != tc.extraSources {
					t.Errorf("sources = %d, want %d", len(got), tc.extraSources)
				}
			} else if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("scans = %v, want %v", got, tc.want)
			}
			if r.flatpak == nil {
				t.Error("flatpak manager not kept for community output")
			}
			listed := rootSet(r.roots)
			if listed["flatpak user user-installation"] != tc.userRoot || listed["flatpak machine system-installations"] != tc.systemRoot {
				t.Errorf("roots = %v, want user %v system %v", listed, tc.userRoot, tc.systemRoot)
			}
			raw, _ := json.Marshal(scans)
			if strings.Contains(string(raw), "secret detail") || strings.Contains(string(raw), "Unable") {
				t.Error("warning text reached the scans")
			}
			for _, s := range scans {
				for _, p := range s.Packages {
					if s.ScanType == "flatpak" && p.InstallPath != s.SourceID+"/app/"+p.Name+"/"+p.Arch+"/"+p.Channel+"/active" {
						t.Errorf("install path %q not under source %q", p.InstallPath, s.SourceID)
					}
				}
			}
		})
	}
}

// Through the user-aware executor the wrapper reaches the login shell as
// separately quoted words, so flatpak gets the same argv.
func TestSystemPkgDetector_FlatpakWrapperThroughUserShell(t *testing.T) {
	f := newSysPkgFake()
	words := []string{"/bin/sh", "-c", `exec "$@" 2>&1`, "sh", "flatpak", "list", "--app", flatpakListColumns}
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = "'" + w + "'"
	}
	f.SetCommand(flatpakFixtureRows+"F: warning\n", "", 0, "bash", "-c", strings.Join(quoted, " "))
	d := NewSystemPkgDetector(executor.NewUserAwareExecutor(f, "root"), nil)
	rows, unparsed, errText := d.runFlatpakList(context.Background())
	if errText != "" || len(rows) != 3 || unparsed != 1 {
		t.Errorf("through the user shell: error %q, %d rows, %d unparsed; want 3 rows, 1 unparsed", errText, len(rows), unparsed)
	}
}
