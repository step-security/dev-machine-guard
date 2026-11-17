package detector

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// nixFS is a symlink tree: links resolve component by component like the
// guarded reader, and anything not registered is absent. Like the reader, a
// missing path is a path error naming what was missing: the path itself, or
// the rewritten path once a link was followed.
type nixFS struct {
	*executor.Mock
	uid      string
	links    map[string]string
	exists   map[string]bool
	files    map[string][]byte
	dirs     map[string][]string // profiles directory to symlink entry names
	denied   map[string]bool
	resolved map[string]int
	after    func(path string, n int) // runs after path's n-th resolution
}

func newNixFS(goos string) *nixFS {
	m := executor.NewMock()
	m.SetGOOS(goos)
	m.SetHomeDir("/home/alice")
	m.SetUsername("alice")
	return &nixFS{Mock: m, uid: "1000", links: map[string]string{}, exists: map[string]bool{}, files: map[string][]byte{},
		dirs: map[string][]string{}, denied: map[string]bool{}, resolved: map[string]int{}}
}

func (f *nixFS) GuardedFiles([]string, func(string) string, int64) executor.Executor { return f }

func (f *nixFS) CurrentUser() (*user.User, error) {
	return &user.User{Uid: f.uid, Username: "alice", HomeDir: "/home/alice"}, nil
}

func (f *nixFS) EvalSymlinks(p string) (string, error) {
	orig := p
	defer func() {
		f.resolved[orig]++
		if f.after != nil {
			f.after(orig, f.resolved[orig])
		}
	}()
	for hop := 0; hop <= 16; hop++ {
		changed := false
		for link, target := range f.links {
			if f.denied[link] && (p == link || strings.HasPrefix(p, link+"/")) {
				return "", fs.ErrPermission
			}
			if p == link || strings.HasPrefix(p, link+"/") {
				p, changed = target+p[len(link):], true
				break
			}
		}
		if !changed {
			if f.exists[p] || f.files[p] != nil || f.dirs[p] != nil {
				return p, nil
			}
			return "", &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
		}
	}
	return "", fs.ErrInvalid
}

func (f *nixFS) Readlink(p string) (string, error) {
	if t, ok := f.links[p]; ok {
		return t, nil
	}
	if _, err := f.EvalSymlinks(p); err != nil {
		return "", err
	}
	return "", fs.ErrInvalid // exists, not a link
}

func (f *nixFS) ReadFile(p string) ([]byte, error) {
	r, err := f.EvalSymlinks(p)
	if err != nil {
		return nil, err
	}
	if data, ok := f.files[r]; ok {
		return data, nil
	}
	return nil, fs.ErrNotExist
}

func (f *nixFS) ReadDirLimit(dir string, max int) ([]os.DirEntry, bool, error) {
	if f.denied[dir] {
		return nil, false, fs.ErrPermission
	}
	names, ok := f.dirs[dir]
	if !ok {
		return nil, false, fs.ErrNotExist
	}
	var out []os.DirEntry
	for _, n := range names {
		out = append(out, executor.MockSymlinkDirEntry(n))
	}
	return out, false, nil
}

// profile links P to P-1-link to store path G holding the manifest, when given.
func (f *nixFS) profile(p, g, manifestFile string) {
	f.links[p] = p + "-1-link"
	f.links[p+"-1-link"] = g
	f.exists[g] = true
	if manifestFile != "" {
		data, err := os.ReadFile("testdata/nix/" + manifestFile)
		if err != nil {
			panic(err)
		}
		f.files[g+"/"+manifestFile[strings.LastIndex(manifestFile, "-")+1:]] = data // manifest.json or manifest.nix
	}
}

const (
	nixXDG     = "/home/alice/.local/state/nix/profiles"
	nixHMGen   = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-home-manager-generation"
	nixHMPath  = "/nix/store/h1crmzbbn7mv1j6x3ki2kc72l1qwvwjs-home-manager-path"
	nixEnvA    = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-profile"
	nixEnvDef  = "/nix/store/cccccccccccccccccccccccccccccccc-user-environment"
	nixEnvLead = "/nix/store/dddddddddddddddddddddddddddddddd-profile"
	nixSW      = "/nix/store/ffffffffffffffffffffffffffffffff-system-path"
	// A booted system whose store path is gone.
	nixNixOSSystem = "/nix/store/gggggggggggggggggggggggggggggggg-nixos-system"
)

// nixHost is a Linux host with an XDG profile (zlib), a Home Manager profile,
// a legacy default profile (inactive hello) and ~/.nix-profile aliasing the
// XDG profile.
func nixHost(goos string) *nixFS {
	f := newNixFS(goos)
	f.dirs[nixXDG] = []string{"home-manager", "home-manager-5-link", "profile", "profile-1-link"}
	f.profile(nixXDG+"/profile", nixEnvA, "multi-manifest.json")
	f.profile(nixXDG+"/home-manager", nixHMGen, "")
	f.links[nixHMGen+"/home-path"] = nixHMPath
	f.exists[nixHMPath] = true
	f.profile(nixDefaultProfile, nixEnvDef, "legacy-inactive-manifest.nix")
	f.links["/home/alice/.nix-profile"] = nixXDG + "/profile"
	return f
}

func hmRefs(t *testing.T) map[string][]string {
	data, err := os.ReadFile("testdata/nix/hm-direct-references.txt")
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]string{nixHMPath: append(strings.Fields(string(data)), nixHMPath)}
}

// runNix runs the Nix reader for alice on r, with the Home Manager references.
func runNix(t *testing.T, f *nixFS, refsErr error, r *sysPkgRun) {
	t.Helper()
	refs := hmRefs(t)
	s := newNixScanner(f, nil)
	s.refs = func(context.Context, executor.Executor, []string) (map[string][]string, error) { return refs, refsErr }
	s.scan(context.Background(), r, &user.User{Uid: "1000", Username: "alice", HomeDir: "/home/alice"}, nil)
}

func TestNixScanner_DarwinProbesNoNixOSPaths(t *testing.T) {
	r := newSysPkgRun()
	runNix(t, nixHost(model.PlatformDarwin), nil, r)
	if roots := rootSet(r.roots); roots["nix machine "+nixSystemSW] || roots["nix user /etc/profiles/per-user/alice"] || !roots["nix user "+nixXDG] {
		t.Errorf("darwin roots = %v", roots)
	}
}

func TestNixScanner_Discovery(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(f *nixFS)
		refsErr  error
		want     map[string]string // source to "status [error]"
		listed   []string
		unlisted []string
	}{
		{
			name:     "unresolvable Home Manager link withholds only its root",
			setup:    func(f *nixFS) { f.denied[nixHMGen+"/home-path"] = true },
			want:     map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager": "failed unsupported profile layout", nixDefaultProfile: "complete"},
			listed:   []string{nixDefaultProfile},
			unlisted: []string{nixXDG},
		},
		{
			name: "Home Manager under the default profile",
			setup: func(f *nixFS) {
				f.links[nixEnvDef+"/home-path"] = nixHMPath
				delete(f.links, nixHMGen+"/home-path")
			},
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager": "failed unsupported profile layout",
				nixDefaultProfile: "complete", nixDefaultProfile + "/home-path": "complete"},
			listed: []string{nixXDG, nixDefaultProfile},
		},
		{
			name: "two user profiles holding one home-path: the first owns it",
			setup: func(f *nixFS) {
				f.dirs[nixXDG] = append(f.dirs[nixXDG], "other", "other-1-link")
				f.profile(nixXDG+"/other", nixEnvLead, "")
				f.links[nixEnvLead+"/home-path"] = nixHMPath
			},
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "complete",
				nixDefaultProfile: "complete"},
			listed: []string{nixXDG, nixDefaultProfile},
		},
		{
			name:  "machine and user profiles holding one home-path stay distinct",
			setup: func(f *nixFS) { f.links[nixEnvDef+"/home-path"] = nixHMPath },
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "complete",
				nixDefaultProfile: "complete", nixDefaultProfile + "/home-path": "complete"},
			listed: []string{nixXDG, nixDefaultProfile},
		},
		{
			name: "unresolved Home Manager profile withholds its directory root",
			setup: func(f *nixFS) {
				delete(f.exists, nixHMGen)
				delete(f.links, nixHMGen+"/home-path")
			},
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager": "failed profile unresolved",
				nixDefaultProfile: "complete"},
			listed:   []string{nixDefaultProfile},
			unlisted: []string{nixXDG},
		},
		{
			name: "absent default profile lists its root with no source",
			setup: func(f *nixFS) {
				delete(f.links, nixDefaultProfile)
				delete(f.links, nixDefaultProfile+"-1-link")
			},
			want:   map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "complete"},
			listed: []string{nixXDG, nixDefaultProfile},
		},
		{
			name: "dangling default profile is failed and withholds its root",
			setup: func(f *nixFS) {
				delete(f.exists, nixEnvDef)
				delete(f.files, nixEnvDef+"/manifest.nix")
			},
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "complete",
				nixDefaultProfile: "failed profile unresolved"},
			listed:   []string{nixXDG},
			unlisted: []string{nixDefaultProfile},
		},
		{
			name:  "dangling current-system is failed, not absent",
			setup: func(f *nixFS) { f.links["/run/current-system"] = nixNixOSSystem },
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "complete",
				nixDefaultProfile: "complete", nixSystemSW: "failed profile unresolved"},
		},
		{
			name: "refused current-system is failed, not absent",
			setup: func(f *nixFS) {
				f.links["/run/current-system"] = nixNixOSSystem
				f.denied["/run/current-system"] = true
			},
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "complete",
				nixDefaultProfile: "complete", nixSystemSW: "failed profile unresolved"},
		},
		{
			name: "direct ~/.nix-profile is its own root",
			setup: func(f *nixFS) {
				delete(f.links, "/home/alice/.nix-profile")
				f.profile("/home/alice/.nix-profile", nixEnvLead, "direct-manifest.json")
			},
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "complete",
				nixDefaultProfile: "complete", "/home/alice/.nix-profile": "complete"},
			listed: []string{"/home/alice/.nix-profile"},
		},
		{
			name: "NIX_PROFILES leads",
			setup: func(f *nixFS) {
				f.SetEnv("NIX_PROFILES", "/nix/var/nix/profiles/default relative /opt/lead /opt/absent /opt/bad /run/wrappers")
				f.profile("/opt/lead", nixEnvLead, "direct-manifest.json")
				f.links["/opt/bad"] = "/opt/bad-target"
				f.denied["/opt/bad"] = true
				f.exists["/run/wrappers"] = true
			},
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "complete",
				nixDefaultProfile: "complete", "/opt/lead": "complete", "/opt/bad": "failed profile unresolved"},
			listed: []string{nixXDG, nixDefaultProfile},
		},
		{
			name: "env leads are ignored when the agent is not the user",
			setup: func(f *nixFS) {
				f.uid = "0"
				f.SetEnv("NIX_PROFILES", "/opt/lead")
				f.profile("/opt/lead", nixEnvLead, "direct-manifest.json")
			},
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "complete", nixDefaultProfile: "complete"},
		},
		{
			name: "profile changed during the scan keeps records",
			setup: func(f *nixFS) {
				f.after = func(p string, n int) {
					if p == nixXDG+"/profile" && n == 1 {
						f.links[nixXDG+"/profile-1-link"] = nixEnvLead
						f.exists[nixEnvLead] = true
					}
				}
			},
			want:   map[string]string{nixXDG + "/profile": "partial profile changed during scan", nixXDG + "/home-manager/home-path": "complete", nixDefaultProfile: "complete"},
			listed: []string{nixXDG},
		},
		{
			name:  "unsupported manifest version",
			setup: func(f *nixFS) { f.files[nixEnvA+"/manifest.json"] = []byte(`{"version":9,"elements":{}}`) },
			want: map[string]string{nixXDG + "/profile": "failed unsupported manifest version", nixXDG + "/home-manager/home-path": "complete",
				nixDefaultProfile: "complete"},
			listed: []string{nixXDG},
		},
		{
			name:    "store database unavailable fails only database sources",
			refsErr: fmt.Errorf("locked"),
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "failed store database unavailable",
				nixDefaultProfile: "complete"},
			listed: []string{nixXDG},
		},
		{
			name: "NixOS system path not registered",
			setup: func(f *nixFS) {
				f.links[nixSystemSW] = nixSW
				f.exists[nixSW] = true
			},
			want: map[string]string{nixXDG + "/profile": "complete", nixXDG + "/home-manager/home-path": "complete",
				nixDefaultProfile: "complete", nixSystemSW: "failed store path not registered"},
			listed: []string{nixSystemSW},
		},
		{
			name: "custom store location",
			setup: func(f *nixFS) {
				f.SetEnv("NIX_STORE_DIR", "/gnu/store")
				f.links[nixXDG+"/profile-1-link"] = "/gnu/store/x-profile"
				f.exists["/gnu/store/x-profile"] = true
			},
			want: map[string]string{nixXDG + "/profile": "failed unsupported store location", nixXDG + "/home-manager/home-path": "failed unsupported store location",
				nixDefaultProfile: "complete"},
			listed: []string{nixXDG},
		},
		{
			name:     "unreadable profiles directory withholds its root",
			setup:    func(f *nixFS) { f.denied[nixXDG] = true },
			want:     map[string]string{nixDefaultProfile: "complete"},
			listed:   []string{nixDefaultProfile},
			unlisted: []string{nixXDG},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := nixHost(model.PlatformLinux)
			if tc.setup != nil {
				tc.setup(f)
			}
			r := newSysPkgRun()
			runNix(t, f, tc.refsErr, r)
			roots := rootSet(r.roots)
			got := map[string]string{}
			for _, s := range r.scans {
				got[s.SourceID] = strings.TrimSpace(s.Status + " " + s.Error)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("sources = %v\nwant %v", got, tc.want)
			}
			for _, r := range tc.listed {
				if !roots["nix user "+r] && !roots["nix machine "+r] {
					t.Errorf("root %s not listed", r)
				}
			}
			for _, r := range tc.unlisted {
				if roots["nix user "+r] || roots["nix machine "+r] {
					t.Errorf("root %s listed", r)
				}
			}
		})
	}
}

func TestNixScanner_Bounds(t *testing.T) {
	t.Run("service identity reads machine profiles only", func(t *testing.T) {
		r := newSysPkgRun()
		newNixScanner(nixHost(model.PlatformLinux), nil).scan(context.Background(), r, &user.User{Uid: "0", Username: "root", HomeDir: "/root"}, nil)
		if len(r.scans) != 1 || r.scans[0].SourceID != nixDefaultProfile || len(r.roots) != 2 {
			t.Errorf("scans %v roots %v", viewScans(r.scans), rootSet(r.roots))
		}
	})
	t.Run("cancelled scan lists nothing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		f := nixHost(model.PlatformLinux)
		u, _ := f.CurrentUser()
		r := newSysPkgRun()
		newNixScanner(f, nil).scan(ctx, r, u, nil)
		if len(r.scans) != 0 || len(r.roots) != 0 {
			t.Errorf("scans %v roots %v", viewScans(r.scans), rootSet(r.roots))
		}
	})
	t.Run("budget spent before Nix", func(t *testing.T) {
		r := &sysPkgRun{}
		runNix(t, nixHost(model.PlatformLinux), nil, r)
		got := viewScans(r.scans)
		if s := got["nix "+nixXDG+"/profile"]; s.status != "partial" || len(r.roots) != 0 {
			t.Errorf("first source %+v, roots %v", s, r.roots)
		}
		if len(got) != 1 {
			t.Errorf("sources after the cut were emitted: %v", got)
		}
	})
	t.Run("sources past the bound are dropped and no root is listed", func(t *testing.T) {
		f := nixHost(model.PlatformLinux)
		f.dirs[nixXDG] = nil
		for i := range maxNixSources + 1 {
			f.dirs[nixXDG] = append(f.dirs[nixXDG], fmt.Sprintf("p%04d", i))
		}
		r := newSysPkgRun()
		runNix(t, f, nil, r)
		if len(r.scans) != maxNixSources || len(r.roots) != 0 {
			t.Errorf("%d sources, roots %v", len(r.scans), rootSet(r.roots))
		}
	})
}

// The guarded reader names the missing component in a path error. nixAbsent
// relies on that shape, so it is checked against the real reader.
func TestNixAbsent_GuardedReader(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("creating symlinks needs privileges on Windows")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"profiles/dangling": "store/gone", "current-system": "store/gone-system"} {
		if err := os.Symlink(filepath.Join(root, target), filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	refused := filepath.Join(root, "refused")
	files := executor.NewReal().GuardedFiles([]string{root}, func(p string) string {
		if p == refused {
			return "refused"
		}
		return ""
	}, 1<<20)
	tests := []struct {
		name, path string
		want       bool
	}{
		{"missing leaf", "profiles/default", true},
		{"missing ancestor", "none/profiles/default", true},
		{"dangling leaf", "profiles/dangling", false},
		{"dangling parent", "current-system/sw", false},
		{"refused", "refused/sw", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, tc.path)
			_, err := files.EvalSymlinks(path)
			if got := nixAbsent(path, err); got != tc.want {
				t.Errorf("nixAbsent(%s, %v) = %v, want %v", tc.path, err, got, tc.want)
			}
		})
	}
}
