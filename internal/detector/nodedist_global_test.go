package detector

import (
	"context"
	"os/user"
	"path/filepath"
	"slices"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// ScanGlobalModules marks immediate children of the global root as direct
// (globally-installed) and anything below a nested node_modules as transitive.
func TestScanGlobalModules(t *testing.T) {
	// Real global roots end in "node_modules"; the package-path rule keys on
	// that segment, so the fixture must too.
	root := filepath.Join(t.TempDir(), "lib", "node_modules")
	mustWrite(t, filepath.Join(root, "typescript", "package.json"), `{"name":"typescript","version":"5.4.0"}`)
	mustWrite(t, filepath.Join(root, "@scope", "cli", "package.json"), `{"name":"@scope/cli","version":"1.0.0"}`)
	mustWrite(t, filepath.Join(root, "typescript", "node_modules", "dep", "package.json"), `{"name":"dep","version":"2.0.0"}`)

	got := newDistDetector().ScanGlobalModules(root)
	assertPkgs(t, got, "typescript@5.4.0+direct", "@scope/cli@1.0.0+direct", "dep@2.0.0")
}

// An explicit npm prefix override is resolved to <prefix>/lib/node_modules.
func TestNodeGlobalRoots_PrefixOverride(t *testing.T) {
	prefix := t.TempDir()
	nm := filepath.Join(prefix, "lib", "node_modules")
	mustWrite(t, filepath.Join(nm, "typescript", "package.json"), `{"name":"typescript","version":"5.4.0"}`)
	t.Setenv("npm_config_prefix", prefix)

	found := false
	for _, r := range NodeGlobalRoots(executor.NewReal()) {
		if r.pm == "npm" && filepath.Clean(r.dir) == filepath.Clean(nm) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected npm global root %q from prefix override", nm)
	}
}

type nodeConsoleExecutor struct {
	*executor.Mock
	consoleHome string
}

func (e nodeConsoleExecutor) LoggedInUser() (*user.User, error) {
	return &user.User{HomeDir: e.consoleHome}, nil
}

func TestNodeHomeDir_Linux(t *testing.T) {
	for _, tc := range []struct {
		name, home, accountHome, want string
		root                          bool
	}{
		{"user home", "/home/testuser", "/home/testuser", "/home/testuser", false},
		{"user override", "/custom/home", "/home/testuser", "/custom/home", false},
		{"root override", "/home/testuser", "/root", "/home/testuser", true},
		{"root home", "/root", "/root", "/root", true},
		{"user unset home", "", "/home/testuser", "", false},
		{"root unset home", "", "/root", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetGOOS(model.PlatformLinux)
			mock.SetIsRoot(tc.root)
			mock.SetEnv("HOME", tc.home)
			mock.SetHomeDir(tc.accountHome)
			if got := nodeHomeDir(mock); got != tc.want {
				t.Fatalf("nodeHomeDir() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNodeGlobalRoots_MacOSUsesLoggedInUserHome(t *testing.T) {
	serviceHome := "/root"
	userHome := "/home/testuser"
	npmRoot := filepath.Join(userHome, ".npm-global", "lib", "node_modules")
	pnpmRoot := filepath.Join(userHome, "Library", "pnpm", "global", "5", "node_modules")
	yarnRoot := filepath.Join(userHome, ".config", "yarn", "global", "node_modules")
	serviceNPMRoot := filepath.Join(serviceHome, ".npm-global", "lib", "node_modules")
	servicePNPMRoot := filepath.Join(serviceHome, "Library", "pnpm", "global", "5", "node_modules")
	serviceYarnRoot := filepath.Join(serviceHome, ".config", "yarn", "global", "node_modules")
	want := []nodeGlobalRoot{
		{pm: "npm", dir: npmRoot},
		{pm: "pnpm", dir: pnpmRoot},
		{pm: "yarn", dir: yarnRoot},
	}
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformDarwin)
	mock.SetIsRoot(true)
	mock.SetEnv("HOME", serviceHome)
	mock.SetHomeDir(serviceHome)
	for _, dir := range []string{
		npmRoot,
		pnpmRoot,
		yarnRoot,
		serviceNPMRoot,
		servicePNPMRoot,
		serviceYarnRoot,
	} {
		mock.SetDir(dir)
	}
	mock.SetGlob(filepath.Join(userHome, "Library", "pnpm", "global", "*", "node_modules"), []string{pnpmRoot})
	mock.SetGlob(filepath.Join(serviceHome, "Library", "pnpm", "global", "*", "node_modules"), []string{servicePNPMRoot})

	if got := NodeGlobalRoots(nodeConsoleExecutor{Mock: mock, consoleHome: userHome}); !slices.Equal(got, want) {
		t.Fatalf("NodeGlobalRoots() = %+v, want %+v", got, want)
	}
}

// Enterprise disk mode: ScanProjects emits structured packages with no raw
// output and no package-manager invocation.
func TestNodeScanner_DiskMode_Project(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(root, "app")
	mustWrite(t, filepath.Join(proj, "package.json"), `{"name":"app","dependencies":{"lodash":"^4"}}`)
	mustWrite(t, filepath.Join(proj, "package-lock.json"), `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name":"app"},
	    "node_modules/lodash": {"version":"4.17.21"},
	    "node_modules/dep": {"version":"1.0.0"}
	  }
	}`)
	// Isolate the scan cache to a temp file and bypass it for a deterministic run.
	t.Setenv("STEPSEC_NODE_SCAN_CACHE", filepath.Join(t.TempDir(), "cache.json"))
	t.Setenv("STEPSEC_NODE_SCAN_CACHE_BYPASS", "1")

	exec := executor.NewReal()
	scanner := NewNodeScanner(exec, progress.NewNoop(), "").
		WithDiskScan(NewNodeDistDetector(exec))

	results, discovered := scanner.ScanProjects(context.Background(), []string{root}, nil)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	r := results[0]
	if r.RawStdoutBase64 != "" {
		t.Errorf("disk mode must not emit raw stdout, got %d bytes", len(r.RawStdoutBase64))
	}
	if r.PackagesCount != 2 || len(r.Packages) != 2 {
		t.Fatalf("want 2 packages, got count=%d slice=%v", r.PackagesCount, r.Packages)
	}
	assertPkgs(t, r.Packages, "lodash@4.17.21+direct", "dep@1.0.0")
	if len(discovered) != 1 {
		t.Errorf("want 1 discovered project, got %d", len(discovered))
	}
}

// Every global result names the root it was read from — the backend reads
// ProjectPath into the row's project_paths — and two prefixes stay two
// results. Prefixes come from npm_config_prefix / PREFIX so the fixture does
// not depend on the host's nvm or homebrew layout.
func TestNodeScanner_DiskMode_GlobalsCarryRoot(t *testing.T) {
	pfxA, pfxB := t.TempDir(), t.TempDir()
	rootA := filepath.Join(pfxA, "lib", "node_modules")
	rootB := filepath.Join(pfxB, "lib", "node_modules")
	mustWrite(t, filepath.Join(rootA, "chalk", "package.json"), `{"name":"chalk","version":"5.6.1"}`)
	mustWrite(t, filepath.Join(rootB, "chalk", "package.json"), `{"name":"chalk","version":"5.6.1"}`)
	mustWrite(t, filepath.Join(rootB, "typescript", "package.json"), `{"name":"typescript","version":"5.4.0"}`)
	t.Setenv("npm_config_prefix", pfxA)
	t.Setenv("PREFIX", pfxB)

	exec := executor.NewReal()
	scanner := NewNodeScanner(exec, progress.NewNoop(), "").
		WithDiskScan(NewNodeDistDetector(exec))

	byRoot := make(map[string][]string)
	for _, r := range scanner.ScanGlobalPackages(context.Background()) {
		if r.PackageManager != "npm" {
			continue
		}
		if r.ProjectPath == "" {
			t.Fatalf("global npm result has no ProjectPath: %+v", r)
		}
		if r.WorkingDirectory != r.ProjectPath {
			t.Errorf("WorkingDirectory = %q, want it to match ProjectPath %q", r.WorkingDirectory, r.ProjectPath)
		}
		for _, p := range r.Packages {
			byRoot[filepath.Clean(r.ProjectPath)] = append(byRoot[filepath.Clean(r.ProjectPath)], p.Name)
		}
	}

	if got := byRoot[filepath.Clean(rootA)]; len(got) != 1 || got[0] != "chalk" {
		t.Errorf("prefix A packages = %v, want [chalk]; all roots seen: %v", got, keysOf(byRoot))
	}
	if got := byRoot[filepath.Clean(rootB)]; len(got) != 2 {
		t.Errorf("prefix B packages = %v, want chalk and typescript; all roots seen: %v", got, keysOf(byRoot))
	}
}

func keysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
