//go:build darwin

package detector

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

type protectedFixtureExecutor struct {
	executor.Executor
	home string
}

func (e protectedFixtureExecutor) CurrentUser() (*user.User, error) {
	return &user.User{Uid: "501", Username: "test-user", HomeDir: e.home}, nil
}
func (e protectedFixtureExecutor) LoggedInUser() (*user.User, error) { return e.CurrentUser() }
func (e protectedFixtureExecutor) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	e.Executor = e.Executor.GuardedFiles(roots, guard, max)
	return e
}
func (e protectedFixtureExecutor) Getenv(key string) string {
	if key == "HOME" {
		return e.home
	}
	return ""
}

func TestProtectedReadsKeepOrdinaryInventory(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		name := "ordinary"
		if blocked {
			name = "protected-redirect"
		}
		t.Run(name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			exec := protectedFixtureExecutor{Executor: executor.NewReal(), home: home}
			skipper := tcc.New(home)
			put := func(path, data string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			target := filepath.Join(home, "Library", "Containers", "test-app", "Data")
			file := func(path, data string) {
				t.Helper()
				if blocked {
					dest := filepath.Join(target, filepath.Base(path))
					put(dest, data)
					if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(dest, path); err != nil {
						t.Fatal(err)
					}
				} else {
					put(path, data)
				}
			}
			directory := func(path string) string {
				t.Helper()
				if !blocked {
					return path
				}
				dest := filepath.Join(target, filepath.Base(path))
				if err := os.MkdirAll(dest, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dest, path); err != nil {
					t.Fatal(err)
				}
				return dest
			}
			want := 1
			if blocked {
				want = 0
			}
			mcp := filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
			file(mcp, `{"mcpServers":{"example":{"command":"example-tool"}}}`)
			if got := len(NewMCPDetector(exec).WithSkipper(skipper).DetectEnterprise(context.Background(), nil)); got != want {
				t.Errorf("MCP count = %d, want %d", got, want)
			}
			ideRoot := filepath.Join(home, ".vscode", "extensions")
			put(filepath.Join(directory(ideRoot), "example.extension-1.0.0", "package.json"), `{}`)
			if got := len(NewExtensionDetector(exec).WithSkipper(skipper).collectFromDir(ideRoot, "vscode")); got != want {
				t.Errorf("IDE count = %d, want %d", got, want)
			}
			jbRoot := filepath.Join(home, "Library", "Application Support", "JetBrains", "GoLand2026.1", "plugins")
			put(filepath.Join(directory(jbRoot), "example", "lib", "example-1.0.0.jar"), "fixture")
			if got := len(NewJetBrainsPluginDetector(exec).WithSkipper(skipper).collectPlugins(jbRoot, "goland")); got != want {
				t.Errorf("JetBrains count = %d, want %d", got, want)
			}
			pyRoot := filepath.Join(home, "Library", "Python", "3.12", "site-packages")
			file(filepath.Join(pyRoot, "example-1.0.0.dist-info", "METADATA"), "Name: example\nVersion: 1.0.0\n")
			py := NewPythonDistDetector(exec).WithSkipper(skipper).ScanRoots([]string{pyRoot})
			if len(py) != want || (blocked && py != nil) {
				t.Errorf("Python count = %d, want %d, nil=%v", len(py), want, py == nil)
			}
			nodeRoot := filepath.Join(home, "Library", "pnpm", "global", "node_modules")
			file(filepath.Join(nodeRoot, "example", "package.json"), `{"name":"example","version":"1.0.0"}`)
			node := NewNodeDistDetector(exec).WithSkipper(skipper)
			if got := len(node.ScanGlobalModules(nodeRoot)); got != want || node.readFailed != blocked {
				t.Errorf("Node count=%d failed=%v, want %d/%v", got, node.readFailed, want, blocked)
			}
		})
	}
}

func TestProtectedPluginArchiveAndManifest(t *testing.T) {
	home := t.TempDir()
	protected := filepath.Join(home, "Library", "Containers", "test-app")
	safe := filepath.Join(home, "plugins")
	for _, p := range []string{protected, filepath.Join(safe, ".claude-plugin")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	f, err := z.Create("META-INF/plugin.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("<idea-plugin/>")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(protected, "plugin.jar")
	if err := os.WriteFile(target, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(safe, "plugin.jar")
	if err := os.Symlink(target, jar); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(safe, ".claude-plugin", "plugin.json")); err != nil {
		t.Fatal(err)
	}
	exec := executor.NewReal()
	skipper := tcc.New(home)
	if got := NewExtensionDetector(exec).WithSkipper(skipper).readFileFromZip(jar, "META-INF/plugin.xml"); got != nil {
		t.Fatal("read protected archive")
	}
	if _, _, ok := pluginPackageRoot(tcc.GuardedFiles(exec, skipper, 1024), safe, safe); ok {
		t.Fatal("read protected manifest")
	}
}

// Only the fixed build is used here. Targets are existing protected locations;
// the test creates links in its own temporary directory and never writes targets.
func TestLiveProtectedScannerRedirects(t *testing.T) {
	if os.Getenv("DMG_TCC_VALIDATE_LIVE") != "1" {
		t.Skip("explicit live validation only")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	target := filepath.Join(u.HomeDir, "Library", "Containers", "com.apple.TextEdit", "Data")
	link := filepath.Join(scratch, "redirect")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	skipper := tcc.New(u.HomeDir)
	e := executor.NewReal()
	mcp := NewMCPDetector(e).WithSkipper(skipper)
	if mcp.exec.FileExists(filepath.Join(link, ".mcp.json")) || tcc.Refusals(mcp.exec) == 0 {
		t.Fatal("MCP did not refuse target")
	}
	ide := NewExtensionDetector(e).WithSkipper(skipper)
	if got := ide.collectFromDir(link, "vscode"); len(got) != 0 || tcc.Refusals(ide.exec) == 0 {
		t.Fatal("IDE did not refuse target")
	}
	jb := NewJetBrainsPluginDetector(e).WithSkipper(skipper)
	if got := jb.collectPlugins(link, "goland"); len(got) != 0 || tcc.Refusals(jb.exec) == 0 {
		t.Fatal("JetBrains did not refuse target")
	}
	py := NewPythonDistDetector(e).WithSkipper(skipper)
	if got := py.ScanRoots([]string{link}); got != nil || tcc.Refusals(py.exec) == 0 {
		t.Fatal("Python did not refuse target")
	}
	node := NewNodeDistDetector(e).WithSkipper(skipper)
	if got := node.ScanGlobalModules(link); len(got) != 0 || !node.readFailed || tcc.Refusals(node.exec) == 0 {
		t.Fatal("Node did not refuse target")
	}
	t.Log("MCP, IDE extensions, JetBrains, Python and Node refused before protected access")
}

func TestProtectedNodeConcurrentResults(t *testing.T) {
	home := t.TempDir()
	safe, denied := filepath.Join(home, "project"), filepath.Join(home, "Documents", "project")
	if err := os.MkdirAll(safe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(safe, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	e := executor.NewReal()
	scanner := NewNodeScanner(e, progress.NewNoop(), "").WithDiskScan(NewNodeDistDetector(e).WithSkipper(tcc.New(home)))
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			path := safe
			if i%2 != 0 {
				path = denied
			}
			result, _ := scanner.scanProjectFromDisk(path, "npm")
			if path == denied {
				if result.ExitCode == 0 || result.Error == "" {
					t.Error("refused project reported success")
				}
			} else if result.ExitCode != 0 || result.PackagesCount != 1 {
				t.Errorf("ordinary project lost: %+v", result)
			}
		})
	}
	wg.Wait()
}

func TestProtectedPythonVenvDiscoveryIsNotEmptySuccess(t *testing.T) {
	for _, intermediate := range []bool{false, true} {
		home := t.TempDir()
		venv := filepath.Join(home, "project", ".venv")
		site := filepath.Join(venv, "lib", "python3.12", "site-packages")
		target := filepath.Join(home, "Library", "Containers", "test-app", "site-packages")
		if intermediate {
			site = filepath.Dir(site)
		}
		for _, path := range []string{filepath.Dir(site), target} {
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(target, site); err != nil {
			t.Fatal(err)
		}
		d := NewPythonDistDetector(executor.NewReal()).WithSkipper(tcc.New(home))
		if got := d.ScanVenv(venv); got != nil {
			t.Fatalf("intermediate=%v: refused venv returned successful inventory: %v", intermediate, got)
		}
	}
}
