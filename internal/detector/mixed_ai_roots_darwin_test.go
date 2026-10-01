//go:build darwin

package detector

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

type mixedAIExecutor struct{ protectedFixtureExecutor }

func (e mixedAIExecutor) LookPath(string) (string, error) { return "", fs.ErrNotExist }
func (e mixedAIExecutor) FileExists(p string) bool {
	return strings.HasPrefix(p, e.home+string(filepath.Separator)) && e.Executor.FileExists(p)
}
func (e mixedAIExecutor) Glob(p string) ([]string, error) {
	if !strings.HasPrefix(p, e.home+string(filepath.Separator)) {
		return nil, nil
	}
	return e.Executor.Glob(p)
}
func (e mixedAIExecutor) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	e.Executor = e.Executor.GuardedFiles(roots, guard, max)
	return e
}

func TestMixedFNMKeepsReadableAmpIdentity(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	versions := filepath.Join(home, ".local", "share", "fnm", "node-versions")
	installation := filepath.Join(versions, "v22.0.0", "installation")
	manifestRoot := filepath.Join(installation, "lib", "node_modules", "@ampcode", "cli")
	target := filepath.Join(manifestRoot, "bin", "amp.js")
	binary := filepath.Join(installation, "bin", "amp")
	for _, dir := range []string{filepath.Dir(target), filepath.Dir(binary)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(manifestRoot, "package.json"), []byte(`{"name":"@ampcode/cli","version":"1.2.3"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("fixture, never executed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, binary); err != nil {
		t.Fatal(err)
	}
	e := mixedAIExecutor{protectedFixtureExecutor{Executor: executor.NewReal(), home: home}}
	skipper := tcc.New(home)
	guarded := tcc.GuardedFiles(e, skipper, maxLockfileSize, "pnpm", "Application Support/fnm")
	spec := cliToolSpec{Name: "amp", Binaries: []string{"amp"}}
	resolve := func() (cliResolution, bool) {
		return resolveAmp(context.Background(), guarded, progress.NewNoop(), skipper, spec, home)
	}
	control, ok := resolve()
	if !ok || control.BinaryPath != binary || control.StaticVersion != "1.2.3" {
		t.Fatalf("readable control identity missing: %+v found=%v", control, ok)
	}
	protected := filepath.Join(home, "Documents", "node")
	if err := os.MkdirAll(filepath.Join(protected, "installation", "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(versions, "v23.0.0")); err != nil {
		t.Fatal(err)
	}
	baseline, baselineFound := resolveAmp(context.Background(), e, progress.NewNoop(), skipper, spec, home)
	if !baselineFound || baseline != control {
		t.Fatalf("baseline-shaped mixed-root control lost identity: %+v found=%v", baseline, baselineFound)
	}
	t.Logf("baseline-shaped mixed-root control=%+v found=%v", baseline, baselineFound)
	matches, globErr := guarded.Glob(filepath.Join(versions, "*", "installation", "bin"))
	if len(matches) != 1 || matches[0] != filepath.Dir(binary) || globErr == nil {
		t.Fatalf("fixture must retain safe match plus refusal: %v %v", matches, globErr)
	}
	got, found := resolve()
	t.Logf("control=%+v found=%v; mixed=%+v found=%v; matches=%v globErr=%v", control, ok, got, found, matches, globErr)
	if !found || got != control {
		t.Fatalf("protected sibling removed readable Amp identity: %+v found=%v", got, found)
	}
}

func TestMixedFactoryConfigKeepsReadableIdentity(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, ".local", "bin", "droid")
	config := filepath.Join(home, ".factory")
	protected := filepath.Join(home, "Documents", "factory")
	for _, dir := range []string{filepath.Dir(binary), config, protected} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{binary, filepath.Join(config, "settings.json")} {
		if err := os.WriteFile(p, []byte("fixture, never executed"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	e := mixedAIExecutor{protectedFixtureExecutor{Executor: executor.NewReal(), home: home}}
	skipper := tcc.New(home)
	guarded := tcc.GuardedFiles(e, skipper, maxLockfileSize)
	spec := cliToolSpec{Name: "factory", Binaries: []string{"~/.local/bin/droid"}}
	control, ok := resolveFactory(context.Background(), guarded, progress.NewNoop(), skipper, spec, home)
	if !ok || control.BinaryPath != binary {
		t.Fatalf("ordinary Factory control missing: %+v found=%v", control, ok)
	}
	if err := os.Symlink(protected, filepath.Join(config, "protected")); err != nil {
		t.Fatal(err)
	}
	matches, globErr := guarded.Glob(filepath.Join(config, "*"))
	if len(matches) != 2 || globErr != nil {
		t.Fatalf("one-level existence check should not traverse the protected sibling: %v %v", matches, globErr)
	}
	got, found := resolveFactory(context.Background(), guarded, progress.NewNoop(), skipper, spec, home)
	if !found || got != control {
		t.Fatalf("protected config sibling removed readable Factory identity: %+v found=%v", got, found)
	}
}
