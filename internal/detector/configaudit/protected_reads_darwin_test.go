//go:build darwin

package configaudit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

func TestProtectedConfigReads(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		home := t.TempDir()
		target := filepath.Join(home, "Library", "Containers", "test-app", "config")
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("registry=https://registry.npmjs.org/\n"), 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(home, "config")
		if blocked {
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("registry=https://registry.npmjs.org/\n"), 0600); err != nil {
			t.Fatal(err)
		}
		e, s := executor.NewReal(), tcc.New(home)
		ctx := context.Background()
		npm := NewNPMRCDetector(e).WithSkipper(s).collectFile(ctx, path, "user")
		pnpm := NewPnpmDetector(e).WithSkipper(s).collectFile(ctx, path, "user")
		bun := NewBunDetector(e).WithSkipper(s).collectFile(ctx, path, "user")
		yarn := NewYarnDetector(e).WithSkipper(s).collectFile(ctx, path, "user", "classic")
		pip := model.PipConfigFile{Path: path, Layer: "user"}
		NewPipConfigDetector(e).WithSkipper(s).populateFileMetadata(ctx, &pip)
		for _, got := range []struct {
			name     string
			readable bool
			err      string
		}{{"npm", npm.Readable, npm.ParseError}, {"pnpm", pnpm.Readable, pnpm.ParseError}, {"bun", bun.Readable, bun.ParseError}, {"yarn", yarn.Readable, yarn.ParseError}, {"pip", pip.Readable, pip.ParseError}} {
			if got.readable == blocked || (blocked && !strings.Contains(got.err, "tcc_protected")) {
				t.Errorf("%s blocked=%v readable=%v error=%s", got.name, blocked, got.readable, got.err)
			}
		}
	}
}

func TestProtectedConfigCommandsAreSkipped(t *testing.T) {
	e, s := executor.NewMock(), tcc.New("/Users/test-user")
	ctx := context.Background()
	if got := NewNPMRCDetector(e).WithSkipper(s).captureEffective(ctx); got == nil || got.Error != protectedCommandReason {
		t.Fatalf("npm effective=%+v", got)
	}
	if got := NewPnpmDetector(e).WithSkipper(s).captureEffective(ctx); got == nil || got.Error != protectedCommandReason {
		t.Fatalf("pnpm effective=%+v", got)
	}
	if _, err := NewPipConfigDetector(e).WithSkipper(s).captureEffective(ctx); err == nil || err.Error() != protectedCommandReason {
		t.Fatalf("pip err=%v", err)
	}
}

func TestProtectedConfigOrdinarySymlinkMetadata(t *testing.T) {
	home := t.TempDir()
	target, link := filepath.Join(home, "config"), filepath.Join(home, ".npmrc")
	if err := os.WriteFile(target, []byte("registry=https://registry.npmjs.org/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	e, s := executor.NewReal(), tcc.New(home)
	ctx := context.Background()
	npm := NewNPMRCDetector(e).WithSkipper(s).collectFile(ctx, link, "user")
	pnpm := NewPnpmDetector(e).WithSkipper(s).collectFile(ctx, link, "user")
	bun := NewBunDetector(e).WithSkipper(s).collectFile(ctx, link, "user")
	yarn := NewYarnDetector(e).WithSkipper(s).collectFile(ctx, link, "user", "classic")
	for _, got := range []struct {
		readable bool
		target   string
	}{{npm.Readable, npm.SymlinkTo}, {pnpm.Readable, pnpm.SymlinkTo}, {bun.Readable, bun.SymlinkTo}, {yarn.Readable, yarn.SymlinkTo}} {
		if !got.readable || got.target != target {
			t.Errorf("ordinary symlink metadata = %+v", got)
		}
	}
}
