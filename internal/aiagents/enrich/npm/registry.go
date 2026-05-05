package npm

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Source identifies which command produced the resolution. Empty when
// resolution failed.
type Source string

const (
	SourceNPM    Source = "npm config get registry"
	SourcePNPM   Source = "pnpm config get registry"
	SourceYarnV2 Source = "yarn config get npmRegistryServer"
	SourceYarnV1 Source = "yarn config get registry"
	SourceBun    Source = "bun pm config get registry"
)

var runFunc = execRun

func execRun(ctx context.Context, cwd, bin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			return "", ctx.Err()
		}
		return "", err
	}
	return string(out), nil
}

// Resolve returns the effective registry URL for pm rooted at cwd. ok=false on
// failure; callers should treat that as data unavailable, not as a verdict.
func Resolve(ctx context.Context, pm, cwd string) (registry string, source Source, ok bool) {
	switch pm {
	case "npm", "npx":
		return resolveSimple(ctx, cwd, "npm", []string{"config", "get", "registry"}, SourceNPM)
	case "pnpm", "pnpx":
		return resolveSimple(ctx, cwd, "pnpm", []string{"config", "get", "registry"}, SourcePNPM)
	case "yarn":
		return resolveYarn(ctx, cwd)
	case "bun", "bunx":
		return resolveSimple(ctx, cwd, "bun", []string{"pm", "config", "get", "registry"}, SourceBun)
	}
	return "", "", false
}

func resolveSimple(ctx context.Context, cwd, bin string, args []string, src Source) (string, Source, bool) {
	if _, err := exec.LookPath(bin); err != nil {
		return "", "", false
	}
	out, err := runFunc(ctx, cwd, bin, args...)
	if err != nil {
		return "", "", false
	}
	v := strings.TrimSpace(out)
	if v == "" || v == "undefined" {
		return "", "", false
	}
	return v, src, true
}

func resolveYarn(ctx context.Context, cwd string) (string, Source, bool) {
	if _, err := exec.LookPath("yarn"); err != nil {
		return "", "", false
	}
	if isYarnBerry(cwd) {
		out, err := runFunc(ctx, cwd, "yarn", "config", "get", "npmRegistryServer")
		if err == nil {
			if v := strings.TrimSpace(out); v != "" && v != "undefined" {
				return v, SourceYarnV2, true
			}
		}
		return "", "", false
	}
	out, err := runFunc(ctx, cwd, "yarn", "config", "get", "registry")
	if err != nil {
		return "", "", false
	}
	v := strings.TrimSpace(out)
	if v == "" || v == "undefined" {
		return "", "", false
	}
	return v, SourceYarnV1, true
}

func isYarnBerry(cwd string) bool {
	if cwd == "" {
		return false
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, ".yarnrc.yml")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}
