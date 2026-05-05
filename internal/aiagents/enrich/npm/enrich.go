package npm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
)

// Enrich runs detection plus light enrichment for the supplied shell command.
// It returns nil when no package manager is detected. The second return reports
// whether the underlying context was cancelled by its deadline.
func Enrich(ctx context.Context, cmd, cwd string) (*event.PackageManagerInfo, bool) {
	det := Detect(cmd)
	if det == nil {
		return nil, false
	}

	info := &event.PackageManagerInfo{
		Detected:    true,
		Name:        string(det.Manager),
		CommandKind: det.CommandKind,
		Confidence:  confidence(det.Manager),
	}

	if reg, source, ok := Resolve(ctx, string(det.Manager), cwd); ok {
		info.Registry = reg
		info.Evidence = append(info.Evidence, string(source))
		if source == SourceNPM {
			info.ConfigSources = npmConfigSources(ctx, cwd)
		}
	}
	addLockfileEvidence(info, det.Manager, cwd)

	if isCtxCanceled(ctx) {
		return info, true
	}
	return info, false
}

func addLockfileEvidence(info *event.PackageManagerInfo, m Manager, cwd string) {
	if cwd == "" {
		return
	}
	pairs := []struct {
		mgr  Manager
		file string
	}{
		{NPM, "package-lock.json"},
		{PNPM, "pnpm-lock.yaml"},
		{Yarn, "yarn.lock"},
		{Bun, "bun.lockb"},
		{Bun, "bun.lock"},
	}
	for _, p := range pairs {
		if p.mgr != m {
			continue
		}
		if _, err := os.Stat(filepath.Join(cwd, p.file)); err == nil {
			info.Evidence = append(info.Evidence, p.file)
		}
	}
}

func npmConfigSources(ctx context.Context, cwd string) []string {
	out, err := runFunc(ctx, cwd, "npm", "config", "ls", "-l")
	if err != nil || out == "" {
		return nil
	}
	var sources []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "; ") || !strings.Contains(line, "config from ") {
			continue
		}
		idx := strings.Index(line, "config from ")
		path := strings.Trim(line[idx+len("config from "):], `"' `)
		if path != "" {
			sources = append(sources, redact.String(path))
		}
	}
	return sources
}

func isCtxCanceled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return errors.Is(ctx.Err(), context.DeadlineExceeded)
	default:
		return false
	}
}
