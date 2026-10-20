package launchd

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func TestPlistTemplate_RunAtLoadAndScheduled(t *testing.T) {
	tmpl, err := template.New("plist").Parse(plistTmpl)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, plistTemplateData{
		Label:           label,
		BinaryPath:      "/usr/local/bin/stepsecurity-dev-machine-guard",
		IntervalSeconds: 14400,
		LogDir:          "/Users/dev/.stepsecurity",
	}); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	out := sb.String()

	// RunAtLoad must be true so login/boot is a (gated) catch-up trigger.
	if !strings.Contains(out, "<key>RunAtLoad</key>\n    <true/>") {
		t.Errorf("plist must set RunAtLoad=true:\n%s", out)
	}
	if strings.Contains(out, "<false/>") {
		t.Errorf("plist must not contain RunAtLoad=false:\n%s", out)
	}
	if !strings.Contains(out, "<string>send-telemetry</string>") {
		t.Errorf("plist must invoke send-telemetry:\n%s", out)
	}
}

func TestDomainTarget(t *testing.T) {
	root := executor.NewMock()
	root.SetIsRoot(true)
	if domain, target := DomainTarget(root); domain != "system" || target != "system/"+label {
		t.Errorf("root DomainTarget = %q,%q; want system, system/%s", domain, target, label)
	}

	user := executor.NewMock()
	user.SetIsRoot(false)
	domain, target := DomainTarget(user)
	if !strings.HasPrefix(domain, "gui/") {
		t.Errorf("non-root domain = %q, want gui/<uid>", domain)
	}
	if target != domain+"/"+label {
		t.Errorf("target = %q, want %q", target, domain+"/"+label)
	}
}

type runResult struct {
	stderr string
	exit   int
}

// seqExec returns scripted results per command in order; the last repeats.
type seqExec struct {
	*executor.Mock
	script map[string][]runResult
	calls  map[string]int
}

func (s *seqExec) Run(_ context.Context, name string, args ...string) (string, string, int, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	rs, ok := s.script[key]
	if !ok {
		return "", "", -1, fmt.Errorf("no stub for %q", key)
	}
	i := s.calls[key]
	s.calls[key]++
	if i >= len(rs) {
		i = len(rs) - 1
	}
	return "", rs[i].stderr, rs[i].exit, nil
}

func noSleep(t *testing.T) *[]time.Duration {
	var slept []time.Duration
	orig := sleep
	sleep = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { sleep = orig })
	return &slept
}

func TestBootstrap_RetriesOnInProgress(t *testing.T) {
	noSleep(t)
	ex := &seqExec{Mock: executor.NewMock(), calls: map[string]int{}, script: map[string][]runResult{
		"launchctl bootstrap system /p.plist": {{"Bootstrap failed: 37: Operation already in progress", 37}, {"", 0}},
	}}
	if err := bootstrap(context.Background(), ex, progress.NewLogger(progress.LevelInfo), "system", "/p.plist"); err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if n := ex.calls["launchctl bootstrap system /p.plist"]; n != 2 {
		t.Errorf("bootstrap calls = %d, want 2", n)
	}
}

func TestBootstrap_PersistentFailure(t *testing.T) {
	slept := noSleep(t)
	ex := &seqExec{Mock: executor.NewMock(), calls: map[string]int{}, script: map[string][]runResult{
		"launchctl bootstrap system /p.plist": {{"Bootstrap failed: 5: Input/output error", 5}},
	}}
	err := bootstrap(context.Background(), ex, progress.NewLogger(progress.LevelInfo), "system", "/p.plist")
	if err == nil || !strings.Contains(err.Error(), "NOT loaded") {
		t.Fatalf("expected not-loaded error, got %v", err)
	}
	if n := ex.calls["launchctl bootstrap system /p.plist"]; n != len(bootstrapBackoff)+1 {
		t.Errorf("bootstrap calls = %d, want %d", n, len(bootstrapBackoff)+1)
	}
	var total time.Duration
	for _, d := range *slept {
		total += d
	}
	if total > 10*time.Second {
		t.Errorf("total backoff %v exceeds 10s", total)
	}
}

func TestBootstrap_NoRetryOnOtherErrors(t *testing.T) {
	noSleep(t)
	ex := &seqExec{Mock: executor.NewMock(), calls: map[string]int{}, script: map[string][]runResult{
		"launchctl bootstrap system /p.plist": {{"Bootstrap failed: 113", 113}},
	}}
	if err := bootstrap(context.Background(), ex, progress.NewLogger(progress.LevelInfo), "system", "/p.plist"); err == nil {
		t.Fatal("expected error")
	}
	if n := ex.calls["launchctl bootstrap system /p.plist"]; n != 1 {
		t.Errorf("bootstrap calls = %d, want 1", n)
	}
}

func TestWaitForBootout_PollsUntilGone(t *testing.T) {
	noSleep(t)
	target := "system/" + label
	ex := &seqExec{Mock: executor.NewMock(), calls: map[string]int{}, script: map[string][]runResult{
		"launchctl print " + target: {{"", 0}, {"", 0}, {"Could not find service", 113}},
	}}
	waitForBootout(context.Background(), ex, progress.NewLogger(progress.LevelInfo), target)
	if n := ex.calls["launchctl print "+target]; n != 3 {
		t.Errorf("print calls = %d, want 3", n)
	}
}

func TestWaitForBootout_Bounded(t *testing.T) {
	slept := noSleep(t)
	target := "system/" + label
	ex := &seqExec{Mock: executor.NewMock(), calls: map[string]int{}, script: map[string][]runResult{
		"launchctl print " + target: {{"", 0}},
	}}
	waitForBootout(context.Background(), ex, progress.NewLogger(progress.LevelInfo), target)
	var total time.Duration
	for _, d := range *slept {
		total += d
	}
	if total > 10*time.Second {
		t.Errorf("waited %v, want <= 10s", total)
	}
}

// hangExec blocks every Run until ctx is done, like a stalled launchctl.
type hangExec struct {
	*executor.Mock
	calls int
}

func (h *hangExec) Run(ctx context.Context, _ string, _ ...string) (string, string, int, error) {
	h.calls++
	<-ctx.Done()
	return "", "", -1, ctx.Err()
}

func TestWaitForBootout_DeadlineStopsHungPrint(t *testing.T) {
	noSleep(t)
	orig := bootoutPollTimeout
	bootoutPollTimeout = 50 * time.Millisecond
	t.Cleanup(func() { bootoutPollTimeout = orig })

	ex := &hangExec{Mock: executor.NewMock()}
	done := make(chan struct{})
	go func() {
		waitForBootout(context.Background(), ex, progress.NewLogger(progress.LevelInfo), "system/"+label)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("waitForBootout did not return after deadline")
	}
	if ex.calls != 1 {
		t.Errorf("print calls = %d, want 1 (polling should stop at deadline)", ex.calls)
	}
}
