//go:build windows

package selfupdate

import (
	"context"
	"encoding/base64"
	"os"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// The scheduled task's action invokes the launcher, so a Windows update that
// refreshed the agent alone would keep launching the old launcher forever.
func TestRun_UpdatesLauncherAlongsideAgent(t *testing.T) {
	st := stageAll(t, validMeta(), fixturePayload)
	// Undo the harness's up-to-date launcher: both artifacts are now stale.
	if err := os.WriteFile(st.launcher, []byte("old-launcher-content\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = false, want an installed update")
	}
	for _, c := range []struct {
		label, path string
	}{{"agent", st.exe}, {"launcher", st.launcher}} {
		got, err := os.ReadFile(c.path)
		if err != nil || string(got) != fixturePayload {
			t.Errorf("%s content = %q err=%v, want the downloaded payload", c.label, got, err)
		}
	}
	if st.downloads.Load() != 1 || st.launcherDownloads.Load() != 1 {
		t.Errorf("downloads = agent %d / launcher %d, want 1 each", st.downloads.Load(), st.launcherDownloads.Load())
	}
}

// A stale launcher alone is enough to trigger an update: the agent matching
// the release must not short-circuit the launcher's convergence.
func TestRun_UpdatesLauncherWhenAgentIsCurrent(t *testing.T) {
	st := stageAll(t, validMeta(), fixturePayload)
	if err := os.WriteFile(st.exe, []byte(fixturePayload), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.launcher, []byte("old-launcher-content\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = false, want the launcher updated")
	}
	if st.downloads.Load() != 0 {
		t.Errorf("agent downloads = %d, want 0 (agent already matched)", st.downloads.Load())
	}
	if st.launcherDownloads.Load() != 1 {
		t.Errorf("launcher downloads = %d, want 1", st.launcherDownloads.Load())
	}
}

// A response missing the launcher fields must abort the whole update rather
// than land a half-updated pair. The endpoint omits them only below v1.11.4
// (far under the self-update floor) or leaves them empty on a transient
// signature-sidecar fetch failure.
func TestRun_MissingLauncherFieldsAbortsUpdate(t *testing.T) {
	wrapped := base64.StdEncoding.EncodeToString([]byte(fixturePayloadSig))
	meta := `{"version":"9.9.9","checksum":"` + fixturePayloadChecksum + `","signed_checksum":"` + wrapped + `"}`
	st := stageAll(t, meta, fixturePayload)

	if Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = true despite a response with no launcher fields")
	}
	if st.downloads.Load() != 0 || st.launcherDownloads.Load() != 0 {
		t.Errorf("downloads = agent %d / launcher %d, want 0 each", st.downloads.Load(), st.launcherDownloads.Load())
	}
	got, _ := os.ReadFile(st.exe)
	if string(got) != "old-binary-content\n" {
		t.Error("agent was replaced despite the incomplete response")
	}
}

// An absent launcher is installed rather than failing the update: a partial
// earlier install (or a hand-deleted launcher) must be able to recover, and
// the scheduled task cannot fire at all without one.
func TestRun_InstallsMissingLauncher(t *testing.T) {
	st := stageAll(t, validMeta(), fixturePayload)
	if err := os.Remove(st.launcher); err != nil {
		t.Fatal(err)
	}

	if !Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = false, want the missing launcher installed")
	}
	if got, err := os.ReadFile(st.launcher); err != nil || string(got) != fixturePayload {
		t.Errorf("launcher content = %q err=%v, want the downloaded payload", got, err)
	}
	if st.launcherDownloads.Load() != 1 {
		t.Errorf("launcher downloads = %d, want 1", st.launcherDownloads.Load())
	}
}

// Windows cannot overwrite or unlink a mapped executable image, so the swap
// renames the live image aside and drops the new one into its path. The
// leftover is what a later run sweeps.
func TestSwapBinary_RenamesTargetAsideAndSweeps(t *testing.T) {
	dir := t.TempDir()
	dst := dir + `\agent.exe`
	src := dir + `\agent.exe.new`
	if err := os.WriteFile(dst, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := swapBinary(src, dst); err != nil {
		t.Fatalf("swapBinary: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "new" {
		t.Errorf("dst = %q, want the new content", got)
	}
	if got, err := os.ReadFile(dst + oldSuffix); err != nil || string(got) != "old" {
		t.Errorf("aside copy = %q err=%v, want the previous image preserved", got, err)
	}

	sweepLeftovers(dst)
	if _, err := os.Stat(dst + oldSuffix); !os.IsNotExist(err) {
		t.Errorf("sweepLeftovers left %s behind (err=%v)", dst+oldSuffix, err)
	}
}

// A missing target is installed rather than treated as an error: the swap is
// also the path a half-finished earlier update recovers through.
func TestSwapBinary_InstallsWhenTargetAbsent(t *testing.T) {
	dir := t.TempDir()
	dst := dir + `\agent.exe`
	src := dir + `\agent.exe.new`
	if err := os.WriteFile(src, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := swapBinary(src, dst); err != nil {
		t.Fatalf("swapBinary: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "new" {
		t.Errorf("dst = %q, want the new content", got)
	}
}

// An update sweeps the previous update's renamed-aside images before adding
// another one, so the install dir never accumulates them.
func TestRun_SweepsPriorLeftovers(t *testing.T) {
	st := stageAll(t, validMeta(), fixturePayload)
	stale := st.exe + oldSuffix
	if err := os.WriteFile(stale, []byte("two-releases-ago\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = false, want an installed update")
	}
	// The sweep cleared the old leftover; this run's own swap then created a
	// fresh one holding the image that was live a moment ago.
	if got, err := os.ReadFile(stale); err != nil || string(got) != "old-binary-content\n" {
		t.Errorf("aside copy = %q err=%v, want this run's replaced image", got, err)
	}
}
