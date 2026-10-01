//go:build darwin

package credentials

import (
	"context"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"os"
	"path/filepath"
	"testing"
)

func TestTCCPreservesCredentialGitTracking(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, awsTree)
	if err := os.MkdirAll(filepath.Join(home, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	e := newMock(t, home)
	e.SetCommand("credentials", "", 0, "git", "-C", filepath.Join(home, ".aws"), "ls-files", "--error-unmatch", "credentials")
	got := New(e).WithSkipper(tcc.New(home)).withEnv(staticEnv(nil)).Detect(context.Background())
	f, ok := findingFor(got, sourceAWSCredentials)
	if !ok || !f.InGitRepo || !f.GitTracked {
		t.Fatalf("tracked credential became untracked: found=%v in_repo=%v tracked=%v", ok, f.InGitRepo, f.GitTracked)
	}
}
