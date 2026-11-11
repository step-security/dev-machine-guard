package schtasks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

type logACLExecutor struct {
	*executor.Mock
	calls     int
	failAt    int
	code      int
	err       error
	unbounded bool
}

func (e *logACLExecutor) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	e.unbounded = true
	return e.RunWithTimeout(ctx, 0, name, args...)
}
func (e *logACLExecutor) RunWithTimeout(_ context.Context, limit time.Duration, _ string, _ ...string) (string, string, int, error) {
	if limit <= 0 || limit > 30*time.Second {
		e.unbounded = true
	}
	e.calls++
	if e.calls == e.failAt {
		return "", "", e.code, e.err
	}
	return "", "", 0, nil
}
func TestPrepareLogDirectory_FailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		at, code int
		err      error
	}{
		{"remove nonzero", 1, 5, nil}, {"remove process error", 1, 0, errors.New("denied")},
		{"replace nonzero", 2, 5, nil}, {"replace process error", 2, 0, errors.New("denied")},
		{"inherit nonzero", 3, 5, nil}, {"inherit process error", 3, 0, errors.New("denied")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &logACLExecutor{Mock: executor.NewMock(), failAt: tc.at, code: tc.code, err: tc.err}
			e.SetIsRoot(true)
			err := prepareLogDirectory(context.Background(), e, filepath.Join(plainACLTestDir(t), "data"))
			if err == nil {
				t.Fatal("permission failure must abort setup")
			}
			if e.calls != tc.at {
				t.Fatalf("calls=%d, want stop at failed command %d", e.calls, tc.at)
			}
			if e.unbounded {
				t.Fatal("ACL command must have a deadline")
			}
		})
	}
}

func TestPrepareLogDirectory_RejectsRedirectedPath(t *testing.T) {
	for _, ancestor := range []bool{false, true} {
		t.Run(fmt.Sprint(ancestor), func(t *testing.T) {
			root := plainACLTestDir(t)
			target := filepath.Join(root, "target")
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			path := link
			if ancestor {
				path = filepath.Join(link, "child")
			}
			e := &logACLExecutor{Mock: executor.NewMock()}
			e.SetIsRoot(true)
			if err := prepareLogDirectory(context.Background(), e, path); err == nil {
				t.Fatal("redirected ACL target accepted")
			}
			if e.calls != 0 {
				t.Fatalf("ACL commands=%d for redirected path", e.calls)
			}
		})
	}
}
func TestPrepareLogDirectory_NonAdminDoesNotChangeACL(t *testing.T) {
	e := &logACLExecutor{Mock: executor.NewMock()}
	if err := prepareLogDirectory(context.Background(), e, filepath.Join(t.TempDir(), "logs")); err != nil {
		t.Fatal(err)
	}
	if e.calls != 0 {
		t.Fatal("non-admin install changed ACL")
	}
}

func plainACLTestDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPrepareLogDirectory_RejectsFile(t *testing.T) {
	path := filepath.Join(plainACLTestDir(t), "file")
	if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	e := &logACLExecutor{Mock: executor.NewMock()}
	e.SetIsRoot(true)
	if err := prepareLogDirectory(context.Background(), e, path); err == nil {
		t.Fatal("file accepted as directory")
	}
	if e.calls != 0 {
		t.Fatal("ACL command ran on a file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "unchanged" {
		t.Fatal("file changed")
	}
}
