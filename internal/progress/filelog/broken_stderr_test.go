package filelog

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

// A broken stderr (EPIPE) must not stop the file copy.
func TestTee_BrokenStderrKeepsFileLogging(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	defer func() { _ = w.Close() }()
	withStderr(t, w)

	path := filepath.Join(t.TempDir(), "err.log")
	c, err := Start(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		fmt.Fprintf(os.Stderr, "line %d\n", i)
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "line 0") || !strings.Contains(string(got), "line 2") {
		t.Errorf("file log = %q, want all lines", got)
	}
}

// When fd 2 itself is a broken pipe, Go's default SIGPIPE handling would kill
// the process on the tee's first write. Runs in a child so fd 2 can be broken.
func TestTee_BrokenFD2DoesNotKillProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGPIPE on windows")
	}
	if path := os.Getenv("FILELOG_SIGPIPE_CHILD"); path != "" {
		proctest.Guard()
		c, err := Start(path, 0)
		if err != nil {
			os.Exit(3)
		}
		fmt.Fprintln(os.Stderr, "first")
		fmt.Fprintln(os.Stderr, "second")
		_ = c.Stop()
		os.Exit(0)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	path := filepath.Join(t.TempDir(), "err.log")
	cmd := proctest.Command(t, os.Args[0], "-test.run=^TestTee_BrokenFD2DoesNotKillProcess$")
	cmd.Env = append(cmd.Env, "FILELOG_SIGPIPE_CHILD="+path)
	cmd.Stderr = w
	err = cmd.Run()
	_ = w.Close()
	if err != nil {
		t.Fatalf("child died: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "second") {
		t.Errorf("file log = %q, want both lines", got)
	}
}
