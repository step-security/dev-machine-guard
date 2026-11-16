package executor

import (
	"context"
	"errors"
	"os/user"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

type stalledConsoleExecutor struct {
	*Mock
	started chan struct{}
	release chan struct{}
}

func (e *stalledConsoleExecutor) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	close(e.started)
	select {
	case <-ctx.Done():
		return "", "", 124, ctx.Err()
	case <-e.release:
		return "", "", 1, errors.New("released probe")
	}
}

func TestLoggedInUserContextCancelsConsoleProbe(t *testing.T) {
	mock := NewMock()
	mock.SetGOOS(model.PlatformDarwin)
	mock.SetIsRoot(true)
	exec := &stalledConsoleExecutor{mock, make(chan struct{}), make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); _, err := loggedInUserContext(ctx, exec, user.Lookup); result <- err }()
	defer func() { close(exec.release); <-finished }()
	<-exec.started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("probe error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("console probe ignored caller cancellation")
	}
}

func TestLoggedInUserContextCancelsDirectoryLookup(t *testing.T) {
	mock := NewMock()
	mock.SetGOOS(model.PlatformDarwin)
	mock.SetIsRoot(true)
	mock.SetCommand("alice\n", "", 0, "stat", "-f%Su", "/dev/console")
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	lookup := func(string) (*user.User, error) {
		close(started)
		defer close(finished)
		<-release
		return &user.User{Username: "alice"}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := loggedInUserContext(ctx, mock, lookup); result <- err }()
	defer func() { close(release); <-finished }()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lookup error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("directory lookup ignored caller cancellation")
	}
}

func TestLoggedInUserContextConsoleOutcomes(t *testing.T) {
	for _, username := range []string{"", "root", "_windowserver", "alice"} {
		t.Run(username, func(t *testing.T) {
			mock := NewMock()
			mock.SetGOOS(model.PlatformDarwin)
			mock.SetIsRoot(true)
			mock.SetCommand(username, "", 0, "stat", "-f%Su", "/dev/console")
			lookedUp := false
			got, err := loggedInUserContext(context.Background(), mock, func(name string) (*user.User, error) {
				lookedUp = true
				return &user.User{Username: name, HomeDir: "/Users/" + name}, nil
			})
			if username == "alice" {
				if err != nil || got.Username != "alice" || got.HomeDir != "/Users/alice" || !lookedUp {
					t.Fatalf("console user: %+v %v", got, err)
				}
			} else if err == nil || got != nil || lookedUp {
				t.Fatalf("no-user outcome: %+v %v lookup=%v", got, err, lookedUp)
			}
		})
	}
}

func TestLoggedInUserContextCapsBackgroundProbe(t *testing.T) {
	mock := NewMock()
	mock.SetGOOS(model.PlatformDarwin)
	mock.SetIsRoot(true)
	exec := &stalledConsoleExecutor{mock, make(chan struct{}), make(chan struct{})}
	result, finished := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(finished)
		_, err := loggedInUserContext(context.Background(), exec, user.Lookup)
		result <- err
	}()
	defer func() { close(exec.release); <-finished }()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("uncapped background lookup: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("background session lookup exceeded its default cap")
	}
}
