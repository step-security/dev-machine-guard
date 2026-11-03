package device

import (
	"context"
	"os/user"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type stalledSessionExecutor struct {
	*executor.Mock
	release chan struct{}
}

func (e *stalledSessionExecutor) LoggedInUser() (*user.User, error) {
	<-e.release
	return nil, context.DeadlineExceeded
}

// Extra method before the fix, and the bounded interface after it. The legacy
// method models a session probe that ignores cancellation entirely.
func (e *stalledSessionExecutor) LoggedInUserContext(ctx context.Context) (*user.User, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestGatherSessionRespectsCallerDeadline(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "email", true: "configured"}[configured], func(t *testing.T) {
			previous := config.UserID
			t.Cleanup(func() { config.UserID = previous })
			config.UserID = ""
			if configured {
				config.UserID = "configured-user"
			}
			mock := executor.NewMock()
			mock.SetGOOS(model.PlatformDarwin)
			mock.SetIsRoot(true)
			mock.SetEnv("USER_EMAIL", "email@example.com")
			blocked := &stalledSessionExecutor{Mock: mock, release: make(chan struct{})}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			result := make(chan model.Device, 1)
			finished := make(chan struct{})
			go func() { defer close(finished); result <- Gather(ctx, blocked) }()
			defer func() { close(blocked.release); <-finished }()
			select {
			case dev := <-result:
				want := "email@example.com"
				if configured {
					want = "configured-user"
				}
				if dev.UserIdentity != want || !dev.NoUserLoggedIn {
					t.Fatalf("attribution/session after timeout: %+v", dev)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("session lookup ignored the caller's deadline")
			}
		})
	}
}
