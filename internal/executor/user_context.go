package executor

import (
	"context"
	"fmt"
	"os/user"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

const sessionLookupTimeout = time.Second

// LoggedInUserContext bounds both the console probe and directory lookup by the
// caller's deadline. The default cap also applies when no deadline was supplied.
func (r *Real) LoggedInUserContext(ctx context.Context) (*user.User, error) {
	return loggedInUserContext(ctx, r, user.Lookup)
}

func loggedInUserContext(ctx context.Context, exec Executor, lookup func(string) (*user.User, error)) (*user.User, error) {
	ctx, cancel := context.WithTimeout(ctx, sessionLookupTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if exec.GOOS() != model.PlatformDarwin || !exec.IsRoot() {
		return lookupUserContext(ctx, exec.CurrentUser)
	}
	stdout, _, _, err := exec.Run(ctx, "stat", "-f%Su", "/dev/console")
	if err != nil {
		return nil, fmt.Errorf("stat /dev/console failed: %w", err)
	}
	username := strings.TrimSpace(stdout)
	if username == "" || username == "root" || username == "_windowserver" {
		return nil, fmt.Errorf("no GUI console user (owner=%q)", username)
	}
	u, err := lookupUserContext(ctx, func() (*user.User, error) { return lookup(username) })
	if err != nil {
		return nil, fmt.Errorf("console user %q lookup failed: %w", username, err)
	}
	return u, nil
}

// OS directory services have no context API. A buffered result lets a delayed
// lookup finish after cancellation without blocking its sender or the caller.
func lookupUserContext(ctx context.Context, lookup func() (*user.User, error)) (*user.User, error) {
	type result struct {
		user *user.User
		err  error
	}
	done := make(chan result, 1)
	go func() { u, err := lookup(); done <- result{u, err} }()
	select {
	case r := <-done:
		return r.user, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
