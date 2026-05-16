package state

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

type fakeFetcher struct {
	res FetchResult
	err error
}

func (f *fakeFetcher) Fetch(_ context.Context, _, _ string) (FetchResult, error) {
	return f.res, f.err
}

type callRec struct {
	calls []string
	codes []int
	exit  int
}

func (r *callRec) fn(name string) HookCommandFn {
	return func(_ context.Context, _ executor.Executor, _ string, _, _ io.Writer) int {
		r.calls = append(r.calls, name)
		r.codes = append(r.codes, r.exit)
		return r.exit
	}
}

func newReconciler(t *testing.T, fetch FetchResult, fetchErr error, exitCode int) (*Reconciler, *callRec) {
	t.Helper()
	withTempCache(t)
	rec := &callRec{exit: exitCode}
	return &Reconciler{
		Exec:        executor.NewMock(),
		Fetcher:     &fakeFetcher{res: fetch, err: fetchErr},
		CustomerID:  "cust",
		DeviceID:    "dev-1",
		Stdout:      io.Discard,
		Stderr:      io.Discard,
		InstallFn:   rec.fn("install"),
		UninstallFn: rec.fn("uninstall"),
		Now:         func() time.Time { return time.Date(2026, 5, 14, 8, 0, 0, 0, time.UTC) },
	}, rec
}

func TestReconcileEnabledCallsInstallAndWritesCache(t *testing.T) {
	r, rec := newReconciler(t, FetchResult{Enabled: true}, nil, 0)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0] != "install" {
		t.Fatalf("calls = %v, want [install]", rec.calls)
	}
	s, ok := Read()
	if !ok {
		t.Fatal("cache should be written")
	}
	if !s.Hooks.Enabled || s.Source != SourcePoll {
		t.Fatalf("cache = %+v", s)
	}
}

func TestReconcileDisabledCallsUninstall(t *testing.T) {
	r, rec := newReconciler(t, FetchResult{Enabled: false}, nil, 0)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0] != "uninstall" {
		t.Fatalf("calls = %v, want [uninstall]", rec.calls)
	}
	s, _ := Read()
	if s.Hooks.Enabled {
		t.Fatal("cache should record disabled")
	}
}

func TestReconcileFetchErrorPreservesCache(t *testing.T) {
	r, rec := newReconciler(t, FetchResult{}, errors.New("network down"), 0)
	// Seed prior cache so we can verify it's untouched.
	prior := Default()
	prior.Hooks.Enabled = false
	prior.Source = SourcePoll
	if err := Write(prior); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile should surface fetch error")
	}
	if len(rec.calls) != 0 {
		t.Fatalf("no install/uninstall on fetch error; got %v", rec.calls)
	}
	s, ok := Read()
	if !ok || s.Hooks.Enabled || s.Source != SourcePoll {
		t.Fatalf("cache should be untouched, got %+v ok=%v", s, ok)
	}
}

func TestReconcileInstallFailureSurfacesError(t *testing.T) {
	r, _ := newReconciler(t, FetchResult{Enabled: true}, nil, 1)
	err := r.Reconcile(context.Background())
	if err == nil {
		t.Fatal("non-zero install exit should surface as error")
	}
	// Cache should still be written — settings retry is the next tick's job.
	s, ok := Read()
	if !ok || !s.Hooks.Enabled {
		t.Fatalf("cache should still reflect desired state, got %+v ok=%v", s, ok)
	}
}

func TestReconcileNilFetcherIsError(t *testing.T) {
	withTempCache(t)
	r := &Reconciler{}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("nil fetcher should error")
	}
}
