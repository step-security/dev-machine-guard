package state

import (
	"context"
	"errors"
	"io"
	"testing"

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

func newReconciler(_ *testing.T, fetch FetchResult, fetchErr error, exitCode int) (*Reconciler, *callRec) {
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
	}, rec
}

func TestReconcileEnabledCallsInstall(t *testing.T) {
	r, rec := newReconciler(t, FetchResult{Enabled: true}, nil, 0)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0] != "install" {
		t.Fatalf("calls = %v, want [install]", rec.calls)
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
}

func TestReconcileFetchErrorSkipsConverge(t *testing.T) {
	r, rec := newReconciler(t, FetchResult{}, errors.New("network down"), 0)
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile should surface fetch error")
	}
	if len(rec.calls) != 0 {
		t.Fatalf("no install/uninstall on fetch error; got %v", rec.calls)
	}
}

func TestReconcileInstallFailureSurfacesError(t *testing.T) {
	r, _ := newReconciler(t, FetchResult{Enabled: true}, nil, 1)
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("non-zero install exit should surface as error")
	}
}

func TestReconcileNilFetcherIsError(t *testing.T) {
	r := &Reconciler{}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("nil fetcher should error")
	}
}
