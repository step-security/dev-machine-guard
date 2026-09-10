package main

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/devicepolicy"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

type packageConfigFetcher struct {
	calls    []string
	contexts map[string]context.Context
	failures map[string]error
}

func (f *packageConfigFetcher) Fetch(ctx context.Context, _, _, _, target string) (devicepolicy.EffectivePolicy, error) {
	f.calls = append(f.calls, target)
	if f.contexts != nil {
		f.contexts[target] = ctx
	}
	return devicepolicy.EffectivePolicy{}, f.failures[target]
}

type packageConfigReporter struct{}

func (packageConfigReporter) Report(context.Context, string, string, devicepolicy.ComplianceReport) error {
	return nil
}

type npmLaneExecutor struct {
	*executor.Mock
	user *user.User
}

func (e npmLaneExecutor) LoggedInUser() (*user.User, error) { return e.user, nil }

type npmLaneFetcher struct{}

func (npmLaneFetcher) Fetch(context.Context, string, string, string, string) (devicepolicy.EffectivePolicy, error) {
	return devicepolicy.EffectivePolicy{
		Category: devicepolicy.CategoryPackageConfig,
		Target:   devicepolicy.TargetNPM,
		Policy:   []byte(`{"ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"device-secret"}}`),
		Hash:     "sha256:npm",
	}, nil
}

type invalidNPMSettingsFetcher struct{}

func (invalidNPMSettingsFetcher) Fetch(context.Context, string, string, string, string) (devicepolicy.EffectivePolicy, error) {
	return devicepolicy.EffectivePolicy{
		Category: devicepolicy.CategoryPackageConfig,
		Target:   devicepolicy.TargetNPM,
		Policy:   []byte(`{"ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"device-secret"},"settings":null}`),
		Hash:     "sha256:npm",
	}, nil
}

type countingTargetExecutor struct {
	*executor.Mock
	user  *user.User
	calls int
}

func (e *countingTargetExecutor) LoggedInUser() (*user.User, error) {
	e.calls++
	u := *e.user
	return &u, nil
}

func TestResolveDevicePolicyTargetPinsOneIdentityPerCycle(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	current.HomeDir = t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	exec := &countingTargetExecutor{Mock: mock, user: current}
	target, restore, ok := resolveDevicePolicyTarget(exec, progress.NewNoop())
	if !ok {
		t.Fatal("resolveDevicePolicyTarget failed")
	}
	defer restore()
	for range 2 {
		if _, err := target.LoggedInUser(); err != nil {
			t.Fatal(err)
		}
	}
	if exec.calls != 1 {
		t.Fatalf("LoggedInUser calls = %d, want one per cycle", exec.calls)
	}
}

func TestNPMPackageConfigLanePersistsSecretFreeOwnership(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	statePath := filepath.Join(t.TempDir(), devicepolicy.CacheFilename)
	t.Cleanup(devicepolicy.SetCachePathForTest(statePath))
	exec := npmLaneExecutor{Mock: executor.NewMock(), user: &user.User{
		Username: current.Username,
		Uid:      current.Uid,
		Gid:      current.Gid,
		HomeDir:  home,
	}}

	if err := runNPMPackageConfigLane(context.Background(), exec, progress.NewNoop(), npmLaneFetcher{}, packageConfigReporter{}, "customer", "serial", "linux"); err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), "device-secret") || strings.Contains(string(state), "_authToken") {
		t.Fatalf("state contains npm credential material: %s", state)
	}
	record, ok := devicepolicy.ReadAppliedState(devicepolicy.CategoryPackageConfig, devicepolicy.TargetNPM)
	if !ok || record.WrittenSettings[devicepolicy.NPMOwnedKey] != "dmg_marker_v1" {
		t.Fatalf("npm ownership = %+v, %v; want constant marker", record, ok)
	}
}

func TestNPMPackageConfigLane_ValidatesSettingsBeforeResolvingTargetUser(t *testing.T) {
	exec := &countingTargetExecutor{Mock: executor.NewMock()}
	err := runNPMPackageConfigLane(context.Background(), exec, progress.NewNoop(), invalidNPMSettingsFetcher{}, packageConfigReporter{}, "customer", "serial", "linux")
	if err == nil {
		t.Fatal("invalid settings must fail")
	}
	if got, want := exec.calls, 0; got != want {
		t.Fatalf("LoggedInUser calls = %d, want %d", got, want)
	}
}

func TestPackageConfigLanes_FailureDoesNotSuppressSibling(t *testing.T) {
	logDir := t.TempDir()
	t.Setenv("STEPSECURITY_HOME", logDir)
	tests := []struct {
		name       string
		failTarget string
	}{
		{"npm failure still runs siblings", devicepolicy.TargetNPM},
		{"PyPI failure still runs siblings", devicepolicy.TargetPyPI},
		{"Go failure keeps earlier lanes", devicepolicy.TargetGo},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fetcher := &packageConfigFetcher{failures: map[string]error{tc.failTarget: errors.New("lane failed")}}
			mock := executor.NewMock()
			mock.SetLoggedInUserError(errors.New("no user needed for absent policy"))

			runPackageConfigLanes(mock, progress.NewNoop(), fetcher, packageConfigReporter{}, "customer", "serial", "linux")

			if got, want := strings.Join(fetcher.calls, ","), devicepolicy.TargetNPM+","+devicepolicy.TargetPyPI+","+devicepolicy.TargetGo; got != want {
				t.Errorf("lane calls = %q, want %q", got, want)
			}
			if _, err := os.Stat(filepath.Join(logDir, "ai-agent-hook-errors.jsonl")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("device-policy failure wrote to hook error log: stat error = %v", err)
			}
		})
	}
}

func TestPackageConfigLanes_UseSeparateTimeoutContexts(t *testing.T) {
	fetcher := &packageConfigFetcher{contexts: map[string]context.Context{}, failures: map[string]error{}}
	mock := executor.NewMock()
	mock.SetLoggedInUserError(errors.New("no user needed for absent policy"))

	runPackageConfigLanes(mock, progress.NewNoop(), fetcher, packageConfigReporter{}, "customer", "serial", "linux")

	npmCtx := fetcher.contexts[devicepolicy.TargetNPM]
	pypiCtx := fetcher.contexts[devicepolicy.TargetPyPI]
	goCtx := fetcher.contexts[devicepolicy.TargetGo]
	if npmCtx == nil || pypiCtx == nil || goCtx == nil {
		t.Fatalf("lane contexts = %#v, want all three", fetcher.contexts)
	}
	if npmCtx == pypiCtx || npmCtx == goCtx || pypiCtx == goCtx {
		t.Error("package-config lanes shared a context")
	}
	if _, ok := npmCtx.Deadline(); !ok {
		t.Error("npm context has no deadline")
	}
	if _, ok := pypiCtx.Deadline(); !ok {
		t.Error("PyPI context has no deadline")
	}
	if _, ok := goCtx.Deadline(); !ok {
		t.Error("Go context has no deadline")
	}
}
