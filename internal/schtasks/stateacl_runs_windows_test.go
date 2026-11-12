//go:build windows

package schtasks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// The scheduled scan runs as the signed-in (standard) user. Under the
// hardened ACLs each user must still write their own run record and mark it
// started (v1.19.0 couldn't: runs\ had no user grant, so probation never saw
// a run), must not write another user's, and the SYSTEM updater must read
// them all. Two real local users, impersonated; needs an elevated token.
func TestHardenStateDirACLs_NativeStandardUserRunRecords(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token to create users and set owners")
	}
	root, err := os.MkdirTemp(os.Getenv("ProgramData"), "dmg-runs-acl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	exec := executor.NewReal()
	// An upgraded install: the earlier blanket grant, and runs\ with a
	// record a user's scan wrote before the hardening.
	if _, stderr, code, err := exec.Run(context.Background(), "icacls", root, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/Q"); err != nil || code != 0 {
		t.Fatalf("legacy grant: exit %d err %v: %s", code, err, stderr)
	}
	if err := os.MkdirAll(filepath.Join(root, "runs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runs", "1.19.0.json"), []byte(`{"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hardenStateDirACLs(context.Background(), exec, root); err != nil {
		t.Fatalf("hardenStateDirACLs: %v", err)
	}
	l := updatestate.Layout{DataRoot: root}
	v := updatestate.Version{Major: 1, Minor: 20}

	alice, bob := newStandardUser(t, exec), newStandardUser(t, exec)
	aliceFile := l.RunFileFor(v, alice.sid)
	scan := func(u testUser, runID string) {
		asUser(t, u, func() {
			if owner := updatestate.RunOwner(); owner != u.sid {
				t.Errorf("%s: RunOwner = %q, want the user's SID %s", u.name, owner, u.sid)
			}
			file := l.RunFileFor(v, updatestate.RunOwner())
			if err := withLock(updatestate.RunLockPath(file), func() error {
				return updatestate.AppendRun(file, updatestate.RunRecord{RunID: runID, Version: v.String()})
			}); err != nil {
				t.Errorf("%s: appending a run record: %v", u.name, err)
				return
			}
			if err := updatestate.MarkRunStartedLocked(file, runID, 0); err != nil {
				t.Errorf("%s: marking started: %v", u.name, err)
			}
			if err := withLock(updatestate.RunLockPath(file), func() error {
				return updatestate.FinalizeRun(file, runID, 0, false, time.Now())
			}); err != nil {
				t.Errorf("%s: finalizing: %v", u.name, err)
			}
		})
	}
	for _, u := range []testUser{alice, bob} {
		scan(u, "first-"+u.name)
	}
	// The updater re-applies the grants every tick; each user still writes
	// the file they created.
	if err := hardenStateDirACLs(context.Background(), exec, root); err != nil {
		t.Fatalf("re-applying the grants: %v", err)
	}
	for _, u := range []testUser{alice, bob} {
		scan(u, "second-"+u.name)
	}
	asUser(t, bob, func() {
		if err := updatestate.AppendRun(aliceFile, updatestate.RunRecord{RunID: "forged", Version: v.String()}); err == nil {
			t.Errorf("%s wrote %s's run file", bob.name, alice.name)
		}
	})

	files := l.RunFiles(v)
	if len(files) != 2 {
		t.Fatalf("RunFiles = %v, want both users' files", files)
	}
	for _, f := range files {
		recs := updatestate.ReadRuns(f)
		if len(recs) != 2 || updatestate.ClassifyRun(recs[0]) != updatestate.RunHealthy || updatestate.ClassifyRun(recs[1]) != updatestate.RunHealthy {
			t.Errorf("%s: records = %+v, want two healthy runs", filepath.Base(f), recs)
		}
	}
}

type testUser struct {
	name, password, sid string
}

// newStandardUser creates a local user (a member of Users only), deleted
// when the test ends.
func newStandardUser(t *testing.T, exec executor.Executor) testUser {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	// net user prompts for a password over 14 characters.
	u := testUser{name: "dmgrun" + hex.EncodeToString(b), password: "D9!" + hex.EncodeToString(b) + "q"}
	ctx := context.Background()
	if _, stderr, code, err := exec.Run(ctx, "net", "user", u.name, u.password, "/add"); err != nil || code != 0 {
		t.Fatalf("creating user %s: exit %d err %v: %s", u.name, code, err, stderr)
	}
	t.Cleanup(func() { _, _, _, _ = exec.Run(ctx, "net", "user", u.name, "/delete") })
	sid, _, _, err := windows.LookupSID("", u.name)
	if err != nil {
		t.Fatalf("looking up %s: %v", u.name, err)
	}
	u.sid = sid.String()
	return u
}

var (
	advapi32                = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW          = advapi32.NewProc("LogonUserW")
	procImpersonateLoggedOn = advapi32.NewProc("ImpersonateLoggedOnUser")
)

const (
	logon32LogonNetwork    = 3
	logon32ProviderDefault = 0
)

// asUser runs fn on this OS thread impersonating u (a network logon: file
// access is all it needs).
func asUser(t *testing.T, u testUser, fn func()) {
	t.Helper()
	name, _ := windows.UTF16PtrFromString(u.name)
	domain, _ := windows.UTF16PtrFromString(".")
	pw, _ := windows.UTF16PtrFromString(u.password)
	var tok windows.Token
	if r, _, err := procLogonUserW.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(pw)),
		logon32LogonNetwork, logon32ProviderDefault, uintptr(unsafe.Pointer(&tok))); r == 0 {
		t.Fatalf("logging on %s: %v", u.name, err)
	}
	defer func() { _ = tok.Close() }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, err := procImpersonateLoggedOn.Call(uintptr(tok)); r == 0 {
		t.Fatalf("impersonating %s: %v", u.name, err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			panic(err) // never leave the thread impersonating
		}
	}()
	fn()
}

func withLock(path string, fn func() error) error {
	lk, err := updatestate.AcquireLock(path)
	if err != nil {
		return err
	}
	defer lk.Release()
	return fn()
}
