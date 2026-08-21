// Package execguard decides whether a detector may safely launch a
// third-party binary on this machine.
//
// On macOS, executing a quarantined binary (com.apple.quarantine xattr, set
// by browser downloads and Homebrew cask installs) makes Gatekeeper assess
// it; when the binary or a native library it loads is not notarized, the OS
// shows a "could not verify … free of malware / Move to Bin" dialog in the
// logged-in user's session — a scary popup for something the user never ran
// themselves. SafeToExec answers, without any UI side effects, whether that
// would happen, so version probes can skip the exec (reporting "unknown")
// instead of triggering it. This generalizes the existing IsAppleCLTStub
// guard (which prevents the analogous Command Line Tools install prompt).
//
// On Linux the cause differs and the effect is the same: a packaged Electron
// app does not implement --version (only the unpackaged `electron` binary's
// default app does), so the flag is ignored and its window opens on the user's
// desktop. Reported by an Ubuntu 22.04 customer via LM Studio.
package execguard

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

const probeTimeout = 5 * time.Second

// SafeToExec reports whether launching binaryPath is safe from a
// GUI-popup perspective. Windows always returns true.
//
// On macOS it resolves symlinks, then checks the binary and its containing
// directory for the com.apple.quarantine attribute (cask installs quarantine
// the whole install tree, so the parent dir catches partially-cleared
// installs). Unquarantined binaries are safe: Gatekeeper only assesses
// quarantined files. For quarantined ones, `spctl --assess --type execute`
// gives Gatekeeper's verdict silently — accepted means executing shows no
// popup; rejected (or any spctl failure, conservatively) means skip.
//
// Both probes execute only Apple-provided utilities (/usr/bin/xattr,
// /usr/sbin/spctl), which carry none of the third-party-binary risk this
// package exists to avoid.
//
// On Linux it answers whether the binary is an Electron app's GUI entry point,
// purely from stats.
func SafeToExec(ctx context.Context, exec executor.Executor, binaryPath string) bool {
	if binaryPath == "" {
		return true
	}
	resolved, err := exec.EvalSymlinks(binaryPath)
	if err != nil || resolved == "" {
		resolved = binaryPath
	}

	switch exec.GOOS() {
	case model.PlatformLinux:
		return !isElectronAppEntryPoint(exec, resolved)
	case model.PlatformDarwin:
		if !isQuarantined(ctx, exec, resolved) && !isQuarantined(ctx, exec, parentDir(resolved)) {
			return true
		}
		_, _, exitCode, err := exec.RunWithTimeout(ctx, probeTimeout, "/usr/sbin/spctl", "--assess", "--type", "execute", resolved)
		return err == nil && exitCode == 0
	default:
		return true
	}
}

// electronBundleMarkers are files an Electron app ships beside its executable
// and nothing else ships: the packed app archive and the Chromium runtime.
var electronBundleMarkers = []string{
	"resources/app.asar",
	"libffmpeg.so",
	"chrome_100_percent.pak",
	"icudtl.dat",
}

// isElectronAppEntryPoint reports whether resolved is the GUI executable at
// the root of an Electron app tree.
//
// Only the binary's OWN directory is examined, which is what separates the app
// from its CLI: /usr/share/code/code sits beside libffmpeg.so, while the shim
// at /usr/share/code/bin/code does not. Checking the parent too — as the macOS
// quarantine probe must, since cask installs mark whole trees — would reject
// exactly the shims we need.
//
// Electron-only is deliberate: a GTK or Qt app on $PATH needs its own signal.
func isElectronAppEntryPoint(exec executor.Executor, resolved string) bool {
	dir := parentDir(resolved)
	if dir == "" {
		return false
	}
	for _, marker := range electronBundleMarkers {
		if exec.FileExists(dir + "/" + marker) {
			return true
		}
	}
	return false
}

// isQuarantined reports whether path carries the com.apple.quarantine
// extended attribute. xattr -p exits non-zero when the attribute (or the
// file) is absent.
func isQuarantined(ctx context.Context, exec executor.Executor, path string) bool {
	if path == "" {
		return false
	}
	_, _, exitCode, err := exec.RunWithTimeout(ctx, probeTimeout, "/usr/bin/xattr", "-p", "com.apple.quarantine", path)
	return err == nil && exitCode == 0
}

// parentDir returns the directory containing path ("" when there is none).
// Manual instead of filepath.Dir so mock paths behave identically on any
// test host OS.
func parentDir(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return ""
}
