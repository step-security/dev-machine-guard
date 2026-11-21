//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/updatestate"
	"github.com/step-security/dev-machine-guard/internal/winproc"
	"golang.org/x/sys/windows"
)

// MSI installs the same signed console binary as dmg.exe. Resolve the
// active version on every invocation, independently of scheduler run state.
func handleAlias() {
	exe, err := os.Executable()
	if err != nil || !strings.EqualFold(filepath.Base(exe), "dmg.exe") {
		return
	}
	root := filepath.Dir(exe)
	if _, err := os.Lstat(filepath.Join(root, updatestate.BootstrapFile)); errors.Is(err, os.ErrNotExist) {
		return
	}
	layout, err := updatestate.ResolveLayout(exe)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	p, corrupt, loadErr := updatestate.LoadPointers(layout.StateFile())
	choices := updatestate.ResolveRunChain(layout, p, updatestate.LoadReason(p != nil, corrupt, loadErr))
	for _, c := range choices {
		cmd := exec.Command(filepath.Join(c.Dir, updatestate.AgentFile), os.Args[1:]...)
		// Reuse the terminal when one exists; background parents cannot create a window.
		if cp, _ := windows.GetConsoleCP(); cp == 0 {
			winproc.HideWindow(cmd)
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			continue
		}
		if err := cmd.Wait(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				os.Exit(exit.ExitCode())
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, "dmg: no installed agent version is runnable")
	os.Exit(1)
}
