//go:build !windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// The deployment loader invokes this verb as the developer, never as root.
func handleAlias() {
	if len(os.Args) < 2 || os.Args[1] != "_cli-link" {
		return
	}
	if len(os.Args) != 3 || os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "_cli-link requires install or uninstall as the developer")
		os.Exit(1)
	}
	home, err := os.UserHomeDir()
	if err == nil {
		var exe string
		exe, err = os.Executable()
		if err == nil {
			err = configureAlias(home, exe, os.Args[2], os.Getenv("SHELL"), os.Getenv("PATH"))
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func configureAlias(home, exe, action, shell, path string) error {
	bin := filepath.Join(home, ".local", "bin")
	link := filepath.Join(bin, "dmg")
	target, err := os.Readlink(link)
	switch action {
	case "uninstall":
		if err == nil && target == exe {
			return os.Remove(link)
		}
		return nil
	case "install":
	default:
		return fmt.Errorf("unknown _cli-link operation %q", action)
	}
	if existing, err := exec.LookPath("dmg"); err == nil && existing != link {
		return fmt.Errorf("dmg already resolves to %s; the full command is %s", existing, exe)
	}
	if target != exe {
		if err := os.MkdirAll(bin, 0700); err != nil {
			return err
		}
		if err := os.Symlink(exe, link); err != nil {
			return fmt.Errorf("create %s: %w", link, err)
		}
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == bin {
			return nil
		}
	}

	line := "# StepSecurity developer CLI\n" + `case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$PATH:$HOME/.local/bin" ;; esac`
	profiles := []string{".profile"}
	switch filepath.Base(shell) {
	case "zsh":
		profiles = []string{".zshrc"}
	case "bash":
		for _, name := range []string{".bash_profile", ".bash_login"} {
			if _, err := os.Stat(filepath.Join(home, name)); err == nil {
				profiles = []string{name}
				break
			}
		}
		profiles = append(profiles, ".bashrc")
	case "fish":
		profiles = []string{".config/fish/conf.d/stepsecurity-cli.fish"}
		line = "# StepSecurity developer CLI\n" + `contains -- "$HOME/.local/bin" $PATH; or set -gx PATH $PATH "$HOME/.local/bin"`
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range profiles {
		profile := filepath.Join(home, name)
		if err := appendPath(root, name, line); err != nil {
			return fmt.Errorf("add %s to PATH in %s: %w", bin, profile, err)
		}
	}
	return nil
}

func appendPath(root *os.Root, profile, line string) error {
	if err := root.MkdirAll(filepath.Dir(profile), 0700); err != nil {
		return err
	}
	f, err := root.OpenFile(profile, os.O_CREATE|os.O_RDWR|os.O_APPEND|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("shell profile is not a regular file")
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil { // #nosec G115 -- a file descriptor fits in int
		return err
	}
	const maxProfileBytes = 4 << 20
	content, err := io.ReadAll(io.LimitReader(f, maxProfileBytes+1))
	if err != nil {
		return err
	}
	if len(content) > maxProfileBytes {
		return errors.New("shell profile exceeds 4 MiB")
	}
	if bytes.Contains(content, []byte(line)) {
		return nil
	}
	_, err = f.WriteString("\n" + strings.TrimSpace(line) + "\n")
	return err
}
