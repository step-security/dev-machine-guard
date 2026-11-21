//go:build !windows

package devcli

import (
	"bytes"
	"io"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func pageBuffer(path string, b *bytes.Buffer) error {
	cmd := exec.Command(path, "-F", "-R", "-X")
	cmd.Env = append(os.Environ(), "LESSSECURE=1", "LESS=", "LESSOPEN=", "LESSCLOSE=", "LESSHISTFILE=-")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = b, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		_, err = io.Copy(os.Stdout, b)
		return err
	}
	return cmd.Wait()
}

func terminalRows(f *os.File) int {
	size, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0
	}
	return int(size.Row)
}

// enableVT reports whether the terminal acts on ANSI escape sequences.
func enableVT(*os.File) bool { return true }

func terminalWidth(f *os.File) (int, bool) {
	size, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, false
	}
	return int(size.Col), true
}
