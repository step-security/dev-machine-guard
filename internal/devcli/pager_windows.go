//go:build windows

package devcli

import (
	"bytes"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// Windows Terminal supplies scrollback even when less is absent.
func pageBuffer(_ string, b *bytes.Buffer) error {
	_, err := io.Copy(os.Stdout, b)
	return err
}

func terminalRows(f *os.File) int {
	var size windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(windows.Handle(f.Fd()), &size) != nil {
		return 0
	}
	return int(size.Window.Bottom) - int(size.Window.Top) + 1
}

// enableVT turns on ANSI escape handling, which a Windows console leaves off
// by default, and reports whether the console has it.
func enableVT(f *os.File) bool {
	handle := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(handle, &mode) != nil {
		return false
	}
	return mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 ||
		windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}

func terminalWidth(f *os.File) (int, bool) {
	handle := windows.Handle(f.Fd())
	var size windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(handle, &size); err == nil {
		return int(size.Window.Right) - int(size.Window.Left) + 1, true
	}
	// Input console handles support GetConsoleMode but have no screen buffer.
	var mode uint32
	return 0, windows.GetConsoleMode(handle, &mode) == nil
}
