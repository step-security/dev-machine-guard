package devcli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
)

// Page leaves redirected input and output alone. Render before starting the
// pager so a collector can't consume the pager's terminal input.
func Page(render func(io.Writer) error) error {
	if !terminal(os.Stdin) || !terminal(os.Stdout) || os.Getenv("TERM") == "dumb" {
		return render(os.Stdout)
	}
	path, err := exec.LookPath("less")
	if err != nil {
		return render(os.Stdout)
	}
	var b bytes.Buffer
	if err := render(&b); err != nil {
		return err
	}
	return pageBuffer(path, &b)
}

func terminal(f *os.File) bool {
	_, ok := terminalWidth(f)
	return ok
}
