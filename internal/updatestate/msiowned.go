package updatestate

import (
	"os"
	"path/filepath"
)

// BootstrapFile is the MSI-owned stable entry point in the install root.
const BootstrapFile = "stepsecurity-dev-machine-guard-bootstrap.exe"

// MSIOwnedFiles lists the files Windows Installer replaces or removes: the
// bootstrap and every file under seed\. Nothing may hold them open when
// the MSI's file actions run (D29), or the change needs a reboot.
func (l Layout) MSIOwnedFiles() []string {
	var out []string
	if fi, err := os.Lstat(filepath.Join(l.InstallRoot, BootstrapFile)); err == nil && fi.Mode().IsRegular() {
		out = append(out, filepath.Join(l.InstallRoot, BootstrapFile))
	}
	_ = filepath.WalkDir(filepath.Join(l.InstallRoot, "seed"), func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// MSIHelperFile is the copy of the bootstrap the MSI's stop-for-msi action
// runs (state\msi\…): not an MSI file, so the action's own image never
// holds a file the MSI is about to replace.
func (l Layout) MSIHelperFile() string { return filepath.Join(l.StateDir(), "msi", BootstrapFile) }
