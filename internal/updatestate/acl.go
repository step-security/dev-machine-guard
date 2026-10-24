package updatestate

import (
	"fmt"
	"os"
)

// checkDirNotReparse rejects anything at path that is not a plain directory
// (files, symlinks, junctions), so ACL work never follows a redirect.
func checkDirNotReparse(path string) (exists bool, err error) {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return true, fmt.Errorf("updatestate: %s is not a plain directory", path)
	}
	return true, nil
}
