//go:build !linux

package containerlife

import "fmt"

func Run(args []string) error {
	if len(args) == 3 && args[0] == "scripts" && args[1] == "--output" {
		return WriteScripts(args[2])
	}
	return fmt.Errorf("container lifecycle requires Linux; scripts --output DIR is available on the host")
}
