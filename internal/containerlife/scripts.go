package containerlife

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteScripts emits the integration scripts owned by this DMG version.
func WriteScripts(dir string) error {
	if dir == "" {
		return fmt.Errorf("--output is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for name, body := range map[string]string{
		"start.sh": "#!/bin/sh\nset -eu\nexec stepsecurity-dev-machine-guard container start\n",
		"stop.sh": `#!/bin/sh
set -eu
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 CONTAINER USER" >&2
  exit 2
fi
case "$1" in -*) echo "Invalid container name" >&2; exit 2;; esac
if ! docker exec --user "$2" "$1" stepsecurity-dev-machine-guard container stop; then
  echo "Warning: DMG could not confirm shutdown; the device will become offline after timeout." >&2
fi
docker stop "$1"
`,
		"devcontainer.json": `{
  "postStartCommand": "sh .devcontainer/dmg/start.sh"
}
`,
	} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			return err
		}
	}
	return nil
}
