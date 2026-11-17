package containerlife

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScriptsContract(t *testing.T) {
	dir := t.TempDir()
	if err := WriteScripts(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "devcontainer.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]string
	if err = json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["postStartCommand"] != "sh .devcontainer/dmg/start.sh" {
		t.Fatal("unexpected start hook")
	}
	b, err = os.ReadFile(filepath.Join(dir, "stop.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "if ! docker exec") || !strings.Contains(string(b), "docker stop") {
		t.Fatal("stop must survive reporting failure")
	}
	if err = WriteScripts(dir); err == nil {
		t.Fatal("must not overwrite custom scripts")
	}
}

func TestScriptsRejectDanglingSymlinks(t *testing.T) {
	for _, name := range []string{"start.sh", "stop.sh", "devcontainer.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(t.TempDir(), "outside")
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Skip(err)
			}
			if err := WriteScripts(dir); err == nil {
				t.Error("accepted dangling symlink")
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Error("wrote outside output directory")
			}
		})
	}
}
