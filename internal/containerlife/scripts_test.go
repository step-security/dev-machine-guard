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
