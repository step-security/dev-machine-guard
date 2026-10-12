package configaudit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestCargoConfigSettings_URLTableNamesRedacted(t *testing.T) {
	doc := map[string]any{}
	if err := toml.Unmarshal([]byte(`
[patch."https://user:canary-pass@git.example/repo.git?token=canary-query"]
foo = { path = "vendor/foo" }
[source."https://u:canary-src@mirror.example/"]
registry = "https://mirror.example/index"
[registries.corp]
index = "https://registry.example/index"
`), &doc); err != nil {
		t.Fatal(err)
	}
	settings, _ := cargoConfigSettings(doc, "/work/.cargo/config.toml")
	out, _ := json.Marshal(settings)
	for _, secret := range []string{"canary-pass", "canary-query", "canary-src"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("settings leak %q: %s", secret, out)
		}
	}
	for _, s := range settings {
		switch {
		case strings.HasPrefix(s.Key, "patch."), strings.HasPrefix(s.Key, "source."):
			if !s.Redacted {
				t.Errorf("%s: redacted = false, want true", s.Key)
			}
		case s.Key == "registries.corp.index":
			if s.Redacted {
				t.Errorf("%s: redacted = true, want false", s.Key)
			}
		}
	}
}

func TestCargoConfigDetect_UnreadProjectConfigKeepsSelectionPartial(t *testing.T) {
	home := goTestHome(t)
	cargoHome := filepath.Join(home, ".cargo")
	project := filepath.Join(home, "code", "app")
	mustWriteGoFile(t, filepath.Join(cargoHome, "config.toml"), `
[registries.corp]
index = "https://registry.example/index"
[resolver]
lockfile-path = "`+filepath.ToSlash(filepath.Join(home, "locks", "Cargo.lock"))+`"
`)
	mustWriteGoFile(t, filepath.Join(project, ".cargo", "config.toml"), "[registries.corp\n")

	scope := CargoConfigScope{
		Username: "dev", Home: home, Roots: []string{home}, Protected: goProtectedFor(home),
		Volume: func(string) bool { return false }, CargoHome: cargoHome,
		Contexts: []CargoContextDir{{Project: project}},
	}
	_, snap := NewCargoConfigDetector(executor.NewReal()).Detect(context.Background(), scope)

	// The malformed project file may redefine both values, so neither is definitive there.
	if u, ok := snap.RegistryIndex(project, "corp"); ok {
		t.Errorf("RegistryIndex(project) = %q, true; want unknown", u)
	}
	if path, unresolved := snap.LockfilePath(project); !unresolved || path == "" {
		t.Errorf("LockfilePath(project) = %q, %v; want the observed path, unresolved", path, unresolved)
	}
	// The home context has no unread file.
	if u, ok := snap.RegistryIndex("", "corp"); !ok || u != "https://registry.example/index" {
		t.Errorf("RegistryIndex(home) = %q, %v", u, ok)
	}
	if _, unresolved := snap.LockfilePath(""); unresolved {
		t.Error("LockfilePath(home) unresolved, want resolved")
	}
}

func TestCargoConfigSettings_DeterministicOrder(t *testing.T) {
	root := filepath.Join(t.TempDir(), "work")
	file := filepath.Join(root, ".cargo", "config.toml")
	doc := map[string]any{}
	if err := toml.Unmarshal([]byte(`
paths = ["vendor/second", "vendor/first"]
include = ["b.toml", "a.toml"]
[registry]
global-credential-providers = ["cargo:wincred", "cargo:token"]
[patch."https://git.example/repo.git?token=one"]
widgets = { path = "vendor/one" }
[patch."https://git.example/repo.git?token=two"]
widgets = { path = "vendor/two" }
`), &doc); err != nil {
		t.Fatal(err)
	}
	var first string
	for i := range 64 {
		settings, _ := cargoConfigSettings(doc, file)
		raw, err := json.Marshal(settings)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = string(raw)
			got := map[string][]string{}
			for _, s := range settings {
				got[s.Key] = append(got[s.Key], s.Display)
			}
			for key, want := range map[string][]string{
				"patch.https://git.example/repo.git.widgets.path": {filepath.Join(root, "vendor", "one"), filepath.Join(root, "vendor", "two")},
				"paths":                                {filepath.Join(root, "vendor", "second"), filepath.Join(root, "vendor", "first")},
				"include":                              {filepath.Join(root, ".cargo", "b.toml"), filepath.Join(root, ".cargo", "a.toml")},
				"registry.global-credential-providers": {"cargo:wincred", "cargo:token"},
			} {
				if !reflect.DeepEqual(got[key], want) {
					t.Errorf("%s order = %v, want %v", key, got[key], want)
				}
			}
		} else if string(raw) != first {
			t.Fatal("identical config produced different settings order")
		}
	}
}
