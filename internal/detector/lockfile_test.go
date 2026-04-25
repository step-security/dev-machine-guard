package detector

import (
	"testing"
)

func TestParseNPMLockfile_V3(t *testing.T) {
	data := []byte(`{
		"name": "my-project",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "my-project",
				"version": "1.0.0",
				"dependencies": {
					"express": "^4.18.0"
				}
			},
			"node_modules/express": {
				"version": "4.18.2",
				"resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
			},
			"node_modules/accepts": {
				"version": "1.3.8",
				"dev": true
			},
			"node_modules/express/node_modules/qs": {
				"version": "6.11.0"
			}
		}
	}`)

	result, err := ParseNPMLockfile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Source != "lockfile" {
		t.Errorf("expected source 'lockfile', got %q", result.Source)
	}
	if result.LockfileFormat != "npm-v3" {
		t.Errorf("expected format 'npm-v3', got %q", result.LockfileFormat)
	}
	if result.LockfileVersion != 3 {
		t.Errorf("expected lockfileVersion 3, got %d", result.LockfileVersion)
	}
	if len(result.Packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(result.Packages))
	}

	// Check that packages were extracted correctly
	pkgMap := make(map[string]LockfilePackage)
	for _, p := range result.Packages {
		pkgMap[p.Name] = p
	}

	if p, ok := pkgMap["express"]; !ok {
		t.Error("expected to find 'express' package")
	} else if p.Version != "4.18.2" {
		t.Errorf("expected express version 4.18.2, got %s", p.Version)
	}

	if p, ok := pkgMap["accepts"]; !ok {
		t.Error("expected to find 'accepts' package")
	} else if !p.Dev {
		t.Error("expected accepts to be a dev dependency")
	}

	if p, ok := pkgMap["qs"]; !ok {
		t.Error("expected to find 'qs' (nested) package")
	} else if p.Version != "6.11.0" {
		t.Errorf("expected qs version 6.11.0, got %s", p.Version)
	}
}

func TestParseNPMLockfile_V2(t *testing.T) {
	data := []byte(`{
		"name": "test-project",
		"lockfileVersion": 2,
		"packages": {
			"": {
				"name": "test-project",
				"version": "0.1.0"
			},
			"node_modules/lodash": {
				"version": "4.17.21"
			}
		},
		"dependencies": {
			"lodash": {
				"version": "4.17.21"
			}
		}
	}`)

	result, err := ParseNPMLockfile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.LockfileFormat != "npm-v2" {
		t.Errorf("expected format 'npm-v2', got %q", result.LockfileFormat)
	}
	// Should use packages map (v2+), not the deprecated dependencies map
	if len(result.Packages) != 1 {
		t.Fatalf("expected 1 package from v2 packages map, got %d", len(result.Packages))
	}
	if result.Packages[0].Name != "lodash" {
		t.Errorf("expected lodash, got %s", result.Packages[0].Name)
	}
}

func TestParseNPMLockfile_V1(t *testing.T) {
	data := []byte(`{
		"name": "legacy-project",
		"lockfileVersion": 1,
		"dependencies": {
			"express": {
				"version": "4.17.1",
				"dev": false,
				"dependencies": {
					"accepts": {
						"version": "1.3.7",
						"dev": true
					}
				}
			},
			"debug": {
				"version": "2.6.9"
			}
		}
	}`)

	result, err := ParseNPMLockfile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.LockfileFormat != "npm-v1" {
		t.Errorf("expected format 'npm-v1', got %q", result.LockfileFormat)
	}
	if result.LockfileVersion != 1 {
		t.Errorf("expected lockfileVersion 1, got %d", result.LockfileVersion)
	}
	// Should flatten: express, accepts (nested), debug = 3 packages
	if len(result.Packages) != 3 {
		t.Fatalf("expected 3 packages (flattened from v1), got %d", len(result.Packages))
	}

	pkgMap := make(map[string]LockfilePackage)
	for _, p := range result.Packages {
		pkgMap[p.Name] = p
	}

	if _, ok := pkgMap["express"]; !ok {
		t.Error("expected 'express' in flattened packages")
	}
	if _, ok := pkgMap["accepts"]; !ok {
		t.Error("expected nested 'accepts' in flattened packages")
	}
	if _, ok := pkgMap["debug"]; !ok {
		t.Error("expected 'debug' in flattened packages")
	}
}

func TestParseNPMLockfile_Empty(t *testing.T) {
	data := []byte(`{"lockfileVersion": 3, "packages": {}}`)
	result, err := ParseNPMLockfile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Packages) != 0 {
		t.Errorf("expected 0 packages, got %d", len(result.Packages))
	}
}

func TestParseNPMLockfile_InvalidJSON(t *testing.T) {
	data := []byte(`{not valid json}`)
	_, err := ParseNPMLockfile(data)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseNPMLockfile_ScopedPackages(t *testing.T) {
	data := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "test"},
			"node_modules/@babel/core": {"version": "7.23.0"},
			"node_modules/@types/node": {"version": "20.8.0", "dev": true}
		}
	}`)

	result, err := ParseNPMLockfile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Packages) != 2 {
		t.Fatalf("expected 2 scoped packages, got %d", len(result.Packages))
	}

	pkgMap := make(map[string]LockfilePackage)
	for _, p := range result.Packages {
		pkgMap[p.Name] = p
	}

	if p, ok := pkgMap["@babel/core"]; !ok {
		t.Error("expected @babel/core")
	} else if p.Version != "7.23.0" {
		t.Errorf("expected version 7.23.0, got %s", p.Version)
	}

	if p, ok := pkgMap["@types/node"]; !ok {
		t.Error("expected @types/node")
	} else if !p.Dev {
		t.Error("expected @types/node to be dev")
	}
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"node_modules/express", "express"},
		{"node_modules/@babel/core", "@babel/core"},
		{"node_modules/express/node_modules/qs", "qs"},
		{"node_modules/@scope/pkg/node_modules/@other/dep", "@other/dep"},
		{"", ""},
		{"express", ""},
		// Windows-style paths
		{`node_modules\lodash`, "lodash"},
		{`node_modules\@types\node`, "@types/node"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := extractPackageName(tt.key)
			if got != tt.want {
				t.Errorf("extractPackageName(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestParseNpmrcPrefix(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"with prefix", "registry=https://registry.npmjs.org/\nprefix=/home/user/.npm-global\n", "/home/user/.npm-global"},
		{"prefix with space", "prefix = /custom/path\n", "/custom/path"},
		{"no prefix", "registry=https://registry.npmjs.org/\n", ""},
		{"comment", "# prefix=/not/this\nprefix=/real/path\n", "/real/path"},
		{"empty", "", ""},
		{"windows path", "prefix=C:\\Users\\dev\\AppData\\Roaming\\npm\n", `C:\Users\dev\AppData\Roaming\npm`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNpmrcPrefix(tt.content)
			if got != tt.want {
				t.Errorf("parseNpmrcPrefix() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNPMGlobalPrefix(t *testing.T) {
	tests := []struct {
		name    string
		home    string
		appdata string
		goos    string
		files   map[string]string
		want    string
	}{
		{
			name: "linux default",
			home: "/home/user",
			goos: "linux",
			want: "/usr/local",
		},
		{
			name: "darwin default",
			home: "/Users/user",
			goos: "darwin",
			want: "/usr/local",
		},
		{
			name:    "windows default",
			home:    `C:\Users\dev`,
			appdata: `C:\Users\dev\AppData\Roaming`,
			goos:    "windows",
			want:    `C:\Users\dev\AppData\Roaming\npm`,
		},
		{
			name:  "npmrc override",
			home:  "/home/user",
			goos:  "linux",
			files: map[string]string{"/home/user/.npmrc": "prefix=/custom/npm\n"},
			want:  "/custom/npm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readFile := func(path string) ([]byte, error) {
				if tt.files != nil {
					if content, ok := tt.files[path]; ok {
						return []byte(content), nil
					}
				}
				return nil, &mockFileError{}
			}

			got := NPMGlobalPrefix(tt.home, tt.appdata, tt.goos, readFile)
			if got != tt.want {
				t.Errorf("NPMGlobalPrefix() = %q, want %q", got, tt.want)
			}
		})
	}
}

type mockFileError struct{}

func (e *mockFileError) Error() string { return "file not found" }

func TestGlobalNodeModulesDir(t *testing.T) {
	tests := []struct {
		prefix string
		goos   string
		want   string
	}{
		{"/usr/local", "linux", "/usr/local/lib/node_modules"},
		{"/usr/local", "darwin", "/usr/local/lib/node_modules"},
		{`C:\Users\dev\AppData\Roaming\npm`, "windows", `C:\Users\dev\AppData\Roaming\npm\node_modules`},
	}

	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			got := GlobalNodeModulesDir(tt.prefix, tt.goos)
			if got != tt.want {
				t.Errorf("GlobalNodeModulesDir(%q, %q) = %q, want %q", tt.prefix, tt.goos, got, tt.want)
			}
		})
	}
}
