package runtimeinv

import "testing"

func TestAttributeSource(t *testing.T) {
	cases := []struct{ path, nvmHome, want string }{
		{"/Users/a/.nvm/versions/node/v18.0.0/bin/node", "", "nvm"},
		{`C:\Users\a\AppData\Roaming\nvm\v18.0.0\node.exe`, "", "nvm"},
		{`D:\tools\nvm\v18.0.0\node.exe`, `D:\tools\nvm`, "nvm"},
		{`C:\Users\a\AppData\Local\Volta\tools\image\node\20.1.0\node.exe`, "", "volta"},
		{"/Users/a/Library/Application Support/fnm/node-versions/v22.0.0/installation/bin/node", "", "fnm"},
		{"/opt/homebrew/Cellar/php/8.3.1/bin/php", "", "brew"},
		{`C:\Users\a\scoop\apps\nodejs\22.0.0\node.exe`, "", "scoop"},
		{`C:\ProgramData\chocolatey\lib\php\tools\php.exe`, "", "choco"},
		{`C:\xampp\php\php.exe`, "", "xampp"},
		{"/usr/bin/python3.12", "", "system"},
		{"/usr/lib/jvm/java-21-openjdk/bin/java", "", "system"},
		{`C:\Program Files\nodejs\node.exe`, "", "installer"},
		{"/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home/bin/java", "", "installer"},
		{"/home/a/.sdkman/candidates/java/21.0.2-tem/bin/java", "", "sdkman"},
		{"/Users/a/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.0.darwin-arm64/bin/go", "", "go-toolchain"},
		{"/usr/local/bin/node", "", "manual"},
		{"/home/a/Downloads/node-v18.0.0-linux-x64/bin/node", "", "manual"},
	}
	for _, c := range cases {
		if got := attributeSource(c.path, c.nvmHome); got != c.want {
			t.Errorf("attributeSource(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestBundledBy(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/Applications/Docker.app/Contents/Resources/bin/node", "Docker"},
		{"/Applications/IntelliJ IDEA.app/Contents/jbr/Contents/Home/bin/java", "IntelliJ IDEA"},
		{"/opt/android-studio/jbr/bin/java", "android-studio"},
		{"/home/a/.vscode-server/bin/abc123/node", "vscode-server"},
		{"/home/a/.vscode/extensions/ms-python.python-2024.1/python/bin/python3", "vscode extension ms-python.python-2024.1"},
		{`C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Microsoft\VisualStudio\NodeJs\node.exe`, "Visual Studio"},
		{`C:\Program Files\Adobe\Adobe Creative Cloud Experience\libs\node.exe`, "Adobe"},
		{"/home/a/.nvm/versions/node/v18.0.0/bin/node", ""},
		{`C:\Program Files\nodejs\node.exe`, ""},
	}
	for _, c := range cases {
		if got := bundledBy(c.path); got != c.want {
			t.Errorf("bundledBy(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestCleanVersion(t *testing.T) {
	cases := map[string]string{
		"18.20.4.0":      "18.20.4",
		"3.12.1":         "3.12.1",
		"8.2.12":         "8.2.12",
		"21.0.2+13":      "21.0.2",
		"1.22.1 ":        "1.22.1",
		"3.12.1150.1013": "3.12.1150.1013",
		"":               "",
		"abc":            "",
	}
	for in, want := range cases {
		if got := cleanVersion(in); got != want {
			t.Errorf("cleanVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchSignature(t *testing.T) {
	cases := []struct{ name, goos, want string }{
		{"node", "linux", "node"},
		{"nodejs", "linux", "node"},
		{"python3.12", "linux", "python"},
		{"python3.12-config", "linux", ""},
		{"php8.2", "linux", "php"},
		{"php-fpm", "linux", ""},
		{"node.exe", "windows", "node"},
		{"Node.EXE", "windows", "node"},
		{"node", "windows", ""},
		{"php-cgi.exe", "windows", ""},
		{"java", "darwin", "java"},
		{"javac", "darwin", ""},
		{"Python", "darwin", ""}, // framework library, not the interpreter
		{"node-22", "linux", "node"},
		{"ruby-mri", "linux", "ruby"},
		{"ruby3.3", "linux", "ruby"},
		{"node-gyp", "linux", ""},
		{"rubocop", "linux", ""},
	}
	for _, c := range cases {
		got := ""
		if s := matchSignature(c.name, c.goos); s != nil {
			got = s.runtime
		}
		if got != c.want {
			t.Errorf("matchSignature(%q, %s) = %q, want %q", c.name, c.goos, got, c.want)
		}
	}
}
