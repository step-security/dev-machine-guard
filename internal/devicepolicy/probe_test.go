package devicepolicy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJSONFileHasKey(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"key present", write("a.json", `{"AllowedExtensions": "{}", "Other": 1}`), true},
		{"key absent", write("b.json", `{"Other": 1}`), false},
		{"missing file", filepath.Join(dir, "nope.json"), false},
		// Unparseable but mentions the key in quotes: over-detect → safe yield.
		{"lenient fallback", write("c.json", `{"AllowedExtensions": trailing-garbage`), true},
		{"unparseable without key", write("d.json", `not json`), false},
	}
	for _, tc := range cases {
		if got := jsonFileHasKey(tc.path, allowedExtensionsName); got != tc.want {
			t.Errorf("%s: jsonFileHasKey = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFileMentionsKey(t *testing.T) {
	dir := t.TempDir()
	// Simulated binary plist: arbitrary bytes with the key name as an ASCII run.
	withKey := filepath.Join(dir, "with.plist")
	if err := os.WriteFile(withKey, append([]byte{0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0x00},
		[]byte("AllowedExtensions\x00more")...), 0o644); err != nil {
		t.Fatal(err)
	}
	withoutKey := filepath.Join(dir, "without.plist")
	if err := os.WriteFile(withoutKey, []byte("bplist00\x00SomethingElse"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !fileMentionsKey(withKey, allowedExtensionsName) {
		t.Error("key bytes present: want true")
	}
	if fileMentionsKey(withoutKey, allowedExtensionsName) {
		t.Error("key bytes absent: want false")
	}
	if fileMentionsKey(filepath.Join(dir, "missing"), allowedExtensionsName) {
		t.Error("missing file: want false")
	}
}
