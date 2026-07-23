package devicepolicy

import (
	"encoding/json"
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

// TestProbeHelpersDetectEitherPolicyName exercises the shared probe helpers
// against the gallery policy name (the per-OS ProbeManagedPolicy loops over
// managedPolicyNames, so proving both names are detectable + the name set is
// the linux/darwin either-key coverage that runs on any OS).
func TestProbeHelpersDetectEitherPolicyName(t *testing.T) {
	dir := t.TempDir()

	// jsonFileHasKey (linux policy.json shape) finds the gallery policy name.
	p := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(p, []byte(`{"ExtensionGalleryServiceUrl":"https://mkt.example/api/v1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if !jsonFileHasKey(p, galleryServiceURLName) {
		t.Error("jsonFileHasKey must detect ExtensionGalleryServiceUrl")
	}
	if jsonFileHasKey(p, allowedExtensionsName) {
		t.Error("AllowedExtensions absent → false")
	}

	// fileMentionsKey (darwin plist byte scan) finds it too.
	plist := filepath.Join(dir, "vscode.plist")
	if err := os.WriteFile(plist, append([]byte("bplist00\x00"), []byte("ExtensionGalleryServiceUrl\x00")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if !fileMentionsKey(plist, galleryServiceURLName) {
		t.Error("fileMentionsKey must detect ExtensionGalleryServiceUrl")
	}

	// managedPolicyNames covers both, allowlist first (reporting preference).
	if names := managedPolicyNames(); len(names) != 2 || names[0] != allowedExtensionsName || names[1] != galleryServiceURLName {
		t.Fatalf("managedPolicyNames = %v", names)
	}
}

// TestBuildObserved covers the shared policy-name → setting-id translation the
// per-OS content probes funnel through, including malformed values as errors.
func TestBuildObserved(t *testing.T) {
	cases := []struct {
		name    string
		raw     map[string]string
		present bool
		want    string // marshaled observed (map keys sort); "" when !present
		wantErr bool
	}{
		{
			name:    "allowlist only",
			raw:     map[string]string{allowedExtensionsName: `{"*":false,"ms-python.python":"stable"}`},
			present: true,
			want:    `{"extensions.allowed":{"*":false,"ms-python.python":"stable"}}`,
		},
		{
			name:    "allowlist whitespace normalized",
			raw:     map[string]string{allowedExtensionsName: "{ \"*\" : false }"},
			present: true,
			want:    `{"extensions.allowed":{"*":false}}`,
		},
		{
			name:    "gallery only wrapped as JSON string",
			raw:     map[string]string{galleryServiceURLName: "https://mkt.example/api/v1"},
			present: true,
			want:    `{"extensions.gallery.serviceUrl":"https://mkt.example/api/v1"}`,
		},
		{
			name: "both",
			raw: map[string]string{
				allowedExtensionsName: `{"*":false}`,
				galleryServiceURLName: "https://mkt.example/api/v1",
			},
			present: true,
			want:    `{"extensions.allowed":{"*":false},"extensions.gallery.serviceUrl":"https://mkt.example/api/v1"}`,
		},
		{name: "neither", raw: map[string]string{}, present: false},
		{name: "allowlist is an array not an object", raw: map[string]string{allowedExtensionsName: `["a","b"]`}, wantErr: true},
		{name: "allowlist is not valid JSON", raw: map[string]string{allowedExtensionsName: `{oops`}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			present, observed, err := buildObserved(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got observed=%v", observed)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildObserved: %v", err)
			}
			if present != tc.present {
				t.Fatalf("present = %v, want %v", present, tc.present)
			}
			if !tc.present {
				return
			}
			got, err := json.Marshal(observed)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("observed = %s, want %s", got, tc.want)
			}
		})
	}
}
