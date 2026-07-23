//go:build linux

package devicepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProbeLinuxEitherKey(t *testing.T) {
	cases := []struct {
		name    string
		content string // empty → no file
		want    bool
		detail  string
	}{
		{"allowlist only", `{"AllowedExtensions":{"*":false}}`, true, allowedExtensionsName},
		{"gallery only", `{"ExtensionGalleryServiceUrl":"https://mkt.example/api/v1"}`, true, galleryServiceURLName},
		{"both (allowlist preferred)", `{"AllowedExtensions":{},"ExtensionGalleryServiceUrl":"x"}`, true, allowedExtensionsName},
		{"neither", `{"Other":1}`, false, ""},
		{"missing file", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			if tc.content != "" {
				if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			managed, detail := probeLinuxPolicyFile(path)
			if managed != tc.want {
				t.Fatalf("managed = %v, want %v (detail %q)", managed, tc.want, detail)
			}
			if tc.want && !strings.Contains(detail, tc.detail) {
				t.Fatalf("detail = %q, want to contain %q", detail, tc.detail)
			}
		})
	}
}

// AllowedExtensions may be stringified or a direct object; an absent file is
// not-managed, a present-but-malformed one an error.
func TestProbeLinuxPolicyContent(t *testing.T) {
	cases := []struct {
		name    string
		content string
		writeIt bool
		present bool
		want    string
		wantErr bool
	}{
		{
			name:    "stringified allowlist",
			content: `{"AllowedExtensions":"{\"*\":false,\"ms-python.python\":\"stable\"}"}`,
			writeIt: true, present: true,
			want: `{"extensions.allowed":{"*":false,"ms-python.python":"stable"}}`,
		},
		{
			name:    "direct-object allowlist (hand-authored)",
			content: `{"AllowedExtensions":{"*":false}}`,
			writeIt: true, present: true,
			want: `{"extensions.allowed":{"*":false}}`,
		},
		{
			name:    "gallery only",
			content: `{"ExtensionGalleryServiceUrl":"https://mkt.example/api/v1"}`,
			writeIt: true, present: true,
			want: `{"extensions.gallery.serviceUrl":"https://mkt.example/api/v1"}`,
		},
		{
			name:    "both",
			content: `{"AllowedExtensions":{"golang.go":true},"ExtensionGalleryServiceUrl":"https://mkt.example/api/v1"}`,
			writeIt: true, present: true,
			want: `{"extensions.allowed":{"golang.go":true},"extensions.gallery.serviceUrl":"https://mkt.example/api/v1"}`,
		},
		{name: "neither key", content: `{"Other":1}`, writeIt: true, present: false},
		{name: "absent file", writeIt: false, present: false},
		{name: "malformed json file", content: `{oops`, writeIt: true, wantErr: true},
		{name: "allowlist wrong type", content: `{"AllowedExtensions":123}`, writeIt: true, wantErr: true},
		{name: "stringified but not an object", content: `{"AllowedExtensions":"[1,2]"}`, writeIt: true, wantErr: true},
		{name: "gallery null is malformed", content: `{"ExtensionGalleryServiceUrl":null}`, writeIt: true, wantErr: true},
		{name: "allowlist null is malformed", content: `{"AllowedExtensions":null}`, writeIt: true, wantErr: true},
		{name: "top-level null document", content: `null`, writeIt: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			if tc.writeIt {
				if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			present, observed, err := probeLinuxPolicyContent(path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got present=%v observed=%v", present, observed)
				}
				return
			}
			if err != nil {
				t.Fatalf("probeLinuxPolicyContent: %v", err)
			}
			if present != tc.present {
				t.Fatalf("present = %v, want %v", present, tc.present)
			}
			if !tc.present {
				return
			}
			got, _ := json.Marshal(observed)
			if string(got) != tc.want {
				t.Fatalf("observed = %s, want %s", got, tc.want)
			}
		})
	}
}
