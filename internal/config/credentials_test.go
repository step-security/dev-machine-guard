package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEffectiveCredentialsMatchesLoad(t *testing.T) {
	oldMode := MultiUserDetection
	t.Cleanup(func() { MultiUserDetection = oldMode })
	oldCustomer, oldEndpoint, oldKey, oldOverride := CustomerID, APIEndpoint, APIKey, fileOverride
	t.Cleanup(func() { CustomerID, APIEndpoint, APIKey, fileOverride = oldCustomer, oldEndpoint, oldKey, oldOverride })
	cfg := ConfigFile{MultiUserDetection: "off", CustomerID: "file-org", APIEndpoint: " https://file.example/ ", APIKey: "file-key"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fileOverride = filepath.Join(t.TempDir(), "config.json")
	if err = os.WriteFile(fileOverride, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, customer, endpoint, key string
		want                          Credentials
	}{
		{"file", "{{CUSTOMER_ID}}", "{{API_ENDPOINT}}", "{{API_KEY}}", Credentials{"file-org", "https://file.example", "file-key"}},
		{"embedded", "embedded", "https://embedded.example", "embedded-key", Credentials{"embedded", "https://embedded.example", "embedded-key"}},
		{"embedded-endpoint-preserved", "embedded", " https://embedded.example/ ", "embedded-key", Credentials{"embedded", " https://embedded.example/ ", "embedded-key"}},
		{"mixed", "embedded", "{{API_ENDPOINT}}", "", Credentials{"embedded", "https://file.example", "file-key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			CustomerID, APIEndpoint, APIKey = tc.customer, tc.endpoint, tc.key
			MultiUserDetection = ""
			if got := EffectiveCredentials(cfg); got != tc.want {
				t.Fatalf("resolved=%+v want=%+v", got, tc.want)
			}
			Load()
			if MultiUserDetection != "off" {
				t.Fatal("credential loading lost the multi-user detection setting")
			}
			if got := (Credentials{CustomerID, APIEndpoint, APIKey}); got != tc.want {
				t.Fatalf("Load differs: %+v", got)
			}
		})
	}
	CustomerID, APIEndpoint, APIKey = "{{CUSTOMER_ID}}", "{{API_ENDPOINT}}", "{{API_KEY}}"
	if got := EffectiveCredentials(ConfigFile{}); got != (Credentials{}) {
		t.Fatalf("unresolved placeholders: %+v", got)
	}
}
