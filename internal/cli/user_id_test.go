package cli

import "testing"

func TestParseUserID(t *testing.T) {
	for _, args := range [][]string{{"configure", "--non-interactive", "--user-id", "abc"}, {"configure", "--user-id=abc"}, {"configure", "--user-id=  abc  "}} {
		cfg, err := Parse(args)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ConfigValues["user_id"] == nil || cfg.ConfigValues["user_id"] == "" {
			t.Fatalf("not forwarded: %+v", cfg)
		}
	}
	cfg, err := Parse([]string{"configure", "--user-id="})
	if err != nil || cfg.ConfigValues["user_id"] != "" {
		t.Fatalf("explicit empty lost: %+v %v", cfg, err)
	}
	cfg, err = Parse([]string{"configure"})
	if err != nil || cfg.ConfigValues["user_id"] != nil {
		t.Fatalf("omission lost: %+v %v", cfg, err)
	}
	for _, args := range [][]string{{"configure", "--user-id"}, {"configure", "--user-id", "--api-key", "secret"}, {"configure", "--user-id=abc", "--user-id=abc"}, {"--user-id=abc"}, {"configure", "show", "--user-id=abc"}, {"send-telemetry", "--user-id=abc"}} {
		if cfg, err := Parse(args); err == nil {
			t.Fatalf("accepted %v: %+v", args, cfg)
		}
	}
}
