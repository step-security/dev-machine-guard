package identity

import (
	"errors"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestNormalizeConfiguredIDs(t *testing.T) {
	for _, kind := range []string{"user", "device"} {
		for _, value := range []string{"a", "abc", "employee-123", "alice@example.com", "team+agent_01", "550e8400-e29b-41d4-a716-446655440000", ".", "..", "@", strings.Repeat("A", 255), strings.Repeat("z", 256)} {
			got, err := Normalize("  "+value+"  ", kind)
			if err != nil || got != value {
				t.Errorf("%s %q: %q %v", kind, value, got, err)
			}
		}
		for _, value := range []string{"", " ", "unknown", "UnKnOwN", "root", "ROOT", strings.Repeat("a", 257), "a b", "a/b", `a\b`, "é", "😀", string([]byte{0xff}), "\tabc", "abc\n", "\rabc", "abc\x00", "abc\x7f", "a\u200bb"} {
			if _, err := Normalize(value, kind); err == nil {
				t.Errorf("%s accepted %q", kind, value)
			}
		}
		for c := 0; c < 128; c++ {
			value := "a" + string(rune(c)) + "z"
			_, err := Normalize(value, kind)
			allowed := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@._+-", rune(c))
			if (err == nil) != allowed {
				t.Errorf("%s char %d accepted=%v", kind, c, err == nil)
			}
		}
	}
	got, err := Normalize("\u00a0AbC\u00a0", "user")
	if err != nil || got != "AbC" {
		t.Fatalf("Unicode boundary whitespace: %q %v", got, err)
	}
}

func TestDetectUserSession(t *testing.T) {
	m := executor.NewMock()
	m.SetUsername("root")
	if got, noUser := DetectUserSession(m); got != "unknown" || !noUser {
		t.Fatalf("root: %s %v", got, noUser)
	}
	m.SetEnv("USER_EMAIL", "  UNKNOWN ")
	m.SetEnv("DEVELOPER_EMAIL", " ")
	m.SetUsername("DOMAIN\\alice")
	if got, noUser := DetectUserSession(m); got != "DOMAIN\\alice" || noUser {
		t.Fatalf("fallback: %s %v", got, noUser)
	}
	m.SetEnv("STEPSEC_DEVELOPER_EMAIL", "third@example.com")
	m.SetEnv("DEVELOPER_EMAIL", "second@example.com")
	if got := DetectUser(m); got != "second@example.com" {
		t.Fatal(got)
	}
	m.SetEnv("USER_EMAIL", "first@example.com")
	m.SetLoggedInUserError(errors.New("no console"))
	if got, noUser := DetectUserSession(m); got != "first@example.com" || !noUser {
		t.Fatalf("email without session: %s %v", got, noUser)
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"abc", "root", "a+b@example.com", "\tabc", "\u00a0ABC ", strings.Repeat("x", 256), "\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := Normalize(s, "user")
		if err != nil {
			return
		}
		if len(got) < 1 || len(got) > 256 {
			t.Fatalf("length %d", len(got))
		}
		for _, c := range got {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@._+-", c) {
				t.Fatalf("character %q", c)
			}
		}
		again, err := Normalize(got, "user")
		if err != nil || again != got {
			t.Fatal("non-idempotent normalization")
		}
	})
}
