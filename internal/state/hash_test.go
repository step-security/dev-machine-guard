package state

import (
	"regexp"
	"testing"
)

var hashFormat = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func TestCanonicalHashJSON_KeyReorderingStable(t *testing.T) {
	a := []byte(`{"name":"lodash","version":"4.17.21","deps":{"a":"1","b":"2"}}`)
	b := []byte(`{"deps":{"b":"2","a":"1"},"version":"4.17.21","name":"lodash"}`)

	ha, err := CanonicalHashJSON(a)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	hb, err := CanonicalHashJSON(b)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if ha != hb {
		t.Errorf("expected equal hashes for key-reordered JSON; got %s vs %s", ha, hb)
	}
}

func TestCanonicalHashJSON_ValueChangeDiffers(t *testing.T) {
	a := []byte(`{"deps":{"lodash":"4.17.21"}}`)
	b := []byte(`{"deps":{"lodash":"4.17.22"}}`)

	ha, _ := CanonicalHashJSON(a)
	hb, _ := CanonicalHashJSON(b)
	if ha == hb {
		t.Errorf("expected different hashes for version bump; both %s", ha)
	}
}

func TestCanonicalHashJSON_ArrayChangeDiffers(t *testing.T) {
	a := []byte(`{"pkgs":["a","b","c"]}`)
	b := []byte(`{"pkgs":["a","b","c","d"]}`)

	ha, _ := CanonicalHashJSON(a)
	hb, _ := CanonicalHashJSON(b)
	if ha == hb {
		t.Errorf("expected different hashes when array grows; both %s", ha)
	}
}

func TestCanonicalHashJSON_MalformedFallbackDeterministic(t *testing.T) {
	bad := []byte(`{not json}`)
	h1, err1 := CanonicalHashJSON(bad)
	h2, err2 := CanonicalHashJSON(bad)
	if err1 == nil || err2 == nil {
		t.Error("expected non-nil error to surface JSON parse failure")
	}
	if h1 != h2 {
		t.Errorf("fallback should be deterministic; %s vs %s", h1, h2)
	}
	if !hashFormat.MatchString(h1) {
		t.Errorf("fallback hash format mismatch: %s", h1)
	}
}

func TestCanonicalHashJSON_OutputFormat(t *testing.T) {
	h, err := CanonicalHashJSON([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !hashFormat.MatchString(h) {
		t.Errorf("hash format mismatch: %s", h)
	}
}

func TestCanonicalHashJSON_ArrayOrderMatters(t *testing.T) {
	// Dependency tree order is semantically significant for npm ls output —
	// reordering peers can mean a re-resolution. Don't canonicalize arrays.
	a := []byte(`["a","b","c"]`)
	b := []byte(`["c","b","a"]`)
	ha, _ := CanonicalHashJSON(a)
	hb, _ := CanonicalHashJSON(b)
	if ha == hb {
		t.Errorf("array order must affect hash; both %s", ha)
	}
}
