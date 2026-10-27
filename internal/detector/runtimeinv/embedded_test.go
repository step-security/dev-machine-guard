package runtimeinv

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeBin(t *testing.T, parts ...[]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(p, bytes.Join(parts, nil), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanEmbedded(t *testing.T) {
	pad := bytes.Repeat([]byte{0}, embeddedChunk-10) // puts the match across the first chunk boundary
	node := writeBin(t, pad, []byte("https://nodejs.org/download/release/v22.21.1/node-v22.21.1.tar.gz"))
	if got := scanEmbedded(context.Background(), node, nodeEmbeddedRe); got != "22.21.1" {
		t.Errorf("node across chunk boundary = %q", got)
	}
	deno := writeBin(t, []byte("x Deno/0.82.0 y"), pad, []byte("ua Deno/2.9.8 z nodejs.org/download/release/v21.2.0/"))
	if got := scanEmbedded(context.Background(), deno, denoEmbeddedRe); got != "2.9.8" {
		t.Errorf("deno highest = %q", got)
	}
	bun := writeBin(t, []byte("Bun/1.3.6 nodejs.org/download/release/v24.3.0/"))
	if got := scanEmbedded(context.Background(), bun, bunEmbeddedRe); got != "1.3.6" {
		t.Errorf("bun = %q", got)
	}
	none := writeBin(t, []byte("no versions here"))
	if got := scanEmbedded(context.Background(), none, nodeEmbeddedRe); got != "" {
		t.Errorf("none = %q", got)
	}
}

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"0.82.0", "2.9.8", true}, {"8.2.9", "8.2.12", true}, {"2.9.8", "2.9.8", false}, {"1.10.0", "1.9.9", false}} {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%s,%s)=%v", c.a, c.b, got)
		}
	}
}
