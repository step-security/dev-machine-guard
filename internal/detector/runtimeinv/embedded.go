package runtimeinv

import (
	"bufio"
	"context"
	"io"
	"os"
	"regexp"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const (
	versionFromBinary = "binary" // version string embedded in the executable
	maxEmbeddedScan   = 256 << 20
	embeddedChunk     = 1 << 20
	embeddedOverlap   = 128 // longer than any match, so a match split across chunks is still seen
)

// Per-runtime version strings compiled into the executable. Bun and Deno
// also embed a Node compatibility version, so each runtime has its own
// pattern rather than a shared one.
var (
	nodeEmbeddedRe = regexp.MustCompile(`nodejs\.org/download/release/v(\d+\.\d+\.\d+)/`)
	denoEmbeddedRe = regexp.MustCompile(`Deno/(\d+\.\d+\.\d+)`)
	bunEmbeddedRe  = regexp.MustCompile(`Bun/(\d+\.\d+\.\d+)`)
)

// embeddedVersion returns a strategy that streams the executable (never runs
// it) for re. The highest match wins: Deno also carries an old Deno/0.x
// string from a dependency.
func embeddedVersion(re *regexp.Regexp) versionStrategy {
	return func(ctx context.Context, _ executor.Executor, exe, _ string) (versionResult, bool) {
		if v := scanEmbedded(ctx, exe, re); v != "" {
			return versionResult{version: v, source: versionFromBinary}, true
		}
		return versionResult{}, false
	}
}

func scanEmbedded(ctx context.Context, path string, re *regexp.Regexp) string {
	// #nosec G304 -- path is a runtime binary found by the walk; it is read, never executed.
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReaderSize(io.LimitReader(f, maxEmbeddedScan), embeddedChunk)
	buf := make([]byte, 0, embeddedChunk+embeddedOverlap)
	best := ""
	chunk := make([]byte, embeddedChunk)
	for ctx.Err() == nil {
		n, err := io.ReadFull(r, chunk)
		buf = append(buf, chunk[:n]...)
		for _, m := range re.FindAllSubmatch(buf, -1) {
			if v := string(m[1]); best == "" || versionLess(best, v) {
				best = v
			}
		}
		if err != nil {
			return best
		}
		keep := buf[max(0, len(buf)-embeddedOverlap):]
		buf = append(buf[:0], keep...)
	}
	return best
}

// versionLess compares dotted numeric versions.
func versionLess(a, b string) bool {
	pa, pb := numericParts(a), numericParts(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func numericParts(v string) []int {
	var out []int
	n, in := 0, false
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n, in = n*10+int(c-'0'), true
			continue
		}
		if in {
			out = append(out, n)
		}
		n, in = 0, false
		if c != '.' {
			break
		}
	}
	if in {
		out = append(out, n)
	}
	return out
}
