package secrets

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
)

// MaxFileBytes caps how much of any single file we load. Transcripts can
// grow large; we cap at 16 MiB per file to keep scanning bounded.
const MaxFileBytes int64 = 16 * 1024 * 1024

// ScanTranscript scans path for likely secrets and returns redacted
// findings. The returned bool reports whether ctx was cancelled (timeout).
//
// We read the whole bounded buffer once so multi-line patterns (PEM blocks)
// match correctly. Line numbers are recovered by counting newlines up to
// each match offset.
func ScanTranscript(ctx context.Context, path string) (*event.SecretsScanInfo, bool) {
	if path == "" {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, false
	}

	limit := st.Size()
	if limit > MaxFileBytes {
		limit = MaxFileBytes
	}
	buf, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false
	}

	info := &event.SecretsScanInfo{Scanned: true, FilesSeen: 1, BytesSeen: int64(len(buf))}
	if ctx.Err() != nil {
		info.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		return info, info.TimedOut
	}

	text := string(buf)
	seenFP := map[string]struct{}{}

	for _, r := range rules {
		if ctx.Err() != nil {
			info.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
			return info, info.TimedOut
		}
		matches := r.RE.FindAllStringSubmatchIndex(text, -1)
		for _, m := range matches {
			value := extract(text, m, r.Group)
			if value == "" {
				continue
			}
			fp := fingerprint(value)
			if _, dup := seenFP[fp]; dup {
				continue
			}
			seenFP[fp] = struct{}{}
			startLine, endLine := lineRange(text, m[0], m[1])
			info.Findings = append(info.Findings, event.SecretFinding{
				RuleID:        r.ID,
				FilePath:      path,
				LineStart:     startLine,
				LineEnd:       endLine,
				Fingerprint:   fp,
				MaskedPreview: mask(value),
				Confidence:    r.Confidence,
			})
		}
	}
	return info, info.TimedOut
}

func extract(s string, indices []int, group int) string {
	if group == 0 {
		if len(indices) < 2 {
			return ""
		}
		return s[indices[0]:indices[1]]
	}
	if len(indices) < 2*(group+1) {
		return ""
	}
	start := indices[2*group]
	end := indices[2*group+1]
	if start < 0 || end < 0 || start >= end || end > len(s) {
		return ""
	}
	return s[start:end]
}

// lineRange returns the 1-indexed line numbers for byte offsets [start, end)
// in s. Both are inclusive in the returned [startLine, endLine] range.
func lineRange(s string, start, end int) (int, int) {
	startLine := 1
	for i := 0; i < start && i < len(s); i++ {
		if s[i] == '\n' {
			startLine++
		}
	}
	endLine := startLine
	for i := start; i < end && i < len(s); i++ {
		if s[i] == '\n' {
			endLine++
		}
	}
	return startLine, endLine
}
