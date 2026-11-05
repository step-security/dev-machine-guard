package main

import (
	"io"
	"os"
	"strings"
	"time"
)

const (
	adoptSeedTailBytes = 64 << 10
	adoptSeedMaxLines  = 3
	adoptSeedRunWindow = 2 * time.Minute
)

// stateReasons are fallbacks where the MSI's adopt-seed never wrote
// state.json; its last log lines say why.
var stateReasons = map[string]bool{"state_missing": true, "state_corrupt": true, "state_unreadable": true}

// adoptSeedOutcome returns the last adopt-seed run's lines from update.log
// (at most adoptSeedMaxLines, timestamps and prefix stripped, joined by
// " | "), or "" when there are none or the log is unreadable.
func adoptSeedOutcome(logPath string) string {
	f, err := os.Open(logPath) // #nosec G304 -- fixed path in the install root's state dir
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err == nil && fi.Size() > adoptSeedTailBytes {
		if _, err := f.Seek(-adoptSeedTailBytes, io.SeekEnd); err != nil {
			return ""
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, adoptSeedTailBytes))
	if err != nil {
		return ""
	}
	type entry struct {
		at  time.Time
		msg string
	}
	var runs []entry
	for _, line := range strings.Split(string(b), "\n") {
		ts, rest, ok := strings.Cut(strings.TrimSpace(line), " bootstrap: ")
		if !ok || !strings.HasPrefix(rest, "adopt-seed") || strings.HasPrefix(rest, "adopt-seed --") {
			continue
		}
		at, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		runs = append(runs, entry{at, rest})
	}
	if len(runs) == 0 {
		return ""
	}
	last := runs[len(runs)-1].at
	var out []string
	for i := len(runs) - 1; i >= 0 && len(out) < adoptSeedMaxLines; i-- {
		if last.Sub(runs[i].at) > adoptSeedRunWindow {
			break
		}
		out = append([]string{runs[i].msg}, out...)
	}
	return strings.Join(out, " | ")
}

// withAdoptSeedOutcome appends adopt-seed's last outcome to a state_* fallback
// reason, so update_pointer_invalid says why the MSI left no state.json.
func withAdoptSeedOutcome(reason, logPath string) string {
	if !stateReasons[reason] {
		return reason
	}
	if o := adoptSeedOutcome(logPath); o != "" {
		return reason + "; " + o
	}
	return reason
}
