package firewall

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// reportStateFile, in StateDir, records when each failure was last posted.
const reportStateFile = "firewall-reports.json"

// reportState maps a failure key (code, plus the served release when there
// is one) to when it was last posted.
type reportState struct {
	Reported map[string]time.Time `json:"reported"`
}

// fail posts a run-status failure "<code>: <msg>", at most once per
// reportWindow per (code, release): a failed row changes the device's latest
// execution status in the console, and the update tick runs hourly. A new
// release, or another failure, posts at once.
func (m *Manager) fail(ctx context.Context, code, releaseKey, msg string) {
	key := code
	if releaseKey != "" {
		key += "|" + releaseKey
	}
	st := m.loadReports()
	now := m.Now()
	if last, ok := st.Reported[key]; ok && now.Sub(last) < reportWindow && !last.After(now) {
		return
	}
	if err := m.Report(ctx, code+": "+msg); err != nil {
		m.Logf("firewall: %s not reported: %v", code, err)
		return
	}
	for k, t := range st.Reported {
		if now.Sub(t) >= reportWindow {
			delete(st.Reported, k)
		}
	}
	st.Reported[key] = now
	m.saveReports(st)
}

// clearReports forgets posted failures after a success, so the next failure
// is posted at once.
func (m *Manager) clearReports() {
	if m.StateDir == "" {
		return
	}
	_ = os.Remove(filepath.Join(m.StateDir, reportStateFile))
}

func (m *Manager) loadReports() reportState {
	st := reportState{Reported: map[string]time.Time{}}
	if m.StateDir == "" {
		return st
	}
	b, err := os.ReadFile(filepath.Join(m.StateDir, reportStateFile))
	if err != nil {
		return st
	}
	if json.Unmarshal(b, &st) != nil || st.Reported == nil {
		return reportState{Reported: map[string]time.Time{}}
	}
	return st
}

func (m *Manager) saveReports(st reportState) {
	if m.StateDir == "" {
		return
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	dst := filepath.Join(m.StateDir, reportStateFile)
	tmp, err := os.CreateTemp(m.StateDir, ".firewall-reports-*.tmp")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return
	}
	_ = os.Remove(dst) // Windows Rename won't overwrite
	if os.Rename(tmp.Name(), dst) != nil {
		_ = os.Remove(tmp.Name())
	}
}
