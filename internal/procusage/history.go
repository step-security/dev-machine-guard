package procusage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxHistoryRecords caps run-metrics.jsonl. An enterprise record with
// its full phase list measures ~1.3KB, so the file tops out near 250KB
// and stays there — the trim runs on every append, not on a schedule.
// At a 4h cadence that is over a month of history.
// TestHistoryDiskFootprintAtCap pins the ceiling.
const maxHistoryRecords = 200

// Phase is one analysis phase's cost. Declared here rather than reusing
// telemetry.PhaseCompletion because telemetry imports this package.
type Phase struct {
	Name       string `json:"name"`
	DurationMs int64  `json:"duration_ms"`
	CPUMs      int64  `json:"cpu_ms,omitempty"`
}

// Record is one line of run-metrics.jsonl: what the run was, plus what
// it cost.
type Record struct {
	Timestamp        time.Time `json:"ts"`
	AgentVersion     string    `json:"agent_version,omitempty"`
	Command          string    `json:"command,omitempty"`
	InvocationMethod string    `json:"invocation_method,omitempty"`
	OS               string    `json:"os,omitempty"`
	ExecutionID      string    `json:"execution_id,omitempty"`
	Usage            Sample    `json:"usage"`
	Phases           []Phase   `json:"phases,omitempty"`
}

// AppendHistory adds rec to the JSONL history at path, trimming to the
// newest maxHistoryRecords. An empty path is a no-op returning nil —
// paths.RunMetricsFile() is "" when the install dir is disabled.
//
// Read-trim-rewrite rather than a bare append so the trim happens in the
// same atomic replace; the file is small enough that reading it per run
// costs nothing. It deliberately does not use atomicfile.WriteAtomic,
// which takes a .bak-<epoch> copy on every write — churn that makes
// sense for config.json and not for a file rewritten every run.
func AppendHistory(path string, rec Record) error {
	if path == "" {
		return nil
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("procusage: marshal record: %w", err)
	}

	kept := tailLines(path, maxHistoryRecords-1)
	var buf bytes.Buffer
	for _, l := range kept {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}
	buf.Write(line)
	buf.WriteByte('\n')

	return replaceFile(path, buf.Bytes())
}

// LoadHistory reads the history back, skipping lines that don't parse so
// one truncated write never hides the rest of the file.
func LoadHistory(path string) ([]Record, error) {
	if path == "" {
		return nil, nil
	}
	// #nosec G304 -- path is paths.RunMetricsFile(): the agent's own
	// install dir, or a test temp dir. Never attacker-supplied.
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []Record
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, scanner.Err()
}

// tailLines returns at most n trailing non-blank lines from path. A
// missing or unreadable file yields nothing — history is advisory.
func tailLines(path string, n int) []string {
	if n <= 0 {
		return nil
	}
	// #nosec G304 -- same provenance as LoadHistory: the agent's own
	// install dir.
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	if scanner.Err() != nil || len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}

// replaceFile writes data to path via a same-directory temp file and
// rename, so a reader never sees a partial history.
func replaceFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("procusage: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("procusage: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("procusage: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("procusage: close temp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("procusage: chmod temp: %w", err)
	}
	return os.Rename(tmpPath, path)
}
