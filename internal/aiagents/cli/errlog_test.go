package cli

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withErrorLog redirects the errors log to a temp path for the test and
// restores the previous value on cleanup. Tests using this helper must
// not run in parallel — errorLogPathOverride is package-level state.
func withErrorLog(t *testing.T) string {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "errors.jsonl")
	prev := errorLogPathOverride
	errorLogPathOverride = tmp
	t.Cleanup(func() { errorLogPathOverride = prev })
	return tmp
}

func TestAppendError_CreatesFileWithMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits aren't preserved on Windows")
	}
	path := withErrorLog(t)
	AppendError("install", "no_console_user", "running as root", "")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %o, want 0o600", info.Mode().Perm())
	}
}

func TestAppendError_WritesJSONLEntry(t *testing.T) {
	path := withErrorLog(t)
	AppendError("upload", "http_500", "server error", "evt-abc")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d (%q)", len(lines), string(data))
	}
	var entry ErrorEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshal: %v (line=%q)", err, lines[0])
	}
	if entry.Stage != "upload" || entry.Code != "http_500" || entry.Message != "server error" || entry.EventID != "evt-abc" {
		t.Errorf("unexpected entry: %+v", entry)
	}
	if entry.Timestamp == "" {
		t.Error("missing timestamp")
	}
}

func TestAppendError_OmitsEmptyEventID(t *testing.T) {
	path := withErrorLog(t)
	AppendError("install", "chown_failed", "permission denied", "")

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "event_id") {
		t.Errorf("expected event_id field omitted when empty, got %q", string(data))
	}
}

func TestAppendError_MultipleEntriesAppend(t *testing.T) {
	path := withErrorLog(t)
	AppendError("a", "1", "first", "")
	AppendError("b", "2", "second", "evt-2")
	AppendError("c", "3", "third", "")

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
		var e ErrorEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Errorf("line %d unmarshal: %v", count, err)
		}
	}
	if count != 3 {
		t.Errorf("expected 3 entries, got %d", count)
	}
}

func TestAppendError_TruncatesAtFiveMiB(t *testing.T) {
	path := withErrorLog(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// Pre-seed the file with > 5 MiB of garbage so the next AppendError
	// trips the truncate-and-restart branch.
	big := make([]byte, MaxErrorLogBytes+1024)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}

	AppendError("install", "after_truncate", "fresh entry", "")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() >= int64(MaxErrorLogBytes) {
		t.Errorf("expected file truncated and restarted, size = %d bytes", info.Size())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "after_truncate") {
		t.Errorf("expected fresh entry after truncate, got %q", string(data))
	}
}

func TestAppendError_NoHomeIsSilent(t *testing.T) {
	prev := errorLogPathOverride
	errorLogPathOverride = ""
	t.Cleanup(func() { errorLogPathOverride = prev })

	// Force the default-path branch with HOME unset. On Unix, t.Setenv
	// works; on Windows os.UserHomeDir consults USERPROFILE/HOMEDRIVE,
	// so we skip the assertion there — the contract under test is "no
	// panic, silent drop" which is platform-independent in practice.
	if runtime.GOOS != "windows" {
		t.Setenv("HOME", "")
	}

	// Must not panic, must not error, must not write anywhere observable.
	AppendError("install", "no_home", "should be silently dropped", "")
}

func TestAppendError_TimestampIsUTCNanoFormat(t *testing.T) {
	path := withErrorLog(t)
	AppendError("test", "fmt", "checking timestamp", "")

	data, _ := os.ReadFile(path)
	var entry ErrorEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil {
		t.Fatal(err)
	}
	// RFC3339Nano UTC timestamps end with 'Z'.
	if !strings.HasSuffix(entry.Timestamp, "Z") {
		t.Errorf("timestamp %q is not UTC RFC3339Nano (no trailing Z)", entry.Timestamp)
	}
}

func TestAppendError_RedactsMessage(t *testing.T) {
	// AppendError must run the message through redact.String before it
	// hits disk. A bearer token in the message must NOT survive in the
	// on-disk JSONL line.
	path := withErrorLog(t)
	AppendError("upload", "http_500",
		"failed POST with Authorization: Bearer eyJ.payload.sig.AAAAAAAAAAA",
		"evt-1")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "eyJ.payload.sig.AAAAAAAAAAA") {
		t.Errorf("bearer leaked into error log: %s", string(data))
	}
	if !strings.Contains(string(data), "[REDACTED]") {
		t.Errorf("expected [REDACTED] placeholder in log line, got: %s", string(data))
	}
}

func TestErrorLogPath_DefaultUnderHome(t *testing.T) {
	// Don't override; test the default branch.
	prev := errorLogPathOverride
	errorLogPathOverride = ""
	t.Cleanup(func() { errorLogPathOverride = prev })

	if runtime.GOOS == "windows" {
		t.Skip("HOME isn't the canonical home env var on Windows")
	}
	t.Setenv("HOME", "/tmp/fake-home")

	got := ErrorLogPath()
	want := "/tmp/fake-home/.stepsecurity/ai-agent-hook-errors.jsonl"
	if got != want {
		t.Errorf("ErrorLogPath = %q, want %q", got, want)
	}
}
