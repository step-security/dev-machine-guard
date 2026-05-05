package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
)

// ErrorLogFilename is the basename of the per-user errors log. It lives
// directly under ~/.stepsecurity/ — no `anchor/` subdir per the rebrand
// in port plan §1.14.
const ErrorLogFilename = "ai-agent-hook-errors.jsonl"

// MaxErrorLogBytes triggers a truncate-and-restart before each append.
// 5 MiB matches port plan §1.10. Phase 1 deliberately skips advisory
// locks; entries < 4 KiB are atomic on POSIX `O_APPEND` writes.
const MaxErrorLogBytes = 5 * 1024 * 1024

const (
	errorLogFileMode      os.FileMode = 0o600
	errorLogParentDirMode os.FileMode = 0o700
)

// ErrorEntry is the JSONL shape of a single line in the errors log.
// Field tags are short to keep the file compact when something goes
// wrong on the hot path; eventID is omitted when not correlated to an
// upload.
type ErrorEntry struct {
	Timestamp string `json:"ts"`
	Stage     string `json:"stage"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	EventID   string `json:"event_id,omitempty"`
}

// errorLogPathOverride redirects writes to a test-controlled location.
// "" means "use the default ~/.stepsecurity/<filename> path." Only
// touched from same-package _test.go files; tests must restore on
// cleanup since this is package-level mutable state.
var errorLogPathOverride string

// AppendError writes a single JSONL entry to the errors log. The call
// is best-effort: any failure (no $HOME, mkdir denied, marshal error,
// open denied, partial write) is silently dropped — the hot path's
// allow response must never be blocked by logging.
//
// The message is run through redact.String before being written to
// disk so a stray secret in an error message never lands in the
// on-disk log.
func AppendError(stage, code, message, eventID string) {
	path := errorLogPath()
	if path == "" {
		return
	}

	entry := ErrorEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Stage:     stage,
		Code:      code,
		Message:   redact.String(message),
		EventID:   eventID,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), errorLogParentDirMode); err != nil {
		return
	}

	// Truncate-and-restart at the size cap. We stat first to avoid the
	// truncate when the file is small (the common case). Failure here is
	// non-fatal: if we can't stat or truncate, fall through to append
	// anyway so the entry isn't lost on a non-cap-related stat error.
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > MaxErrorLogBytes {
		_ = os.Truncate(path, 0)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, errorLogFileMode)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(data)
}

// ErrorLogPath returns the absolute path of the errors log for the
// current user (or the test override). Exposed for diagnostics paths
// that want to surface the location to the user.
func ErrorLogPath() string {
	return errorLogPath()
}

func errorLogPath() string {
	if errorLogPathOverride != "" {
		return errorLogPathOverride
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".stepsecurity", ErrorLogFilename)
}

