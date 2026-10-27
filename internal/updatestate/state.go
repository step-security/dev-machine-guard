package updatestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/step-security/dev-machine-guard/internal/faultinject"
)

// SchemaVersion is the state.json schema this package writes. A file with a
// higher schema is read for its known fields and written back with its own
// schema number and unknown keys intact.
const SchemaVersion = 1

// maxStateSize bounds what Load reads; anything larger is corrupt.
const maxStateSize = 1 << 20

// State is state.json (schema 1, spec "Contracts"). Version fields hold
// strict x.y.z strings; Load guarantees they parse.
type State struct {
	Schema          int                   `json:"schema"`
	Current         string                `json:"current"`
	Previous        string                `json:"previous"`
	Probation       *Probation            `json:"probation"`
	Quarantine      map[string]Quarantine `json:"quarantine"`
	Updater         Updater               `json:"updater"`
	SwitchDeferrals int                   `json:"switch_deferrals"`
	Dedupe          map[string]time.Time  `json:"dedupe"`

	// Additive fields (schema 1 readers ignore them).

	// Generation is incremented by every Save. After a write error, a
	// re-read showing the expected generation proves the write landed.
	Generation uint64 `json:"generation,omitempty"`
	// LastCheck is when the updater last asked latest-binary for a target.
	LastCheck time.Time `json:"last_check,omitzero"`
	// Outbox holds update events not yet accepted by the backend. Events
	// are added in the same atomic write as the state change they report.
	Outbox []OutboxEvent `json:"outbox,omitempty"`
	// SmokeTimeouts counts consecutive smoke-test timeouts per version; the
	// third quarantines it (a timeout alone is retried).
	SmokeTimeouts map[string]int `json:"smoke_timeouts,omitempty"`
	// Restages counts re-stagings of a version whose dir was damaged (an AV
	// deleting a file); RestageBackoff pauses them (version -> until).
	Restages       map[string]Restage   `json:"restages,omitempty"`
	RestageBackoff map[string]time.Time `json:"restage_backoff,omitempty"`
	// PendingSwitch is a staged target whose switch was deferred; its
	// versions dir is kept and SwitchDeferrals counts for it alone.
	PendingSwitch string `json:"pending_switch,omitempty"`
	// OutboxDropped counts events dropped because the outbox was full.
	OutboxDropped uint64 `json:"outbox_dropped,omitempty"`

	// Extra holds keys this version doesn't know; Save writes them back.
	Extra map[string]json.RawMessage `json:"-"`
}

// Restage counts re-stagings of one version since First (Last: the latest).
type Restage struct {
	Count int       `json:"count"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// OutboxEvent is a pending update event (spec Contracts: Update event).
type OutboxEvent struct {
	ExecutionID string    `json:"execution_id"`
	Event       string    `json:"update_event"`
	From        string    `json:"update_from,omitempty"`
	To          string    `json:"update_to,omitempty"`
	Error       string    `json:"error_message,omitempty"`
	At          time.Time `json:"at"`
	// Attempts and NextAttempt implement the retry backoff.
	Attempts    int       `json:"attempts,omitempty"`
	NextAttempt time.Time `json:"next_attempt,omitzero"`

	Extra map[string]json.RawMessage `json:"-"` // unknown keys, kept on Save
}

// Probation tracks a newly switched-to version until it is confirmed or
// rolled back. OK and Bad count runs (Bad counts consecutive bad runs).
type Probation struct {
	Version string    `json:"version"`
	Since   time.Time `json:"since"`
	OK      int       `json:"ok"`
	Bad     int       `json:"bad"`
	SmokeOK bool      `json:"smoke_ok"`
	// SinceSeq is the run file's highest sequence number at the switch;
	// runs with a higher seq belong to the probation (additive).
	SinceSeq *int `json:"since_seq,omitempty"` // nil: an older probation (time rule)
	// Ticks counts update ticks that evaluated this probation, so it closes
	// even if the clock jumps (additive).
	Ticks int `json:"ticks,omitempty"`

	Extra map[string]json.RawMessage `json:"-"` // unknown keys, kept on Save
}

type Quarantine struct {
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
	// Until, when set, ends the quarantine (D5: inconclusive probation).
	// Zero means permanent.
	Until time.Time `json:"until,omitzero"`

	Extra map[string]json.RawMessage `json:"-"` // unknown keys, kept on Save
}

// Updater records which version last ran the updater and how often in a
// row it failed, for the bootstrap's updater selection.
type Updater struct {
	Version             string `json:"version"`
	ConsecutiveFailures int    `json:"consecutive_failures"`

	Extra map[string]json.RawMessage `json:"-"` // unknown keys, kept on Save
}

// Validate reports why s is not a well-formed schema-1 state. Current is
// required; the other version fields are optional but strict when set.
func (s *State) Validate() error {
	switch {
	case s.Schema < SchemaVersion:
		// A higher schema is read for the fields this version knows; the
		// rest is preserved (frozen read contract, D3/D15).
		return fmt.Errorf("unsupported schema %d", s.Schema)
	case !validVersion(s.Current):
		return fmt.Errorf("invalid current %q", s.Current)
	case s.Previous != "" && !validVersion(s.Previous):
		return fmt.Errorf("invalid previous %q", s.Previous)
	case s.Updater.Version != "" && !validVersion(s.Updater.Version):
		return fmt.Errorf("invalid updater version %q", s.Updater.Version)
	case s.SwitchDeferrals < 0 || s.Updater.ConsecutiveFailures < 0:
		return errors.New("negative counter")
	}
	if p := s.Probation; p != nil {
		if !validVersion(p.Version) {
			return fmt.Errorf("invalid probation version %q", p.Version)
		}
		if p.OK < 0 || p.Bad < 0 {
			return errors.New("negative probation counter")
		}
	}
	for v := range s.Quarantine {
		if !validVersion(v) {
			return fmt.Errorf("invalid quarantined version %q", v)
		}
	}
	return nil
}

// decodeState parses and validates state.json. Unknown fields are ignored
// so an older agent can still read a newer schema-1 file after a rollback.
func decodeState(data []byte) (*State, error) {
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.Quarantine == nil {
		s.Quarantine = map[string]Quarantine{}
	}
	if s.Dedupe == nil {
		s.Dedupe = map[string]time.Time{}
	}
	return &s, nil
}

// Load reads state.json. A missing file returns (nil, false, nil). An
// unreadable-as-state file (bad JSON, unknown schema, invalid fields,
// oversize) returns (nil, true, nil): callers treat it as missing and report
// update_state_corrupt. err is set only for I/O failures other than absence.
func Load(path string) (st *State, corrupt bool, err error) {
	data, err := readBounded(path, maxStateSize)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	case errors.Is(err, errUnreadable):
		return nil, true, nil
	case err != nil:
		return nil, false, err
	}
	s, derr := decodeState(data)
	if derr != nil {
		return nil, true, nil
	}
	return s, false, nil
}

// errUnreadable marks content that can never be valid: oversize or not a
// regular file.
var errUnreadable = errors.New("updatestate: not a bounded regular file")

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := openShared(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errUnreadable
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errUnreadable
	}
	return data, nil
}

// checkpoint is swapped by tests that kill a subprocess mid-Save.
var checkpoint = faultinject.Point

// Save atomically replaces state.json with st (schema set to 1). It refuses
// a state that Load would reject. After a crash at any point, Load returns
// either the old or the new state.
func Save(path string, st *State) error { return SaveCheckpointed(path, st, "") }

// SaveCheckpointed writes st with Generation+1 (and sets st.Generation on
// success). It is Save with fault checkpoints <prefix>.state-temp (temp
// file durable, target untouched) and <prefix>.state-renamed (target
// replaced), e.g. prefix "S6", "rollback" or "adopt". An empty prefix
// disables them. An injected error at state-renamed is returned although the
// new state is already in place, as a late write error would be.
func SaveCheckpointed(path string, st *State, prefix string) error {
	out := *st
	if out.Schema < SchemaVersion {
		out.Schema = SchemaVersion
	}
	out.Generation = st.Generation + 1
	if out.Quarantine == nil {
		out.Quarantine = map[string]Quarantine{}
	}
	if out.Dedupe == nil {
		out.Dedupe = map[string]time.Time{}
	}
	if err := out.Validate(); err != nil {
		return fmt.Errorf("updatestate: refusing to save invalid state: %w", err)
	}
	data, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return err
	}
	var afterTemp, afterRename func() error
	if prefix != "" {
		afterTemp = func() error { return checkpoint(prefix + ".state-temp") }
		afterRename = func() error { return checkpoint(prefix + ".state-renamed") }
	}
	if err := writeAtomic(path, append(data, '\n'), afterTemp, afterRename); err != nil {
		return err
	}
	st.Generation = out.Generation
	return nil
}
