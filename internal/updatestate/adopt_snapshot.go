package updatestate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// AdoptSnapshotMaxAge bounds how long an adopt-seed snapshot is honoured: an
// MSI transaction is far shorter, so an older one belongs to an MSI that
// ended without its commit or rollback action and is swept, never applied.
const AdoptSnapshotMaxAge = time.Hour

// AdoptSnapshot is what adopt-seed recorded before changing anything, so
// the MSI's rollback action can undo it if the transaction fails.
type AdoptSnapshot struct {
	Seed         string `json:"seed"`
	StatePresent bool   `json:"state_present"`
	State        []byte `json:"state,omitempty"` // state.json bytes before adopt-seed
	CreatedDir   bool   `json:"created_dir"`     // adopt-seed created versions\<seed>
	// AfterGeneration is the generation adopt-seed wrote; nil when it left
	// state.json unchanged. A rollback restores state only while the file
	// still carries it (nobody wrote since).
	AfterGeneration *uint64 `json:"after_generation,omitempty"`
}

// AdoptSnapshotFile is state\adopt-snapshot.json.
func (l Layout) AdoptSnapshotFile() string { return filepath.Join(l.StateDir(), "adopt-snapshot.json") }

// WriteAdoptSnapshot writes s atomically.
func WriteAdoptSnapshot(path string, s *AdoptSnapshot) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeAtomic(path, data, nil, nil)
}

// ReadAdoptSnapshot returns the snapshot and its age by file time; a
// missing file is (nil, 0, nil).
func ReadAdoptSnapshot(path string) (*AdoptSnapshot, time.Duration, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	data, err := readBounded(path, 2*maxStateSize)
	if err != nil {
		return nil, 0, err
	}
	var s AdoptSnapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, 0, err
	}
	return &s, time.Since(fi.ModTime()), nil
}

// SweepStaleAdoptSnapshot removes a snapshot older than AdoptSnapshotMaxAge
// (or unreadable). Callers hold the update lock.
func SweepStaleAdoptSnapshot(path string) {
	s, age, err := ReadAdoptSnapshot(path)
	if err != nil || (s != nil && age > AdoptSnapshotMaxAge) {
		_ = os.Remove(path)
	}
}

// StateGeneration reads state.json's generation without full validation
// (0 when absent).
func StateGeneration(path string) (uint64, bool) {
	data, err := readBounded(path, maxStateSize)
	if err != nil {
		return 0, false
	}
	var g struct {
		Generation uint64 `json:"generation"`
	}
	if json.Unmarshal(data, &g) != nil {
		return 0, false
	}
	return g.Generation, true
}
