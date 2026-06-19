// Package state manages the device-side scan state used to skip re-uploading
// unchanged npm and Python project scans across telemetry runs. See the design
// proposal in docs/ (or memory) for the full protocol.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const hashPrefix = "sha256:"

// CanonicalHashJSON returns sha256:<hex> of `data`. When `data` is valid JSON it
// is re-marshaled with sorted map keys first, so two PM-version-induced key
// reorderings of the same logical output produce the same hash. When `data` is
// not valid JSON (e.g. malformed PM stdout, non-zero exit) the raw bytes are
// hashed instead — the design's invariant is "never silently produce no hash."
// The returned error is non-nil only to surface the parse failure for logging;
// the hash is always populated.
func CanonicalHashJSON(data []byte) (string, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return sum(data), err
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return sum(data), err
	}
	return sum(canon), nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hashPrefix + hex.EncodeToString(h[:])
}
