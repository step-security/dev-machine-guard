package state

import (
	"encoding/base64"
	"encoding/json"
)

// ScanRecordFromBase64 builds a ScanRecord from a PM scan result whose raw
// stdout is base64-encoded (NodeScanResult.RawStdoutBase64). When the base64
// decode fails the raw string is hashed instead so the record is never empty.
func ScanRecordFromBase64(path, pm, pmVersion, rawStdoutBase64 string, exitCode int) ScanRecord {
	decoded, err := base64.StdEncoding.DecodeString(rawStdoutBase64)
	if err != nil {
		decoded = []byte(rawStdoutBase64)
	}
	hash, _ := CanonicalHashJSON(decoded)
	return ScanRecord{
		Path:           path,
		Hash:           hash,
		PackageManager: pm,
		PMVersion:      pmVersion,
		ExitCode:       exitCode,
	}
}

// ScanRecordFromValue builds a ScanRecord by JSON-marshaling `value` and
// canonical-hashing the result. Used for ecosystems like Python where the
// scanner returns parsed package data instead of raw PM stdout. exitCode
// must reflect whether the upstream scan succeeded — failed scans are never
// cached so the next run retries them.
func ScanRecordFromValue(path, pm, pmVersion string, value any, exitCode int) ScanRecord {
	raw, err := json.Marshal(value)
	if err != nil {
		raw = []byte{}
	}
	hash, _ := CanonicalHashJSON(raw)
	return ScanRecord{
		Path:           path,
		Hash:           hash,
		PackageManager: pm,
		PMVersion:      pmVersion,
		ExitCode:       exitCode,
	}
}
