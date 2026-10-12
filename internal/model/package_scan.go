package model

// PackageScanConfig is the backend authorization for delta package uploads.
// Missing, null, and false all select legacy full-snapshot reporting.
type PackageScanConfig struct {
	DeltaEnabled bool `json:"delta_enabled"`
}
