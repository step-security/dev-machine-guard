package model

const DeveloperReportSchemaVersion = 2

// Area status. Only "complete" lets zero items mean "none found".
const (
	AreaComplete    = "complete"
	AreaPartial     = "partial"
	AreaDisabled    = "disabled"
	AreaUnsupported = "unsupported"
	AreaUnavailable = "unavailable"
)

const (
	AttentionHigh   = "high"
	AttentionMedium = "medium"
	AttentionInfo   = "info"
)

// DeveloperReport is the versioned, read-only view behind `dmg findings`. The
// terminal and JSON present the same attention items and area rows.
type DeveloperReport struct {
	SchemaVersion int             `json:"schema_version"`
	AgentVersion  string          `json:"agent_version,omitempty"`
	ScannedAt     string          `json:"scanned_at,omitempty"`
	Cached        bool            `json:"cached"`
	Scope         *ReportScope    `json:"scope,omitempty"`
	Attention     []AttentionItem `json:"attention"`
	Areas         []ReportArea    `json:"areas"`
}

// ReportScope says where the scan looked. SkippedPaths could not be read;
// ProtectedPaths were left alone so the OS would not prompt for access.
type ReportScope struct {
	Note           string   `json:"note,omitempty"`
	Home           string   `json:"home,omitempty"`
	SearchDirs     []string `json:"search_dirs"`
	SkippedPaths   []string `json:"skipped_paths"`
	ProtectedPaths []string `json:"protected_paths"`
}

// AttentionItem is something a developer may want to act on, derived from the
// rows of one area. Action is the command that shows the evidence.
type AttentionItem struct {
	Severity string `json:"severity"`
	Area     string `json:"area"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Action   string `json:"action,omitempty"`
}

type ReportArea struct {
	ID         string       `json:"id"`
	Title      string       `json:"title"`
	Status     string       `json:"status"`
	StatusNote string       `json:"status_note,omitempty"`
	Summary    string       `json:"summary,omitempty"`
	Items      []ReportItem `json:"items"`
}

// ReportItem is one row. Kind groups rows inside an area (an ecosystem, an
// agent, a browser). Flags name what the attention rules matched.
type ReportItem struct {
	Name      string   `json:"name"`
	Version   string   `json:"version,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Location  string   `json:"location,omitempty"`
	Locations []string `json:"locations,omitempty"`
	Count     int      `json:"count,omitempty"`
	Flags     []string `json:"flags,omitempty"`
}
