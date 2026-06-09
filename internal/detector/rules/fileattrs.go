package rules

import (
	"os"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// fileAttrs builds the Stat-only metadata reported for a candidate file. Size
// and modified-time are portable; created (birth) and changed (ctime) times are
// best-effort per platform (statTimes), 0 when unavailable. Never reads or
// returns file content.
func fileAttrs(info os.FileInfo) model.FileAttrs {
	if info == nil {
		return model.FileAttrs{}
	}
	createdAt, changedAt := statTimes(info)
	return model.FileAttrs{
		SizeBytes:  info.Size(),
		ModifiedAt: info.ModTime().Unix(),
		CreatedAt:  createdAt,
		ChangedAt:  changedAt,
	}
}
