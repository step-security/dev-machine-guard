package updatestate

import (
	"os"
	"sync"
	"time"
)

// liveness of a run record's owning bootstrap process.
type liveness int

const (
	ownerUnknown liveness = iota // no owner recorded, or it can't be queried
	ownerAlive
	ownerDead // gone, or the PID now belongs to another process
)

var (
	selfStartOnce sync.Once
	selfStart     time.Time
)

// stampOwner records this process as the owner of a new record.
func stampOwner(r *RunRecord) {
	if r.OwnerPID != 0 {
		return
	}
	r.OwnerPID = os.Getpid()
	selfStartOnce.Do(func() { selfStart, _ = processStartTime(r.OwnerPID) })
	r.OwnerStart = selfStart
}

func ownerOf(r RunRecord) liveness {
	if r.OwnerPID <= 0 {
		return ownerUnknown
	}
	return processLiveness(r.OwnerPID, r.OwnerStart)
}
