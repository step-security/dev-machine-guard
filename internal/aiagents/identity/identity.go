// Package identity computes AI-event identity for a hook invocation.
//
// This is a thin wrapper over DMG's `internal/device.Gather`. The only
// adapter logic that lives here is:
//
//  1. Bound the device probe with a 1-second context timeout. Hook
//     invocations have a 15s total budget; identity must not be the
//     thing that exhausts it.
//
//  2. Use the resolved machine
//     ID; "unknown" when the probe budget ran out, as before (the event
//     ingest contract for an empty device_id is unverified).
//
//  3. Single Gather call per Resolve — no probing twice for the two
//     fields we need.
//
// CustomerID is plumbed through as-is from the caller (typically read
// from `internal/aiagents/ingest.Snapshot`); device.Gather has no
// awareness of it.
package identity

import (
	"context"
	"time"

	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// ProbeTimeout is the upper bound on the device.Gather call. Tuned to
// leave room for enrichment + a 5s upload inside the 15s hook cap.
const ProbeTimeout = time.Second

// Info is the identity payload attached to every AI-agent event.
//
// The wire field for DeviceID is `device_id`; the wire field for
// UserIdentity is `user_identity`. See internal/aiagents/event.
type Info struct {
	CustomerID   string
	DeviceID     string
	UserIdentity string
}

// Resolve returns identity information for the current host, using the configured
// device ID when present.
//
// On probe timeout, DeviceID and other gathered fields fall back to
// "unknown". Admin-managed display IDs do not alter hook identity.
func Resolve(ctx context.Context, exec executor.Executor, customerID string) Info {
	probeCtx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	d := device.Gather(probeCtx, exec)
	id := device.ID(d)
	if id == "" {
		id = "unknown"
	}
	return Info{
		CustomerID:   customerID,
		DeviceID:     id,
		UserIdentity: d.UserIdentity,
	}
}
