// Package identity computes AI-event identity for a hook invocation.
//
// This is a thin wrapper over DMG's `internal/device.Gather` — the rule
// in the port plan is "no modifications to internal/device", so the only
// adapter logic that lives here is:
//
//   1. Bound the device probe with a 1-second context timeout. Hook
//      invocations have a 15s total budget; identity must not be the
//      thing that exhausts it.
//
//   2. Pass `"unknown"` through verbatim. device.Gather already returns
//      that sentinel for failed probes; we do NOT rewrite it to "" — the
//      backend distinguishes "not collected" from "actively unknown".
//
//   3. Single Gather call per Resolve — no probing twice for the two
//      fields we need.
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
// UserIdentity is `user_identity`. See internal/aiagents/event when 2.1
// lands.
type Info struct {
	CustomerID   string
	DeviceID     string
	UserIdentity string
}

// Resolve returns identity information for the current host.
//
// On probe timeout or any executor error, fields fall back to the
// `"unknown"` sentinel that device.Gather emits internally — this
// function does not synthesize "" or any other replacement.
func Resolve(ctx context.Context, exec executor.Executor, customerID string) Info {
	probeCtx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	d := device.Gather(probeCtx, exec)
	return Info{
		CustomerID:   customerID,
		DeviceID:     d.SerialNumber,
		UserIdentity: d.UserIdentity,
	}
}
