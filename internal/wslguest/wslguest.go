// Package wslguest derives the device identity of an agent running inside a
// WSL distribution. It is deliberately tiny and dependency-free: both the
// telemetry payload and the run gate need the same id, and internal/telemetry
// already imports internal/rungate, so neither can own it.
package wslguest

import (
	"strings"

	"github.com/google/uuid"
)

// namespace namespaces derived guest ids. A fixed namespace keeps derivation
// stable across agent versions — change it and every WSL distribution in every
// fleet becomes a new device.
var namespace = uuid.MustParse("6f2c1f8e-3b6d-5a4e-9c1d-7f5a2b8e0d31")

// DeviceID derives a distribution's device id from its Windows host's serial
// and its own registry GUID, both passed in by the host that triggered the
// scan. Returns "" unless both are present: a half-pair identifies nothing.
//
// Deterministic, so re-scans converge on one device record instead of breeding
// rows; unique per (host, distro), so distributions on one host never collide —
// which they would if we fell back to the hostname they all share. The backend
// does not recompute this (it pairs on distro_id), so the value only has to be
// stable and unique, not verifiable.
func DeviceID(hostSerial, distroID string) string {
	host := strings.TrimSpace(hostSerial)
	distro := strings.TrimSpace(distroID)
	if host == "" || distro == "" {
		return ""
	}
	return uuid.NewSHA1(namespace, []byte(strings.ToLower(host+"|"+distro))).String()
}
