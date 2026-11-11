package telemetry

import (
	"github.com/step-security/dev-machine-guard/internal/identity"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// applyDevice stamps identity and its availability from the same snapshot.
// Session state was collected independently of configured attribution.
func (p *Payload) applyDevice(dev model.Device, deviceID, serialIdentity string) {
	p.DeviceID = deviceID
	p.SerialNumber = serialIdentity
	p.UserIdentity = dev.UserIdentity
	p.UserToken = dev.UserToken
	p.UserIDMissing = identity.MissingUser(dev.UserIdentity)
	p.DeviceIDMissing = identity.MissingDevice(deviceID)
	p.NoUserLoggedIn = dev.NoUserLoggedIn
	p.Hostname = dev.Hostname
	p.Platform = dev.Platform
	p.OSVersion = dev.OSVersion
	p.Resources = dev.Resources
}
