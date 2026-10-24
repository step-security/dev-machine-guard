package faultinject

import "testing"

var badSpecs = []string{
	"S0.locked:explode", "S0.locked:exit", "S0.locked:exit-1", "nocolon", "S0.locked:", ":kill",
	"S0.locked@sytem:err", "S0.locked@SYSTEM:err", "S4.downloaded:agent.exe", "S0.locked@:err",
	"unrelated:kill,S0.locked:bogus",
	"S0.locked:exit64", // 64 is reserved for the malformed-spec exit
	"S6.mutex:sleep", "S6.mutex:sleep0s", "S6.mutex:sleep-1s", "S6.mutex:sleep11m", "S6.mutex:sleepforever",
}

// Validate works in every build, so drivers can reject typos at setup.
func TestValidate(t *testing.T) {
	for _, spec := range badSpecs {
		if Validate(spec) == nil {
			t.Errorf("Validate(%q) = nil", spec)
		}
	}
	for _, spec := range []string{"", "S0.locked:kill", "S4.downloaded:agent.exe:err", "agent.prestart@system:exit3, boot.launched@user:hang", "S6.mutex:diskfull", "S6.mutex:sleep45s", "S6.mutex:sleep10m", "S6.mutex:sleep250ms"} {
		if err := Validate(spec); err != nil {
			t.Errorf("Validate(%q) = %v", spec, err)
		}
	}
}
