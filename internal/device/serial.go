package device

import "strings"

// placeholderSerials are firmware/OEM defaults shared across many machines.
// Accepting one would merge distinct devices into a single device_id.
var placeholderSerials = map[string]bool{
	"unknown":                true,
	"none":                   true,
	"null":                   true,
	"n/a":                    true,
	"na":                     true,
	"default":                true,
	"default string":         true,
	"not specified":          true,
	"not applicable":         true,
	"not available":          true,
	"not set":                true,
	"invalid":                true,
	"oem":                    true,
	"o.e.m.":                 true,
	"to be filled by o.e.m.": true,
	"to be filled by oem":    true,
	"system serial number":   true,
	"chassis serial number":  true,
	"serial number":          true,
	"serialnumber":           true,
	"123456789":              true,
	"1234567890":             true,
	"0123456789":             true,
}

// usableSerial reports whether s (trimmed, case-insensitive) can identify a
// single machine: non-empty, not a known placeholder, not all zeros.
func usableSerial(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || placeholderSerials[s] {
		return false
	}
	return strings.Trim(s, "0-. ") != ""
}
