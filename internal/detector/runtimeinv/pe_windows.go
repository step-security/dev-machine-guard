//go:build windows

package runtimeinv

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() { peVersion = readPEVersion }

// readPEVersion returns the ProductVersion string from the version resource,
// falling back to the numeric VS_FIXEDFILEINFO product version.
func readPEVersion(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return ""
	}

	// First translation entry -> \StringFileInfo\<lang><codepage>\ProductVersion.
	var trans *[2]uint16
	var n uint32
	if windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&trans), &n) == nil && n >= 4 {
		sub := fmt.Sprintf(`\StringFileInfo\%04x%04x\ProductVersion`, trans[0], trans[1])
		var str *uint16
		var l uint32
		if windows.VerQueryValue(unsafe.Pointer(&buf[0]), sub, unsafe.Pointer(&str), &l) == nil && l > 0 {
			if v := windows.UTF16PtrToString(str); v != "" {
				return v
			}
		}
	}

	var fixed *windows.VS_FIXEDFILEINFO
	if windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&fixed), &n) != nil || fixed == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		fixed.ProductVersionMS>>16, fixed.ProductVersionMS&0xffff,
		fixed.ProductVersionLS>>16, fixed.ProductVersionLS&0xffff)
}
