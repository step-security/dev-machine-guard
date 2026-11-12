//go:build windows

package updatestate

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RunOwner names this process's run file: the token's default owner, the
// account CREATOR OWNER gives full control of what it creates. That is the
// user's SID, or BUILTIN\Administrators for an elevated admin, so an
// elevated run never takes the file the user's limited runs write. "" when
// the token can't be read.
func RunOwner() string {
	tok := windows.GetCurrentThreadEffectiveToken() // the process token unless impersonating
	var n uint32
	if err := windows.GetTokenInformation(tok, windows.TokenOwner, nil, 0, &n); !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return ""
	}
	buf := make([]byte, n)
	if windows.GetTokenInformation(tok, windows.TokenOwner, &buf[0], n, &n) != nil {
		return ""
	}
	owner := (*struct{ Owner *windows.SID })(unsafe.Pointer(&buf[0])).Owner // TOKEN_OWNER
	return owner.String()
}
