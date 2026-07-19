//go:build windows

package devicepolicy

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// enforcePOSIXMetadata is false on Windows: the file is governed by inherited
// NTFS ACLs, so the writer neither asserts a POSIX mode nor chowns.
const enforcePOSIXMetadata = false

// nonblockOpenFlag is a no-op on Windows — there is no O_NONBLOCK and no
// npm-relevant FIFO to guard against.
func nonblockOpenFlag() int { return 0 }

// chownHandle is a no-op on Windows (ACL ownership model).
func chownHandle(f *os.File, uid, gid int) error { return nil }

func newOwnerReader() ownerReader { return windowsOwnerReader{} }

// windowsOwnerReader reports enforced=false so the writer skips every ownership
// decision on this platform.
type windowsOwnerReader struct{}

func (windowsOwnerReader) ownerUIDGID(f *os.File) (uid, gid uint32, enforced bool, err error) {
	return 0, 0, false, nil
}

const (
	wtsCurrentServerHandle = 0
	wtsInfoUserName        = 5 // WTSUserName
	wtsInfoDomainName      = 7 // WTSDomainName
	sidLocalSystem         = "S-1-5-18"
)

// WTSQuerySessionInformationW is not exposed by golang.org/x/sys/windows, so it
// is bound directly. wtsapi32.dll is always present on Windows.
var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
)

// interactiveSessionOK reports whether this process is the interactive user of
// an active session — the only state in which writing ~/.npmrc lands in the
// developer's own profile. It rejects LocalSystem, session 0 (services), any
// non-active (disconnected) session, and alternate-credential (runas) processes
// whose token user differs from the session's logged-on user. A standard
// elevated admin inside their own active session passes both checks. A true
// cross-session resolver (WTSQueryUserToken impersonation) needs SeTcbPrivilege
// and is deliberately out of scope here.
func interactiveSessionOK() bool {
	tokenSID, err := currentTokenUserSID()
	if err != nil {
		return false
	}
	if tokenSID.String() == sidLocalSystem {
		return false
	}

	var sessionID uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID); err != nil {
		return false
	}
	if sessionID == 0 {
		// Session 0 is the non-interactive services session; never a developer.
		return false
	}

	state, ok := sessionConnectState(sessionID)
	if !ok || state != uint32(windows.WTSActive) {
		return false
	}

	sessionSID, err := sessionUserSID(sessionID)
	if err != nil {
		return false
	}
	// Session membership alone cannot catch runas: the alternate-credential
	// process lives in the caller's session but carries a different user SID.
	return tokenSID.String() == sessionSID.String()
}

func currentTokenUserSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid, nil
}

// sessionConnectState returns the WTS connect state for a session id.
func sessionConnectState(sessionID uint32) (uint32, bool) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return 0, false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	for _, s := range unsafe.Slice(info, count) {
		if s.SessionID == sessionID {
			return s.State, true
		}
	}
	return 0, false
}

// sessionUserSID resolves the SID of the user logged on to a session via its
// WTS user/domain name. Unlike WTSQueryUserToken this needs no SeTcbPrivilege,
// so it works from a normal elevated admin process.
func sessionUserSID(sessionID uint32) (*windows.SID, error) {
	name, err := wtsQueryString(sessionID, wtsInfoUserName)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, errors.New("npmrc: session has no logged-on user")
	}
	domain, _ := wtsQueryString(sessionID, wtsInfoDomainName)
	account := name
	if domain != "" {
		account = domain + `\` + name
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return nil, err
	}
	return sid, nil
}

// wtsQueryString calls WTSQuerySessionInformationW for a string info class and
// returns the decoded value, freeing the buffer the API allocates.
func wtsQueryString(sessionID uint32, infoClass uint32) (string, error) {
	var buf *uint16
	var bytesReturned uint32
	r1, _, callErr := procWTSQuerySessionInformationW.Call(
		uintptr(wtsCurrentServerHandle),
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r1 == 0 {
		return "", callErr
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf), nil
}
