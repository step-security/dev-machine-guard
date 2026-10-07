//go:build windows

package secureuserfile

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"unsafe"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"golang.org/x/sys/windows"
)

const enforcePOSIXMetadata = false

// FILE_ALL_ACCESS from WinNT.h; x/sys/windows does not export it.
const windowsFileAllAccess windows.ACCESS_MASK = 0x001F01FF

func nonblockOpenFlag() int { return 0 }

func secureUserIDs(u *user.User) (int, int, error) {
	if u.Uid == "" {
		return 0, 0, fmt.Errorf("secure user file: target user %q has no SID", u.Username)
	}
	if _, err := windows.StringToSid(u.Uid); err != nil {
		return 0, 0, fmt.Errorf("secure user file: target user %q has invalid SID: %w", u.Username, err)
	}
	return 0, 0, nil
}

func newOwnerReader() ownerReader { return windowsOwnerReader{} }

type windowsOwnerReader struct{}

func (windowsOwnerReader) ownerUIDGID(*os.File) (uint32, uint32, bool, error) {
	return 0, 0, false, nil
}

func applySecureMetadata(h *Home, f *os.File, _ os.FileMode, directory bool) error {
	return setSecureDACL(h, f, directory, true)
}

// repairSecureMetadata rewrites only the DACL of an object whose owner is
// already verified. The owner's implicit READ_CONTROL|WRITE_DAC suffices, so a
// legacy object granting the user only Modify (no WRITE_OWNER) stays repairable.
func repairSecureMetadata(h *Home, f *os.File, _ os.FileMode, directory bool) error {
	return setSecureDACL(h, f, directory, false)
}

func setSecureDACL(h *Home, f *os.File, directory, assignOwner bool) error {
	targetSID, err := windows.StringToSid(h.targetUser.Uid)
	if err != nil {
		return fmt.Errorf("secure user file: target SID: %w", err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("secure user file: SYSTEM SID: %w", err)
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{
		secureExplicitAccess(targetSID, windowsFileAllAccess, inheritance, windows.TRUSTEE_IS_USER),
		secureExplicitAccess(systemSID, windowsFileAllAccess, inheritance, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("secure user file: build ACL: %w", err)
	}
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC)
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var owner *windows.SID
	if assignOwner {
		access |= windows.WRITE_OWNER
		info |= windows.OWNER_SECURITY_INFORMATION
		owner = targetSID
	}
	handle, err := reopenSecurityHandle(f, access)
	if err != nil {
		return fmt.Errorf("secure user file: reopen for metadata: %w", err)
	}
	defer windows.CloseHandle(handle)
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		info,
		owner,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("secure user file: set metadata: %w", err)
	}
	return nil
}

func secureExplicitAccess(sid *windows.SID, permissions windows.ACCESS_MASK, inheritance uint32, trusteeType windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func (windowsOwnerReader) secure(f *os.File, h *Home, _ os.FileMode) (bool, error) {
	handle, err := reopenSecurityHandle(f, windows.READ_CONTROL)
	if err != nil {
		return false, fmt.Errorf("secure user file: reopen for ACL check: %w", err)
	}
	defer windows.CloseHandle(handle)
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("secure user file: read ACL: %w", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return false, fmt.Errorf("secure user file: read ACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return false, fmt.Errorf("secure user file: parse ACL: %w", err)
	}
	if acl == nil || acl.AceCount != 2 {
		return false, nil
	}
	targetSID, err := windows.StringToSid(h.targetUser.Uid)
	if err != nil {
		return false, fmt.Errorf("secure user file: target SID: %w", err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, fmt.Errorf("secure user file: SYSTEM SID: %w", err)
	}
	seenTarget, seenSystem := false, false
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return false, fmt.Errorf("secure user file: read ACL entry: %w", err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return false, nil
		}
		if ace.Mask != windowsFileAllAccess {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(targetSID):
			seenTarget = true
		case sid.Equals(systemSID):
			seenSystem = true
		default:
			return false, nil
		}
	}
	return seenTarget && seenSystem, nil
}

func checkSecurePlatformOwner(h *Home, f *os.File) error {
	handle, err := reopenSecurityHandle(f, windows.READ_CONTROL)
	if err != nil {
		return fmt.Errorf("secure user file: reopen for owner check: %w", err)
	}
	defer windows.CloseHandle(handle)
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("secure user file: read owner: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("secure user file: parse owner: %w", err)
	}
	target, err := windows.StringToSid(h.targetUser.Uid)
	if err != nil {
		return fmt.Errorf("secure user file: target SID: %w", err)
	}
	if owner == nil || !owner.Equals(target) {
		return fmt.Errorf("secure user file: wrong owner: %w", ErrTargetUnusable)
	}
	return nil
}

var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
)

func reopenSecurityHandle(f *os.File, access uint32) (windows.Handle, error) {
	path, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, err := windows.CreateFile(
		path,
		access|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	if err := requireSameFileIdentity(windows.Handle(f.Fd()), handle); err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	return handle, nil
}

func requireSameFileIdentity(original, reopened windows.Handle) error {
	var originalInfo, reopenedInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(original, &originalInfo); err != nil {
		return fmt.Errorf("inspect original file identity: %w", err)
	}
	if err := windows.GetFileInformationByHandle(reopened, &reopenedInfo); err != nil {
		return fmt.Errorf("inspect reopened file identity: %w", err)
	}
	if originalInfo.VolumeSerialNumber != reopenedInfo.VolumeSerialNumber ||
		originalInfo.FileIndexHigh != reopenedInfo.FileIndexHigh ||
		originalInfo.FileIndexLow != reopenedInfo.FileIndexLow {
		return fmt.Errorf("reopened file identity changed: %w", ErrTargetUnusable)
	}
	return nil
}

const (
	wtsCurrentServerHandle = 0
	wtsInfoUserName        = 5
	wtsInfoDomainName      = 7
	sidLocalSystem         = "S-1-5-18"
)

func interactiveSessionOK(exec executor.Executor) bool {
	if exec.GOOS() != model.PlatformWindows {
		return true
	}
	tokenSID, err := currentTokenUserSID()
	if err != nil || tokenSID.String() == sidLocalSystem {
		return false
	}
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID); err != nil || sessionID == 0 {
		return false
	}
	state, ok := sessionConnectState(sessionID)
	if !ok || state != uint32(windows.WTSActive) {
		return false
	}
	sessionSID, err := sessionUserSID(sessionID)
	return err == nil && tokenSID.String() == sessionSID.String()
}

func currentTokenUserSID() (*windows.SID, error) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tokenUser.User.Sid, nil
}

func sessionConnectState(sessionID uint32) (uint32, bool) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return 0, false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	for _, session := range unsafe.Slice(info, count) {
		if session.SessionID == sessionID {
			return session.State, true
		}
	}
	return 0, false
}

func sessionUserSID(sessionID uint32) (*windows.SID, error) {
	name, err := wtsQueryString(sessionID, wtsInfoUserName)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, errors.New("secure user file: session has no logged-on user")
	}
	domain, _ := wtsQueryString(sessionID, wtsInfoDomainName)
	account := name
	if domain != "" {
		account = domain + `\` + name
	}
	sid, _, _, err := windows.LookupSID("", account)
	return sid, err
}

func wtsQueryString(sessionID uint32, infoClass uint32) (string, error) {
	var buffer *uint16
	var bytesReturned uint32
	result, _, callErr := procWTSQuerySessionInformationW.Call(
		uintptr(wtsCurrentServerHandle),
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if result == 0 {
		return "", callErr
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buffer)))
	return windows.UTF16PtrToString(buffer), nil
}
