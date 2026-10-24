//go:build windows

package authenticode

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	trustENoSignature    = 0x800B0100 // TRUST_E_NOSIGNATURE
	trustESubjectFormUnk = 0x800B0003 // TRUST_E_SUBJECT_FORM_UNKNOWN
)

// newTrustData builds the WINTRUST_DATA for a file: no UI, no revocation.
// For GENERIC_VERIFY_V2 revocation is off only with
// WTD_REVOCATION_CHECK_NONE in dwProvFlags (fdwRevocationChecks=WTD_REVOKE_NONE
// alone applies to HTTPSPROV_ACTION), so both are set.
func newTrustData(file *windows.WinTrustFileInfo) *windows.WinTrustData {
	data := &windows.WinTrustData{
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_NONE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(file),
	}
	data.Size = uint32(unsafe.Sizeof(*data))
	return data
}

var (
	modwintrust                        = windows.NewLazySystemDLL("wintrust.dll")
	procWTHelperProvDataFromStateData  = modwintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain = modwintrust.NewProc("WTHelperGetProvSignerFromChain")
)

// cryptProviderCert is the head of CRYPT_PROVIDER_CERT.
type cryptProviderCert struct {
	_     uint32 // cbStruct
	pCert *windows.CertContext
}

// cryptProviderSgnr is CRYPT_PROVIDER_SGNR (wintrust.h).
type cryptProviderSgnr struct {
	_                uint32           // cbStruct
	_                windows.Filetime // sftVerifyAsOf
	csCertChain      uint32
	pasCertChain     *cryptProviderCert
	_                uint32         // dwSignerType
	_                unsafe.Pointer // psSigner
	_                uint32         // dwError
	csCounterSigners uint32
	_                unsafe.Pointer // pasCounterSigners
	_                unsafe.Pointer // pChainContext
}

// verifyTrusted runs WINTRUST_ACTION_GENERIC_VERIFY_V2 on path (no UI, no
// revocation) and, while the state data is still open, reads the primary
// signer's validated chain: the leaf certificate's subject and the
// countersigner count. Chain building may still fetch missing roots through
// Windows root auto-update.
func verifyTrusted(path string) (*trustedSigner, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	file := &windows.WinTrustFileInfo{FilePath: p}
	file.Size = uint32(unsafe.Sizeof(*file))
	data := newTrustData(file)
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	defer func() {
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	}()
	if verr != nil {
		var errno windows.Errno
		if errors.As(verr, &errno) && (uint32(errno) == trustENoSignature || uint32(errno) == trustESubjectFormUnk) {
			return nil, fmt.Errorf("%w: %s", ErrUnsigned, path)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrUntrusted, path, verr)
	}
	return validatedSigner(data.StateData, path)
}

func validatedSigner(state windows.Handle, path string) (*trustedSigner, error) {
	if err := procWTHelperProvDataFromStateData.Find(); err != nil {
		return nil, err
	}
	provData, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if provData == 0 {
		return nil, fmt.Errorf("%w: %s: no provider data", ErrUntrusted, path)
	}
	sg, _, _ := procWTHelperGetProvSignerFromChain.Call(provData, 0, 0, 0)
	if sg == 0 {
		return nil, fmt.Errorf("%w: %s: no signer in provider data", ErrUntrusted, path)
	}
	// Pointer returned by wintrust, valid until WTD_STATEACTION_CLOSE.
	sgnr := *(**cryptProviderSgnr)(unsafe.Pointer(&sg))
	if sgnr.csCertChain == 0 || sgnr.pasCertChain == nil || sgnr.pasCertChain.pCert == nil {
		return nil, fmt.Errorf("%w: %s: signer has no certificate chain", ErrUntrusted, path)
	}
	leaf := sgnr.pasCertChain.pCert
	der := bytes.Clone(unsafe.Slice(leaf.EncodedCert, leaf.Length))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: leaf certificate: %w", ErrUntrusted, path, err)
	}
	return &trustedSigner{subject: cert.Subject.String(), counterSigners: int(sgnr.csCounterSigners)}, nil
}

// winVerifyTrust reports only whether path verifies.
func winVerifyTrust(path string) error {
	_, err := verifyTrusted(path)
	return err
}
