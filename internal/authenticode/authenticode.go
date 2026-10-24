// Package authenticode checks Windows code signatures for the self-updater:
// the candidate must carry a valid, timestamped Authenticode signature whose
// leaf signer subject equals the running updater's own signer subject, so
// no publisher is hard-coded and a Trusted Signing certificate rotation
// (same subject, new key) keeps working.
//
// Trust (chain, digest) AND the signer subject come from WinVerifyTrust: the
// subject is read from the leaf of the chain it validated (provider data),
// never from the PE's certificate bag, which lies outside the signed digest
// and can carry look-alike certificates. The bag is still parsed in Go to
// reject an ambiguous signer (two certs with the signer's issuer+serial) and
// to recognise an RFC 3161 timestamp WinVerifyTrust doesn't count.
package authenticode

import (
	"errors"
	"fmt"
)

var (
	// ErrUnsigned means the file has no Authenticode signature.
	ErrUnsigned = errors.New("authenticode: file is not signed")
	// ErrNotTimestamped means the signature has no countersignature
	// timestamp, so it stops validating when the signing cert expires.
	ErrNotTimestamped = errors.New("authenticode: signature is not timestamped")
	// ErrUntrusted means WinVerifyTrust rejected the signature.
	ErrUntrusted = errors.New("authenticode: signature not trusted")
	// ErrPublisherMismatch means the candidate's signer differs from ours.
	ErrPublisherMismatch = errors.New("authenticode: publisher differs from the running updater")
	// ErrNoPublisher means the running updater has no signer to compare
	// against (an unsigned dev build) and no test pin is configured.
	ErrNoPublisher = errors.New("authenticode: running updater is unsigned; refusing updates")
	// ErrAmbiguousSigner means the certificate bag holds more than one
	// certificate matching the signer's issuer+serial (or key id).
	ErrAmbiguousSigner = errors.New("authenticode: signer certificate is ambiguous")
	// ErrUnsupported is returned off Windows, where WinVerifyTrust is absent.
	ErrUnsupported = errors.New("authenticode: verification is only supported on Windows")
)

// Signature describes a file's primary Authenticode signature.
type Signature struct {
	Subject     string // leaf signer subject, RFC 2253 form
	Timestamped bool
}

// trustedSigner is what WinVerifyTrust validated: the leaf subject of the
// primary signer's chain and its countersigner (timestamp) count.
type trustedSigner struct {
	subject        string
	counterSigners int
}

// Verify checks path with WinVerifyTrust (revocation off), takes the
// subject from the validated chain and requires a timestamped signature.
func Verify(path string) (*Signature, error) {
	ts, err := verifyTrusted(path)
	if err != nil {
		return nil, err
	}
	bag, err := Inspect(path)
	if err != nil {
		return nil, err // includes ErrAmbiguousSigner
	}
	// Countersigners are what WinVerifyTrust counted; an RFC 3161 token is
	// only recognised in the bag (its validity is WinVerifyTrust's job).
	timestamped := ts.counterSigners > 0 || bag.Timestamped
	if !timestamped {
		return nil, fmt.Errorf("%w: %s", ErrNotTimestamped, path)
	}
	return &Signature{Subject: ts.subject, Timestamped: true}, nil
}

// ownSubject is the subject of the running updater's own signature, from
// WinVerifyTrust like any candidate (no timestamp requirement).
func ownSubject(self string) (string, error) {
	ts, err := verifyTrusted(self)
	if err != nil {
		return "", err
	}
	return ts.subject, nil
}

// SamePublisher verifies candidate and checks that its leaf subject equals
// the subject of self (the running updater). A selfupdate_testkeys build may
// pin the expected subject instead (DMG_TEST_AUTHENTICODE_SUBJECT). An
// unsigned self with no pin refuses every candidate.
func SamePublisher(candidate, self string) error {
	return samePublisher(candidate, self, Verify, ownSubject, testPinnedSubject())
}

func samePublisher(candidate, self string, verify func(string) (*Signature, error), own func(string) (string, error), pin string) error {
	got, err := verify(candidate)
	if err != nil {
		return err
	}
	want := pin
	if want == "" {
		subject, err := own(self)
		switch {
		case errors.Is(err, ErrUnsigned):
			return ErrNoPublisher
		case err != nil:
			return fmt.Errorf("authenticode: own signature: %w", err)
		}
		want = subject
	}
	if want == "" || got.Subject != want {
		return fmt.Errorf("%w: %q, want %q", ErrPublisherMismatch, got.Subject, want)
	}
	return nil
}

// SameSeedPublisher is the publisher rule for adopting an MSI seed: as
// SamePublisher, except that an unsigned running binary (a dev or CI
// build, which has no publisher to compare) accepts the seed. The seed was
// installed by the MSI into an admin-only directory; its copy is still
// checked against hashes of the source.
func SameSeedPublisher(candidate, self string) error {
	if testPinnedSubject() == "" {
		if _, err := ownSubject(self); errors.Is(err, ErrUnsigned) {
			return nil
		}
	}
	return SamePublisher(candidate, self)
}
