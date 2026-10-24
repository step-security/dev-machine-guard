package authenticode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeCert(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"StepSecurity Test"}},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func rawSet(t *testing.T, elems ...[]byte) asn1.RawValue {
	t.Helper()
	var b []byte
	for _, e := range elems {
		b = append(b, e...)
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: b}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// buildSignedData returns a PKCS#7 ContentInfo whose first signer is signer
// (by issuer+serial), embedding certs, optionally with a timestamp attribute.
func buildSignedData(t *testing.T, signer *x509.Certificate, certs []*x509.Certificate, tsOID asn1.ObjectIdentifier) []byte {
	t.Helper()
	sid := mustMarshal(t, issuerAndSerial{Issuer: asn1.RawValue{FullBytes: signer.RawIssuer}, Serial: signer.SerialNumber})
	algo := mustMarshal(t, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}})
	si := signerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    asn1.RawValue{FullBytes: algo},
		SignatureAlgorithm: asn1.RawValue{FullBytes: algo},
		Signature:          []byte{1, 2, 3},
	}
	if tsOID != nil {
		attr := mustMarshal(t, attribute{Type: tsOID, Values: rawSet(t, mustMarshal(t, 1))})
		si.UnsignedAttrs = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: attr}
	}
	var certBytes []byte
	for _, c := range certs {
		certBytes = append(certBytes, c.Raw...)
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: rawSet(t, algo),
		ContentInfo:      asn1.RawValue{FullBytes: mustMarshal(t, contentInfo{ContentType: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}})},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certBytes},
		SignerInfos:      rawSet(t, mustMarshal(t, si)),
	}
	sdDER := mustMarshal(t, sd)
	return mustMarshal(t, contentInfo{ContentType: oidSignedData, Content: asn1.RawValue{FullBytes: wrapExplicit0(sdDER)}})
}

func wrapExplicit0(inner []byte) []byte {
	b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
	return b
}

// writePE writes a minimal PE32+ image, with sig (if non-nil) as its
// WIN_CERTIFICATE in the security directory.
func writePE(t *testing.T, sig []byte) string {
	t.Helper()
	const lfanew = 0x40
	img := make([]byte, lfanew+4+20+240)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3c:], lfanew)
	copy(img[lfanew:], "PE\x00\x00")
	coff := img[lfanew+4:]
	binary.LittleEndian.PutUint16(coff[0:], 0x8664) // Machine
	binary.LittleEndian.PutUint16(coff[16:], 240)   // SizeOfOptionalHeader
	opt := img[lfanew+24:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20b) // PE32+
	binary.LittleEndian.PutUint32(opt[108:], 16)  // NumberOfRvaAndSizes
	if sig != nil {
		off := len(img)
		wc := make([]byte, 8+len(sig))
		binary.LittleEndian.PutUint32(wc[0:], uint32(len(wc)))
		binary.LittleEndian.PutUint16(wc[4:], 0x0200)
		binary.LittleEndian.PutUint16(wc[6:], winCertTypePKCSSigned)
		copy(wc[8:], sig)
		for len(wc)%8 != 0 {
			wc = append(wc, 0)
		}
		dd := opt[112+imageDirectoryEntrySec*8:]
		binary.LittleEndian.PutUint32(dd[0:], uint32(off))
		binary.LittleEndian.PutUint32(dd[4:], uint32(len(wc)))
		img = append(img, wc...)
	}
	p := filepath.Join(t.TempDir(), "x.exe")
	if err := os.WriteFile(p, img, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInspectSubjectAndTimestamp(t *testing.T) {
	leaf := makeCert(t, "StepSecurity Inc", 7)
	other := makeCert(t, "Intermediate", 8)
	for _, tc := range []struct {
		name string
		oid  asn1.ObjectIdentifier
		ts   bool
	}{
		{"rfc3161", oidRFC3161CounterSign, true},
		{"legacy countersignature", oidCounterSignature, true},
		{"no timestamp", nil, false},
		{"unrelated unsigned attr", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writePE(t, buildSignedData(t, leaf, []*x509.Certificate{other, leaf}, tc.oid))
			sig, err := Inspect(p)
			if err != nil {
				t.Fatal(err)
			}
			if sig.Subject != leaf.Subject.String() || sig.Timestamped != tc.ts {
				t.Fatalf("sig = %+v, want subject %q ts=%v", sig, leaf.Subject.String(), tc.ts)
			}
		})
	}
}

func TestInspectUnsignedAndMalformed(t *testing.T) {
	if _, err := Inspect(writePE(t, nil)); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned PE: %v", err)
	}
	if _, err := Inspect(writePE(t, []byte("garbage"))); err == nil {
		t.Fatal("garbage signature accepted")
	}
	leaf := makeCert(t, "Leaf", 1)
	notEmbedded := makeCert(t, "Other", 2)
	if _, err := Inspect(writePE(t, buildSignedData(t, leaf, []*x509.Certificate{notEmbedded}, nil))); err == nil {
		t.Fatal("signer missing from certificates accepted")
	}
	txt := filepath.Join(t.TempDir(), "a.txt")
	_ = os.WriteFile(txt, []byte("not a PE"), 0o644)
	if _, err := Inspect(txt); err == nil {
		t.Fatal("non-PE accepted")
	}
}

func TestSamePublisher(t *testing.T) {
	sig := func(subject string, err error) func(string) (*Signature, error) {
		return func(string) (*Signature, error) {
			if err != nil {
				return nil, err
			}
			return &Signature{Subject: subject, Timestamped: true}, nil
		}
	}
	own := func(subject string, err error) func(string) (string, error) {
		return func(string) (string, error) { return subject, err }
	}
	a := "CN=StepSecurity Inc"
	if err := samePublisher("c", "s", sig(a, nil), own(a, nil), ""); err != nil {
		t.Fatalf("same subject: %v", err)
	}
	if err := samePublisher("c", "s", sig("CN=Evil", nil), own(a, nil), ""); !errors.Is(err, ErrPublisherMismatch) {
		t.Fatalf("other subject: %v", err)
	}
	if err := samePublisher("c", "s", sig(a, nil), own("", ErrUnsigned), ""); !errors.Is(err, ErrNoPublisher) {
		t.Fatalf("unsigned self: %v", err)
	}
	if err := samePublisher("c", "s", sig(a, nil), own("", ErrUnsigned), a); err != nil {
		t.Fatalf("unsigned self with pin: %v", err)
	}
	if err := samePublisher("c", "s", sig(a, nil), own(a, nil), "CN=Pinned"); !errors.Is(err, ErrPublisherMismatch) {
		t.Fatalf("pin must win over own subject: %v", err)
	}
	if err := samePublisher("c", "s", sig("", ErrNotTimestamped), own(a, nil), ""); !errors.Is(err, ErrNotTimestamped) {
		t.Fatalf("candidate error not propagated: %v", err)
	}
}

// makeLookalike is a certificate with leaf's issuer, serial and public key
// but another subject, signed by an unrelated key (so it never chains).
func makeLookalike(t *testing.T, leaf *x509.Certificate, cn string) *x509.Certificate {
	t.Helper()
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{RawSubject: leaf.RawIssuer, PublicKey: &other.PublicKey, SerialNumber: big.NewInt(1)}
	tmpl := &x509.Certificate{
		SerialNumber: leaf.SerialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    leaf.NotBefore, NotAfter: leaf.NotAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, leaf.PublicKey, other)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// R-C1-1 (belt and braces): a bag with a look-alike of the signer, before
// or after the real one, is rejected rather than resolved by bag order.
func TestInspectRejectsAmbiguousSigner(t *testing.T) {
	leaf := makeCert(t, "Evil Corp", 9)
	fake := makeLookalike(t, leaf, "StepSecurity Inc")
	for _, bag := range [][]*x509.Certificate{{fake, leaf}, {leaf, fake}} {
		p := writePE(t, buildSignedData(t, leaf, bag, oidRFC3161CounterSign))
		if sig, err := Inspect(p); !errors.Is(err, ErrAmbiguousSigner) {
			t.Fatalf("bag %s,%s: Inspect = %+v, %v; want ErrAmbiguousSigner", bag[0].Subject, bag[1].Subject, sig, err)
		}
	}
}
