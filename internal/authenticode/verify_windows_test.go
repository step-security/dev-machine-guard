//go:build windows

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
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// testCert is a self-signed code-signing cert in LocalMachine\My, trusted
// through LocalMachine\Root and TrustedPublisher for the test's duration.
type testCert struct {
	thumb   string
	subject string
}

// psCommand runs Windows PowerShell without the caller's PSModulePath: on
// GitHub runners it points at PowerShell 7 modules, which hides the Cert:
// drive from Windows PowerShell 5.1.
func psCommand(script string) *exec.Cmd {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "PSMODULEPATH=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	return cmd
}

func powershell(t *testing.T, script string) string {
	t.Helper()
	out, err := psCommand("$ErrorActionPreference='Stop'; " + script).CombinedOutput()
	if err != nil {
		t.Fatalf("powershell: %v\n%s\nscript: %s", err, out, script)
	}
	return strings.TrimSpace(string(out))
}

func newTestCert(t *testing.T, cn string) *testCert {
	t.Helper()
	subject := fmt.Sprintf("CN=%s %d", cn, time.Now().UnixNano())
	thumb := powershell(t, fmt.Sprintf(`
$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject '%s' -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddDays(2)
$f = Join-Path $env:TEMP ($c.Thumbprint + '.cer')
Export-Certificate -Cert $c -FilePath $f | Out-Null
Import-Certificate -FilePath $f -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $f -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Remove-Item $f
$c.Thumbprint`, subject))
	t.Cleanup(func() {
		for _, store := range []string{"My", "Root", "TrustedPublisher"} {
			_ = psCommand(fmt.Sprintf(`Remove-Item -Force -ErrorAction SilentlyContinue Cert:\LocalMachine\%s\%s`, store, thumb)).Run()
		}
	})
	return &testCert{thumb: thumb, subject: subject}
}

// sign signs path; tsa empty means no timestamp. It reports false when the
// timestamp server could not be reached.
func (c *testCert) sign(t *testing.T, path, tsa string) bool {
	t.Helper()
	ts := ""
	if tsa != "" {
		ts = "-TimestampServer '" + tsa + "'"
	}
	out, err := psCommand(fmt.Sprintf(`
$c = Get-Item Cert:\LocalMachine\My\%s
$r = Set-AuthenticodeSignature -FilePath '%s' -Certificate $c -HashAlgorithm SHA256 %s
$r.Status`, c.thumb, path, ts)).CombinedOutput()
	status := strings.TrimSpace(string(out))
	if err != nil || status != "Valid" {
		if tsa != "" {
			t.Logf("timestamped signing unavailable (%v): %s", err, status)
			return false
		}
		t.Fatalf("signing %s: %v: %s", path, err, status)
	}
	return true
}

func copyExe(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	p := filepath.Join(t.TempDir(), "candidate.exe")
	out, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token to trust a test certificate machine-wide")
	}
}

func TestVerifyUnsignedWindows(t *testing.T) {
	if _, err := Verify(copyExe(t)); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned: %v, want ErrUnsigned", err)
	}
	// The test binary is unsigned, so without a pin no update is allowed.
	if testPinnedSubject() == "" {
		self, _ := os.Executable()
		if err := samePublisher(copyExe(t), self, func(string) (*Signature, error) { return &Signature{Subject: "CN=x"}, nil }, ownSubject, ""); !errors.Is(err, ErrNoPublisher) {
			t.Fatalf("unsigned self: %v, want ErrNoPublisher", err)
		}
	}
}

func TestVerifySignedWindows(t *testing.T) {
	requireElevated(t)
	a := newTestCert(t, "DMG Test Publisher A")

	noTS := copyExe(t)
	a.sign(t, noTS, "")
	if _, err := Verify(noTS); !errors.Is(err, ErrNotTimestamped) {
		t.Fatalf("untimestamped: %v, want ErrNotTimestamped", err)
	}
	if sig, err := Inspect(noTS); err != nil || sig.Subject != a.subject {
		t.Fatalf("Inspect = %+v, %v; want subject %q", sig, err, a.subject)
	}

	// A flipped byte after signing breaks the digest.
	tampered := copyExe(t)
	a.sign(t, tampered, "")
	f, err := os.OpenFile(tampered, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	_, _ = f.ReadAt(b, 4096)
	b[0] ^= 0xff
	_, _ = f.WriteAt(b, 4096)
	_ = f.Close()
	if err := winVerifyTrust(tampered); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("tampered: %v, want ErrUntrusted", err)
	}

	const tsa = "http://timestamp.digicert.com"
	good := copyExe(t)
	if !a.sign(t, good, tsa) {
		t.Skip("timestamp server unreachable; timestamped cases not run")
	}
	sig, err := Verify(good)
	if err != nil {
		t.Fatalf("timestamped signed: %v", err)
	}
	if sig.Subject != a.subject || !sig.Timestamped {
		t.Fatalf("sig = %+v", sig)
	}
	self := copyExe(t)
	a.sign(t, self, tsa)
	if err := SamePublisher(good, self); err != nil && testPinnedSubject() == "" {
		t.Fatalf("same publisher: %v", err)
	}

	bCert := newTestCert(t, "DMG Test Publisher B")
	wrong := copyExe(t)
	if !bCert.sign(t, wrong, tsa) {
		t.Skip("timestamp server unreachable")
	}
	if err := SamePublisher(wrong, self); !errors.Is(err, ErrPublisherMismatch) {
		t.Fatalf("wrong publisher: %v, want ErrPublisherMismatch", err)
	}
	if err := samePublisher(good, copyExe(t), Verify, ownSubject, a.subject); err != nil {
		t.Fatalf("pinned subject: %v", err)
	}
}

// R-C1-2: for GENERIC_VERIFY_V2, revocation is only off with
// WTD_REVOCATION_CHECK_NONE in the provider flags.
func TestTrustDataDisablesRevocation(t *testing.T) {
	file := &windows.WinTrustFileInfo{}
	d := newTrustData(file)
	if d.ProvFlags&windows.WTD_REVOCATION_CHECK_NONE == 0 || d.RevocationChecks != windows.WTD_REVOKE_NONE {
		t.Fatalf("ProvFlags=%#x RevocationChecks=%d", d.ProvFlags, d.RevocationChecks)
	}
	if d.UIChoice != windows.WTD_UI_NONE || d.StateAction != windows.WTD_STATEACTION_VERIFY {
		t.Fatalf("data = %+v", d)
	}
}

// rewriteBag inserts extra into the PKCS#7 certificate bag of a signed PE
// (before or after the existing certs). The bag is outside the Authenticode
// digest, so the signature itself still verifies.
func rewriteBag(t *testing.T, path string, extra *x509.Certificate, before bool) *x509.Certificate {
	t.Helper()
	img, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lfanew := binary.LittleEndian.Uint32(img[0x3c:])
	opt := int(lfanew) + 24
	ddOff := opt + 96
	if binary.LittleEndian.Uint16(img[opt:]) == 0x20b {
		ddOff = opt + 112
	}
	entry := ddOff + imageDirectoryEntrySec*8
	off := binary.LittleEndian.Uint32(img[entry:])
	blob, err := peSignature(path)
	if err != nil {
		t.Fatal(err)
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(blob, &ci); err != nil {
		t.Fatal(err)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var si signerInfo
	if _, err := asn1.Unmarshal(sd.SignerInfos.Bytes, &si); err != nil {
		t.Fatal(err)
	}
	leaf := findSigner(certs, si.SID)[0]
	if extra == nil {
		return leaf
	}
	bag := sd.Certificates.Bytes
	if before {
		bag = append(append([]byte{}, extra.Raw...), bag...)
	} else {
		bag = append(append([]byte{}, bag...), extra.Raw...)
	}
	sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: bag}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER})
	der, err := asn1.Marshal(contentInfo{ContentType: oidSignedData, Content: asn1.RawValue{FullBytes: inner}})
	if err != nil {
		t.Fatal(err)
	}
	wc := make([]byte, 8+len(der))
	binary.LittleEndian.PutUint32(wc[0:], uint32(len(wc)))
	binary.LittleEndian.PutUint16(wc[4:], 0x0200)
	binary.LittleEndian.PutUint16(wc[6:], winCertTypePKCSSigned)
	copy(wc[8:], der)
	for len(wc)%8 != 0 {
		wc = append(wc, 0)
	}
	out := append(img[:off:off], wc...)
	binary.LittleEndian.PutUint32(out[entry+4:], uint32(len(wc)))
	if err := os.WriteFile(path, out, 0o755); err != nil {
		t.Fatal(err)
	}
	return leaf
}

func makeLookalikeWin(t *testing.T, leaf *x509.Certificate, cn string) *x509.Certificate {
	t.Helper()
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{RawSubject: leaf.RawIssuer, PublicKey: &other.PublicKey, SerialNumber: big.NewInt(1)}
	tmpl := &x509.Certificate{SerialNumber: leaf.SerialNumber, Subject: pkix.Name{CommonName: cn},
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, leaf.PublicKey, other)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// R-C1-1: a timestamped binary signed by publisher B whose bag also carries
// a forged look-alike of B's cert with A's subject must fail a pin on A's
// subject, wherever the forgery sits; and the subject Verify reports for a
// clean file comes from the chain WinVerifyTrust validated.
func TestForgedBagFailsPublisherPin(t *testing.T) {
	requireElevated(t)
	const tsa = "http://timestamp.digicert.com"
	a := newTestCert(t, "DMG Test Publisher A")
	b := newTestCert(t, "DMG Test Publisher B")
	clean := copyExe(t)
	if !b.sign(t, clean, tsa) {
		t.Skip("timestamp server unreachable")
	}
	ts, err := verifyTrusted(clean)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("validated subject %q, countersigners %d", ts.subject, ts.counterSigners)
	if ts.subject != b.subject {
		t.Fatalf("provider subject %q, want %q", ts.subject, b.subject)
	}
	for _, before := range []bool{true, false} {
		f := copyExe(t)
		b.sign(t, f, tsa)
		leaf := rewriteBag(t, f, nil, false)
		rewriteBag(t, f, makeLookalikeWin(t, leaf, strings.TrimPrefix(a.subject, "CN=")), before)
		if tsF, err := verifyTrusted(f); err == nil && tsF.subject != b.subject {
			t.Fatalf("before=%v: WinVerifyTrust validated %q, the forged subject", before, tsF.subject)
		}
		if err := samePublisher(f, "", Verify, ownSubject, a.subject); err == nil {
			t.Fatalf("before=%v: forged bag passed the publisher pin", before)
		} else {
			t.Logf("before=%v: refused: %v", before, err)
		}
	}
}

// FR1-8: seed adoption follows the publisher rule; only an unsigned (dev)
// running binary, which has nothing to compare, accepts any seed.
func TestSameSeedPublisher(t *testing.T) {
	if testPinnedSubject() != "" {
		t.Skip("pinned subject build")
	}
	unsignedSelf, unsignedSeed := copyExe(t), copyExe(t)
	if err := SameSeedPublisher(unsignedSeed, unsignedSelf); err != nil {
		t.Fatalf("unsigned self: %v", err)
	}
	requireElevated(t)
	a := newTestCert(t, "DMG Test Publisher A")
	signedSelf := copyExe(t)
	a.sign(t, signedSelf, "")
	if err := SameSeedPublisher(unsignedSeed, signedSelf); err == nil {
		t.Fatal("signed self accepted an unsigned seed")
	}
}
