package selfupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"strings"
	"testing"
)

// testSigner produces SSHSIG signatures like `ssh-keygen -Y sign -n
// stepsecurity-mdm-checksum` with a throwaway key.
type testSigner struct {
	priv   ed25519.PrivateKey
	pubB64 string
}

func newTestSigner(t testing.TB) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := appendSSHString(appendSSHString(nil, []byte(keyTypeEd)), pub)
	return &testSigner{priv: priv, pubB64: base64.StdEncoding.EncodeToString(blob)}
}

// armored signs msg in namespace ns.
func (s *testSigner) armored(msg, ns string) string {
	pubBlob, _ := base64.StdEncoding.DecodeString(s.pubB64)
	h := sha512.Sum512([]byte(msg))
	signed := []byte(sshSigMagic)
	signed = appendSSHString(signed, []byte(ns))
	signed = appendSSHString(signed, nil)
	signed = appendSSHString(signed, []byte("sha512"))
	signed = appendSSHString(signed, h[:])
	sig := ed25519.Sign(s.priv, signed)
	sigBlob := appendSSHString(appendSSHString(nil, []byte(keyTypeEd)), sig)

	blob := []byte(sshSigMagic)
	blob = append(blob, 0, 0, 0, 1)
	blob = appendSSHString(blob, pubBlob)
	blob = appendSSHString(blob, []byte(ns))
	blob = appendSSHString(blob, nil)
	blob = appendSSHString(blob, []byte("sha512"))
	blob = appendSSHString(blob, sigBlob)
	b64 := base64.StdEncoding.EncodeToString(blob)
	var lines []string
	for len(b64) > 70 {
		lines = append(lines, b64[:70])
		b64 = b64[70:]
	}
	lines = append(lines, b64)
	return sigArmorBegin + "\n" + strings.Join(lines, "\n") + "\n" + sigArmorEnd + "\n"
}

// transport wraps the armored block the way latest-binary does.
func (s *testSigner) transport(checksum string) string {
	return base64.StdEncoding.EncodeToString([]byte(s.armored(checksum, signatureNamespace)))
}

func TestTestSignerRoundTrip(t *testing.T) {
	s := newTestSigner(t)
	if err := verifySSHSig(s.armored("abc", signatureNamespace), []byte("abc"), s.pubB64, signatureNamespace); err != nil {
		t.Fatalf("own signature rejected: %v", err)
	}
}
