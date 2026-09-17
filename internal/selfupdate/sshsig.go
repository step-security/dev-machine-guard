package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Dep-free SSHSIG verification (the format `ssh-keygen -Y sign` produces;
// see OpenSSH PROTOCOL.sshsig). The loaders verify release checksums by
// shelling out to `ssh-keygen -Y verify`; the binary verifies the same
// signatures natively so the self-update path needs no external tools —
// stdlib crypto/ed25519 plus hand-rolled wire parsing (AGENTS.md:
// stdlib first).

const (
	sigArmorBegin = "-----BEGIN SSH SIGNATURE-----"
	sigArmorEnd   = "-----END SSH SIGNATURE-----"
	sshSigMagic   = "SSHSIG"
	sshSigVersion = 1
	keyTypeEd     = "ssh-ed25519"

	// signatureNamespace pins `ssh-keygen -Y sign -n <ns>` — a signature made
	// by the same key for any other purpose does not validate here. Must
	// match SIGNATURE_NAMESPACE in the loader scripts.
	signatureNamespace = "stepsecurity-mdm-checksum"
)

// releasePublicKeyB64 is the pinned Ed25519 release-signing key: the base64
// SSH wire blob from the `ssh-ed25519 <this> releases@stepsecurity.io` line
// the loader scripts embed as PUBLIC_KEY_SSH. Comparing wire blobs pins both
// the algorithm and the key in one equality check.
const releasePublicKeyB64 = "AAAAC3NzaC1lZDI1NTE5AAAAILN+WG4lOH/x6MysYOf1oY0PKXLLu9d3ZvQDcvq5Cboi"

func readSSHString(r *bytes.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if int64(n) > int64(r.Len()) {
		return nil, fmt.Errorf("truncated ssh string (%d > %d remaining)", n, r.Len())
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func appendSSHString(dst, s []byte) []byte {
	var n [4]byte
	// #nosec G115 -- inputs are protocol strings we compose ourselves
	// (namespace, hash name, a 64-byte digest), always far below uint32.
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	return append(append(dst, n[:]...), s...)
}

// verifySSHSig checks that `armored` is a valid SSHSIG over `message`, made
// by the key whose SSH wire blob base64-encodes to allowedKeyB64, in the
// given namespace. Errors are diagnostic (safe to log; carry no secrets).
func verifySSHSig(armored string, message []byte, allowedKeyB64, namespace string) error {
	beg := strings.Index(armored, sigArmorBegin)
	end := strings.Index(armored, sigArmorEnd)
	// The END marker must start at or after the END of the BEGIN marker —
	// the two markers share the "-----" run, so a crafted blob like
	// "-----BEGIN SSH SIGNATUREEND SSH SIGNATURE-----" can make END match
	// inside BEGIN's tail; slicing with that index would panic.
	if beg == -1 || end == -1 || end < beg+len(sigArmorBegin) {
		return fmt.Errorf("not an armored SSH signature block")
	}
	b64 := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, armored[beg+len(sigArmorBegin):end])
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("decode signature body: %w", err)
	}

	r := bytes.NewReader(blob)
	magic := make([]byte, len(sshSigMagic))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != sshSigMagic {
		return fmt.Errorf("missing SSHSIG magic preamble")
	}
	var version uint32
	if err := binary.Read(r, binary.BigEndian, &version); err != nil || version != sshSigVersion {
		return fmt.Errorf("unsupported SSHSIG version %d", version)
	}
	pubkeyBlob, err := readSSHString(r)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	ns, err := readSSHString(r)
	if err != nil {
		return fmt.Errorf("read namespace: %w", err)
	}
	reserved, err := readSSHString(r)
	if err != nil {
		return fmt.Errorf("read reserved: %w", err)
	}
	hashAlg, err := readSSHString(r)
	if err != nil {
		return fmt.Errorf("read hash algorithm: %w", err)
	}
	sigBlob, err := readSSHString(r)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}

	if string(ns) != namespace {
		return fmt.Errorf("signature namespace %q, want %q", ns, namespace)
	}
	allowed, err := base64.StdEncoding.DecodeString(allowedKeyB64)
	if err != nil {
		return fmt.Errorf("decode pinned key: %w", err)
	}
	if !bytes.Equal(pubkeyBlob, allowed) {
		return fmt.Errorf("signing key is not the pinned release key")
	}

	// Pubkey wire: string "ssh-ed25519" || string key(32).
	pr := bytes.NewReader(pubkeyBlob)
	keyType, err := readSSHString(pr)
	if err != nil || string(keyType) != keyTypeEd {
		return fmt.Errorf("unsupported key type %q", keyType)
	}
	key, err := readSSHString(pr)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("malformed ed25519 public key")
	}

	// Signature wire: string "ssh-ed25519" || string sig(64).
	sr := bytes.NewReader(sigBlob)
	sigType, err := readSSHString(sr)
	if err != nil || string(sigType) != keyTypeEd {
		return fmt.Errorf("unsupported signature type %q", sigType)
	}
	sig, err := readSSHString(sr)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("malformed ed25519 signature")
	}

	var hashed []byte
	switch string(hashAlg) {
	case "sha256":
		h := sha256.Sum256(message)
		hashed = h[:]
	case "sha512":
		h := sha512.Sum512(message)
		hashed = h[:]
	default:
		return fmt.Errorf("unsupported hash algorithm %q", hashAlg)
	}

	// Signed blob per PROTOCOL.sshsig: MAGIC || namespace || reserved ||
	// hash_algorithm || H(message), each as an ssh string except the magic.
	signed := []byte(sshSigMagic)
	signed = appendSSHString(signed, ns)
	signed = appendSSHString(signed, reserved)
	signed = appendSSHString(signed, hashAlg)
	signed = appendSSHString(signed, hashed)

	if !ed25519.Verify(ed25519.PublicKey(key), signed, sig) {
		return fmt.Errorf("ed25519 signature verification failed")
	}
	return nil
}
