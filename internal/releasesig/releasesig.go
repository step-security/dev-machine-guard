// Package releasesig verifies the signed checksums published with every
// dev-machine-guard release (`<asset>.sha256.sig`). The release operator signs
// the asset's hex SHA-256 with `ssh-keygen -Y sign` under a fixed namespace;
// the loaders verify it with `ssh-keygen -Y verify`. This package does the
// same check with the standard library only, so the agent can trust a binary
// it downloads itself without shelling out to ssh-keygen.
//
// Format reference: OpenSSH PROTOCOL.sshsig. Only ssh-ed25519 keys are
// accepted, which is what the release key is.
package releasesig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// PublicKey is the release signing key, the same one the agent-api loaders
// pin (scripts/*/stepsecurity-loader.* PUBLIC_KEY_SSH).
const PublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILN+WG4lOH/x6MysYOf1oY0PKXLLu9d3ZvQDcvq5Cboi releases@stepsecurity.io"

// Namespace is bound into every release signature; a signature made for any
// other namespace is rejected.
const Namespace = "stepsecurity-mdm-checksum"

const (
	sigMagic   = "SSHSIG"
	sigVersion = 1
	keyType    = "ssh-ed25519"
)

// VerifyChecksum reports whether sigFile is a valid release signature over
// checksum (the lowercase hex SHA-256 of the asset). sigFile is the content of
// a `.sha256.sig` release asset: base64 of the armored SSH signature. A raw
// armored signature is accepted too.
func VerifyChecksum(checksum string, sigFile []byte) error {
	return verify(PublicKey, Namespace, []byte(strings.ToLower(strings.TrimSpace(checksum))), sigFile)
}

func verify(authorizedKey, namespace string, message, sigFile []byte) error {
	wantKey, err := parseAuthorizedKey(authorizedKey)
	if err != nil {
		return err
	}
	blob, err := decodeArmor(sigFile)
	if err != nil {
		return err
	}

	r := reader{b: blob}
	if magic := r.bytes(len(sigMagic)); string(magic) != sigMagic {
		return errors.New("releasesig: not an SSH signature")
	}
	if v := r.uint32(); v != sigVersion {
		return fmt.Errorf("releasesig: unsupported signature version %d", v)
	}
	pubBlob := r.str()
	sigNamespace := r.str()
	reserved := r.str()
	hashAlg := r.str()
	sigBlob := r.str()
	if r.err != nil {
		return fmt.Errorf("releasesig: malformed signature: %w", r.err)
	}

	pub, err := parseKeyBlob(pubBlob)
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, wantKey) {
		return errors.New("releasesig: signed by an unexpected key")
	}
	if string(sigNamespace) != namespace {
		return fmt.Errorf("releasesig: signature namespace %q, want %q", sigNamespace, namespace)
	}

	var digest []byte
	switch string(hashAlg) {
	case "sha512":
		d := sha512.Sum512(message)
		digest = d[:]
	case "sha256":
		d := sha256.Sum256(message)
		digest = d[:]
	default:
		return fmt.Errorf("releasesig: unsupported hash algorithm %q", hashAlg)
	}

	sr := reader{b: sigBlob}
	sigType := sr.str()
	sig := sr.str()
	if sr.err != nil {
		return fmt.Errorf("releasesig: malformed signature blob: %w", sr.err)
	}
	if string(sigType) != keyType || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("releasesig: unsupported signature type %q", sigType)
	}

	var signed bytes.Buffer
	signed.WriteString(sigMagic)
	writeString(&signed, sigNamespace)
	writeString(&signed, reserved)
	writeString(&signed, hashAlg)
	writeString(&signed, digest)

	if !ed25519.Verify(ed25519.PublicKey(pub), signed.Bytes(), sig) {
		return errors.New("releasesig: signature does not match")
	}
	return nil
}

// decodeArmor accepts the release asset form (base64 of the armored
// signature) or the armored signature itself, and returns the binary blob.
func decodeArmor(sigFile []byte) ([]byte, error) {
	data := bytes.TrimSpace(sigFile)
	if !bytes.HasPrefix(data, []byte("-----BEGIN")) {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("releasesig: decode signature file: %w", err)
		}
		data = decoded
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "SSH SIGNATURE" {
		return nil, errors.New("releasesig: no SSH SIGNATURE block")
	}
	return block.Bytes, nil
}

// parseAuthorizedKey returns the raw ed25519 key from an authorized_keys
// line ("ssh-ed25519 <base64> [comment]").
func parseAuthorizedKey(line string) ([]byte, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != keyType {
		return nil, errors.New("releasesig: public key is not ssh-ed25519")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("releasesig: decode public key: %w", err)
	}
	return parseKeyBlob(blob)
}

func parseKeyBlob(blob []byte) ([]byte, error) {
	r := reader{b: blob}
	typ := r.str()
	key := r.str()
	if r.err != nil || string(typ) != keyType || len(key) != ed25519.PublicKeySize || len(r.b) != 0 {
		return nil, errors.New("releasesig: unsupported public key")
	}
	return key, nil
}

func writeString(b *bytes.Buffer, s []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s))) // #nosec G115 -- fields are a namespace, a hash name and a digest, all tiny
	b.Write(n[:])
	b.Write(s)
}

// reader walks SSH wire-format fields. The first failure sticks in err and
// every later read returns nil, so callers check once at the end.
type reader struct {
	b   []byte
	err error
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = errors.New("truncated")
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) uint32() uint32 {
	b := r.bytes(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *reader) str() []byte {
	n := r.uint32()
	if r.err != nil {
		return nil
	}
	if uint64(n) > uint64(len(r.b)) {
		r.err = errors.New("truncated")
		return nil
	}
	return r.bytes(int(n))
}
