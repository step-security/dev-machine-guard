package selfupdate

import (
	"strings"
	"testing"
)

// Fixtures generated with a throwaway ed25519 key:
//
//	ssh-keygen -t ed25519 -f testkey -N "" -C test@fixture
//	printf '%s' "<message>" > msg && ssh-keygen -Y sign -f testkey -n stepsecurity-mdm-checksum msg
const (
	fixtureKeyB64 = "AAAAC3NzaC1lZDI1NTE5AAAAIPyrd8mRqV8sf32kNxdbqNcM7O6nnkpZBZuUkRzgV4Vi"

	fixtureMessage = "b9c566a0abef0c004c8550a4c06e7702c1ee4cedeb98a441b4362a8d38d8a215"
	fixtureSig     = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg/Kt3yZGpXyx/faQ3F1uo1wzs7q
eeSlkFm5SRHOBXhWIAAAAZc3RlcHNlY3VyaXR5LW1kbS1jaGVja3N1bQAAAAAAAAAGc2hh
NTEyAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEA54k4Rj3+JfaX1jh5KQF2RaWrtSxeQBDPCBt
1ONaiZ63fUUNmX2tH3KkkJo4Ul/v/GhTS+zCZI/tT8FWeGjG4D
-----END SSH SIGNATURE-----`

	// Payload fixtures for the update-flow tests (selfupdate_test.go).
	fixturePayload         = "poc-new-binary-payload\n"
	fixturePayloadChecksum = "83aff4e3d909750027b906bfc78a11f22b11b82c045be1dcf8ee320f469621b4"
	fixturePayloadSig      = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg/Kt3yZGpXyx/faQ3F1uo1wzs7q
eeSlkFm5SRHOBXhWIAAAAZc3RlcHNlY3VyaXR5LW1kbS1jaGVja3N1bQAAAAAAAAAGc2hh
NTEyAAAAUwAAAAtzc2gtZWQyNTUxOQAAAED/6oSFt0xYTqzYcwemQ4GQ8bZlHSOo4L1t0A
kmHXZoiG6RbdQlYusI4+laaYjXNr0gvXIViYBO0v3vwgdBK3wI
-----END SSH SIGNATURE-----`
)

func TestVerifySSHSig(t *testing.T) {
	tests := []struct {
		name      string
		armored   string
		message   string
		key       string
		namespace string
		wantErr   string // substring; "" = must verify
	}{
		{
			name: "valid signature verifies", armored: fixtureSig,
			message: fixtureMessage, key: fixtureKeyB64, namespace: signatureNamespace,
		},
		{
			name: "wrong namespace rejected", armored: fixtureSig,
			message: fixtureMessage, key: fixtureKeyB64, namespace: "other-namespace",
			wantErr: "namespace",
		},
		{
			name: "signature by non-pinned key rejected", armored: fixtureSig,
			message: fixtureMessage, key: releasePublicKeyB64, namespace: signatureNamespace,
			wantErr: "not the pinned release key",
		},
		{
			name: "tampered message rejected", armored: fixtureSig,
			message: fixtureMessage[:len(fixtureMessage)-1] + "0", key: fixtureKeyB64, namespace: signatureNamespace,
			wantErr: "verification failed",
		},
		{
			name: "garbage armor rejected", armored: "base64  --  Encode/decode file as base64.  Call:",
			message: fixtureMessage, key: fixtureKeyB64, namespace: signatureNamespace,
			wantErr: "not an armored SSH signature",
		},
		{
			name: "truncated blob rejected", armored: fixtureSig[:120] + "\n-----END SSH SIGNATURE-----",
			message: fixtureMessage, key: fixtureKeyB64, namespace: signatureNamespace,
			wantErr: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifySSHSig(tc.armored, []byte(tc.message), tc.key, tc.namespace)
			if tc.name == "truncated blob rejected" {
				if err == nil {
					t.Fatal("truncated blob verified, want any error")
				}
				return
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verify error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
