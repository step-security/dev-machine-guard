package devicepolicy

import "testing"

func TestVerify(t *testing.T) {
	cases := []struct {
		name string
		in   VerifyInput
		want string
	}{
		{"write failed", VerifyInput{WriteOK: false, ReadbackMatch: false}, StateWriteFailed},
		{"write failed trumps readback", VerifyInput{WriteOK: false, ReadbackMatch: true}, StateWriteFailed},
		{"readback mismatch", VerifyInput{WriteOK: true, ReadbackMatch: false}, StatePolicyNotApplied},
		{"applied", VerifyInput{WriteOK: true, ReadbackMatch: true}, StateCompliant},
	}
	for _, tc := range cases {
		if got := Verify(tc.in); got != tc.want {
			t.Errorf("%s: Verify(%+v) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}
