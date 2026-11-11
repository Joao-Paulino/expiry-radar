package admin

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

var rfcSecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))

func TestTOTPCode_RFC6238Vectors(t *testing.T) {
	cases := map[int64]string{1: "287082", 37037036: "081804", 37037037: "050471"}
	for step, want := range cases {
		got, err := TOTPCode(rfcSecret, step)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("step %d: got %s, want %s", step, got, want)
		}
	}
}

func TestVerifyTOTP_AcceptsAdjacentSteps(t *testing.T) {
	now := time.Unix(1111111111, 0)
	cur := now.Unix() / 30
	for _, d := range []int64{-1, 0, 1} {
		code, _ := TOTPCode(rfcSecret, cur+d)
		if step, ok := VerifyTOTP(rfcSecret, code, now, 0); !ok || step != cur+d {
			t.Errorf("offset %d: ok=%v step=%d", d, ok, step)
		}
	}
	for _, d := range []int64{-2, 2} {
		code, _ := TOTPCode(rfcSecret, cur+d)
		if _, ok := VerifyTOTP(rfcSecret, code, now, 0); ok {
			t.Errorf("offset %d accepted", d)
		}
	}
}

func TestVerifyTOTP_RejectsReplay(t *testing.T) {
	now := time.Unix(1111111111, 0)
	cur := now.Unix() / 30
	code, _ := TOTPCode(rfcSecret, cur)
	if _, ok := VerifyTOTP(rfcSecret, code, now, cur); ok {
		t.Fatal("code for an already-used step accepted")
	}
	prev, _ := TOTPCode(rfcSecret, cur-1)
	if _, ok := VerifyTOTP(rfcSecret, prev, now, cur); ok {
		t.Fatal("code for a step older than the last used one accepted")
	}
}

func TestVerifyTOTP_RejectsMalformedCode(t *testing.T) {
	now := time.Unix(1111111111, 0)
	for _, c := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := VerifyTOTP(rfcSecret, c, now, 0); ok {
			t.Errorf("malformed code %q accepted", c)
		}
	}
}

func TestNewTOTPSecret_Is20Bytes(t *testing.T) {
	s, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || len(raw) != 20 {
		t.Fatalf("secret %q: len=%d err=%v", s, len(raw), err)
	}
}

func TestTOTPURI_Format(t *testing.T) {
	u := TOTPURI("ABC")
	if !strings.HasPrefix(u, "otpauth://totp/Expiry%20Radar:Administrator?secret=ABC") || !strings.Contains(u, "&issuer=Expiry%20Radar") {
		t.Fatalf("unexpected URI %q", u)
	}
}

func TestNewRecoveryCodes(t *testing.T) {
	plain, hashes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 8 || len(hashes) != 8 {
		t.Fatalf("want 8 codes, got %d/%d", len(plain), len(hashes))
	}
	seen := map[string]bool{}
	for i, c := range plain {
		if len(c) != 10 || strings.Trim(c, recoveryAlphabet) != "" {
			t.Errorf("bad code %q", c)
		}
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
		if hashes[i] != HashRecoveryCode(c) {
			t.Errorf("hash %d does not match its code", i)
		}
	}
}
