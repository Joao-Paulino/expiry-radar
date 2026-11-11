package admin

import (
	"errors"
	"strings"
	"testing"
)

func TestHashPassword_VerifyRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyPassword(h, "correct horse battery"); err != nil || !ok {
		t.Fatalf("correct password rejected: ok=%v err=%v", ok, err)
	}
	if ok, err := VerifyPassword(h, "wrong"); err != nil || ok {
		t.Fatalf("wrong password accepted: ok=%v err=%v", ok, err)
	}
}

func TestHashPassword_UsesRandomSalt(t *testing.T) {
	a, _ := HashPassword("correct horse battery")
	b, _ := HashPassword("correct horse battery")
	if a == b {
		t.Fatal("two hashes of the same password are identical; salt is not random")
	}
}

func TestHashPassword_EncodedFormat(t *testing.T) {
	h, _ := HashPassword("correct horse battery")
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Fatalf("unexpected prefix: %q", h)
	}
	if parts := strings.Split(h, "$"); len(parts) != 4 {
		t.Fatalf("want 4 $-separated parts, got %d: %q", len(parts), h)
	}
}

func TestHashPassword_RejectsShort(t *testing.T) {
	if _, err := HashPassword("elevenchars"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("want ErrPasswordTooShort, got %v", err)
	}
}

func TestVerifyPassword_RejectsMalformed(t *testing.T) {
	if _, err := VerifyPassword("garbage", "whatever"); err == nil {
		t.Fatal("expected an error for a malformed hash")
	}
}
