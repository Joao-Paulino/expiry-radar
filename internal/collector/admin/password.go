// Package admin manages the Collector's single local Administrator
// account: password hashing, TOTP, recovery codes, lockout and login.
package admin

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// MinPasswordLength is the shortest Administrator password accepted.
	MinPasswordLength = 12

	pbkdf2Iterations = 600000
	pbkdf2SaltLen    = 16
	pbkdf2KeyLen     = 32
	pbkdf2Scheme     = "pbkdf2-sha256"
)

// ErrPasswordTooShort is returned by HashPassword for a password
// shorter than MinPasswordLength.
var ErrPasswordTooShort = fmt.Errorf("admin: password must be at least %d characters", MinPasswordLength)

var b64 = base64.RawStdEncoding

// HashPassword returns the PBKDF2-HMAC-SHA256 encoding of password,
// in the form pbkdf2-sha256$<iterations>$<salt>$<key>.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLength {
		return "", ErrPasswordTooShort
	}
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", pbkdf2Scheme, pbkdf2Iterations, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches encoded, comparing
// in constant time. It returns an error only for a malformed encoding.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != pbkdf2Scheme {
		return false, errors.New("admin: malformed password hash")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false, errors.New("admin: malformed password hash iterations")
	}
	salt, err := b64.DecodeString(parts[2])
	if err != nil {
		return false, errors.New("admin: malformed password hash salt")
	}
	want, err := b64.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false, errors.New("admin: malformed password hash key")
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(want))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
