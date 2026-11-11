package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	totpStepSeconds = 30
	totpDigits      = 6
	totpSecretLen   = 20
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh 20-byte TOTP secret, base32 without padding.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, totpSecretLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(raw), nil
}

// TOTPCode returns the 6-digit code for secret at the given 30-second
// step (RFC 6238 with HMAC-SHA1, RFC 4226 dynamic truncation).
func TOTPCode(secret string, step int64) (string, error) {
	key, err := totpEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("admin: invalid TOTP secret: %w", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, value%1000000), nil
}

// VerifyTOTP checks code against the steps now-1, now and now+1, and
// rejects any step at or below lastStep (replay protection). It returns
// the accepted step so the caller can store it as the new lastStep.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != totpDigits || strings.Trim(code, "0123456789") != "" {
		return 0, false
	}
	current := now.Unix() / totpStepSeconds
	for _, step := range []int64{current - 1, current, current + 1} {
		if step <= lastStep {
			continue
		}
		want, err := TOTPCode(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// TOTPURI returns the otpauth:// URI an authenticator app imports.
func TOTPURI(secret string) string {
	return "otpauth://totp/Expiry%20Radar:Administrator?secret=" + secret +
		"&issuer=Expiry%20Radar&algorithm=SHA1&digits=6&period=30"
}
