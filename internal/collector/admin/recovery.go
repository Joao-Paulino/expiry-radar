package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

const (
	recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	recoveryCodeLen  = 10
	recoveryCodeN    = 8
)

// NewRecoveryCodes returns 8 single-use recovery codes and their
// SHA-256 hashes (the only form that is stored).
func NewRecoveryCodes() (plain []string, hashes []string, err error) {
	seen := map[string]bool{}
	for len(plain) < recoveryCodeN {
		buf := make([]byte, recoveryCodeLen)
		for i := range buf {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(recoveryAlphabet))))
			if err != nil {
				return nil, nil, err
			}
			buf[i] = recoveryAlphabet[n.Int64()]
		}
		code := string(buf)
		if seen[code] {
			continue
		}
		seen[code] = true
		plain = append(plain, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return plain, hashes, nil
}

// HashRecoveryCode returns the hex SHA-256 of code.
func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
