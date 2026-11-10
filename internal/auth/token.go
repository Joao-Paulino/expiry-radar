// Package auth implements bearer-token authentication between the
// Agent and the Collector.
package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AttachToken sets the Authorization header on req using token.
func AttachToken(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
}

// Middleware wraps next, requiring a Bearer token matching one of
// validTokens in the Authorization header. Requests without a valid
// token get 401 Unauthorized; the token value itself is never logged.
func Middleware(validTokens []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		for _, candidate := range validTokens {
			if subtle.ConstantTimeCompare([]byte(got), []byte(candidate)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.WriteHeader(http.StatusUnauthorized)
	})
}
