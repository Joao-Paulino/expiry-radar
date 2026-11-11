package session

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"strings"

	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

type csrfKey struct{}

// CSRFToken returns the CSRF token of the session that authenticated
// the request, or "" for bearer-token requests.
func CSRFToken(ctx context.Context) string {
	v, _ := ctx.Value(csrfKey{}).(string)
	return v
}

func validBearer(r *http.Request, tokens []string) (present, ok bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return false, false
	}
	got, found := strings.CutPrefix(h, "Bearer ")
	if !found || got == "" {
		return true, false
	}
	for _, t := range tokens {
		if t != "" && subtle.ConstantTimeCompare([]byte(got), []byte(t)) == 1 {
			return true, true
		}
	}
	return true, false
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// Middleware lets a request through when it carries a valid admin
// bearer token, or a valid session cookie (state-changing session
// requests must also carry the session's csrf_token form field).
// Otherwise browsers are redirected to /login and other clients get 401.
func Middleware(st *Store, adminTokens []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if present, ok := validBearer(r, adminTokens); present {
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if c, err := r.Cookie(CookieName); err == nil {
			sess, ok, err := st.Lookup(r.Context(), c.Value)
			if err != nil {
				log.Printf("session: lookup error: %s", logging.Sanitize(err.Error()))
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if ok {
				if !safeMethod(r.Method) {
					if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf_token")), []byte(sess.CSRFToken)) != 1 {
						http.Error(w, "invalid CSRF token", http.StatusForbidden)
						return
					}
				}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), csrfKey{}, sess.CSRFToken)))
				return
			}
		}

		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
}
