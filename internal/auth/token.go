// Package auth implements bearer-token authentication between the
// Agent and the Collector.
package auth

import (
	"context"
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

// Credential is one agent token. AgentID, when set, binds the token: a
// batch pushed with it may only claim that agent ID. An empty AgentID
// is a shared token (auth_tokens), which can claim any agent ID.
type Credential struct {
	Token   string
	AgentID string
}

type boundAgentKey struct{}

// WithBoundAgent returns ctx carrying the agent ID a token is bound to.
func WithBoundAgent(ctx context.Context, agentID string) context.Context {
	return context.WithValue(ctx, boundAgentKey{}, agentID)
}

// BoundAgent returns the agent ID the request's token is bound to, and
// false for a shared token.
func BoundAgent(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(boundAgentKey{}).(string)
	return id, ok && id != ""
}

// AgentMiddleware is Middleware for agent credentials: it accepts any
// listed token and, for a bound one, passes the agent ID on through the
// request context (see BoundAgent). Every candidate is compared, in
// constant time, so the response time does not reveal which one matched.
func AgentMiddleware(creds []Credential, next http.Handler) http.Handler {
	reserved := map[string]bool{}
	for _, c := range creds {
		if c.AgentID != "" {
			reserved[c.AgentID] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		matched, agentID := false, ""
		for _, c := range creds {
			if subtle.ConstantTimeCompare([]byte(got), []byte(c.Token)) == 1 {
				matched, agentID = true, c.AgentID
			}
		}
		if !matched {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if agentID != "" {
			r = r.WithContext(WithBoundAgent(r.Context(), agentID))
		} else {
			r = r.WithContext(WithReservedAgents(r.Context(), reserved))
		}
		next.ServeHTTP(w, r)
	})
}

type reservedAgentsKey struct{}

// WithReservedAgents returns ctx carrying the agent IDs that have their
// own token. AgentMiddleware sets it for shared (unbound) tokens.
func WithReservedAgents(ctx context.Context, ids map[string]bool) context.Context {
	return context.WithValue(ctx, reservedAgentsKey{}, ids)
}

// IsReservedAgent reports whether agentID has its own token, so a shared
// token must not report as it.
func IsReservedAgent(ctx context.Context, agentID string) bool {
	ids, _ := ctx.Value(reservedAgentsKey{}).(map[string]bool)
	return ids[agentID]
}
