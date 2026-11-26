// Package netaddr extracts the address a request should be attributed
// to for rate limiting and logging, trusting a reverse proxy's
// X-Forwarded-For only when it can't have been forged.
package netaddr

import (
	"net"
	"net/http"
	"strings"
)

// Client returns the address to key rate limits and logs on: the
// first (leftmost, i.e. original client) entry of X-Forwarded-For
// when the request's own TCP peer is loopback, or the TCP peer's
// address otherwise.
//
// A same-host reverse proxy (Caddy, nginx, ...) connects to the
// collector over loopback and sets X-Forwarded-For to the real
// client's address, overwriting rather than appending to whatever a
// client sent — so when the TCP peer is loopback, the header can only
// have come from that proxy, never have been forged by a remote
// client (a forged source address can't complete a TCP handshake).
// Over any other peer, a client could write any X-Forwarded-For value
// itself, so it is ignored and the TCP peer's own address is used.
func Client(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
				return first
			}
		}
	}
	return host
}
