package netaddr

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"direct connection, no proxy", "203.0.113.9:51515", "", "203.0.113.9"},
		{"direct connection ignores a self-supplied XFF", "203.0.113.9:51515", "10.0.0.1", "203.0.113.9"},
		{"loopback proxy trusts XFF", "127.0.0.1:51515", "203.0.113.9", "203.0.113.9"},
		{"loopback proxy, IPv6 peer", "[::1]:51515", "203.0.113.9", "203.0.113.9"},
		{"loopback proxy, multiple hops takes the first (original client)", "127.0.0.1:51515", "203.0.113.9, 127.0.0.1", "203.0.113.9"},
		{"loopback proxy, no XFF set falls back to the peer", "127.0.0.1:51515", "", "127.0.0.1"},
		{"malformed RemoteAddr with no port", "203.0.113.9", "10.0.0.1", "203.0.113.9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = c.remoteAddr
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := Client(r); got != c.want {
				t.Fatalf("Client() = %q, want %q", got, c.want)
			}
		})
	}
}

func FuzzClient(f *testing.F) {
	f.Add("127.0.0.1:1234", "1.2.3.4")
	f.Add("203.0.113.9:1234", "1.2.3.4")
	f.Add("not-an-address", "")
	f.Add("127.0.0.1:1234", "")
	f.Add("127.0.0.1:1234", ",,,")
	f.Fuzz(func(t *testing.T, remoteAddr, xff string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remoteAddr
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		_ = Client(r) // must not panic
	})
}
