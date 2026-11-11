package azure

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAzure serves the Entra token endpoint, the managed identity
// endpoints, ARM and Key Vault (under /kv/<name>/) and records every
// request.
type fakeAzure struct {
	srv          *httptest.Server
	mu           sync.Mutex
	paths        []string
	tokenCalls   int
	lastForm     url.Values
	lastHeaders  http.Header
	certPub      *rsa.PublicKey
	certDER      []byte
	assertion    string // expected workload identity assertion
	failToken    bool
	arcKeyFile   string // realm returned in the Arc challenge
	arcKey       string
	vaults       map[string]map[string][]map[string]any // vault -> "certificates"/"secrets"/"keys" -> items
	failVault    string
	evilNextLink bool
	subs         map[string][]map[string]any // subscription -> ARM resources
	arcAuthSent  bool                        // an Authorization header reached the Arc endpoint
	redirect     string                      // vault collection answered with a 307 to this path
	graph        map[string][]map[string]any // "applications"/"servicePrincipals" -> objects
	graphTokens  []string                    // bearer tokens seen on Graph requests
	throttleOnce bool                        // next Graph request answers 429
}

func newFake(t *testing.T) *fakeAzure {
	t.Helper()
	f := &fakeAzure{vaults: map[string]map[string][]map[string]any{}, subs: map[string][]map[string]any{}, graph: map[string][]map[string]any{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func reply(w http.ResponseWriter, v any) { json.NewEncoder(w).Encode(v) }

func (f *fakeAzure) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	f.lastHeaders = r.Header.Clone()
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/oauth2/v2.0/token"):
		f.tokenCalls++
		r.ParseForm()
		f.lastForm = r.PostForm
		if f.failToken {
			w.WriteHeader(401)
			reply(w, map[string]any{"error": "invalid_client", "error_description": "AADSTS700027: bad assertion"})
			return
		}
		reply(w, map[string]any{"access_token": "tok-" + r.PostForm.Get("scope"), "expires_in": 3600, "token_type": "Bearer"})
		return
	case p == "/imds":
		f.tokenCalls++
		if r.Header.Get("Metadata") != "true" {
			http.Error(w, "no metadata header", 400)
			return
		}
		reply(w, map[string]any{"access_token": "mi-" + r.URL.Query().Get("resource"), "expires_on": "4102444800"})
		return
	case p == "/appservice":
		f.tokenCalls++
		if r.Header.Get("X-IDENTITY-HEADER") != "secret-header" {
			http.Error(w, "bad header", 401)
			return
		}
		reply(w, map[string]any{"access_token": "as-" + r.URL.Query().Get("resource"), "expires_on": 4102444800})
		return
	case p == "/arc":
		f.tokenCalls++
		if auth := r.Header.Get("Authorization"); auth != "" {
			f.arcAuthSent = true
			if auth != "Basic "+f.arcKey {
				http.Error(w, "bad key", 401)
				return
			}
			reply(w, map[string]any{"access_token": "arc-token", "expires_on": "4102444800"})
			return
		}
		w.Header().Set("WWW-Authenticate", "Basic realm="+f.arcKeyFile)
		w.WriteHeader(401)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		http.Error(w, "no token", 401)
		return
	}
	if strings.HasPrefix(p, "/v1.0/") {
		f.graphTokens = append(f.graphTokens, r.Header.Get("Authorization"))
		coll := strings.TrimPrefix(p, "/v1.0/")
		if r.Method != http.MethodGet || strings.Contains(r.URL.Query().Get("$select"), "keyCredentials") {
			http.Error(w, "list only; keyCredentials in $select returns whole certificates", 400)
			return
		}
		if t := r.URL.Query().Get("$top"); t != "100" {
			http.Error(w, "page size above the maximum: "+t, 400)
			return
		}
		if f.throttleOnce {
			f.throttleOnce = false
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		items := f.graph[coll]
		if r.URL.Query().Get("$skiptoken") == "2" {
			reply(w, map[string]any{"value": items[1:]})
			return
		}
		out := map[string]any{"value": items[:min(1, len(items))]}
		if len(items) > 1 {
			out["@odata.nextLink"] = f.srv.URL + p + "?" + r.URL.RawQuery + "&$skiptoken=2"
		}
		reply(w, out)
		return
	}
	if strings.HasPrefix(p, "/subscriptions/") {
		sub := strings.Split(p, "/")[2]
		if r.URL.Query().Get("$filter") != "resourceType eq 'Microsoft.KeyVault/vaults'" {
			http.Error(w, "bad filter", 400)
			return
		}
		items := f.subs[sub]
		if r.URL.Query().Get("page") == "2" {
			reply(w, map[string]any{"value": items[1:]})
			return
		}
		out := map[string]any{"value": items[:min(1, len(items))]}
		if len(items) > 1 {
			out["nextLink"] = f.srv.URL + p + "?" + r.URL.RawQuery + "&page=2"
		}
		reply(w, out)
		return
	}
	if strings.HasPrefix(p, "/kv/") {
		parts := strings.Split(strings.TrimPrefix(p, "/kv/"), "/")
		vault, coll := parts[0], parts[1]
		if len(parts) != 2 || r.Method != http.MethodGet {
			http.Error(w, "only list endpoints", 400)
			return
		}
		if f.redirect != "" && r.URL.Path != f.redirect {
			http.Redirect(w, r, f.redirect, http.StatusTemporaryRedirect)
			return
		}
		if vault == f.failVault {
			w.WriteHeader(403)
			reply(w, map[string]any{"error": map[string]any{"code": "Forbidden", "message": "ForbiddenByFirewall"}})
			return
		}
		items := f.vaults[vault][coll]
		if r.URL.Query().Get("page") == "2" {
			reply(w, map[string]any{"value": items[1:]})
			return
		}
		out := map[string]any{"value": items[:min(1, len(items))]}
		if len(items) > 1 {
			if f.evilNextLink {
				out["nextLink"] = "https://evil.example.com/steal?page=2"
			} else {
				out["nextLink"] = f.srv.URL + p + "?" + r.URL.RawQuery + "&page=2"
			}
		}
		reply(w, out)
		return
	}
	http.NotFound(w, r)
}

// writeCertPEM writes a self-signed RSA certificate and its key (PKCS#8)
// to one PEM file and remembers the public key for verification.
func (f *fakeAzure) writeCertPEM(t *testing.T) string {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "expiry-radar"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(k)
	f.certPub, f.certDER = &k.PublicKey, der
	p := filepath.Join(t.TempDir(), "sp.pem")
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})...)
	os.WriteFile(p, data, 0o600)
	return p
}

func x5tS256(der []byte) string {
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func item(id string, exp int64, enabled, managed bool) map[string]any {
	attrs := map[string]any{"enabled": enabled}
	if exp != 0 {
		attrs["exp"] = exp
	}
	m := map[string]any{"id": id, "attributes": attrs}
	if managed {
		m["managed"] = true
	}
	return m
}
