package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeCert struct {
	serial  string
	pem     string
	revoked bool
}

// fakeVault serves the few Vault endpoints the checker may use and
// records every request path, so tests can prove nothing else is read.
type fakeVault struct {
	srv       *httptest.Server
	mu        sync.Mutex
	paths     []string
	tokens    []string
	namespace []string
	revoked   bool
	certs     map[string][]fakeCert        // mount -> certs
	issuers   map[string]map[string]string // mount -> issuer id -> pem
	issuerNm  map[string]map[string]string // mount -> issuer id -> name
	failMount string
}

func makePEM(t *testing.T, cn string, notAfter time.Time, serial int64) string {
	return makePEMCA(t, cn, notAfter, serial, false)
}

func makePEMCA(t *testing.T, cn string, notAfter time.Time, serial int64, isCA bool) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter, IsCA: isCA, BasicConstraintsValid: isCA}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	f := &fakeVault{certs: map[string][]fakeCert{}, issuers: map[string]map[string]string{}, issuerNm: map[string]map[string]string{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func reply(w http.ResponseWriter, v any) { json.NewEncoder(w).Encode(v) }

func (f *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	f.tokens = append(f.tokens, r.Header.Get("X-Vault-Token"))
	f.namespace = append(f.namespace, r.Header.Get("X-Vault-Namespace"))
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	isList := r.Method == "LIST" || r.URL.Query().Get("list") == "true"
	switch {
	case p == "auth/approle/login" && r.Method == http.MethodPost:
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		if b["role_id"] != "role-1" || b["secret_id"] != "secret-1" {
			http.Error(w, `{"errors":["invalid role or secret ID"]}`, 400)
			return
		}
		reply(w, map[string]any{"auth": map[string]any{"client_token": "approle-token"}})
		return
	case p == "auth/token/revoke-self" && r.Method == http.MethodPost:
		f.revoked = true
		w.WriteHeader(204)
		return
	}
	if tok := r.Header.Get("X-Vault-Token"); tok != "approle-token" && tok != "file-token" {
		http.Error(w, `{"errors":["permission denied"]}`, 403)
		return
	}
	mount, rest, _ := strings.Cut(p, "/")
	if mount == f.failMount {
		http.Error(w, `{"errors":["no handler for route"]}`, 404)
		return
	}
	switch {
	case rest == "certs" && isList:
		var keys []string
		for _, c := range f.certs[mount] {
			keys = append(keys, c.serial)
		}
		reply(w, map[string]any{"data": map[string]any{"keys": keys}})
	case strings.HasPrefix(rest, "cert/"):
		for _, c := range f.certs[mount] {
			if c.serial == strings.TrimPrefix(rest, "cert/") {
				var rt int64
				if c.revoked {
					rt = time.Now().Unix()
				}
				reply(w, map[string]any{"data": map[string]any{"certificate": c.pem, "revocation_time": rt}})
				return
			}
		}
		http.NotFound(w, r)
	case rest == "issuers" && isList:
		var keys []string
		for id := range f.issuers[mount] {
			keys = append(keys, id)
		}
		reply(w, map[string]any{"data": map[string]any{"keys": keys}})
	case strings.HasPrefix(rest, "issuer/"):
		id := strings.TrimPrefix(rest, "issuer/")
		reply(w, map[string]any{"data": map[string]any{"certificate": f.issuers[mount][id], "issuer_name": f.issuerNm[mount][id]}})
	default:
		http.NotFound(w, r)
	}
}
