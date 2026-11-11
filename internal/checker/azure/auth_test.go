package azure

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testEndpoints(f *fakeAzure) endpoints {
	return endpoints{login: f.srv.URL, imds: f.srv.URL + "/imds", arm: f.srv.URL,
		vault: func(n string) string { return f.srv.URL + "/kv/" + n }, arcDir: "/nonexistent"}
}

func noEnv(string) string { return "" }

func mustSource(t *testing.T, f *fakeAzure, cfg Config, ep endpoints, getenv func(string) string) tokenSource {
	t.Helper()
	src, err := newTokenSource(cfg, f.srv.Client(), ep, getenv)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestManagedIdentity_IMDS(t *testing.T) {
	f := newFake(t)
	src := mustSource(t, f, Config{Auth: "managed_identity", ClientID: guid}, testEndpoints(f), noEnv)
	tok, err := src.token(context.Background(), resVault)
	if err != nil || tok != "mi-"+resVault {
		t.Fatalf("got %q, %v", tok, err)
	}
	if !strings.Contains(strings.Join(f.paths, " "), "/imds") {
		t.Fatal("IMDS not used")
	}
}

func TestManagedIdentity_AppService(t *testing.T) {
	f := newFake(t)
	env := map[string]string{"IDENTITY_ENDPOINT": f.srv.URL + "/appservice", "IDENTITY_HEADER": "secret-header"}
	src := mustSource(t, f, Config{Auth: "managed_identity"}, testEndpoints(f), func(k string) string { return env[k] })
	if tok, err := src.token(context.Background(), resARM); err != nil || tok != "as-"+resARM {
		t.Fatalf("got %q, %v", tok, err)
	}
}

func TestManagedIdentity_Arc(t *testing.T) {
	f := newFake(t)
	dir := t.TempDir()
	ep := testEndpoints(f)
	ep.arcDir = dir
	env := map[string]string{"IDENTITY_ENDPOINT": f.srv.URL + "/arc", "IMDS_ENDPOINT": "http://localhost:40342"}
	getenv := func(k string) string { return env[k] }

	good := filepath.Join(dir, "abc.key")
	os.WriteFile(good, []byte("arc-secret"), 0o600)
	f.arcKeyFile, f.arcKey = good, "arc-secret"
	if tok, err := mustSource(t, f, Config{Auth: "managed_identity"}, ep, getenv).token(context.Background(), resVault); err != nil || tok != "arc-token" {
		t.Fatalf("got %q, %v", tok, err)
	}

	outside := filepath.Join(t.TempDir(), "x.key")
	os.WriteFile(outside, []byte("not-for-you"), 0o600)
	big := filepath.Join(dir, "big.key")
	os.WriteFile(big, []byte(strings.Repeat("a", 5000)), 0o600)
	wrongExt := filepath.Join(dir, "passwd")
	os.WriteFile(wrongExt, []byte("x"), 0o600)
	for name, realm := range map[string]string{
		"outside dir": outside,
		"dot-dot":     dir + "/../" + filepath.Base(filepath.Dir(outside)) + "/x.key",
		"too big":     big,
		"wrong ext":   wrongExt,
	} {
		f.arcKeyFile, f.arcKey = realm, "not-for-you"
		if _, err := mustSource(t, f, Config{Auth: "managed_identity"}, ep, getenv).token(context.Background(), resVault); err == nil {
			t.Errorf("%s: challenge file %q accepted", name, realm)
		}
	}
}

func decodeJWT(t *testing.T, jwt string) (hdr, claims map[string]any, signed, sig []byte) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	json.Unmarshal(dec(parts[0]), &hdr)
	json.Unmarshal(dec(parts[1]), &claims)
	return hdr, claims, []byte(parts[0] + "." + parts[1]), dec(parts[2])
}

func TestCertificateAssertion(t *testing.T) {
	f := newFake(t)
	cfg := Config{Auth: "certificate", TenantID: guid, ClientID: "app-1", CertificateFile: f.writeCertPEM(t)}
	tok, err := mustSource(t, f, cfg, testEndpoints(f), noEnv).token(context.Background(), resVault)
	if err != nil || tok != "tok-"+resVault+"/.default" {
		t.Fatalf("got %q, %v", tok, err)
	}
	form := f.lastForm
	if form.Get("grant_type") != "client_credentials" || form.Get("client_id") != "app-1" ||
		form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("form: %v", form)
	}
	hdr, claims, signed, sig := decodeJWT(t, form.Get("client_assertion"))
	if hdr["alg"] != "PS256" || hdr["x5t#S256"] != x5tS256(f.certDER) {
		t.Fatalf("header: %v", hdr)
	}
	h := sha256.Sum256(signed)
	if err := rsa.VerifyPSS(f.certPub, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if claims["aud"] != f.srv.URL+"/"+guid+"/oauth2/v2.0/token" || claims["iss"] != "app-1" || claims["sub"] != "app-1" || claims["jti"] == "" {
		t.Fatalf("claims: %v", claims)
	}
	if life := claims["exp"].(float64) - claims["nbf"].(float64); life <= 0 || life > 600 {
		t.Fatalf("lifetime %v s", life)
	}
	if strings.Contains(form.Encode(), "PRIVATE") {
		t.Fatal("private key sent")
	}
}

func TestWorkloadIdentity(t *testing.T) {
	f := newFake(t)
	file := filepath.Join(t.TempDir(), "token")
	os.WriteFile(file, []byte("federated-1\n"), 0o600)
	src := mustSource(t, f, Config{Auth: "workload_identity", TenantID: guid, ClientID: "app-2", TokenFile: file}, testEndpoints(f), noEnv)
	if _, err := src.token(context.Background(), resVault); err != nil || f.lastForm.Get("client_assertion") != "federated-1" {
		t.Fatalf("assertion %q, %v", f.lastForm.Get("client_assertion"), err)
	}
	// The file is rotated by the platform: read it again for a new token.
	os.WriteFile(file, []byte("federated-2"), 0o600)
	if _, err := src.token(context.Background(), resARM); err != nil || f.lastForm.Get("client_assertion") != "federated-2" {
		t.Fatalf("rotated assertion %q, %v", f.lastForm.Get("client_assertion"), err)
	}
}

func TestTokenCache(t *testing.T) {
	f := newFake(t)
	src := mustSource(t, f, Config{Auth: "managed_identity"}, testEndpoints(f), noEnv)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); src.token(context.Background(), resVault) }()
	}
	wg.Wait()
	if f.tokenCalls != 1 {
		t.Fatalf("want 1 token request under concurrency, got %d", f.tokenCalls)
	}
	c := src.(*cachedSource)
	c.mu.Lock()
	e := c.tokens[resVault]
	e.expires = time.Now().Add(4 * time.Minute) // inside the 5-minute margin
	c.tokens[resVault] = e
	c.mu.Unlock()
	src.token(context.Background(), resVault)
	if f.tokenCalls != 2 {
		t.Fatalf("token about to expire not refreshed (calls %d)", f.tokenCalls)
	}
}

func TestTokenError(t *testing.T) {
	f := newFake(t)
	f.failToken = true
	cfg := Config{Auth: "certificate", TenantID: guid, ClientID: "app-1", CertificateFile: f.writeCertPEM(t)}
	_, err := mustSource(t, f, cfg, testEndpoints(f), noEnv).token(context.Background(), resVault)
	if err == nil || !strings.Contains(err.Error(), "AADSTS700027") {
		t.Fatalf("got %v", err)
	}
}
