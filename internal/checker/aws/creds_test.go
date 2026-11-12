package aws

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func noEnv(string) string { return "" }

func provider(t *testing.T, f *fakeAWS, cfg Config, getenv func(string) string) credentialSource {
	t.Helper()
	if cfg.Region == "" {
		cfg.Region = "eu-west-1"
	}
	p, err := newCredentialSource(cfg, f.srv.Client(), f.endpoints(), getenv)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInstanceRole_IMDSv2(t *testing.T) {
	f := newFakeAWS(t)
	c, err := provider(t, f, Config{Auth: "instance_role"}, noEnv).get(context.Background())
	if err != nil || c.AccessKeyID != "ASIA-BASE" || c.SessionToken != "token-ASIA-BASE" || c.Expiration.IsZero() {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestInstanceRole_ECSAndPodIdentity(t *testing.T) {
	f := newFakeAWS(t)
	env := map[string]string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/ecs-creds"}
	if c, err := provider(t, f, Config{Auth: "instance_role"}, func(k string) string { return env[k] }).get(context.Background()); err != nil || c.AccessKeyID != "ASIA-BASE" {
		t.Fatalf("ECS: %+v, %v", c, err)
	}
	tokFile := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tokFile, []byte("pod-token\n"), 0o600)
	env = map[string]string{"AWS_CONTAINER_CREDENTIALS_FULL_URI": f.meta.URL + "/pod-identity", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": tokFile}
	if c, err := provider(t, f, Config{Auth: "instance_role"}, func(k string) string { return env[k] }).get(context.Background()); err != nil || c.AccessKeyID != "ASIA-BASE" {
		t.Fatalf("Pod Identity: %+v, %v", c, err)
	}
}

// Like the AWS SDKs: a full container credentials URI must be local,
// or the credentials (and the authorization token) would go elsewhere.
func TestInstanceRole_ContainerURIMustBeLocal(t *testing.T) {
	f := newFakeAWS(t)
	for _, uri := range []string{"http://evil.example.com/creds", "http://169.254.170.3/creds", "https://user@127.0.0.1/x", "file:///etc/passwd"} {
		env := map[string]string{"AWS_CONTAINER_CREDENTIALS_FULL_URI": uri}
		if _, err := provider(t, f, Config{Auth: "instance_role"}, func(k string) string { return env[k] }).get(context.Background()); err == nil {
			t.Errorf("%s accepted", uri)
		}
	}
	for _, uri := range []string{"http://169.254.170.2/v2/credentials", "http://169.254.170.23/v1/credentials", "http://[fd00:ec2::23]/v1/credentials", "http://localhost:8080/x"} {
		if err := checkContainerURI(uri); err != nil {
			t.Errorf("%s refused: %v", uri, err)
		}
	}
}

func TestWebIdentity(t *testing.T) {
	f := newFakeAWS(t)
	tok := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tok, []byte("oidc-1"), 0o600)
	env := map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": tok, "AWS_ROLE_ARN": "arn:aws:iam::111111111111:role/expiry-radar"}
	cfg := Config{Auth: "web_identity", Regions: []string{"eu-west-1"}, Services: []string{"acm"}}
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tok)
	t.Setenv("AWS_ROLE_ARN", env["AWS_ROLE_ARN"])
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := provider(t, f, cfg, func(k string) string { return env[k] }).get(context.Background())
	if err != nil || c.AccessKeyID != "ASIA-BASE" {
		t.Fatalf("got %+v, %v", c, err)
	}
	form := f.forms[len(f.forms)-1]
	if form["RoleArn"] != env["AWS_ROLE_ARN"] || form["WebIdentityToken"] != "oidc-1" || form["RoleSessionName"] != "expiry-radar" || form["Version"] != "2011-06-15" {
		t.Fatalf("form %v", form)
	}
}

func TestRolesAnywhere(t *testing.T) {
	f := newFakeAWS(t)
	file, cert := writeECCert(t)
	cfg := Config{Auth: "roles_anywhere", CertificateFile: file, Region: "eu-west-1",
		TrustAnchorARN: "arn:aws:rolesanywhere:eu-west-1:111111111111:trust-anchor/ta",
		ProfileARN:     "arn:aws:rolesanywhere:eu-west-1:111111111111:profile/p",
		RoleARN:        "arn:aws:iam::111111111111:role/expiry-radar"}
	c, err := provider(t, f, cfg, noEnv).get(context.Background())
	if err != nil || c.AccessKeyID != "ASIA-BASE" {
		t.Fatalf("got %+v, %v", c, err)
	}
	h := f.raHeaders
	if h.Get("X-Amz-X509") != base64.StdEncoding.EncodeToString(cert.Raw) {
		t.Fatal("X-Amz-X509 is not the certificate")
	}
	for _, want := range []string{"profileArn=", "roleArn=", "trustAnchorArn="} {
		if !strings.Contains(f.raQuery, want) {
			t.Fatalf("query %q lacks %s (the ARNs are query parameters)", f.raQuery, want)
		}
	}
	if !strings.Contains(f.raBody, `"durationSeconds"`) {
		t.Fatalf("body %q", f.raBody)
	}
	auth := h.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-X509-ECDSA-SHA256 Credential=424242/") || !strings.Contains(auth, "/eu-west-1/rolesanywhere/aws4_request") ||
		!strings.Contains(auth, "x-amz-x509") {
		t.Fatalf("authorization %q", auth)
	}
	// Verify the signature with the certificate's public key, rebuilding
	// the string to sign from the received request.
	req, _ := http.NewRequest("POST", "https://x/sessions?"+f.raQuery, strings.NewReader(f.raBody))
	req.Host = ""
	for k, v := range h {
		if k != "Authorization" && k != "User-Agent" && k != "Content-Length" && k != "Accept-Encoding" {
			req.Header[k] = v
		}
	}
	req.URL.Host = strings.TrimPrefix(f.srv.URL, "https://")
	at, _ := time.Parse(amzDateFormat, h.Get("X-Amz-Date"))
	canon, _ := canonicalRequest(req, []byte(f.raBody), at)
	_, scope, _ := strings.Cut(strings.Split(strings.TrimPrefix(auth, "AWS4-X509-ECDSA-SHA256 Credential="), ",")[0], "/")
	toSign := "AWS4-X509-ECDSA-SHA256\n" + h.Get("X-Amz-Date") + "\n" + scope + "\n" + hashHex([]byte(canon))
	sig, _ := hex.DecodeString(auth[strings.Index(auth, "Signature=")+10:])
	digest := sha256.Sum256([]byte(toSign))
	if !ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("Roles Anywhere signature does not verify with the certificate key")
	}
}

func TestCredentialCache(t *testing.T) {
	f := newFakeAWS(t)
	p := provider(t, f, Config{Auth: "instance_role"}, noEnv)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p.get(context.Background()) }()
	}
	wg.Wait()
	if f.credCalls != 2 { // role name + credentials, once
		t.Fatalf("want one credential fetch under concurrency, got %d calls", f.credCalls)
	}
	c := p.(*cachedSource)
	c.mu.Lock()
	c.creds.Expiration = time.Now().Add(4 * time.Minute)
	c.mu.Unlock()
	p.get(context.Background())
	if f.credCalls != 4 {
		t.Fatalf("credentials about to expire not refreshed (%d calls)", f.credCalls)
	}
}
