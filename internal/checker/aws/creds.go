package aws

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

const refreshMargin = 5 * time.Minute

// endpoints are the AWS hosts; tests point them at fakes.
type endpoints struct {
	imds          string // EC2 instance metadata
	ecsHost       string // ECS container credentials (relative URI)
	sts           func(region string) string
	rolesAnywhere func(region string) string
	acm           func(region string) string
	secrets       func(region string) string
	iam           string
}

func defaultEndpoints() endpoints {
	return endpoints{
		imds:          "http://169.254.169.254",
		ecsHost:       "http://169.254.170.2",
		sts:           func(r string) string { return "https://sts." + r + ".amazonaws.com" },
		rolesAnywhere: func(r string) string { return "https://rolesanywhere." + r + ".amazonaws.com" },
		acm:           func(r string) string { return "https://acm." + r + ".amazonaws.com" },
		secrets:       func(r string) string { return "https://secretsmanager." + r + ".amazonaws.com" },
		iam:           "https://iam.amazonaws.com",
	}
}

type credentialSource interface {
	get(ctx context.Context) (credentials, error)
}

// cachedSource keeps credentials until refreshMargin before they
// expire; the lock is held while fetching (one request at a time).
type cachedSource struct {
	fetch func(ctx context.Context) (credentials, error)
	mu    sync.Mutex
	creds credentials
}

func (c *cachedSource) get(ctx context.Context) (credentials, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.creds.AccessKeyID != "" && time.Until(c.creds.Expiration) > refreshMargin {
		return c.creds, nil
	}
	cr, err := c.fetch(ctx)
	if err != nil {
		return credentials{}, err
	}
	c.creds = cr
	return cr, nil
}

// noProxy: metadata and container endpoints are link-local / local;
// credentials must not travel through a proxy.
func noProxy(hc *http.Client) *http.Client {
	c := *hc
	if tr, ok := hc.Transport.(*http.Transport); ok {
		tr = tr.Clone()
		tr.Proxy = nil
		c.Transport = tr
	} else if hc.Transport == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		c.Transport = tr
	}
	return &c
}

// apiError is a non-2xx answer; retryable for throttling and 5xx.
type apiError struct {
	what   string
	status int
	msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("%s: HTTP %d %s", e.what, e.status, e.msg) }

func (e *apiError) retryable() bool {
	return e.status == 429 || e.status >= 500 || strings.Contains(e.msg, "Throttling") || strings.Contains(e.msg, "RequestLimitExceeded") ||
		strings.Contains(e.msg, "LimitExceeded")
}

func readBody(resp *http.Response, what string) ([]byte, error) {
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode/100 != 2 {
		msg := []rune(strings.TrimSpace(string(data)))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, &apiError{what, resp.StatusCode, logging.Sanitize(string(msg))}
	}
	return data, nil
}

// send builds, signs and sends a request (build is called again for
// every attempt: the signature carries the time) and returns the body.
// Throttling, 5xx and network errors are retried twice with backoff.
func send(ctx context.Context, hc *http.Client, what string, build func() (*http.Request, error)) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryWait * time.Duration(attempt)):
			}
		}
		req, err := build()
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		data, err := readBody(resp, what)
		var ae *apiError
		if err != nil && errors.As(err, &ae) && ae.retryable() {
			lastErr = err
			continue
		}
		return data, err
	}
	return nil, lastErr
}

// retryWait is the backoff unit (tests shorten it).
var retryWait = time.Second

func newCredentialSource(cfg Config, hc *http.Client, ep endpoints, getenv func(string) string) (credentialSource, error) {
	var f func(ctx context.Context) (credentials, error)
	switch cfg.Auth {
	case "instance_role":
		local := noProxy(hc)
		f = func(ctx context.Context) (credentials, error) { return instanceRole(ctx, local, ep, getenv) }
	case "web_identity":
		f = func(ctx context.Context) (credentials, error) { return webIdentity(ctx, hc, ep, cfg) }
	case "roles_anywhere":
		f = func(ctx context.Context) (credentials, error) { return rolesAnywhere(ctx, hc, ep, cfg) }
	default:
		return nil, fmt.Errorf("aws: unknown auth %q", cfg.Auth)
	}
	return &cachedSource{fetch: f}, nil
}

// checkContainerURI allows what the AWS SDKs allow for
// AWS_CONTAINER_CREDENTIALS_FULL_URI: https to any host, http only to
// loopback and the ECS / EKS Pod Identity link-local addresses. Errors
// never repeat the URI (it may carry credentials).
func checkContainerURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return errors.New("aws: AWS_CONTAINER_CREDENTIALS_FULL_URI not allowed (scheme or userinfo)")
	}
	host := u.Hostname()
	if u.Scheme == "https" || host == "localhost" || host == "169.254.170.2" || host == "169.254.170.23" || host == "fd00:ec2::23" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("aws: container credentials host %q not allowed over http", host)
}

type jsonCreds struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

func (j jsonCreds) toCreds(what string) (credentials, error) {
	exp, err := time.Parse(time.RFC3339, j.Expiration)
	if j.AccessKeyID == "" || j.SecretAccessKey == "" || err != nil {
		return credentials{}, fmt.Errorf("aws: %s returned no usable credentials", what)
	}
	return credentials{j.AccessKeyID, j.SecretAccessKey, j.Token, exp}, nil
}

func doGet(ctx context.Context, hc *http.Client, method, u string, hdr map[string]string) ([]byte, error) {
	return send(ctx, hc, method+" credentials endpoint", func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		return req, nil
	})
}

// containerToken is the authorization token for container credentials
// (file re-read every time, as it rotates).
func containerToken(getenv func(string) string) (map[string]string, error) {
	hdr := map[string]string{}
	if f := getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("aws: container authorization token: %w", err)
		}
		hdr["Authorization"] = strings.TrimSpace(string(b))
	} else if t := getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN"); t != "" {
		hdr["Authorization"] = t
	}
	if strings.ContainsAny(hdr["Authorization"], "\r\n") {
		return nil, errors.New("aws: container authorization token contains a line break")
	}
	return hdr, nil
}

// instanceRole: EKS Pod Identity / ECS container credentials when the
// environment says so, else EC2 IMDSv2 (never IMDSv1).
func instanceRole(ctx context.Context, hc *http.Client, ep endpoints, getenv func(string) string) (credentials, error) {
	var j jsonCreds
	// As botocore: the relative URI (ECS) wins over the full one.
	if rel := getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); rel != "" {
		if !strings.HasPrefix(rel, "/") || strings.Contains(rel, "@") {
			return credentials{}, errors.New("aws: invalid AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
		}
		hdr, err := containerToken(getenv)
		if err != nil {
			return credentials{}, err
		}
		b, err := doGet(ctx, hc, http.MethodGet, ep.ecsHost+rel, hdr)
		if err != nil {
			return credentials{}, fmt.Errorf("aws: ECS credentials: %w", err)
		}
		json.Unmarshal(b, &j)
		return j.toCreds("ECS credentials")
	}
	if full := getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); full != "" {
		if err := checkContainerURI(full); err != nil {
			return credentials{}, err
		}
		hdr, err := containerToken(getenv)
		if err != nil {
			return credentials{}, err
		}
		b, err := doGet(ctx, hc, http.MethodGet, full, hdr)
		if err != nil {
			return credentials{}, fmt.Errorf("aws: container credentials: %w", err)
		}
		json.Unmarshal(b, &j)
		return j.toCreds("container credentials")
	}
	tok, err := doGet(ctx, hc, http.MethodPut, ep.imds+"/latest/api/token", map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
	if err != nil {
		return credentials{}, fmt.Errorf("aws: IMDSv2 token: %w", err)
	}
	h := map[string]string{"X-aws-ec2-metadata-token": strings.TrimSpace(string(tok))}
	role, err := doGet(ctx, hc, http.MethodGet, ep.imds+"/latest/meta-data/iam/security-credentials/", h)
	if err != nil {
		return credentials{}, fmt.Errorf("aws: instance role: %w", err)
	}
	name := strings.TrimSpace(strings.Split(string(role), "\n")[0])
	if name == "" || strings.ContainsAny(name, "/?#") {
		return credentials{}, errors.New("aws: no instance role attached")
	}
	b, err := doGet(ctx, hc, http.MethodGet, ep.imds+"/latest/meta-data/iam/security-credentials/"+url.PathEscape(name), h)
	if err != nil {
		return credentials{}, fmt.Errorf("aws: instance role credentials: %w", err)
	}
	json.Unmarshal(b, &j)
	return j.toCreds("instance metadata")
}

type stsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

// stsCall posts a Query API action to STS, signed with c (unsigned when
// c is empty, as AssumeRoleWithWebIdentity is), and decodes the XML.
func stsCall(ctx context.Context, hc *http.Client, ep endpoints, region string, c credentials, form url.Values, out any) error {
	form.Set("Version", "2011-06-15")
	body := []byte(form.Encode())
	data, err := send(ctx, hc, "aws: STS "+form.Get("Action"), func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.sts(region)+"/", strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		if c.AccessKeyID != "" {
			signV4(req, body, c, region, "sts", time.Now())
		}
		return req, nil
	})
	if err != nil {
		return err
	}
	return xml.Unmarshal(data, out)
}

func (s stsCredentials) toCreds(what string) (credentials, error) {
	exp, err := time.Parse(time.RFC3339, s.Expiration)
	if s.AccessKeyID == "" || err != nil {
		return credentials{}, fmt.Errorf("aws: %s returned no usable credentials", what)
	}
	return credentials{s.AccessKeyID, s.SecretAccessKey, s.SessionToken, exp}, nil
}

func webIdentity(ctx context.Context, hc *http.Client, ep endpoints, cfg Config) (credentials, error) {
	tok, err := os.ReadFile(cfg.TokenFile) // rotated by the platform: read every time
	if err != nil {
		return credentials{}, fmt.Errorf("aws: token_file: %w", err)
	}
	var r struct {
		Creds stsCredentials `xml:"AssumeRoleWithWebIdentityResult>Credentials"`
	}
	form := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {cfg.RoleARN}, "RoleSessionName": {"expiry-radar"},
		"WebIdentityToken": {strings.TrimSpace(string(tok))}, "DurationSeconds": {"3600"}}
	if err := stsCall(ctx, hc, ep, cfg.stsRegion(), credentials{}, form, &r); err != nil {
		return credentials{}, err
	}
	return r.Creds.toCreds("AssumeRoleWithWebIdentity")
}

// assumeRole returns credentials for a role in another account.
func assumeRole(ctx context.Context, hc *http.Client, ep endpoints, region string, base credentials, a AssumeRole) (credentials, error) {
	var r struct {
		Creds stsCredentials `xml:"AssumeRoleResult>Credentials"`
	}
	form := url.Values{"Action": {"AssumeRole"}, "RoleArn": {a.RoleARN}, "RoleSessionName": {"expiry-radar"}, "DurationSeconds": {"3600"}}
	if a.ExternalID != "" {
		form.Set("ExternalId", a.ExternalID)
	}
	if err := stsCall(ctx, hc, ep, region, base, form, &r); err != nil {
		return credentials{}, err
	}
	return r.Creds.toCreds("AssumeRole")
}

// rolesAnywhere calls IAM Roles Anywhere CreateSession signed with the
// X.509 key (AWS4-X509-RSA-SHA256 / AWS4-X509-ECDSA-SHA256), as the
// official aws_signing_helper does: certificate serial as credential,
// X-Amz-X509 header, ARNs as query parameters.
func rolesAnywhere(ctx context.Context, hc *http.Client, ep endpoints, cfg Config) (credentials, error) {
	data, err := os.ReadFile(cfg.CertificateFile)
	if err != nil {
		return credentials{}, fmt.Errorf("aws: certificate_file: %w", err)
	}
	var certs []*x509.Certificate
	var key crypto.Signer
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			if c, err := x509.ParseCertificate(b.Bytes); err == nil {
				certs = append(certs, c)
			}
		case "PRIVATE KEY":
			if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
				key, _ = k.(crypto.Signer)
			}
		case "EC PRIVATE KEY":
			if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
				key = k
			}
		case "RSA PRIVATE KEY":
			if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
				key = k
			}
		}
	}
	if key == nil || len(certs) == 0 {
		return credentials{}, errors.New("aws: certificate_file needs a certificate and an unencrypted RSA or ECDSA key")
	}
	var leaf *x509.Certificate
	var chain []string
	for _, c := range certs {
		if leaf == nil && publicKeyEqual(c.PublicKey, key.Public()) {
			leaf = c
		} else {
			chain = append(chain, base64.StdEncoding.EncodeToString(c.Raw))
		}
	}
	if leaf == nil {
		return credentials{}, errors.New("aws: certificate_file has no certificate matching its key")
	}
	alg := "AWS4-X509-RSA-SHA256"
	if _, ok := key.(*ecdsa.PrivateKey); ok {
		alg = "AWS4-X509-ECDSA-SHA256"
	}
	region := cfg.rolesAnywhereRegion()
	q := url.Values{"profileArn": {cfg.ProfileARN}, "roleArn": {cfg.RoleARN}, "trustAnchorArn": {cfg.TrustAnchorARN}}
	body := []byte(`{"durationSeconds":3600}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.rolesAnywhere(region)+"/sessions?"+q.Encode(), strings.NewReader(string(body)))
	if err != nil {
		return credentials{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Amz-X509", base64.StdEncoding.EncodeToString(leaf.Raw))
	if len(chain) > 0 {
		req.Header.Set("X-Amz-X509-Chain", strings.Join(chain, ","))
	}
	at := time.Now()
	canon, signed := canonicalRequest(req, body, at)
	scope := at.UTC().Format("20060102") + "/" + region + "/rolesanywhere/aws4_request"
	toSign := alg + "\n" + at.UTC().Format(amzDateFormat) + "\n" + scope + "\n" + hashHex([]byte(canon))
	digest := sha256.Sum256([]byte(toSign))
	var sig []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, k, digest[:])
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	default:
		err = errors.New("unsupported key type")
	}
	if err != nil {
		return credentials{}, fmt.Errorf("aws: Roles Anywhere signature: %w", err)
	}
	req.Header.Set("Authorization", alg+" Credential="+leaf.SerialNumber.String()+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(sig))
	resp, err := hc.Do(req)
	if err != nil {
		return credentials{}, fmt.Errorf("aws: Roles Anywhere: %w", err)
	}
	out, err := readBody(resp, "aws: Roles Anywhere CreateSession")
	if err != nil {
		return credentials{}, err
	}
	var r struct {
		CredentialSet []struct {
			Credentials struct {
				AccessKeyID     string `json:"accessKeyId"`
				SecretAccessKey string `json:"secretAccessKey"`
				SessionToken    string `json:"sessionToken"`
				Expiration      string `json:"expiration"`
			} `json:"credentials"`
		} `json:"credentialSet"`
	}
	if json.Unmarshal(out, &r) != nil || len(r.CredentialSet) == 0 {
		return credentials{}, errors.New("aws: Roles Anywhere returned no credentials")
	}
	c := r.CredentialSet[0].Credentials
	return jsonCreds{c.AccessKeyID, c.SecretAccessKey, c.SessionToken, c.Expiration}.toCreds("Roles Anywhere")
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(eq); ok {
		return e.Equal(b)
	}
	return false
}
