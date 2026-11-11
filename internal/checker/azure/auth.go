package azure

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	resVault       = "https://vault.azure.net"
	resARM         = "https://management.azure.com"
	resGraph       = "https://graph.microsoft.com"
	refreshMargin  = 5 * time.Minute
	assertionLife  = 10 * time.Minute
	maxArcKeyBytes = 4096
)

// endpoints are the Azure hosts the checker talks to; tests point them
// at a fake.
type endpoints struct {
	login  string                   // Entra ID authority
	imds   string                   // IMDS token URL
	arm    string                   // Azure Resource Manager
	graph  string                   // Microsoft Graph
	vault  func(name string) string // Key Vault data plane base URL
	arcDir string                   // directory Arc challenge key files must live in
}

func defaultEndpoints() endpoints {
	arcDir := "/var/opt/azcmagent/tokens"
	if runtime.GOOS == "windows" {
		arcDir = filepath.Join(os.Getenv("ProgramData"), "AzureConnectedMachineAgent", "Tokens")
	}
	return endpoints{
		login:  "https://login.microsoftonline.com",
		imds:   "http://169.254.169.254/metadata/identity/oauth2/token",
		arm:    "https://management.azure.com",
		graph:  "https://graph.microsoft.com",
		vault:  func(n string) string { return "https://" + n + ".vault.azure.net" },
		arcDir: arcDir,
	}
}

// tokenSource returns an access token for a resource
// (e.g. https://vault.azure.net).
type tokenSource interface {
	token(ctx context.Context, resource string) (string, error)
}

type accessToken struct {
	value   string
	expires time.Time
}

type fetchFunc func(ctx context.Context, resource string) (accessToken, error)

// cachedSource keeps one token per resource until refreshMargin before
// it expires. The lock is held while fetching, so concurrent callers
// share one request.
type cachedSource struct {
	fetch  fetchFunc
	mu     sync.Mutex
	tokens map[string]accessToken
}

func (c *cachedSource) token(ctx context.Context, resource string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[resource]; ok && time.Until(t.expires) > refreshMargin {
		return t.value, nil
	}
	t, err := c.fetch(ctx, resource)
	if err != nil {
		return "", err
	}
	c.tokens[resource] = t
	return t.value, nil
}

// withoutProxy returns hc with a transport that never uses a proxy: the
// managed identity endpoints are link-local or localhost, and a token
// must not travel (in clear text, for IMDS) through a corporate proxy.
func withoutProxy(hc *http.Client) *http.Client {
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

func newTokenSource(cfg Config, hc *http.Client, ep endpoints, getenv func(string) string) (tokenSource, error) {
	if cfg.Auth == "managed_identity" {
		hc = withoutProxy(hc)
	}
	a := &authenticator{cfg: cfg, http: hc, ep: ep, getenv: getenv}
	var f fetchFunc
	switch cfg.Auth {
	case "managed_identity":
		f = a.managedIdentity
	case "certificate":
		f = func(ctx context.Context, res string) (accessToken, error) {
			assertion, err := a.certificateAssertion()
			if err != nil {
				return accessToken{}, err
			}
			return a.clientCredentials(ctx, res, assertion)
		}
	case "workload_identity":
		f = func(ctx context.Context, res string) (accessToken, error) {
			b, err := os.ReadFile(cfg.TokenFile) // rotated by the platform: read every time
			if err != nil {
				return accessToken{}, fmt.Errorf("azure: token_file: %w", err)
			}
			return a.clientCredentials(ctx, res, strings.TrimSpace(string(b)))
		}
	default:
		return nil, fmt.Errorf("azure: unknown auth %q", cfg.Auth)
	}
	return &cachedSource{fetch: f, tokens: map[string]accessToken{}}, nil
}

type authenticator struct {
	cfg    Config
	http   *http.Client
	ep     endpoints
	getenv func(string) string
}

func (a *authenticator) tokenURL() string {
	return strings.TrimRight(a.ep.login, "/") + "/" + url.PathEscape(a.cfg.TenantID) + "/oauth2/v2.0/token"
}

const maxBody = 32 << 20

// readBody reads at most 32 MiB (a larger answer is an error, not a
// truncated parse) and reports a non-2xx answer with the server's error
// description (never the request).
func readBody(resp *http.Response, what string) ([]byte, error) {
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if len(data) > maxBody {
		return nil, fmt.Errorf("%s: response larger than %d MiB", what, maxBody>>20)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error       json.RawMessage `json:"error"`
			Description string          `json:"error_description"`
			Message     string          `json:"message"`
		}
		json.Unmarshal(data, &e)
		msg := e.Description
		if msg == "" {
			msg = e.Message
		}
		if msg == "" && len(e.Error) > 0 {
			msg = string(e.Error)
		}
		return nil, fmt.Errorf("%s: HTTP %d %s", what, resp.StatusCode, msg)
	}
	return data, nil
}

func (a *authenticator) clientCredentials(ctx context.Context, resource, assertion string) (accessToken, error) {
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {a.cfg.ClientID},
		"scope":                 {resource + "/.default"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return accessToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.http.Do(req)
	if err != nil {
		return accessToken{}, fmt.Errorf("azure: token request: %w", err)
	}
	data, err := readBody(resp, "azure: token request")
	if err != nil {
		return accessToken{}, err
	}
	var r struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.AccessToken == "" {
		return accessToken{}, errors.New("azure: token response without access_token")
	}
	return accessToken{r.AccessToken, time.Now().Add(time.Duration(r.ExpiresIn) * time.Second)}, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// certificateAssertion signs a client assertion JWT (PS256) with the
// RSA key in certificate_file. The file is read on every call so a
// rotated certificate is picked up.
func (a *authenticator) certificateAssertion() (string, error) {
	data, err := os.ReadFile(a.cfg.CertificateFile)
	if err != nil {
		return "", fmt.Errorf("azure: certificate_file: %w", err)
	}
	var certs [][]byte
	var key *rsa.PrivateKey
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			certs = append(certs, b.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				return "", fmt.Errorf("azure: certificate_file key: %w", err)
			}
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return "", errors.New("azure: certificate_file key must be RSA")
			}
			key = rk
		case "RSA PRIVATE KEY":
			if key, err = x509.ParsePKCS1PrivateKey(b.Bytes); err != nil {
				return "", fmt.Errorf("azure: certificate_file key: %w", err)
			}
		}
	}
	if key == nil {
		return "", errors.New("azure: certificate_file needs an RSA private key (unencrypted PEM)")
	}
	// A chain file may hold CA certificates too: use the one that matches the key.
	var certDER []byte
	for _, der := range certs {
		if c, err := x509.ParseCertificate(der); err == nil {
			if pub, ok := c.PublicKey.(*rsa.PublicKey); ok && pub.Equal(&key.PublicKey) {
				certDER = der
				break
			}
		}
	}
	if certDER == nil {
		return "", errors.New("azure: certificate_file has no certificate matching its private key")
	}
	thumb := sha256.Sum256(certDER)
	hdr, _ := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": b64(thumb[:])})
	jti := make([]byte, 16)
	rand.Read(jti)
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{
		"aud": a.tokenURL(), "iss": a.cfg.ClientID, "sub": a.cfg.ClientID, "jti": hex.EncodeToString(jti),
		"nbf": now.Unix(), "iat": now.Unix(), "exp": now.Add(assertionLife).Unix(),
	})
	signed := b64(hdr) + "." + b64(claims)
	h := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return signed + "." + b64(sig), nil
}

// parseExpiresOn accepts expires_on as a number or a numeric string.
func parseExpiresOn(raw json.RawMessage) time.Time {
	s := strings.Trim(string(raw), `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Now().Add(refreshMargin + time.Minute) // unknown: reuse briefly
	}
	return time.Unix(n, 0)
}

// managedIdentity picks the endpoint from the environment: App Service /
// Container Apps, Azure Arc, else IMDS.
func (a *authenticator) managedIdentity(ctx context.Context, resource string) (accessToken, error) {
	endpoint, header := a.getenv("IDENTITY_ENDPOINT"), a.getenv("IDENTITY_HEADER")
	q := url.Values{"resource": {resource}}
	var u string
	hdr := http.Header{}
	arc := false
	switch {
	case endpoint != "" && header != "":
		q.Set("api-version", "2019-08-01")
		if a.cfg.ClientID != "" {
			q.Set("client_id", a.cfg.ClientID)
		}
		u = endpoint
		hdr.Set("X-IDENTITY-HEADER", header)
	case endpoint != "" && a.getenv("IMDS_ENDPOINT") != "":
		q.Set("api-version", "2020-06-01") // Arc: system-assigned only
		u, arc = endpoint, true
		hdr.Set("Metadata", "true")
	default:
		q.Set("api-version", "2018-02-01")
		if a.cfg.ClientID != "" {
			q.Set("client_id", a.cfg.ClientID)
		}
		u = a.ep.imds
		hdr.Set("Metadata", "true")
	}
	full := u + "?" + q.Encode()
	resp, err := a.get(ctx, full, hdr)
	if err != nil {
		return accessToken{}, err
	}
	if arc && resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		key, err := a.arcKey(resp.Header.Get("WWW-Authenticate"))
		if err != nil {
			return accessToken{}, err
		}
		hdr.Set("Authorization", "Basic "+key)
		if resp, err = a.get(ctx, full, hdr); err != nil {
			return accessToken{}, err
		}
	}
	data, err := readBody(resp, "azure: managed identity token")
	if err != nil {
		return accessToken{}, err
	}
	var r struct {
		AccessToken string          `json:"access_token"`
		ExpiresOn   json.RawMessage `json:"expires_on"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.AccessToken == "" {
		return accessToken{}, errors.New("azure: managed identity response without access_token")
	}
	return accessToken{r.AccessToken, parseExpiresOn(r.ExpiresOn)}, nil
}

func (a *authenticator) get(ctx context.Context, u string, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header = hdr.Clone()
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure: managed identity endpoint: %w", err)
	}
	return resp, nil
}

// arcKey reads the key file named by the Arc challenge. A malicious
// endpoint could name any file, so it must be a regular *.key file of
// at most 4 KiB directly inside the Arc token directory.
func (a *authenticator) arcKey(challenge string) (string, error) {
	_, realm, ok := strings.Cut(challenge, "realm=")
	if !ok {
		return "", errors.New("azure: Arc challenge without realm")
	}
	p := filepath.Clean(strings.Trim(strings.TrimSpace(realm), `"`))
	dir := filepath.Clean(a.ep.arcDir)
	sameDir := filepath.Dir(p) == dir
	if runtime.GOOS == "windows" { // NTFS paths are case-insensitive
		sameDir = strings.EqualFold(filepath.Dir(p), dir)
	}
	if a.ep.arcDir == "" || !filepath.IsAbs(dir) || !filepath.IsAbs(p) || !sameDir || !strings.EqualFold(filepath.Ext(p), ".key") {
		return "", fmt.Errorf("azure: Arc challenge file %q is not in %s", p, a.ep.arcDir)
	}
	st, err := os.Lstat(p)
	if err != nil {
		return "", fmt.Errorf("azure: Arc challenge file: %w", err)
	}
	if !st.Mode().IsRegular() || st.Size() > maxArcKeyBytes {
		return "", errors.New("azure: Arc challenge file is not a small regular file")
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// The file could be swapped (e.g. for a symlink) between Lstat and
	// Open: the opened file must be the one checked, and is read capped.
	if ost, err := f.Stat(); err != nil || !os.SameFile(st, ost) {
		return "", errors.New("azure: Arc challenge file changed while being read")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxArcKeyBytes+1))
	if err != nil || len(b) > maxArcKeyBytes {
		return "", errors.New("azure: Arc challenge file is too large")
	}
	return strings.TrimSpace(string(b)), nil
}
