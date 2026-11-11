// Package vault checks HashiCorp Vault for things that expire:
// certificates issued by PKI mounts and the mounts' CA issuers, and KV v2
// secrets whose custom metadata holds an expiry date. It uses the HTTP
// API directly and only reads public certificate data and KV metadata,
// never secret values.
package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// Config is the agent's "vault" section.
type Config struct {
	Address   string   `json:"address"`
	CAFile    string   `json:"ca_file"`
	Namespace string   `json:"namespace"`
	Auth      Auth     `json:"auth"`
	PKIMounts []string `json:"pki_mounts"`
	// KVMounts are KV v2 mounts whose secrets may carry an expiry date
	// in their custom metadata, under KVExpiryKey (default "expires_at").
	KVMounts    []string `json:"kv_mounts"`
	KVExpiryKey string   `json:"kv_expiry_key"`
	// CheckTokens lists every token through its accessor. Off by default:
	// listing accessors needs "sudo" on auth/token/accessors.
	CheckTokens      bool `json:"check_tokens"`
	TokenMinTTLHours int  `json:"token_min_ttl_hours"` // default 24
	// AppRoleMounts are AppRole auth mounts whose secret IDs are checked.
	AppRoleMounts []string `json:"approle_mounts"`
	// LeasePrefixes are lease ID prefixes (e.g. "database/creds/") whose
	// dynamic secret leases are checked. Listing leases needs "sudo" on
	// sys/leases/lookup/<prefix>*.
	LeasePrefixes    []string `json:"lease_prefixes"`
	LeaseMinTTLHours int      `json:"lease_min_ttl_hours"` // default 24
}

const defaultExpiryKey = "expires_at"

func (c Config) expiryKey() string {
	if c.KVExpiryKey == "" {
		return defaultExpiryKey
	}
	return c.KVExpiryKey
}

// Auth selects exactly one way to authenticate.
type Auth struct {
	TokenFile string   `json:"token_file"`
	AppRole   *AppRole `json:"approle"`
}

// AppRole logs in with role_id + secret_id; the token is revoked after
// each run.
type AppRole struct {
	RoleID       string `json:"role_id"`
	SecretIDFile string `json:"secret_id_file"`
	Mount        string `json:"mount"` // default "approle"
}

var (
	mountRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)
	keyRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// Validate reports a configuration that cannot work.
func (c Config) Validate() error {
	u, err := url.Parse(c.Address)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("vault: address must be an https URL")
	}
	hasToken, hasAppRole := c.Auth.TokenFile != "", c.Auth.AppRole != nil
	if hasToken == hasAppRole {
		return errors.New("vault: set exactly one of auth.token_file or auth.approle")
	}
	if hasAppRole && (c.Auth.AppRole.RoleID == "" || c.Auth.AppRole.SecretIDFile == "") {
		return errors.New("vault: auth.approle needs role_id and secret_id_file")
	}
	if len(c.PKIMounts)+len(c.KVMounts)+len(c.AppRoleMounts)+len(c.LeasePrefixes) == 0 && !c.CheckTokens {
		return errors.New("vault: set at least one of pki_mounts, kv_mounts, approle_mounts, lease_prefixes or check_tokens")
	}
	if c.TokenMinTTLHours < 0 || c.LeaseMinTTLHours < 0 {
		return errors.New("vault: token_min_ttl_hours and lease_min_ttl_hours must not be negative")
	}
	for _, p := range c.LeasePrefixes {
		if !strings.HasSuffix(p, "/") || !mountRe.MatchString(strings.TrimSuffix(p, "/")) {
			return fmt.Errorf("vault: invalid lease prefix %q (e.g. \"database/creds/\")", p)
		}
	}
	mounts := append(append(append([]string{}, c.PKIMounts...), c.KVMounts...), c.AppRoleMounts...)
	for _, m := range mounts {
		if !mountRe.MatchString(m) {
			return fmt.Errorf("vault: invalid mount path %q", m)
		}
	}
	if !keyRe.MatchString(c.expiryKey()) {
		return fmt.Errorf("vault: invalid kv_expiry_key %q", c.KVExpiryKey)
	}
	return nil
}

const (
	maxParallel    = 8
	expiredHorizon = 30 * 24 * time.Hour // older expired certificates are history, not alerts
)

// Checker reports PKI certificates, CA issuers and expiring KV v2
// secrets from Vault.
type Checker struct {
	cfg        Config
	httpClient *http.Client // tests override
}

// New returns a Vault checker for cfg.
func New(cfg Config) *Checker { return &Checker{cfg: cfg} }

func (c *Checker) Name() string { return "vault" }
func (c *Checker) Kind() string { return "certificate" }

func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return s, nil
}

func (c *Checker) client() (*http.Client, error) {
	if c.httpClient != nil {
		return c.httpClient, nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if c.cfg.CAFile != "" {
		pemBytes, err := os.ReadFile(c.cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("vault: reading ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("vault: ca_file contains no PEM certificates")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}, nil
}

type session struct {
	c     *Checker
	http  *http.Client
	token string
}

// call performs one Vault API request and decodes the JSON response.
func (s *session) call(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	u := strings.TrimRight(s.c.cfg.Address, "/") + "/v1/" + path
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if s.token != "" {
		req.Header.Set("X-Vault-Token", s.token)
	}
	if s.c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.c.cfg.Namespace)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Errors []string `json:"errors"`
		}
		json.Unmarshal(data, &e)
		return &apiError{fmt.Sprintf("%s %s", method, "/v1/"+path), resp.StatusCode, e.Errors}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// apiError is a non-2xx answer from Vault.
type apiError struct {
	request string
	status  int
	errors  []string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s: HTTP %d %s", e.request, e.status, strings.Join(e.errors, "; "))
}

// isEmptyList reports Vault's answer to a LIST of a path with no
// entries: 404 with no error messages.
func isEmptyList(err error) bool {
	var e *apiError
	return errors.As(err, &e) && e.status == http.StatusNotFound && len(e.errors) == 0
}

func (s *session) list(ctx context.Context, path string) ([]string, error) {
	var r struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	err := s.call(ctx, http.MethodGet, path+"?list=true", nil, &r)
	return r.Data.Keys, err
}

func (c *Checker) login(ctx context.Context, hc *http.Client) (*session, bool, error) {
	s := &session{c: c, http: hc}
	if c.cfg.Auth.TokenFile != "" {
		tok, err := readTrimmed(c.cfg.Auth.TokenFile)
		if err != nil {
			return nil, false, fmt.Errorf("vault: token_file: %w", err)
		}
		s.token = tok
		return s, false, nil
	}
	ar := c.cfg.Auth.AppRole
	secret, err := readTrimmed(ar.SecretIDFile)
	if err != nil {
		return nil, false, fmt.Errorf("vault: secret_id_file: %w", err)
	}
	mount := ar.Mount
	if mount == "" {
		mount = "approle"
	}
	var r struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := s.call(ctx, http.MethodPost, "auth/"+mount+"/login", map[string]string{"role_id": ar.RoleID, "secret_id": secret}, &r); err != nil {
		return nil, false, fmt.Errorf("vault: AppRole login failed: %w", err)
	}
	if r.Auth.ClientToken == "" {
		return nil, false, errors.New("vault: AppRole login returned no token")
	}
	s.token = r.Auth.ClientToken
	return s, true, nil
}

func parsePEM(s string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

// Check logs in, reads every configured PKI mount and returns one
// record per certificate name (the latest) plus one per CA issuer. A
// failing mount is reported in the error while the others still count.
func (c *Checker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	hc, err := c.client()
	if err != nil {
		return nil, err
	}
	s, revoke, err := c.login(ctx, hc)
	if err != nil {
		return nil, err
	}
	if revoke {
		defer s.call(context.WithoutCancel(ctx), http.MethodPost, "auth/token/revoke-self", nil, nil)
	}

	host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimRight(c.cfg.Address, "/"), "https://"), "http://")
	var records []checker.ExpiryRecord
	var errs []error
	for _, mount := range c.cfg.PKIMounts {
		recs, err := c.checkMount(ctx, s, "vault://"+host+"/"+mount, mount)
		records = append(records, recs...)
		if err != nil {
			errs = append(errs, fmt.Errorf("mount %s: %w", mount, err))
		}
	}
	for _, mount := range c.cfg.KVMounts {
		recs, err := c.checkKV(ctx, s, "vault://"+host+"/"+mount, mount)
		records = append(records, recs...)
		if err != nil {
			errs = append(errs, fmt.Errorf("kv mount %s: %w", mount, err))
		}
	}
	if c.cfg.CheckTokens {
		recs, err := c.checkTokens(ctx, s, "vault://"+host+"/auth/token")
		records = append(records, recs...)
		if err != nil {
			errs = append(errs, fmt.Errorf("tokens: %w", err))
		}
	}
	for _, mount := range c.cfg.AppRoleMounts {
		recs, err := c.checkSecretIDs(ctx, s, "vault://"+host+"/auth/"+mount, mount)
		records = append(records, recs...)
		if err != nil {
			errs = append(errs, fmt.Errorf("approle mount %s: %w", mount, err))
		}
	}
	for _, prefix := range c.cfg.LeasePrefixes {
		recs, err := c.checkLeases(ctx, s, "vault://"+host+"/sys/leases", prefix)
		records = append(records, recs...)
		if err != nil {
			errs = append(errs, fmt.Errorf("leases %s: %w", prefix, err))
		}
	}
	return records, errors.Join(errs...)
}

// escapePath escapes each segment of a KV path for the URL.
func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// parseExpiry accepts a date (2027-03-31, midnight UTC) or RFC 3339.
func parseExpiry(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if t, err := time.Parse(time.DateOnly, v); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, v)
}

// checkKV walks a KV v2 mount's metadata tree and reports the secrets
// whose custom metadata holds an expiry date. It reads metadata only:
// the data/ endpoints (secret values) are never called.
func (c *Checker) checkKV(ctx context.Context, s *session, source, mount string) ([]checker.ExpiryRecord, error) {
	var paths []string
	folders := []string{""}
	for len(folders) > 0 {
		dir := folders[0]
		folders = folders[1:]
		keys, err := s.list(ctx, mount+"/metadata/"+escapePath(dir))
		if err != nil {
			if isEmptyList(err) {
				continue
			}
			return nil, err
		}
		for _, k := range keys {
			if strings.HasSuffix(k, "/") {
				folders = append(folders, dir+k)
			} else {
				paths = append(paths, dir+k)
			}
		}
	}

	key := c.cfg.expiryKey()
	var (
		records  []checker.ExpiryRecord
		firstErr error
		mu       sync.Mutex
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, maxParallel)
	for _, p := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			var r struct {
				Data struct {
					CurrentVersion int               `json:"current_version"`
					CustomMetadata map[string]string `json:"custom_metadata"`
					Versions       map[string]struct {
						DeletionTime string `json:"deletion_time"`
						Destroyed    bool   `json:"destroyed"`
					} `json:"versions"`
				} `json:"data"`
			}
			err := s.call(ctx, http.MethodGet, mount+"/metadata/"+escapePath(p), nil, &r)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("secret %s: %w", p, err)
				}
				return
			}
			raw, ok := r.Data.CustomMetadata[key]
			if !ok {
				return
			}
			version := fmt.Sprint(r.Data.CurrentVersion)
			if v, ok := r.Data.Versions[version]; ok && (v.DeletionTime != "" || v.Destroyed) {
				return // current version deleted: nothing in use to renew
			}
			exp, err := parseExpiry(raw)
			if err != nil {
				log.Printf("vault: %s/%s: %s %q is not a date (use 2027-03-31 or RFC 3339); skipped",
					mount, logging.Sanitize(p), key, logging.Sanitize(raw))
				// An error, so the run is incomplete and the secret is not
				// taken for gone (its last known date keeps alerting).
				if firstErr == nil {
					firstErr = fmt.Errorf("secret %s: %s is not a date", p, key)
				}
				return
			}
			records = append(records, checker.ExpiryRecord{Source: source, Name: p, Kind: "secret", ExpiresAt: exp,
				Metadata: map[string]string{"mount": mount, "version": version}})
		}(p)
	}
	wg.Wait()
	return records, firstErr
}

func (c *Checker) checkMount(ctx context.Context, s *session, source, mount string) ([]checker.ExpiryRecord, error) {
	serials, err := s.list(ctx, mount+"/certs")
	if err != nil {
		return nil, err
	}
	now := time.Now()
	type found struct {
		cert   *x509.Certificate
		serial string
	}
	latest := map[string]found{}
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for _, serial := range serials {
		wg.Add(1)
		sem <- struct{}{}
		go func(serial string) {
			defer wg.Done()
			defer func() { <-sem }()
			var r struct {
				Data struct {
					Certificate    string `json:"certificate"`
					RevocationTime int64  `json:"revocation_time"`
				} `json:"data"`
			}
			err := s.call(ctx, http.MethodGet, mount+"/cert/"+url.PathEscape(serial), nil, &r)
			var cert *x509.Certificate
			if err == nil {
				cert, err = parsePEM(r.Data.Certificate)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("certificate %s: %w", serial, err)
				}
				return
			}
			// CA certificates are listed here too; they are reported once,
			// as issuers, below.
			if r.Data.RevocationTime > 0 || cert.IsCA || now.Sub(cert.NotAfter) > expiredHorizon {
				return
			}
			name := cert.Subject.CommonName
			if name == "" {
				name = serial
			}
			if prev, ok := latest[name]; !ok || cert.NotAfter.After(prev.cert.NotAfter) {
				latest[name] = found{cert, serial}
			}
		}(serial)
	}
	wg.Wait()

	var records []checker.ExpiryRecord
	for name, f := range latest {
		records = append(records, checker.ExpiryRecord{Source: source, Name: name, Kind: "certificate", ExpiresAt: f.cert.NotAfter,
			Metadata: map[string]string{"serial": f.serial, "issuer": f.cert.Issuer.CommonName, "mount": mount}})
	}

	issuers, err := s.list(ctx, mount+"/issuers")
	if err != nil {
		return records, errors.Join(firstErr, err)
	}
	for _, id := range issuers {
		var r struct {
			Data struct {
				Certificate string `json:"certificate"`
				IssuerName  string `json:"issuer_name"`
			} `json:"data"`
		}
		if err := s.call(ctx, http.MethodGet, mount+"/issuer/"+url.PathEscape(id), nil, &r); err != nil {
			firstErr = errors.Join(firstErr, err)
			continue
		}
		cert, err := parsePEM(r.Data.Certificate)
		if err != nil {
			firstErr = errors.Join(firstErr, fmt.Errorf("issuer %s: %w", id, err))
			continue
		}
		name := r.Data.IssuerName
		if name == "" {
			name = cert.Subject.CommonName
		}
		if name == "" {
			name = id
		}
		records = append(records, checker.ExpiryRecord{Source: source, Name: name, Kind: "ca_certificate", ExpiresAt: cert.NotAfter,
			Metadata: map[string]string{"issuer_id": id, "common_name": cert.Subject.CommonName, "mount": mount}})
	}
	return records, firstErr
}
