// Package vault checks HashiCorp Vault for things that expire. Step 1:
// certificates issued by PKI mounts and the mounts' CA issuers. It uses
// the HTTP API directly and only reads public certificate data.
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
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// Config is the agent's "vault" section.
type Config struct {
	Address   string   `json:"address"`
	CAFile    string   `json:"ca_file"`
	Namespace string   `json:"namespace"`
	Auth      Auth     `json:"auth"`
	PKIMounts []string `json:"pki_mounts"`
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

var mountRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)

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
	if len(c.PKIMounts) == 0 {
		return errors.New("vault: pki_mounts must list at least one PKI mount")
	}
	for _, m := range c.PKIMounts {
		if !mountRe.MatchString(m) {
			return fmt.Errorf("vault: invalid mount path %q", m)
		}
	}
	return nil
}

const (
	maxParallel    = 8
	expiredHorizon = 30 * 24 * time.Hour // older expired certificates are history, not alerts
)

// Checker reports PKI certificates and CA issuers from Vault.
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
		return fmt.Errorf("%s %s: HTTP %d %s", method, "/v1/"+path, resp.StatusCode, strings.Join(e.Errors, "; "))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
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
	return records, errors.Join(errs...)
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
