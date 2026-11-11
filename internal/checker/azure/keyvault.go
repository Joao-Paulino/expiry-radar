package azure

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

const (
	kvAPIVersion  = "7.5"
	armAPIVersion = "2021-04-01"
	maxParallel   = 4
)

// Checker reports Key Vault certificates, secrets and keys that expire.
type Checker struct {
	cfg    Config
	http   *http.Client
	ep     endpoints
	getenv func(string) string

	srcMu sync.Mutex
	src   tokenSource // built on first use, kept across runs (token cache)
}

// New returns an Azure checker for cfg (already validated).
func New(cfg Config) *Checker {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Checker{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second, Transport: tr}, ep: defaultEndpoints(), getenv: os.Getenv}
}

// noRedirects keeps a bearer token on the URL it was meant for:
// redirects are returned as errors, never followed.
func noRedirects(hc *http.Client) *http.Client {
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func (c *Checker) tokenSource() (tokenSource, error) {
	c.srcMu.Lock()
	defer c.srcMu.Unlock()
	if c.src == nil {
		src, err := newTokenSource(c.cfg, noRedirects(c.http), c.ep, c.getenv)
		if err != nil {
			return nil, err
		}
		c.src = src
	}
	return c.src, nil
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "443"
}

// sameOrigin allows a nextLink only on the first page's https host
// (case-insensitive, default port 443 explicit or not) and path, without
// userinfo, so the bearer token never goes anywhere else.
func sameOrigin(first, next string) error {
	fu, err := url.Parse(first)
	if err != nil {
		return err
	}
	nu, err := url.Parse(next)
	if err != nil {
		return fmt.Errorf("refused malformed nextLink")
	}
	if nu.Scheme != "https" || fu.Scheme != "https" || nu.User != nil || !strings.EqualFold(nu.Hostname(), fu.Hostname()) ||
		port(nu) != port(fu) || nu.Path != fu.Path {
		return fmt.Errorf("refused nextLink to another host or path (%s%s)", nu.Hostname(), nu.Path)
	}
	return nil
}

func (c *Checker) Name() string { return "azure" }
func (c *Checker) Kind() string { return "certificate" }

type vaultTarget struct {
	name string
	meta map[string]string
}

// getPages follows nextLink and collects every "value" item. nextLink
// must stay on the first page's scheme and host, so the bearer token is
// never sent anywhere else.
func (c *Checker) getPages(ctx context.Context, first, token string) ([]json.RawMessage, error) {
	hc := noRedirects(c.http)
	var all []json.RawMessage
	next := first
	for page := 0; next != ""; page++ {
		if page == 1000 {
			return all, fmt.Errorf("more than 1000 pages; stopped")
		}
		if err := sameOrigin(first, next); err != nil {
			return all, err
		}
		nu, _ := url.Parse(next)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return all, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := hc.Do(req)
		if err != nil {
			return all, err
		}
		data, err := readBody(resp, "GET "+nu.Path)
		if err != nil {
			return all, err
		}
		var r struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"nextLink"`
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return all, fmt.Errorf("GET %s: %w", nu.Path, err)
		}
		all = append(all, r.Value...)
		next = r.NextLink
	}
	return all, nil
}

// discover lists the Key Vaults of a subscription via ARM.
func (c *Checker) discover(ctx context.Context, src tokenSource, sub string) ([]vaultTarget, error) {
	tok, err := src.token(ctx, resARM)
	if err != nil {
		return nil, err
	}
	q := url.Values{"$filter": {"resourceType eq 'Microsoft.KeyVault/vaults'"}, "api-version": {armAPIVersion}}
	items, err := c.getPages(ctx, strings.TrimRight(c.ep.arm, "/")+"/subscriptions/"+sub+"/resources?"+q.Encode(), tok)
	if err != nil {
		return nil, err
	}
	var out []vaultTarget
	for _, raw := range items {
		var r struct{ ID, Name, Location string }
		if json.Unmarshal(raw, &r) != nil || !vaultNameRe.MatchString(r.Name) {
			continue
		}
		rg := ""
		parts := strings.Split(r.ID, "/")
		for i := 0; i+1 < len(parts); i++ {
			if strings.EqualFold(parts[i], "resourceGroups") {
				rg = parts[i+1]
			}
		}
		out = append(out, vaultTarget{r.Name, map[string]string{"location": r.Location, "resource_group": rg, "subscription": sub}})
	}
	return out, nil
}

type kvItem struct {
	ID         string `json:"id"`
	Kid        string `json:"kid"`
	Managed    bool   `json:"managed"`
	Attributes struct {
		Enabled *bool  `json:"enabled"`
		Exp     *int64 `json:"exp"`
	} `json:"attributes"`
}

var collections = []struct{ path, kind string }{{"certificates", "certificate"}, {"secrets", "secret"}, {"keys", "key"}}

// checkVault lists certificates, secrets and keys (list endpoints only:
// attributes, never values).
func (c *Checker) checkVault(ctx context.Context, token string, v vaultTarget) ([]checker.ExpiryRecord, error) {
	var records []checker.ExpiryRecord
	var errs []error
	for _, col := range collections {
		items, err := c.getPages(ctx, strings.TrimRight(c.ep.vault(v.name), "/")+"/"+col.path+"?api-version="+kvAPIVersion, token)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", col.path, err))
		}
		for _, raw := range items {
			var it kvItem
			if json.Unmarshal(raw, &it) != nil {
				continue
			}
			id := it.ID
			if id == "" {
				id = it.Kid
			}
			name := id[strings.LastIndex(id, "/")+1:]
			if name == "" || it.Managed || it.Attributes.Exp == nil || (it.Attributes.Enabled != nil && !*it.Attributes.Enabled) {
				continue
			}
			meta := map[string]string{"vault": v.name}
			for k, val := range v.meta {
				meta[k] = val
			}
			records = append(records, checker.ExpiryRecord{Source: "azure://" + strings.ToLower(v.name) + ".vault.azure.net", Name: name, Kind: col.kind,
				ExpiresAt: time.Unix(*it.Attributes.Exp, 0).UTC(), Metadata: meta})
		}
	}
	return records, errors.Join(errs...)
}

// Check authenticates, resolves the vault list (configured + discovered)
// and checks every vault. A failing vault or subscription is reported in
// the error while the others still count; an authentication failure for
// Key Vault fails the run.
func (c *Checker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	src, err := c.tokenSource()
	if err != nil {
		return nil, err
	}
	kvToken, err := src.token(ctx, resVault)
	if err != nil {
		return nil, err
	}
	targets := map[string]vaultTarget{}
	for _, n := range c.cfg.KeyVaults {
		targets[strings.ToLower(n)] = vaultTarget{n, nil}
	}
	var errs []error
	for _, sub := range c.cfg.Subscriptions {
		found, err := c.discover(ctx, src, sub)
		if err != nil {
			errs = append(errs, fmt.Errorf("subscription %s: %w", sub, err))
		}
		for _, v := range found {
			targets[strings.ToLower(v.name)] = v
		}
	}
	names := make([]string, 0, len(targets))
	for k := range targets {
		names = append(names, k)
	}
	sort.Strings(names)

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		records []checker.ExpiryRecord
	)
	sem := make(chan struct{}, maxParallel)
	for _, k := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(v vaultTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			recs, err := c.checkVault(ctx, kvToken, v)
			mu.Lock()
			defer mu.Unlock()
			records = append(records, recs...)
			if err != nil {
				errs = append(errs, fmt.Errorf("vault %s: %w", v.name, err))
			}
		}(targets[k])
	}
	wg.Wait()
	return records, errors.Join(errs...)
}
