package gcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

const rotationGrace = 2 * 24 * time.Hour

var assetTypes = map[string]string{
	"certificate_manager":  "certificatemanager.googleapis.com/Certificate",
	"compute_ssl":          "compute.googleapis.com/SslCertificate",
	"service_account_keys": "iam.googleapis.com/ServiceAccountKey",
	"secret_manager":       "secretmanager.googleapis.com/Secret",
}

// Checker reports expiring Google Cloud resources. One instance per
// service group (see Checkers) so a failing service never makes another
// one's run incomplete.
type Checker struct {
	cfg      Config
	name     string
	services []string
	http     *http.Client
	ep       endpoints
	src      *tokenSource
	numbers  map[string]string // project ID -> number
}

func newChecker(cfg Config, name string, services []string) *Checker {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	hc := &http.Client{Timeout: 20 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Checker{cfg: cfg, name: name, services: services, http: hc, ep: defaultEndpoints()}
}

// Checkers: certificates as "gcp", keys as "gcp-service-account-keys",
// secrets as "gcp-secrets".
func Checkers(cfg Config) []checker.Checker {
	groups := map[string][]string{}
	for _, s := range cfg.services() {
		switch s {
		case "service_account_keys":
			groups["gcp-service-account-keys"] = append(groups["gcp-service-account-keys"], s)
		case "secret_manager":
			groups["gcp-secrets"] = append(groups["gcp-secrets"], s)
		default:
			groups["gcp"] = append(groups["gcp"], s)
		}
	}
	var out []checker.Checker
	for _, n := range []string{"gcp", "gcp-service-account-keys", "gcp-secrets"} {
		if g := groups[n]; len(g) > 0 {
			out = append(out, newChecker(cfg, n, g))
		}
	}
	return out
}

func (c *Checker) Name() string { return c.name }
func (c *Checker) Kind() string { return "certificate" }

func (c *Checker) get(ctx context.Context, tok, u string, out any) error {
	data, err := do(ctx, c.http, strings.SplitN(strings.TrimPrefix(u, "https://"), "?", 2)[0], func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		return req, err
	})
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// pages calls base (with pageToken) until done; each page is decoded
// into a fresh value handed to visit, which returns the next token.
func (c *Checker) pages(ctx context.Context, tok, base string, visit func(data json.RawMessage) (string, error)) error {
	next := ""
	for i := 0; i < 1000; i++ {
		u := base
		if next != "" {
			sep := "?"
			if strings.Contains(u, "?") {
				sep = "&"
			}
			u += sep + "pageToken=" + url.QueryEscape(next)
		}
		var raw json.RawMessage
		if err := c.get(ctx, tok, u, &raw); err != nil {
			return err
		}
		n, err := visit(raw)
		if err != nil || n == "" {
			return err
		}
		next = n
	}
	return errors.New("more than 1000 pages")
}

// projects returns the projects to check for one service: the
// configured list, plus (with an organization or folders) every project
// where Asset Inventory finds that asset type. Asset Inventory is used
// to find projects only, never for dates (it can lag by days).
func (c *Checker) projects(ctx context.Context, tok, service string) ([]string, error) {
	set := map[string]bool{}
	var errs []error
	for _, p := range c.cfg.Projects {
		n, err := c.projectNumber(ctx, tok, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("project %s: %w", p, err))
			continue
		}
		set[n] = true
	}
	for _, scope := range c.cfg.scopes() {
		base := c.ep.api("cloudasset") + "/v1/" + scope + ":searchAllResources?pageSize=500&assetTypes=" + url.QueryEscape(assetTypes[service])
		err := c.pages(ctx, tok, base, func(raw json.RawMessage) (string, error) {
			var r struct {
				Results []struct {
					Project string `json:"project"`
				} `json:"results"`
				NextPageToken string `json:"nextPageToken"`
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				return "", err
			}
			for _, x := range r.Results {
				if p := strings.TrimPrefix(x.Project, "projects/"); projectRe.MatchString(p) {
					set[p] = true
				}
			}
			return r.NextPageToken, nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("asset inventory %s: %w", scope, err))
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, errors.Join(errs...)
}

// projectNumber resolves a project ID to its number (Asset Inventory
// reports numbers): one identity per project, whatever the config says.
func (c *Checker) projectNumber(ctx context.Context, tok, p string) (string, error) {
	if idRe.MatchString(p) {
		return p, nil
	}
	if n, ok := c.numbers[p]; ok {
		return n, nil
	}
	var r struct {
		Name string `json:"name"`
	}
	if err := c.get(ctx, tok, c.ep.api("cloudresourcemanager")+"/v3/projects/"+p, &r); err != nil {
		return "", err
	}
	n := strings.TrimPrefix(r.Name, "projects/")
	if !idRe.MatchString(n) {
		return "", errors.New("no project number")
	}
	if c.numbers == nil {
		c.numbers = map[string]string{}
	}
	c.numbers[p] = n
	return n, nil
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t.UTC(), err
}

// Check lists every service of this checker in every project. A project
// where the API is not enabled has nothing of that kind; any other
// failure is reported while the other projects still count.
func (c *Checker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	if c.src == nil {
		src, err := newTokenSource(c.cfg, c.http, c.ep)
		if err != nil {
			return nil, err
		}
		c.src = src
	}
	tok, err := c.src.get(ctx)
	if err != nil {
		return nil, err
	}
	var records []checker.ExpiryRecord
	var errs []error
	for _, svc := range c.services {
		projects, err := c.projects(ctx, tok, svc)
		if err != nil {
			errs = append(errs, err)
		}
		for _, p := range projects {
			if tok, err = c.src.get(ctx); err != nil { // cached; renewed on long runs
				return records, errors.Join(append(errs, err)...)
			}
			recs, err := c.list(ctx, tok, svc, p)
			records = append(records, recs...)
			var ae *apiError
			if err != nil && !(errors.As(err, &ae) && ae.disabled()) {
				errs = append(errs, fmt.Errorf("project %s %s: %w", p, svc, err))
			}
		}
	}
	return records, errors.Join(errs...)
}

func (c *Checker) list(ctx context.Context, tok, svc, project string) ([]checker.ExpiryRecord, error) {
	switch svc {
	case "certificate_manager":
		return c.certificateManager(ctx, tok, project)
	case "compute_ssl":
		return c.computeSSL(ctx, tok, project)
	case "service_account_keys":
		return c.serviceAccountKeys(ctx, tok, project)
	case "secret_manager":
		return c.secretManager(ctx, tok, project)
	}
	return nil, nil
}

func lastSegment(name string) string { return name[strings.LastIndex(name, "/")+1:] }

// certificateManager lists certificates in every location ("-").
func (c *Checker) certificateManager(ctx context.Context, tok, project string) ([]checker.ExpiryRecord, error) {
	var out []checker.ExpiryRecord
	var bad []string
	base := c.ep.api("certificatemanager") + "/v1/projects/" + project + "/locations/-/certificates?pageSize=500"
	err := c.pages(ctx, tok, base, func(raw json.RawMessage) (string, error) {
		var r struct {
			Certificates []struct {
				Name, ExpireTime string
				SanDnsnames      []string                `json:"sanDnsnames"`
				Managed          *struct{ State string } `json:"managed"`
			} `json:"certificates"`
			NextPageToken string   `json:"nextPageToken"`
			Unreachable   []string `json:"unreachable"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return "", err
		}
		if len(r.Unreachable) > 0 { // a location was down: the list is partial
			return "", fmt.Errorf("unreachable locations %s", strings.Join(r.Unreachable, ", "))
		}
		for _, x := range r.Certificates {
			if x.ExpireTime == "" {
				continue // managed certificate not provisioned yet
			}
			exp, err := parseTime(x.ExpireTime)
			if err != nil {
				bad = append(bad, x.Name)
				continue
			}
			parts := strings.Split(x.Name, "/") // projects/P/locations/L/certificates/C
			loc := ""
			if len(parts) == 6 {
				loc = parts[3]
			}
			name := lastSegment(x.Name)
			if len(x.SanDnsnames) > 0 {
				name = x.SanDnsnames[0]
			}
			meta := map[string]string{"project": project, "location": loc, "type": "self_managed"}
			if x.Managed != nil {
				meta["type"], meta["state"] = "managed", x.Managed.State
			}
			out = append(out, checker.ExpiryRecord{Source: "gcp://certificatemanager/" + project + "/" + loc + "/" + lastSegment(x.Name),
				Name: name, Kind: "certificate", ExpiresAt: exp, Metadata: meta})
		}
		return r.NextPageToken, nil
	})
	if err == nil && len(bad) > 0 {
		err = fmt.Errorf("unreadable expireTime on %s", strings.Join(bad, ", "))
	}
	return out, err
}

// computeSSL lists classic load balancer SSL certificates, global and
// regional (aggregated list).
func (c *Checker) computeSSL(ctx context.Context, tok, project string) ([]checker.ExpiryRecord, error) {
	var out []checker.ExpiryRecord
	var bad []string
	base := c.ep.api("compute") + "/compute/v1/projects/" + project + "/aggregated/sslCertificates?maxResults=500"
	err := c.pages(ctx, tok, base, func(raw json.RawMessage) (string, error) {
		var r struct {
			Items map[string]struct {
				SslCertificates []struct {
					Name, ExpireTime, Type  string
					SubjectAlternativeNames []string
				} `json:"sslCertificates"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return "", err
		}
		for scope, it := range r.Items {
			for _, x := range it.SslCertificates {
				if x.ExpireTime == "" {
					continue
				}
				exp, err := parseTime(x.ExpireTime)
				if err != nil {
					bad = append(bad, x.Name)
					continue
				}
				name := x.Name
				if len(x.SubjectAlternativeNames) > 0 {
					name = x.SubjectAlternativeNames[0]
				}
				out = append(out, checker.ExpiryRecord{Source: "gcp://compute/" + project + "/" + scope + "/" + x.Name, Name: name,
					Kind: "certificate", ExpiresAt: exp, Metadata: map[string]string{"project": project, "scope": scope, "type": strings.ToLower(x.Type)}})
			}
		}
		return r.NextPageToken, nil
	})
	if err == nil && len(bad) > 0 {
		err = fmt.Errorf("unreadable expireTime on %s", strings.Join(bad, ", "))
	}
	return out, err
}

// serviceAccountKeys reports user-managed keys: due key_max_age_days
// (default 90, CIS) after creation, or at their own expiry if earlier.
// Disabled keys are listed with alerts=off (they cannot be used, but
// should be deleted). Google-managed keys are skipped.
func (c *Checker) serviceAccountKeys(ctx context.Context, tok, project string) ([]checker.ExpiryRecord, error) {
	maxAge := c.cfg.KeyMaxAgeDays
	if maxAge == 0 {
		maxAge = 90
	}
	var accounts []string
	err := c.pages(ctx, tok, c.ep.api("iam")+"/v1/projects/"+project+"/serviceAccounts?pageSize=100", func(raw json.RawMessage) (string, error) {
		var r struct {
			Accounts []struct {
				Email string `json:"email"`
			} `json:"accounts"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return "", err
		}
		for _, a := range r.Accounts {
			accounts = append(accounts, a.Email)
		}
		return r.NextPageToken, nil
	})
	if err != nil {
		return nil, err
	}
	var out []checker.ExpiryRecord
	var errs []error
	for _, email := range accounts {
		var r struct {
			Keys []struct {
				Name, ValidAfterTime, ValidBeforeTime, KeyType string
				Disabled                                       bool
			} `json:"keys"`
		}
		u := c.ep.api("iam") + "/v1/projects/" + project + "/serviceAccounts/" + url.PathEscape(email) + "/keys?keyTypes=USER_MANAGED"
		if err := c.get(ctx, tok, u, &r); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", email, err))
			continue
		}
		for _, k := range r.Keys {
			if k.KeyType != "" && k.KeyType != "USER_MANAGED" {
				continue
			}
			created, err := parseTime(k.ValidAfterTime)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: unreadable validAfterTime", email))
				continue
			}
			exp := created.Add(time.Duration(maxAge) * 24 * time.Hour)
			if before, err := parseTime(k.ValidBeforeTime); err == nil && before.Before(exp) {
				exp = before
			}
			id := lastSegment(k.Name)
			meta := map[string]string{"project": project, "service_account": email, "key_id": id, "created": created.Format(time.RFC3339),
				"max_age_days": strconv.Itoa(maxAge), "status": "active"}
			if k.Disabled {
				meta["status"], meta["alerts"] = "disabled", "off"
			}
			short := id
			if len(short) > 8 {
				short = short[:8]
			}
			out = append(out, checker.ExpiryRecord{Source: "gcp://iam/" + project + "/" + email + "/keys/" + id, Name: email + " · " + short,
				Kind: "service_account_key", ExpiresAt: exp, Metadata: meta})
		}
	}
	return out, errors.Join(errs...)
}

// secretManager reports secrets with an expiry (Secret Manager deletes
// them then) and secrets with a rotation period: Google only notifies,
// it does not rotate, so rotation is due at the newest enabled
// version's creation + period + grace. The earlier date wins.
func (c *Checker) secretManager(ctx context.Context, tok, project string) ([]checker.ExpiryRecord, error) {
	type secret struct {
		Name, ExpireTime string
		Rotation         *struct{ RotationPeriod, NextRotationTime string } `json:"rotation"`
	}
	var secrets []secret
	err := c.pages(ctx, tok, c.ep.api("secretmanager")+"/v1/projects/"+project+"/secrets?pageSize=250", func(raw json.RawMessage) (string, error) {
		var r struct {
			Secrets       []secret `json:"secrets"`
			NextPageToken string   `json:"nextPageToken"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return "", err
		}
		secrets = append(secrets, r.Secrets...)
		return r.NextPageToken, nil
	})
	if err != nil {
		return nil, err
	}
	var out []checker.ExpiryRecord
	var errs []error
	for _, s := range secrets {
		meta := map[string]string{"project": project}
		var exp time.Time
		if s.ExpireTime != "" {
			t, err := parseTime(s.ExpireTime)
			if err != nil {
				errs = append(errs, fmt.Errorf("secret %s: unreadable expireTime", lastSegment(s.Name)))
				continue
			}
			exp, meta["reason"] = t, "expire_time"
		}
		// rotationPeriod is input-only (not returned on reads):
		// nextRotationTime (+ grace) is the due date; with a period, the
		// newest enabled version + period + grace may be earlier.
		if s.Rotation != nil && s.Rotation.NextRotationTime != "" && s.Rotation.RotationPeriod == "" {
			t, err := parseTime(s.Rotation.NextRotationTime)
			if err != nil {
				errs = append(errs, fmt.Errorf("secret %s: unreadable nextRotationTime", lastSegment(s.Name)))
				continue
			}
			if due := t.Add(rotationGrace); exp.IsZero() || due.Before(exp) {
				exp, meta["reason"] = due, "rotation"
			}
		}
		if s.Rotation != nil && s.Rotation.RotationPeriod != "" {
			period, err := time.ParseDuration(strings.TrimSuffix(s.Rotation.RotationPeriod, "s") + "s")
			if err != nil {
				errs = append(errs, fmt.Errorf("secret %s: unreadable rotationPeriod", lastSegment(s.Name)))
				continue
			}
			var v struct {
				Versions []struct{ CreateTime string } `json:"versions"`
			}
			if err := c.get(ctx, tok, c.ep.api("secretmanager")+"/v1/"+s.Name+"/versions?filter="+url.QueryEscape("state:ENABLED")+"&pageSize=25", &v); err != nil {
				errs = append(errs, fmt.Errorf("secret %s: %v", lastSegment(s.Name), err))
				continue
			}
			var newest time.Time
			for _, ver := range v.Versions {
				if t, err := parseTime(ver.CreateTime); err == nil && t.After(newest) {
					newest = t
				}
			}
			meta["rotation_period_days"] = strconv.Itoa(int(period.Hours() / 24))
			due := time.Now().UTC() // rotation on, no enabled version: due now
			if !newest.IsZero() {
				due = newest.Add(period + rotationGrace)
				meta["last_version"] = newest.Format(time.RFC3339)
			}
			if exp.IsZero() || due.Before(exp) {
				exp, meta["reason"] = due, "rotation"
			}
		}
		if exp.IsZero() {
			continue // neither expiry nor rotation: nothing expires
		}
		out = append(out, checker.ExpiryRecord{Source: "gcp://secretmanager/" + project + "/" + lastSegment(s.Name), Name: lastSegment(s.Name),
			Kind: "secret", ExpiresAt: exp, Metadata: meta})
	}
	return out, errors.Join(errs...)
}
