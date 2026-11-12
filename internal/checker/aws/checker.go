package aws

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// Checker reports AWS certificates (ACM, IAM server certificates) that
// expire, in the base account and in every assumed account.
type Checker struct {
	cfg    Config
	http   *http.Client
	ep     endpoints
	getenv func(string) string

	mu      sync.Mutex
	base    credentialSource
	assumed map[string]credentialSource
	baseAcc string
}

// New returns an AWS checker for cfg (already validated).
func New(cfg Config) *Checker {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	hc := &http.Client{Timeout: 15 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Checker{cfg: cfg, http: hc, ep: defaultEndpoints(), getenv: os.Getenv, assumed: map[string]credentialSource{}}
}

func (c *Checker) Name() string { return "aws" }
func (c *Checker) Kind() string { return "certificate" }

type target struct {
	account string
	creds   credentialSource
}

// targets returns the base account (unless skipped) and every assumed
// account; credentials are kept across runs.
func (c *Checker) targets(ctx context.Context) ([]target, []error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.base == nil {
		src, err := newCredentialSource(c.cfg, c.http, c.ep, c.getenv)
		if err != nil {
			return nil, []error{err}
		}
		c.base = src
	}
	var out []target
	var errs []error
	if !c.cfg.SkipBaseAccount {
		if c.baseAcc == "" {
			cr, err := c.base.get(ctx)
			if err != nil {
				return nil, []error{err}
			}
			var r struct {
				Account string `xml:"GetCallerIdentityResult>Account"`
			}
			if err := stsCall(ctx, c.http, c.ep, c.cfg.stsRegion(), cr, url.Values{"Action": {"GetCallerIdentity"}}, &r); err != nil {
				return nil, []error{err}
			}
			c.baseAcc = r.Account
		}
		out = append(out, target{c.baseAcc, c.base})
	}
	for _, a := range c.cfg.AssumeRoles {
		a := a
		acct := strings.Split(a.RoleARN, ":")[4]
		src, ok := c.assumed[a.RoleARN]
		if !ok {
			src = &cachedSource{fetch: func(ctx context.Context) (credentials, error) {
				base, err := c.base.get(ctx)
				if err != nil {
					return credentials{}, err
				}
				return assumeRole(ctx, c.http, c.ep, c.cfg.stsRegion(), base, a)
			}}
			c.assumed[a.RoleARN] = src
		}
		out = append(out, target{acct, src})
	}
	return out, errs
}

// Check lists every configured service in every account and region. A
// failing account, region or service does not hide the others.
func (c *Checker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	targets, errs := c.targets(ctx)
	if len(targets) == 0 {
		return nil, errors.Join(errs...)
	}
	// Base credentials feed every assumed role: if they cannot be had,
	// say so once instead of waiting on them for each account.
	if _, err := c.base.get(ctx); err != nil {
		return nil, errors.Join(append(errs, err)...)
	}
	var records []checker.ExpiryRecord
	for _, t := range targets {
		cr, err := t.creds.get(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("account %s: %w", t.account, err))
			continue
		}
		for _, s := range c.cfg.services() {
			switch s {
			case "acm":
				for _, region := range c.cfg.Regions {
					recs, err := c.listACM(ctx, cr, t.account, region)
					records = append(records, recs...)
					if err != nil {
						errs = append(errs, fmt.Errorf("account %s acm %s: %w", t.account, region, err))
					}
				}
			case "iam_server_certificates":
				recs, err := c.listServerCertificates(ctx, cr, t.account)
				records = append(records, recs...)
				if err != nil {
					errs = append(errs, fmt.Errorf("account %s iam server certificates: %w", t.account, err))
				}
			}
		}
	}
	return records, errors.Join(errs...)
}

var acmKeyTypes = []string{"RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"}

// listACM pages through ListCertificates with every key type (ACM
// lists RSA_2048 only otherwise). Revoked, failed, timed-out and
// inactive certificates are skipped, and so are the ones without a date
// (pending validation).
func (c *Checker) listACM(ctx context.Context, cr credentials, account, region string) ([]checker.ExpiryRecord, error) {
	var records []checker.ExpiryRecord
	next := ""
	for page := 0; page < 1000; page++ {
		// Every key type and key pair origin: by default ACM lists RSA-1024
		// and RSA-2048 only, and leaves ACME certificates out.
		in := map[string]any{"MaxItems": 1000, "Includes": map[string]any{"keyTypes": acmKeyTypes},
			"CertificateKeyPairOrigins": []string{"AWS_MANAGED", "ACME", "CUSTOMER_PROVIDED"}}
		if next != "" {
			in["NextToken"] = next
		}
		body, _ := json.Marshal(in)
		data, err := send(ctx, c.http, "ListCertificates", func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ep.acm(region)+"/", strings.NewReader(string(body)))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/x-amz-json-1.1")
			req.Header.Set("X-Amz-Target", "CertificateManager.ListCertificates")
			signV4(req, body, cr, region, "acm", time.Now())
			return req, nil
		})
		if err != nil {
			return records, err
		}
		var out struct {
			NextToken string
			List      []struct {
				CertificateArn, DomainName, Type, Status, RenewalEligibility string
				InUse                                                        bool
				NotAfter                                                     *float64
			} `json:"CertificateSummaryList"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return records, fmt.Errorf("ListCertificates: %w", err)
		}
		for _, s := range out.List {
			switch s.Status {
			case "REVOKED", "FAILED", "VALIDATION_TIMED_OUT", "INACTIVE":
				continue
			}
			if s.NotAfter == nil {
				continue
			}
			id := s.CertificateArn[strings.LastIndex(s.CertificateArn, "/")+1:]
			records = append(records, checker.ExpiryRecord{
				Source: "aws://acm/" + account + "/" + region + "/" + id, Name: s.DomainName, Kind: "certificate",
				ExpiresAt: time.Unix(int64(*s.NotAfter), 0).UTC(),
				Metadata: map[string]string{"account": account, "region": region, "type": s.Type, "status": s.Status,
					"in_use": fmt.Sprint(s.InUse), "renewal_eligibility": s.RenewalEligibility,
					"auto_renews": fmt.Sprint(s.Type == "AMAZON_ISSUED" && s.RenewalEligibility == "ELIGIBLE")},
			})
		}
		if out.NextToken == "" {
			return records, nil
		}
		next = out.NextToken
	}
	return records, errors.New("ListCertificates: more than 1000 pages")
}

// listServerCertificates pages through IAM ListServerCertificates
// (global; signed for us-east-1).
func (c *Checker) listServerCertificates(ctx context.Context, cr credentials, account string) ([]checker.ExpiryRecord, error) {
	var records []checker.ExpiryRecord
	var bad []string
	marker := ""
	for page := 0; page < 1000; page++ {
		q := url.Values{"Action": {"ListServerCertificates"}, "Version": {"2010-05-08"}}
		if marker != "" {
			q.Set("Marker", marker)
		}
		data, err := send(ctx, c.http, "ListServerCertificates", func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ep.iam+"/?"+q.Encode(), nil)
			if err != nil {
				return nil, err
			}
			signV4(req, nil, cr, "us-east-1", "iam", time.Now())
			return req, nil
		})
		if err != nil {
			return records, err
		}
		var out struct {
			IsTruncated bool   `xml:"ListServerCertificatesResult>IsTruncated"`
			Marker      string `xml:"ListServerCertificatesResult>Marker"`
			List        []struct {
				Name       string `xml:"ServerCertificateName"`
				Arn        string `xml:"Arn"`
				Expiration string `xml:"Expiration"`
			} `xml:"ListServerCertificatesResult>ServerCertificateMetadataList>member"`
		}
		if err := xml.Unmarshal(data, &out); err != nil {
			return records, fmt.Errorf("ListServerCertificates: %w", err)
		}
		for _, s := range out.List {
			exp, err := time.Parse(time.RFC3339, s.Expiration)
			if err != nil {
				bad = append(bad, s.Name)
				continue
			}
			records = append(records, checker.ExpiryRecord{
				Source: "aws://iam/" + account + "/server-certificate/" + s.Name, Name: s.Name, Kind: "certificate", ExpiresAt: exp.UTC(),
				Metadata: map[string]string{"account": account, "arn": s.Arn},
			})
		}
		if !out.IsTruncated || out.Marker == "" {
			if len(bad) > 0 {
				return records, fmt.Errorf("unreadable Expiration on %s", strings.Join(bad, ", "))
			}
			return records, nil
		}
		marker = out.Marker
	}
	return records, errors.New("ListServerCertificates: more than 1000 pages")
}
