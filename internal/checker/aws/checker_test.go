package aws

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

func newTestChecker(t *testing.T, f *fakeAWS, cfg Config) *Checker {
	t.Helper()
	if cfg.Auth == "" {
		cfg.Auth = "instance_role"
	}
	if cfg.Regions == nil {
		cfg.Regions = []string{"eu-west-1", "us-east-1"}
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c := New(cfg)
	c.http, c.ep, c.getenv = f.srv.Client(), f.endpoints(), noEnv
	return c
}

func acmCert(id, domain, typ, status string, notAfter float64) map[string]any {
	m := map[string]any{"CertificateArn": "arn:aws:acm:eu-west-1:111111111111:certificate/" + id, "DomainName": domain,
		"Type": typ, "Status": status, "InUse": true, "RenewalEligibility": "ELIGIBLE"}
	if notAfter != 0 {
		m["NotAfter"] = notAfter
	}
	return m
}

func byKey(t *testing.T, recs []checker.ExpiryRecord) map[string]checker.ExpiryRecord {
	m := map[string]checker.ExpiryRecord{}
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid %+v: %v", r, err)
		}
		m[r.Source] = r
	}
	return m
}

func TestCheck_ACMAndIAMAcrossAccountsAndRegions(t *testing.T) {
	f := newFakeAWS(t)
	exp := float64(time.Date(2027, 2, 1, 12, 0, 0, 0, time.UTC).Unix())
	f.acm[acct1+"/eu-west-1"] = []map[string]any{
		acmCert("c1", "api.example.com", "AMAZON_ISSUED", "ISSUED", exp),
		acmCert("c2", "legacy.example.com", "IMPORTED", "ISSUED", exp+0.5),
		acmCert("c3", "new.example.com", "AMAZON_ISSUED", "PENDING_VALIDATION", 0), // no date yet
		acmCert("c4", "old.example.com", "AMAZON_ISSUED", "REVOKED", exp),
		func() map[string]any {
			m := acmCert("c7", "acme.example.com", "IMPORTED", "ISSUED", exp)
			m["CertificateKeyPairOrigin"] = "ACME"
			return m
		}(),
	}
	f.acm[acct1+"/us-east-1"] = []map[string]any{acmCert("c5", "cdn.example.com", "AMAZON_ISSUED", "EXPIRED", float64(time.Now().Add(-48*time.Hour).Unix()))}
	f.acm[acct2+"/eu-west-1"] = []map[string]any{acmCert("c6", "shop.example.com", "IMPORTED", "ISSUED", exp)}
	f.serverCerts[acct2] = []map[string]string{
		{"name": "elb-old", "arn": "arn:aws:iam::222222222222:server-certificate/elb-old", "exp": "2027-03-01T00:00:00Z"},
		{"name": "cf-cert", "arn": "arn:aws:iam::222222222222:server-certificate/cloudfront/cf-cert", "exp": "2027-04-01T00:00:00Z"},
	}
	cfg := Config{AssumeRoles: []AssumeRole{{RoleARN: "arn:aws:iam::222222222222:role/expiry-radar-read", ExternalID: "ext-1"}}}
	recs, err := newTestChecker(t, f, cfg).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := byKey(t, recs)
	want := []string{
		"aws://acm/111111111111/eu-west-1/c1", "aws://acm/111111111111/eu-west-1/c2", "aws://acm/111111111111/us-east-1/c5",
		"aws://acm/111111111111/eu-west-1/c7",
		"aws://acm/222222222222/eu-west-1/c6",
		"aws://iam/222222222222/server-certificate/elb-old", "aws://iam/222222222222/server-certificate/cf-cert",
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("missing %s", w)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("want %d records (pending and revoked skipped), got %v", len(want), got)
	}
	c1 := got["aws://acm/111111111111/eu-west-1/c1"]
	if c1.Name != "api.example.com" || !c1.ExpiresAt.Equal(time.Unix(int64(exp), 0)) || c1.Metadata["auto_renews"] != "true" || c1.Metadata["region"] != "eu-west-1" || c1.Kind != "certificate" {
		t.Fatalf("c1 %+v", c1)
	}
	if got["aws://acm/111111111111/eu-west-1/c2"].Metadata["auto_renews"] != "false" {
		t.Fatal("imported certificate marked as auto-renewing")
	}
	// The assumed role carried the external id; IAM was signed for us-east-1.
	var sawExternal bool
	for _, form := range f.forms {
		if form["Action"] == "AssumeRole" && form["ExternalId"] == "ext-1" && form["RoleSessionName"] == "expiry-radar" {
			sawExternal = true
		}
	}
	if !sawExternal {
		t.Fatal("AssumeRole without external id / session name")
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "iam ListServerCertificates") && !strings.Contains(c, " us-east-1 ") {
			t.Fatalf("IAM not signed for us-east-1: %s", c)
		}
	}
}

func TestCheck_FailuresDoNotHideOthers(t *testing.T) {
	f := newFakeAWS(t)
	f.acm[acct1+"/eu-west-1"] = []map[string]any{acmCert("c1", "a.example.com", "IMPORTED", "ISSUED", float64(time.Now().Add(240*time.Hour).Unix()))}
	f.acmFail = acct1 + "/us-east-1"
	cfg := Config{AssumeRoles: []AssumeRole{{RoleARN: "arn:aws:iam::222222222222:role/denied"}}}
	recs, err := newTestChecker(t, f, cfg).Check(context.Background())
	if len(recs) != 1 || err == nil || !strings.Contains(err.Error(), "us-east-1") || !strings.Contains(err.Error(), "222222222222") {
		t.Fatalf("got %d records, %v", len(recs), err)
	}
}

func TestCheck_SkipBaseAccount(t *testing.T) {
	f := newFakeAWS(t)
	f.acm[acct1+"/eu-west-1"] = []map[string]any{acmCert("c1", "a.example.com", "IMPORTED", "ISSUED", float64(time.Now().Add(240*time.Hour).Unix()))}
	f.acm[acct2+"/eu-west-1"] = []map[string]any{acmCert("c2", "b.example.com", "IMPORTED", "ISSUED", float64(time.Now().Add(240*time.Hour).Unix()))}
	cfg := Config{SkipBaseAccount: true, Regions: []string{"eu-west-1"}, Services: []string{"acm"},
		AssumeRoles: []AssumeRole{{RoleARN: "arn:aws:iam::222222222222:role/r"}}}
	recs, err := newTestChecker(t, f, cfg).Check(context.Background())
	if err != nil || len(recs) != 1 || !strings.Contains(recs[0].Source, acct2) {
		t.Fatalf("got %+v, %v", recs, err)
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_ROLE_ARN", "")
	ok := Config{Auth: "instance_role", Regions: []string{"eu-west-1"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(c *Config){
		"unknown auth":       func(c *Config) { c.Auth = "access_keys" },
		"bad region":         func(c *Config) { c.Regions = []string{"eu west 1"} },
		"china partition":    func(c *Config) { c.Regions = []string{"cn-north-1"} },
		"govcloud partition": func(c *Config) { c.Regions = []string{"us-gov-west-1"} },
		"china role arn":     func(c *Config) { c.AssumeRoles = []AssumeRole{{RoleARN: "arn:aws-cn:iam::111111111111:role/r"}} },
		"ra regions differ": func(c *Config) {
			c.Auth, c.CertificateFile, c.RoleARN = "roles_anywhere", "/c", "arn:aws:iam::111111111111:role/r"
			c.TrustAnchorARN = "arn:aws:rolesanywhere:eu-west-1:111111111111:trust-anchor/ta"
			c.ProfileARN = "arn:aws:rolesanywhere:us-east-1:111111111111:profile/p"
		},
		"acm without regions":    func(c *Config) { c.Regions = nil },
		"web identity no token":  func(c *Config) { c.Auth = "web_identity"; c.RoleARN = "arn:aws:iam::111111111111:role/r" },
		"roles anywhere missing": func(c *Config) { c.Auth = "roles_anywhere"; c.CertificateFile = "/c" },
		"bad assume role arn":    func(c *Config) { c.AssumeRoles = []AssumeRole{{RoleARN: "arn:aws:s3:::bucket"}} },
		"unknown service":        func(c *Config) { c.Services = []string{"s3"} },
		"skip base, no roles":    func(c *Config) { c.SkipBaseAccount = true },
	}
	for name, mutate := range cases {
		c := ok
		mutate(&c)
		if c.Validate() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	iamOnly := Config{Auth: "instance_role", Services: []string{"iam_server_certificates"}}
	if err := iamOnly.Validate(); err != nil {
		t.Errorf("IAM only without regions rejected: %v", err)
	}
}

func TestCheck_ThrottlingRetried(t *testing.T) {
	f := newFakeAWS(t)
	f.throttle = 2
	f.acm[acct1+"/eu-west-1"] = []map[string]any{acmCert("c1", "a.example.com", "IMPORTED", "ISSUED", float64(time.Now().Add(240*time.Hour).Unix()))}
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1"}, Services: []string{"acm"}}).Check(context.Background())
	if err != nil || len(recs) != 1 {
		t.Fatalf("throttling not retried: %d records, %v", len(recs), err)
	}
}

func TestCheck_UnreadableIAMDateIsAnError(t *testing.T) {
	f := newFakeAWS(t)
	f.serverCerts[acct1] = []map[string]string{{"name": "x", "arn": "arn:aws:iam::111111111111:server-certificate/x", "exp": "soon"}}
	if _, err := newTestChecker(t, f, Config{Services: []string{"iam_server_certificates"}}).Check(context.Background()); err == nil || !strings.Contains(err.Error(), "x") {
		t.Fatalf("bad date not reported: %v", err)
	}
}

// Base credentials that cannot be obtained are tried once per run, not
// once per assumed account.
func TestCheck_BaseOutageTriedOnce(t *testing.T) {
	f := newFakeAWS(t)
	f.imdsToken = "dead"
	cfg := Config{SkipBaseAccount: true, Regions: []string{"eu-west-1"}, Services: []string{"acm"},
		AssumeRoles: []AssumeRole{{RoleARN: "arn:aws:iam::222222222222:role/a"}, {RoleARN: "arn:aws:iam::333333333333:role/b"}, {RoleARN: "arn:aws:iam::444444444444:role/c"}}}
	c := newTestChecker(t, f, cfg)
	if _, err := c.Check(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if f.credCalls > 3 { // one attempt (with its retries), not one per account
		t.Fatalf("base credentials fetched %d times", f.credCalls)
	}
}
