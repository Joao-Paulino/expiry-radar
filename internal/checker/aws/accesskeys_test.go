package aws

import (
	"context"
	"strings"
	"testing"
	"time"
)

const reportHeader = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active," +
	"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service," +
	"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service," +
	"cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"

func reportRow(user, k1active, k1rot, k2active, k2rot string) string {
	return user + ",arn:aws:iam::111111111111:user/" + user + ",2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,true," +
		k1active + "," + k1rot + ",N/A,N/A,N/A," + k2active + "," + k2rot + ",N/A,N/A,N/A,false,N/A,false,N/A\n"
}

func TestCheck_AccessKeys(t *testing.T) {
	f := newFakeAWS(t)
	f.reportPolls = 1 // first Generate answers STARTED
	day := func(d int) string {
		return time.Now().Add(time.Duration(d) * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05+00:00")
	}
	f.credReport[acct1] = reportHeader +
		reportRow("<root_account>", "true", day(-400), "false", "N/A") +
		reportRow("alice", "true", day(-100), "false", day(-300)) +
		reportRow("bob", "true", day(-10), "false", "N/A") +
		reportRow("carol", "false", "N/A", "false", "N/A")
	cfg := Config{Services: []string{"access_keys"}, AccessKeyMaxAgeDays: 90}
	recs, err := newTestChecker(t, f, cfg).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := byKey(t, recs)
	src := func(user string, slot int) string {
		for k := range got {
			if strings.HasPrefix(k, "aws://iam/111111111111/user/"+user+"/access_key_"+string(rune('0'+slot))+"@") {
				return k
			}
		}
		return ""
	}
	root := got[src("<root_account>", 1)]
	if root.Kind != "access_key" || root.ExpiresAt.After(time.Now()) || root.Metadata["root"] != "true" || root.Metadata["alerts"] == "off" {
		t.Fatalf("root key must be reported as already due: %+v", root)
	}
	alice1 := got[src("alice", 1)]
	wantExp := time.Now().Add(-10 * 24 * time.Hour)
	if alice1.Name != "alice · key 1" || alice1.ExpiresAt.Sub(wantExp).Abs() > time.Minute || alice1.Metadata["status"] != "active" {
		t.Fatalf("alice key 1 (rotated 100 days ago, max 90): %+v", alice1)
	}
	alice2 := got[src("alice", 2)]
	if alice2.Metadata["status"] != "inactive" || alice2.Metadata["alerts"] != "off" {
		t.Fatalf("inactive key must be listed, informational: %+v", alice2)
	}
	if bob := got[src("bob", 1)]; bob.ExpiresAt.Sub(time.Now().Add(80*24*time.Hour)).Abs() > time.Minute {
		t.Fatalf("bob: %+v", bob)
	}
	if len(got) != 4 {
		t.Fatalf("want root, alice x2, bob (carol has no keys): %v", got)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "GetAccessKey") || strings.Contains(c, "ListAccessKeys") {
			t.Fatalf("unexpected call %s", c)
		}
	}
}

func TestCheck_AccessKeysDefaultMaxAge(t *testing.T) {
	f := newFakeAWS(t)
	f.credReport[acct1] = reportHeader + reportRow("dave", "true", time.Now().UTC().Format("2006-01-02T15:04:05+00:00"), "false", "N/A")
	recs, err := newTestChecker(t, f, Config{Services: []string{"access_keys"}}).Check(context.Background())
	if err != nil || len(recs) != 1 || recs[0].ExpiresAt.Sub(time.Now().Add(90*24*time.Hour)).Abs() > time.Minute || recs[0].Metadata["max_age_days"] != "90" {
		t.Fatalf("default 90 days: %+v, %v", recs, err)
	}
}

func TestCheck_AccessKeysBadReport(t *testing.T) {
	f := newFakeAWS(t)
	f.credReport[acct1] = "not,a,report\n1,2,3\n"
	if _, err := newTestChecker(t, f, Config{Services: []string{"access_keys"}}).Check(context.Background()); err == nil {
		t.Fatal("unexpected report format accepted silently")
	}
}

// Key identity includes its creation date: a mute on a deleted key must
// not cover a new key created in the same slot.
func TestCheck_AccessKeyIdentityFollowsTheKey(t *testing.T) {
	f := newFakeAWS(t)
	f.credReport[acct1] = reportHeader + reportRow("alice", "true", "2026-01-01T00:00:00+00:00", "false", "N/A")
	c := newTestChecker(t, f, Config{Services: []string{"access_keys"}})
	r1, _ := c.Check(context.Background())
	f.credReport[acct1] = reportHeader + reportRow("alice", "true", "2026-10-01T00:00:00+00:00", "false", "N/A")
	r2, _ := c.Check(context.Background())
	if len(r1) != 1 || len(r2) != 1 || r1[0].Source == r2[0].Source {
		t.Fatalf("a new key in the same slot kept the old identity: %v / %v", r1, r2)
	}
}

// Fail safe on the report format: any active value other than an
// explicit false alerts; non-values mean "no key" without failing the
// run; an inactive root key still alerts (CIS: root has no keys).
func TestCheck_AccessKeysReportValues(t *testing.T) {
	f := newFakeAWS(t)
	old := "2020-01-01T00:00:00+00:00"
	f.credReport[acct1] = reportHeader +
		reportRow("upper", "TRUE", old, "false", "not_supported") +
		reportRow("odd", "maybe", old, "false", "no_information") +
		reportRow("<root_account>", "false", old, "false", "N/A") +
		reportRow("inactive-doc", "false", "N/A", "false", "N/A") // the doc's reading: inactive keys have no date
	recs, err := newTestChecker(t, f, Config{Services: []string{"access_keys"}}).Check(context.Background())
	if err != nil {
		t.Fatalf("non-values failed the run: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("want upper, odd, root: %+v", recs)
	}
	for _, r := range recs {
		if r.Metadata["alerts"] == "off" {
			t.Fatalf("%s silenced: %+v", r.Name, r)
		}
	}
}

// Report not present / expired / in progress: regenerate and poll again
// instead of failing.
func TestCheck_AccessKeysReportExpired(t *testing.T) {
	f := newFakeAWS(t)
	f.reportGone = 1
	f.credReport[acct1] = reportHeader + reportRow("eve", "true", time.Now().UTC().Format("2006-01-02T15:04:05+00:00"), "false", "N/A")
	if recs, err := newTestChecker(t, f, Config{Services: []string{"access_keys"}}).Check(context.Background()); err != nil || len(recs) != 1 {
		t.Fatalf("got %d, %v", len(recs), err)
	}
}

// Access keys run as their own checker: a report problem must not make
// the certificate run incomplete (which would stop gone-detection there).
func TestSplit_AccessKeysSeparateChecker(t *testing.T) {
	cfg := Config{Auth: "instance_role", Regions: []string{"eu-west-1"}, Services: []string{"acm", "access_keys"}}
	cs := Checkers(cfg)
	if len(cs) != 2 || cs[0].Name() != "aws" || cs[1].Name() != "aws-access-keys" {
		t.Fatalf("got %v", cs)
	}
	only := Checkers(Config{Auth: "instance_role", Services: []string{"access_keys"}})
	if len(only) != 1 || only[0].Name() != "aws-access-keys" {
		t.Fatalf("got %v", only)
	}
}

func TestConfig_AccessKeyMaxAgeBound(t *testing.T) {
	c := Config{Auth: "instance_role", Services: []string{"access_keys"}, AccessKeyMaxAgeDays: 200000}
	if c.Validate() == nil {
		t.Fatal("overflowing max age accepted")
	}
}
