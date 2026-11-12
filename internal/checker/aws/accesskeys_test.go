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
	root := got["aws://iam/111111111111/user/<root_account>/access_key_1"]
	if root.Kind != "access_key" || root.ExpiresAt.After(time.Now()) || root.Metadata["root"] != "true" || root.Metadata["alerts"] == "off" {
		t.Fatalf("root key must be reported as already due: %+v", root)
	}
	alice1 := got["aws://iam/111111111111/user/alice/access_key_1"]
	wantExp := time.Now().Add(-10 * 24 * time.Hour)
	if alice1.Name != "alice · key 1" || alice1.ExpiresAt.Sub(wantExp).Abs() > time.Minute || alice1.Metadata["status"] != "active" {
		t.Fatalf("alice key 1 (rotated 100 days ago, max 90): %+v", alice1)
	}
	alice2 := got["aws://iam/111111111111/user/alice/access_key_2"]
	if alice2.Metadata["status"] != "inactive" || alice2.Metadata["alerts"] != "off" {
		t.Fatalf("inactive key must be listed, informational: %+v", alice2)
	}
	if bob := got["aws://iam/111111111111/user/bob/access_key_1"]; bob.ExpiresAt.Sub(time.Now().Add(80*24*time.Hour)).Abs() > time.Minute {
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
