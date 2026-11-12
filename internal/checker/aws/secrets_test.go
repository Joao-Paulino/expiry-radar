package aws

import (
	"context"
	"strings"
	"testing"
	"time"
)

func secret(name string, fields map[string]any) map[string]any {
	m := map[string]any{"ARN": "arn:aws:secretsmanager:eu-west-1:111111111111:secret:" + name + "-AbCdEf", "Name": name}
	for k, v := range fields {
		m[k] = v
	}
	return m
}

func TestCheck_SecretsManager(t *testing.T) {
	f := newFakeAWS(t)
	ts := func(d time.Duration) float64 { return float64(time.Now().Add(d).Unix()) }
	f.secrets[acct1+"/eu-west-1"] = []map[string]any{
		secret("db/prod", map[string]any{"RotationEnabled": true, "NextRotationDate": ts(5 * 24 * time.Hour), "LastRotatedDate": ts(-25 * 24 * time.Hour)}),
		// rotation failing: the scheduled date stays in the past
		secret("api/stuck", map[string]any{"RotationEnabled": true, "NextRotationDate": ts(-3 * 24 * time.Hour)}),
		secret("legacy/manual", map[string]any{"RotationEnabled": false, "LastChangedDate": ts(-400 * 24 * time.Hour)}),
		secret("rds!db-123", map[string]any{"RotationEnabled": true, "NextRotationDate": ts(6 * 24 * time.Hour), "OwningService": "rds"}),
	}
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1"}, Services: []string{"secrets_manager"}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := byKey(t, recs)
	if len(got) != 3 {
		t.Fatalf("want rotating secrets only (no max age set): %v", got)
	}
	db := got["aws://secretsmanager/111111111111/eu-west-1/db/prod"]
	if db.Kind != "secret" || db.Name != "db/prod" || db.ExpiresAt.Sub(time.Now().Add(5*24*time.Hour)).Abs() > time.Minute || db.Metadata["rotation"] != "enabled" {
		t.Fatalf("db/prod: %+v", db)
	}
	if stuck := got["aws://secretsmanager/111111111111/eu-west-1/api/stuck"]; !stuck.ExpiresAt.Before(time.Now()) {
		t.Fatalf("a failing rotation must show as overdue: %+v", stuck)
	}
	if rds := got["aws://secretsmanager/111111111111/eu-west-1/rds!db-123"]; rds.Metadata["owning_service"] != "rds" {
		t.Fatalf("rds: %+v", rds)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "GetSecretValue") {
			t.Fatal("secret value requested")
		}
	}
}

func TestCheck_SecretsManagerMaxAge(t *testing.T) {
	f := newFakeAWS(t)
	now := time.Now()
	f.secrets[acct1+"/eu-west-1"] = []map[string]any{
		// a tag edit yesterday reset LastChangedDate; the value is 400 days old
		secret("legacy/manual", map[string]any{"LastChangedDate": float64(now.Add(-24 * time.Hour).Unix()), "CreatedDate": float64(now.Add(-900 * 24 * time.Hour).Unix())}),
		secret("new/manual", map[string]any{"CreatedDate": float64(now.Add(-10 * 24 * time.Hour).Unix())}),
		secret("events!connection", map[string]any{"OwningService": "events", "CreatedDate": float64(now.Add(-900 * 24 * time.Hour).Unix())}),
	}
	arn := func(n string) string { return "arn:aws:secretsmanager:eu-west-1:111111111111:secret:" + n + "-AbCdEf" }
	f.versions[arn("legacy/manual")] = []map[string]any{
		{"VersionId": "v2", "VersionStages": []string{"AWSCURRENT"}, "CreatedDate": float64(now.Add(-400 * 24 * time.Hour).Unix())},
		{"VersionId": "v1", "VersionStages": []string{"AWSPREVIOUS"}, "CreatedDate": float64(now.Add(-900 * 24 * time.Hour).Unix())},
	}
	f.versions[arn("new/manual")] = []map[string]any{{"VersionId": "v1", "VersionStages": []string{"AWSCURRENT"}, "CreatedDate": float64(now.Add(-10 * 24 * time.Hour).Unix())}}
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1"}, Services: []string{"secrets_manager"}, SecretMaxAgeDays: 365}).Check(context.Background())
	if err != nil || len(recs) != 2 {
		t.Fatalf("want legacy and new (service-owned secret without rotation skipped): %+v, %v", recs, err)
	}
	got := byKey(t, recs)
	legacy := got["aws://secretsmanager/111111111111/eu-west-1/legacy/manual"]
	if legacy.Metadata["rotation"] != "disabled" || legacy.ExpiresAt.Sub(now.Add(-35*24*time.Hour)).Abs() > time.Minute {
		t.Fatalf("age must come from the current version (400 days), not the tag edit: %+v", legacy)
	}
	if n := got["aws://secretsmanager/111111111111/eu-west-1/new/manual"]; n.ExpiresAt.Sub(now.Add(355*24*time.Hour)).Abs() > time.Minute {
		t.Fatalf("new: %+v", n)
	}
}

func TestSplit_SecretsSeparateChecker(t *testing.T) {
	cs := Checkers(Config{Auth: "instance_role", Regions: []string{"eu-west-1"}, Services: []string{"acm", "access_keys", "secrets_manager"}})
	var names []string
	for _, c := range cs {
		names = append(names, c.Name())
	}
	if strings.Join(names, ",") != "aws,aws-access-keys,aws-secrets" {
		t.Fatalf("got %v", names)
	}
	if (&Config{Auth: "instance_role", Services: []string{"secrets_manager"}}).Validate() == nil {
		t.Fatal("secrets_manager without regions accepted")
	}
}

// A rotation that keeps failing on a schedule may move NextRotationDate
// forward: the last successful rotation + interval (+ grace) still
// makes it due. Rotation on without a date is due, not dropped.
func TestCheck_SecretsRotationOverdue(t *testing.T) {
	f := newFakeAWS(t)
	now := time.Now()
	ts := func(d time.Duration) float64 { return float64(now.Add(d).Unix()) }
	f.secrets[acct1+"/eu-west-1"] = []map[string]any{
		secret("cron/failing", map[string]any{"RotationEnabled": true, "NextRotationDate": ts(20 * 24 * time.Hour),
			"LastRotatedDate": ts(-90 * 24 * time.Hour), "RotationRules": map[string]any{"ScheduleExpression": "rate(30 days)"}}),
		secret("days/failing", map[string]any{"RotationEnabled": true, "NextRotationDate": ts(10 * 24 * time.Hour),
			"LastRotatedDate": ts(-70 * 24 * time.Hour), "RotationRules": map[string]any{"AutomaticallyAfterDays": 30}}),
		secret("unscheduled", map[string]any{"RotationEnabled": true, "CreatedDate": ts(-5 * 24 * time.Hour)}),
		secret("cron/ok", map[string]any{"RotationEnabled": true, "NextRotationDate": ts(3 * 24 * time.Hour),
			"LastRotatedDate": ts(-4 * 24 * time.Hour), "RotationRules": map[string]any{"ScheduleExpression": "cron(0 4 ? * MON *)"}}),
	}
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1"}, Services: []string{"secrets_manager"}}).Check(context.Background())
	if err != nil || len(recs) != 4 {
		t.Fatalf("got %+v, %v", recs, err)
	}
	got := byKey(t, recs)
	for _, n := range []string{"cron/failing", "days/failing", "unscheduled"} {
		if r := got["aws://secretsmanager/111111111111/eu-west-1/"+n]; !r.ExpiresAt.Before(now) {
			t.Errorf("%s must be overdue: %+v", n, r)
		}
	}
	if ok := got["aws://secretsmanager/111111111111/eu-west-1/cron/ok"]; ok.ExpiresAt.Sub(now.Add(3*24*time.Hour)).Abs() > time.Minute {
		t.Fatalf("cron/ok: %+v", ok)
	}
}

// A secret replicated to another configured region is reported once,
// from its primary region.
func TestCheck_SecretsReplicasOnce(t *testing.T) {
	f := newFakeAWS(t)
	next := float64(time.Now().Add(5 * 24 * time.Hour).Unix())
	f.secrets[acct1+"/eu-west-1"] = []map[string]any{secret("shared", map[string]any{"RotationEnabled": true, "NextRotationDate": next})}
	f.secrets[acct1+"/us-east-1"] = []map[string]any{secret("shared", map[string]any{"RotationEnabled": true, "NextRotationDate": next, "PrimaryRegion": "eu-west-1"})}
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1", "us-east-1"}, Services: []string{"secrets_manager"}}).Check(context.Background())
	if err != nil || len(recs) != 1 || recs[0].Metadata["region"] != "eu-west-1" {
		t.Fatalf("replica reported twice: %+v, %v", recs, err)
	}
}
