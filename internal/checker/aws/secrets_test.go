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
	f.secrets[acct1+"/eu-west-1"] = []map[string]any{
		secret("legacy/manual", map[string]any{"LastChangedDate": float64(time.Now().Add(-400 * 24 * time.Hour).Unix())}),
		secret("new/manual", map[string]any{"CreatedDate": float64(time.Now().Add(-10 * 24 * time.Hour).Unix())}),
	}
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1"}, Services: []string{"secrets_manager"}, SecretMaxAgeDays: 365}).Check(context.Background())
	if err != nil || len(recs) != 2 {
		t.Fatalf("got %+v, %v", recs, err)
	}
	got := byKey(t, recs)
	legacy := got["aws://secretsmanager/111111111111/eu-west-1/legacy/manual"]
	if legacy.Metadata["rotation"] != "disabled" || !legacy.ExpiresAt.Before(time.Now()) {
		t.Fatalf("legacy: %+v", legacy)
	}
	if n := got["aws://secretsmanager/111111111111/eu-west-1/new/manual"]; n.ExpiresAt.Sub(time.Now().Add(355*24*time.Hour)).Abs() > time.Minute {
		t.Fatalf("created date as fallback: %+v", n)
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
