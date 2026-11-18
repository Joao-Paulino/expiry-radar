package aws

import (
	"context"
	"strings"
	"testing"
	"time"
)

func iotCert(id string) map[string]any {
	return map[string]any{
		"certificateArn":  "arn:aws:iot:eu-west-1:111111111111:cert/" + id,
		"certificateId":   id,
		"status":          "ACTIVE",
		"certificateMode": "DEFAULT",
		"creationDate":    float64(time.Now().Add(-30 * 24 * time.Hour).Unix()),
	}
}

func TestCheck_IoTCore(t *testing.T) {
	f := newFakeAWS(t)
	exp := time.Now().Add(45 * 24 * time.Hour)
	f.iotCerts[acct1+"/eu-west-1"] = []map[string]any{
		iotCert("cert-active"),
		iotCert("cert-revoked"),
	}
	f.iotCerts[acct1+"/eu-west-1"][1]["status"] = "REVOKED"
	f.iotDescribe["cert-active"] = map[string]any{
		"certificateId": "cert-active",
		"status":        "ACTIVE",
		"validity":      map[string]any{"notBefore": float64(time.Now().Add(-365 * 24 * time.Hour).Unix()), "notAfter": float64(exp.Unix())},
	}
	// revoked certificates are skipped before DescribeCertificate is even called.
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1"}, Services: []string{"iot_core"}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := byKey(t, recs)
	if len(got) != 1 {
		t.Fatalf("want only the active certificate: %v", got)
	}
	rec := got["aws://iot/111111111111/eu-west-1/cert-active"]
	if rec.Kind != "certificate" || rec.Name != "cert-active" || rec.ExpiresAt.Sub(exp).Abs() > time.Minute {
		t.Fatalf("cert-active: %+v", rec)
	}
	if rec.Metadata["account"] != acct1 || rec.Metadata["region"] != "eu-west-1" || rec.Metadata["certificate_mode"] != "DEFAULT" {
		t.Fatalf("metadata: %+v", rec.Metadata)
	}
	describeCalls := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "iot DescribeCertificate ") {
			describeCalls++
		}
	}
	if describeCalls != 1 {
		t.Fatalf("want exactly 1 DescribeCertificate call (revoked cert must be skipped before describing), got %d: %v", describeCalls, f.calls)
	}
}

func TestCheck_IoTCorePaging(t *testing.T) {
	f := newFakeAWS(t)
	f.iotCerts[acct1+"/eu-west-1"] = []map[string]any{iotCert("cert-a"), iotCert("cert-b")}
	for _, id := range []string{"cert-a", "cert-b"} {
		f.iotDescribe[id] = map[string]any{"validity": map[string]any{"notAfter": float64(time.Now().Add(90 * 24 * time.Hour).Unix())}}
	}
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1"}, Services: []string{"iot_core"}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("want both pages: %v", recs)
	}
}
