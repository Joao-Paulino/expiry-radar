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

func iotCACert(id string) map[string]any {
	return map[string]any{
		"certificateArn": "arn:aws:iot:eu-west-1:111111111111:cacert/" + id,
		"certificateId":  id,
		"status":         "ACTIVE",
		"creationDate":   float64(time.Now().Add(-400 * 24 * time.Hour).Unix()),
	}
}

func TestCheck_IoTCoreCACertificates(t *testing.T) {
	f := newFakeAWS(t)
	exp := time.Now().Add(400 * 24 * time.Hour)
	f.iotCACerts[acct1+"/eu-west-1"] = []map[string]any{
		iotCACert("ca-active"),
		iotCACert("ca-inactive"),
	}
	f.iotCACerts[acct1+"/eu-west-1"][1]["status"] = "INACTIVE"
	f.iotDescCA["ca-active"] = map[string]any{
		"certificateId": "ca-active",
		"status":        "ACTIVE",
		"validity":      map[string]any{"notAfter": float64(exp.Unix())},
	}
	// inactive CAs are not in use and are skipped before DescribeCACertificate.
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1"}, Services: []string{"iot_core"}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := byKey(t, recs)
	if len(got) != 1 {
		t.Fatalf("want only the active CA: %v", got)
	}
	rec := got["aws://iot-ca/111111111111/eu-west-1/ca-active"]
	if rec.Kind != "certificate" || rec.Name != "ca-active" || rec.ExpiresAt.Sub(exp).Abs() > time.Minute {
		t.Fatalf("ca-active: %+v", rec)
	}
	if rec.Metadata["resource"] != "ca_certificate" || rec.Metadata["account"] != acct1 {
		t.Fatalf("metadata: %+v", rec.Metadata)
	}
	describeCalls := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "iot DescribeCACertificate ") {
			describeCalls++
		}
	}
	if describeCalls != 1 {
		t.Fatalf("want exactly 1 DescribeCACertificate call (inactive CA must be skipped), got %d: %v", describeCalls, f.calls)
	}
}

func TestCheck_IoTCore_DescribeMissingValidity(t *testing.T) {
	f := newFakeAWS(t)
	f.iotCerts[acct1+"/eu-west-1"] = []map[string]any{iotCert("cert-novalidity")}
	f.iotDescribe["cert-novalidity"] = map[string]any{"certificateId": "cert-novalidity", "status": "ACTIVE"} // no validity: not yet issued
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1"}, Services: []string{"iot_core"}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("want no record for a certificate with no validity: %v", recs)
	}
}

func TestCheck_IoTCore_RepeatedNextMarkerStops(t *testing.T) {
	f := newFakeAWS(t)
	f.iotLoopMarker = true
	f.iotCerts[acct1+"/eu-west-1"] = []map[string]any{iotCert("cert-a"), iotCert("cert-b")}
	f.iotDescribe["cert-a"] = map[string]any{"validity": map[string]any{"notAfter": float64(time.Now().Add(90 * 24 * time.Hour).Unix())}}
	f.iotDescribe["cert-b"] = map[string]any{"validity": map[string]any{"notAfter": float64(time.Now().Add(90 * 24 * time.Hour).Unix())}}
	// The fake now repeats nextMarker "p2" forever instead of
	// terminating; without the repeated-marker guard this would loop
	// until the 1000-page cap.
	recs, err := newTestChecker(t, f, Config{Regions: []string{"eu-west-1"}, Services: []string{"iot_core"}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	listCalls := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "iot ListCertificates ") {
			listCalls++
		}
	}
	if listCalls > 5 {
		t.Fatalf("want the paginator to stop quickly on a repeated marker, made %d ListCertificates calls", listCalls)
	}
	if len(recs) != 2 {
		t.Fatalf("want both certificates (first real page plus the one repeating page): %v", recs)
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
