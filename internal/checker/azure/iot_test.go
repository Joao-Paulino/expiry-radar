package azure

import (
	"context"
	"strings"
	"testing"
	"time"
)

func iotFake(t *testing.T) *fakeAzure {
	f := newFake(t)
	sub := "/subscriptions/" + guid
	// Real IoT Hub/DPS certificate "expiry" values are serialized as
	// RFC 7231 ("RFC1123") strings (e.g. "Sat, 31 Dec 2039 23:59:59 GMT"),
	// per the .NET SDK's DateTimeRfc1123JsonConverter on
	// CertificateProperties.Expiry - not RFC 3339.
	soon := time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.RFC1123)
	f.arm[sub+"/providers/Microsoft.Devices/IotHubs"] = []map[string]any{
		{"id": sub + "/resourceGroups/rg-iot/providers/Microsoft.Devices/IotHubs/myhub", "name": "myhub"},
	}
	f.arm[sub+"/resourceGroups/rg-iot/providers/Microsoft.Devices/IotHubs/myhub/certificates"] = []map[string]any{
		{"id": sub + "/resourceGroups/rg-iot/providers/Microsoft.Devices/IotHubs/myhub/certificates/devicecert", "name": "devicecert",
			"properties": map[string]any{"subject": "CN=devicecert", "expiry": soon, "thumbprint": "AB12", "isVerified": false}},
		{"id": sub + "/resourceGroups/rg-iot/providers/Microsoft.Devices/IotHubs/myhub/certificates/pending", "name": "pending",
			"properties": map[string]any{"subject": "CN=pending", "thumbprint": "CD34"}}, // no expiry yet: not issued
	}
	f.arm[sub+"/providers/Microsoft.Devices/provisioningServices"] = []map[string]any{
		{"id": sub + "/resourceGroups/rg-iot/providers/Microsoft.Devices/provisioningServices/mydps", "name": "mydps"},
	}
	f.arm[sub+"/resourceGroups/rg-iot/providers/Microsoft.Devices/provisioningServices/mydps/certificates"] = []map[string]any{
		{"id": sub + "/resourceGroups/rg-iot/providers/Microsoft.Devices/provisioningServices/mydps/certificates/dpsroot", "name": "dpsroot",
			"properties": map[string]any{"subject": "CN=dpsroot", "expiry": "Tue, 01 Jun 2027 00:00:00 GMT", "thumbprint": "EF56", "isVerified": true}},
	}
	return f
}

func TestCheck_IoTCertificates(t *testing.T) {
	f := iotFake(t)
	recs, err := newTestChecker(t, f, Config{Subscriptions: []string{guid}, IoTCertificates: true}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]string{}
	exp := map[string]time.Time{}
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid record %+v: %v", r, err)
		}
		if r.Kind != "certificate" || !strings.HasPrefix(r.Source, "azure://arm/subscriptions/") {
			t.Fatalf("record %+v", r)
		}
		got[r.Metadata["service"]+"|"+r.Name] = r.Metadata
		exp[r.Metadata["service"]+"|"+r.Name] = r.ExpiresAt
	}
	want := []string{"iot_hub|devicecert", "dps|dpsroot"}
	for _, w := range want {
		if got[w] == nil {
			t.Errorf("missing %s in %v", w, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("want 2 records (the not-yet-issued certificate has no expiry): %v", got)
	}
	if got["iot_hub|devicecert"]["thumbprint"] != "AB12" || got["iot_hub|devicecert"]["resource_group"] != "rg-iot" || got["iot_hub|devicecert"]["hub"] != "myhub" {
		t.Fatalf("iot hub metadata %v", got["iot_hub|devicecert"])
	}
	if got["dps|dpsroot"]["thumbprint"] != "EF56" || got["dps|dpsroot"]["dps"] != "mydps" {
		t.Fatalf("dps metadata %v", got["dps|dpsroot"])
	}
	if !exp["dps|dpsroot"].Equal(time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("dps expiry %v", exp["dps|dpsroot"])
	}
}

// A hub ID that escapes its own resource group (path traversal via "..")
// must be rejected by safeResourceID before being used to build the
// /certificates sub-URL, and reported as an error rather than silently
// skipped or followed.
func TestCheck_IoTHostileHubID(t *testing.T) {
	f := newFake(t)
	sub := "/subscriptions/" + guid
	f.arm[sub+"/providers/Microsoft.Devices/IotHubs"] = []map[string]any{
		{"id": sub + "/resourceGroups/rg-iot/providers/Microsoft.Devices/IotHubs/../../other", "name": "evilhub"},
	}
	_, err := newTestChecker(t, f, Config{Subscriptions: []string{guid}, IoTCertificates: true}).Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unexpected resource id") {
		t.Fatalf("want an 'unexpected resource id' error, got %v", err)
	}
}
