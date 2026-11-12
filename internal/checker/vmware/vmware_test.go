package vmware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pemCert(t *testing.T, cn string, notAfter time.Time) string {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fakeVC struct {
	srv, esxi  *httptest.Server
	soapBodies []string
	loggedOut  bool
}

func newFakeVC(t *testing.T, stsExp, rootExp time.Time) *fakeVC {
	f := &fakeVC{}
	f.esxi = httptest.NewTLSServer(http.NotFoundHandler())
	sts, root := pemCert(t, "ssoserverSign", stsExp), pemCert(t, "CA", rootExp)
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/session" {
			switch r.Method {
			case http.MethodPost:
				if u, p, ok := r.BasicAuth(); !ok || u != "radar@vsphere.local" || p != "s3cr<t" {
					http.Error(w, "unauthorized", 401)
					return
				}
				w.WriteHeader(201)
				json.NewEncoder(w).Encode("sess-1")
			case http.MethodDelete:
				f.loggedOut = true
			}
			return
		}
		if r.URL.Path == "/sdk" {
			b, _ := io.ReadAll(r.Body)
			f.soapBodies = append(f.soapBodies, string(b))
			switch {
			case strings.Contains(string(b), "RetrieveServiceContent"):
				io.WriteString(w, `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><RetrieveServiceContentResponse xmlns="urn:vim25"><returnval><propertyCollector type="PropertyCollector">propertyCollector</propertyCollector><sessionManager type="SessionManager">SessionManager</sessionManager><licenseManager type="LicenseManager">LicenseManager</licenseManager></returnval></RetrieveServiceContentResponse></soapenv:Body></soapenv:Envelope>`)
			case strings.Contains(string(b), "RetrievePropertiesEx"):
				io.WriteString(w, `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><RetrievePropertiesExResponse xmlns="urn:vim25"><returnval><objects><obj type="LicenseManager">LicenseManager</obj><propSet><name>licenses</name><val xsi:type="ArrayOfLicenseManagerLicenseInfo">`+
					`<LicenseManagerLicenseInfo><licenseKey>AAAAA-BBBBB-CCCCC-DDDDD-EVAL1</licenseKey><editionKey>eval</editionKey><name>Evaluation Mode</name><properties><key>expirationDate</key><value xsi:type="xsd:dateTime">2026-12-20T10:00:00.000Z</value></properties></LicenseManagerLicenseInfo>`+
					`<LicenseManagerLicenseInfo><licenseKey>11111-22222-33333-44444-PERP9</licenseKey><editionKey>esx.enterprisePlus.cpuPackage</editionKey><name>vSphere 8 Enterprise Plus</name><properties><key>ProductName</key><value xsi:type="xsd:string">VMware ESX Server</value></properties></LicenseManagerLicenseInfo>`+
					`</val></propSet></objects></returnval></RetrievePropertiesExResponse></soapenv:Body></soapenv:Envelope>`)
			default:
				io.WriteString(w, `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body/></soapenv:Envelope>`)
			}
			return
		}
		if r.Header.Get("vmware-api-session-id") != "sess-1" {
			http.Error(w, "no session", 401)
			return
		}
		host, _, _ := net.SplitHostPort(strings.TrimPrefix(f.esxi.URL, "https://"))
		switch r.URL.Path {
		case "/api/vcenter/certificate-management/vcenter/signing-certificate":
			json.NewEncoder(w).Encode(map[string]any{"active_cert_chain": map[string]any{"cert_chain": []string{sts}}})
		case "/api/vcenter/certificate-management/vcenter/trusted-root-chains":
			json.NewEncoder(w).Encode([]map[string]string{{"chain": "ABC123"}})
		case "/api/vcenter/certificate-management/vcenter/trusted-root-chains/ABC123":
			json.NewEncoder(w).Encode(map[string]any{"cert_chain": map[string]any{"cert_chain": []string{root}}})
		case "/api/vcenter/host":
			json.NewEncoder(w).Encode([]map[string]string{{"name": host, "connection_state": "CONNECTED"}, {"name": "esx-down.example", "connection_state": "DISCONNECTED"}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(func() { f.srv.Close(); f.esxi.Close() })
	return f
}

func TestCheck(t *testing.T) {
	stsExp, rootExp := time.Now().Add(20*24*time.Hour).Truncate(time.Second), time.Now().Add(3650*24*time.Hour).Truncate(time.Second)
	f := newFakeVC(t, stsExp, rootExp)
	dir := t.TempDir()
	pw, ca := filepath.Join(dir, "pw"), filepath.Join(dir, "ca.pem")
	os.WriteFile(pw, []byte("s3cr<t\n"), 0o600)
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600)
	cfg := Config{URL: f.srv.URL, Username: "radar@vsphere.local", PasswordFile: pw, CAFile: ca}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(f.esxi.URL, "https://"))
	cfg.esxiPort = port
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
		got[strings.SplitN(r.Source, "/", 4)[3]] = r.Kind + "|" + r.Name + "|" + r.ExpiresAt.Format(time.RFC3339)
	}
	want := map[string]string{
		"vcenter/tls":         "certificate|vCenter TLS|" + f.srv.Certificate().NotAfter.UTC().Format(time.RFC3339),
		"vcenter/sts-signing": "certificate|vCenter STS signing|" + stsExp.UTC().Format(time.RFC3339),
		"trusted-root/ABC123": "ca_certificate|CA|" + rootExp.UTC().Format(time.RFC3339),
		"esxi/127.0.0.1":      "certificate|127.0.0.1|" + f.esxi.Certificate().NotAfter.UTC().Format(time.RFC3339),
		"license/EVAL1":       "license|Evaluation Mode (…EVAL1)|2026-12-20T10:00:00Z",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("perpetual licence or disconnected host reported: %v", got)
	}
	for _, b := range f.soapBodies {
		if strings.Contains(b, "s3cr<t") {
			t.Fatal("password not XML-escaped")
		}
		if strings.Contains(b, "AAAAA-BBBBB") {
			t.Fatal("licence key echoed")
		}
	}
	if !f.loggedOut {
		t.Fatal("REST session not closed")
	}
	for _, r := range recs {
		for _, v := range r.Metadata {
			if strings.Contains(v, "AAAAA") {
				t.Fatal("licence key stored")
			}
		}
	}
}

func TestConfig(t *testing.T) {
	for name, c := range map[string]Config{
		"http":        {URL: "http://vc", Username: "u", PasswordFile: "/p"},
		"path":        {URL: "https://vc/ui", Username: "u", PasswordFile: "/p"},
		"no password": {URL: "https://vc", Username: "u"},
	} {
		if c.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
