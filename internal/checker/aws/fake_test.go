package aws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	acct1 = "111111111111"
	acct2 = "222222222222"
)

// fakeAWS serves STS, Roles Anywhere, ACM and IAM over TLS and the
// instance metadata / container credential endpoints over plain HTTP.
type fakeAWS struct {
	srv, meta   *httptest.Server
	mu          sync.Mutex
	calls       []string // "service action region accesskey"
	forms       []map[string]string
	raHeaders   http.Header
	raQuery     string
	raBody      string
	credCalls   int
	acm         map[string][]map[string]any // "account/region" -> certificate summaries
	acmFail     string                      // "account/region" answering an error
	serverCerts map[string][]map[string]string
	credReport  map[string]string           // account -> CSV
	secrets     map[string][]map[string]any // "account/region" -> SecretListEntry
	versions    map[string][]map[string]any // secret ARN -> versions
	reportPolls int                         // GenerateCredentialReport answers STARTED this many times first
	reportGone  int                         // GetCredentialReport answers ReportExpired this many times first
	imdsToken   string
	throttle    int    // ACM answers ThrottlingException this many times first
	raRegion    string // region the Roles Anywhere request was sent to
	relAuth     string // Authorization header seen on the ECS relative URI
}

func newFakeAWS(t *testing.T) *fakeAWS {
	f := &fakeAWS{acm: map[string][]map[string]any{}, serverCerts: map[string][]map[string]string{}, credReport: map[string]string{}, secrets: map[string][]map[string]any{}, versions: map[string][]map[string]any{}, imdsToken: "imds-tok"}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serveAPI))
	f.meta = httptest.NewServer(http.HandlerFunc(f.serveMeta))
	t.Cleanup(func() { f.srv.Close(); f.meta.Close() })
	return f
}

// Access keys encode the account they belong to: base creds are
// "ASIA-BASE", assumed ones "ASIA-<account>".
func credsJSON(ak string) map[string]any {
	return map[string]any{"Code": "Success", "AccessKeyId": ak, "SecretAccessKey": "secret-" + ak, "Token": "token-" + ak,
		"Expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
}

func (f *fakeAWS) serveMeta(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/latest/api/token" && r.Method == http.MethodPut:
		if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
			http.Error(w, "ttl", 400)
			return
		}
		io.WriteString(w, f.imdsToken)
	case strings.HasPrefix(r.URL.Path, "/latest/meta-data/iam/security-credentials/"):
		if r.Header.Get("X-aws-ec2-metadata-token") != f.imdsToken {
			http.Error(w, "IMDSv1 refused", 401)
			return
		}
		f.credCalls++
		if f.imdsToken == "dead" {
			http.Error(w, "unreachable", 503)
			return
		}
		if r.URL.Path == "/latest/meta-data/iam/security-credentials/" {
			io.WriteString(w, "expiry-radar-role\n")
			return
		}
		json.NewEncoder(w).Encode(credsJSON("ASIA-BASE"))
	case r.URL.Path == "/ecs-creds" || r.URL.Path == "/pod-identity":
		if r.URL.Path == "/ecs-creds" {
			f.relAuth = r.Header.Get("Authorization")
		}
		if r.URL.Path == "/pod-identity" && r.Header.Get("Authorization") != "pod-token" {
			http.Error(w, "auth", 401)
			return
		}
		f.credCalls++
		json.NewEncoder(w).Encode(credsJSON("ASIA-BASE"))
	default:
		http.NotFound(w, r)
	}
}

// accessKey extracts the access key and scope from a SigV4 header.
func accessKey(auth string) (ak, region, service string) {
	_, cred, ok := strings.Cut(auth, "Credential=")
	if !ok {
		return "", "", ""
	}
	cred, _, _ = strings.Cut(cred, ",")
	p := strings.Split(cred, "/")
	if len(p) < 5 {
		return "", "", ""
	}
	return p[0], p[2], p[3]
}

func accountOf(ak string) string {
	if ak == "ASIA-BASE" {
		return acct1
	}
	return strings.TrimPrefix(ak, "ASIA-")
}

func (f *fakeAWS) serveAPI(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	ak, region, service := accessKey(r.Header.Get("Authorization"))
	if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") && r.Header.Get("X-Amz-Security-Token") != "token-"+ak {
		http.Error(w, "<Error><Code>InvalidClientTokenId</Code></Error>", 403)
		return
	}
	switch {
	case r.URL.Path == "/sessions": // Roles Anywhere
		f.raHeaders, f.raQuery, f.raBody = r.Header.Clone(), r.URL.RawQuery, string(body)
		f.calls = append(f.calls, "rolesanywhere CreateSession")
		json.NewEncoder(w).Encode(map[string]any{"credentialSet": []map[string]any{{"credentials": map[string]any{
			"accessKeyId": "ASIA-BASE", "secretAccessKey": "secret-ASIA-BASE", "sessionToken": "token-ASIA-BASE",
			"expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}}})
	case r.Header.Get("X-Amz-Target") == "secretsmanager.ListSecretVersionIds":
		var in struct{ SecretId string }
		json.Unmarshal(body, &in)
		f.calls = append(f.calls, "secretsmanager ListSecretVersionIds "+in.SecretId)
		v, ok := f.versions[in.SecretId]
		if !ok {
			http.Error(w, `{"__type":"ResourceNotFoundException"}`, 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"Versions": v})
	case r.Header.Get("X-Amz-Target") == "secretsmanager.ListSecrets":
		f.calls = append(f.calls, "secretsmanager ListSecrets "+region+" "+ak)
		if service != "secretsmanager" {
			http.Error(w, "bad scope", 400)
			return
		}
		var in struct {
			NextToken  string
			MaxResults int
		}
		json.Unmarshal(body, &in)
		if in.MaxResults > 100 {
			http.Error(w, `{"__type":"ValidationException"}`, 400)
			return
		}
		items := f.secrets[accountOf(ak)+"/"+region]
		if in.NextToken == "s2" {
			json.NewEncoder(w).Encode(map[string]any{"SecretList": items[1:]})
			return
		}
		out := map[string]any{"SecretList": items[:min(1, len(items))]}
		if len(items) > 1 {
			out["NextToken"] = "s2"
		}
		json.NewEncoder(w).Encode(out)
	case r.Header.Get("X-Amz-Target") == "CertificateManager.ListCertificates":
		key := accountOf(ak) + "/" + region
		f.calls = append(f.calls, "acm ListCertificates "+region+" "+ak)
		if service != "acm" {
			http.Error(w, "bad scope", 400)
			return
		}
		if key == f.acmFail {
			w.WriteHeader(400)
			io.WriteString(w, `{"__type":"AccessDeniedException","message":"not authorized to perform: acm:ListCertificates"}`)
			return
		}
		var in struct {
			NextToken                 string
			CertificateKeyPairOrigins []string
			Includes                  struct {
				KeyTypes []string `json:"keyTypes"`
			}
		}
		json.Unmarshal(body, &in)
		if f.throttle > 0 {
			f.throttle--
			w.WriteHeader(400)
			io.WriteString(w, `{"__type":"ThrottlingException","message":"Rate exceeded"}`)
			return
		}
		if len(in.Includes.KeyTypes) < 5 {
			http.Error(w, `{"__type":"Test","message":"without Includes.keyTypes ACM lists RSA_2048 only"}`, 400)
			return
		}
		var items []map[string]any
		for _, it := range f.acm[key] {
			// Default ACM filtering leaves ACME certificates out.
			if it["CertificateKeyPairOrigin"] == "ACME" && !strings.Contains(strings.Join(in.CertificateKeyPairOrigins, ","), "ACME") {
				continue
			}
			items = append(items, it)
		}
		if in.NextToken == "p2" {
			json.NewEncoder(w).Encode(map[string]any{"CertificateSummaryList": items[1:]})
			return
		}
		out := map[string]any{"CertificateSummaryList": items[:min(1, len(items))]}
		if len(items) > 1 {
			out["NextToken"] = "p2"
		}
		json.NewEncoder(w).Encode(out)
	default: // Query API: STS and IAM
		vals := map[string]string{}
		for k, v := range r.URL.Query() {
			vals[k] = v[0]
		}
		if r.Method == http.MethodPost {
			for _, kv := range strings.Split(string(body), "&") {
				k, v, _ := strings.Cut(kv, "=")
				vals[k], _ = url.QueryUnescape(v)
			}
		}
		f.forms = append(f.forms, vals)
		f.calls = append(f.calls, service+" "+vals["Action"]+" "+region+" "+ak)
		f.queryAPI(w, vals, ak)
	}
}

func (f *fakeAWS) queryAPI(w http.ResponseWriter, v map[string]string, ak string) {
	xmlCreds := func(op, newAK string) {
		fmt.Fprintf(w, `<%sResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><%sResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>secret-%s</SecretAccessKey><SessionToken>token-%s</SessionToken><Expiration>%s</Expiration></Credentials></%sResult></%sResponse>`,
			op, op, newAK, newAK, newAK, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), op, op)
	}
	switch v["Action"] {
	case "AssumeRoleWithWebIdentity":
		if v["WebIdentityToken"] == "" || ak != "" {
			http.Error(w, "<Error><Code>InvalidIdentityToken</Code></Error>", 400)
			return
		}
		f.credCalls++
		xmlCreds("AssumeRoleWithWebIdentity", "ASIA-BASE")
	case "AssumeRole":
		acct := strings.Split(v["RoleArn"], ":")[4]
		if v["RoleArn"] == "arn:aws:iam::"+acct+":role/denied" {
			http.Error(w, "<ErrorResponse><Error><Code>AccessDenied</Code><Message>not authorized to perform: sts:AssumeRole</Message></Error></ErrorResponse>", 403)
			return
		}
		xmlCreds("AssumeRole", "ASIA-"+acct)
	case "GetCallerIdentity":
		fmt.Fprintf(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>%s</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`, accountOf(ak))
	case "GenerateCredentialReport":
		state := "COMPLETE"
		if f.reportPolls > 0 {
			f.reportPolls--
			state = "STARTED"
		}
		fmt.Fprintf(w, `<GenerateCredentialReportResponse><GenerateCredentialReportResult><State>%s</State></GenerateCredentialReportResult></GenerateCredentialReportResponse>`, state)
	case "GetCredentialReport":
		if f.reportGone > 0 {
			f.reportGone--
			http.Error(w, "<ErrorResponse><Error><Code>ReportExpired</Code><Message>expired</Message></Error></ErrorResponse>", 410)
			return
		}
		csv, ok := f.credReport[accountOf(ak)]
		if !ok {
			http.Error(w, "<ErrorResponse><Error><Code>ReportNotPresent</Code></Error></ErrorResponse>", 410)
			return
		}
		fmt.Fprintf(w, `<GetCredentialReportResponse><GetCredentialReportResult><Content>%s</Content><ReportFormat>text/csv</ReportFormat><GeneratedTime>%s</GeneratedTime></GetCredentialReportResult></GetCredentialReportResponse>`,
			base64.StdEncoding.EncodeToString([]byte(csv)), time.Now().UTC().Format(time.RFC3339))
	case "ListServerCertificates":
		items := f.serverCerts[accountOf(ak)]
		page := items
		truncated := false
		if v["Marker"] == "" && len(items) > 1 {
			page, truncated = items[:1], true
		} else if v["Marker"] == "m2" {
			page = items[1:]
		}
		var b strings.Builder
		for _, c := range page {
			fmt.Fprintf(&b, "<member><ServerCertificateName>%s</ServerCertificateName><Path>/</Path><Arn>%s</Arn><Expiration>%s</Expiration></member>", c["name"], c["arn"], c["exp"])
			_ = c
		}
		marker := ""
		if truncated {
			marker = "<Marker>m2</Marker>"
		}
		fmt.Fprintf(w, `<ListServerCertificatesResponse><ListServerCertificatesResult><IsTruncated>%v</IsTruncated>%s<ServerCertificateMetadataList>%s</ServerCertificateMetadataList></ListServerCertificatesResult></ListServerCertificatesResponse>`, truncated, marker, b.String())
	default:
		http.Error(w, "<Error><Code>InvalidAction</Code></Error>", 400)
	}
}

func (f *fakeAWS) endpoints() endpoints {
	return endpoints{
		imds:          f.meta.URL,
		ecsHost:       f.meta.URL,
		sts:           func(string) string { return f.srv.URL },
		rolesAnywhere: func(r string) string { f.raRegion = r; return f.srv.URL },
		acm:           func(string) string { return f.srv.URL },
		secrets:       func(string) string { return f.srv.URL },
		iam:           f.srv.URL,
	}
}

// writeECCert writes a PEM with an ECDSA certificate and key.
func writeECCert(t *testing.T) (string, *x509.Certificate) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(424242), Subject: pkix.Name{CommonName: "server01"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	cert, _ := x509.ParseCertificate(der)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	p := filepath.Join(t.TempDir(), "ra.pem")
	os.WriteFile(p, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})...), 0o600)
	return p, cert
}

func TestMain(m *testing.M) {
	retryWait, reportWait = time.Millisecond, time.Millisecond
	os.Exit(m.Run())
}
