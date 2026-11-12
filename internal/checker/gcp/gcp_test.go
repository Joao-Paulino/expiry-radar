package gcp

import (
	"context"
	"encoding/json"
	"io"
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

type fake struct {
	srv, meta *httptest.Server
	mu        sync.Mutex
	paths     []string
	stsForm   url.Values
	tokens    map[string]bool     // bearer tokens seen on API calls
	assets    map[string][]string // asset type -> project numbers
	routes    map[string]any      // path -> JSON reply
	disabled  map[string]bool     // path -> SERVICE_DISABLED
}

func newFake(t *testing.T) *fake {
	f := &fake{tokens: map[string]bool{}, assets: map[string][]string{}, routes: map[string]any{}, disabled: map[string]bool{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	f.meta = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "no flavor", 403)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "meta-tok", "expires_in": 3600})
	}))
	t.Cleanup(func() { f.srv.Close(); f.meta.Close() })
	return f
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	switch {
	case r.URL.Path == "/v1/token":
		body, _ := io.ReadAll(r.Body)
		f.stsForm, _ = url.ParseQuery(string(body))
		json.NewEncoder(w).Encode(map[string]any{"access_token": "fed-tok", "expires_in": 3600})
		return
	case strings.HasSuffix(r.URL.Path, ":generateAccessToken"):
		if r.Header.Get("Authorization") != "Bearer fed-tok" {
			http.Error(w, "bad", 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"accessToken": "sa-tok", "expireTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		return
	}
	f.tokens[r.Header.Get("Authorization")] = true
	if strings.HasSuffix(r.URL.Path, ":searchAllResources") {
		var res []map[string]string
		for _, p := range f.assets[r.URL.Query().Get("assetTypes")] {
			res = append(res, map[string]string{"project": "projects/" + p})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
		return
	}
	if f.disabled[r.URL.Path] {
		http.Error(w, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"reason":"SERVICE_DISABLED"}]}}`, 403)
		return
	}
	reply, ok := f.routes[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("pageToken") == "" {
		if pages, ok := reply.([]any); ok { // two pages
			m := pages[0].(map[string]any)
			m["nextPageToken"] = "p2"
			json.NewEncoder(w).Encode(m)
			return
		}
	} else if pages, ok := reply.([]any); ok {
		json.NewEncoder(w).Encode(pages[1])
		return
	}
	json.NewEncoder(w).Encode(reply)
}

func (f *fake) checker(t *testing.T, cfg Config, name string) *Checker {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, ch := range Checkers(cfg) {
		if ch.Name() == name {
			c := ch.(*Checker)
			c.http = f.srv.Client()
			c.ep = endpoints{metadata: f.meta.URL, api: func(string) string { return f.srv.URL },
				allowed: func(u *url.URL, host string) bool { return u.Host == strings.TrimPrefix(f.srv.URL, "https://") }}
			return c
		}
	}
	t.Fatalf("no checker %s", name)
	return nil
}

func ts(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339Nano) }

func TestCertificates_DiscoveryAndAPIs(t *testing.T) {
	f := newFake(t)
	f.assets["certificatemanager.googleapis.com/Certificate"] = []string{"111"}
	f.assets["compute.googleapis.com/SslCertificate"] = []string{"222"}
	f.routes["/v1/projects/111/locations/-/certificates"] = []any{
		map[string]any{"certificates": []any{map[string]any{"name": "projects/111/locations/global/certificates/web", "expireTime": ts(20 * 24 * time.Hour),
			"sanDnsnames": []string{"www.example.com"}, "managed": map[string]any{"state": "ACTIVE"}}}},
		map[string]any{"certificates": []any{map[string]any{"name": "projects/111/locations/europe-west1/certificates/new", "managed": map[string]any{"state": "PROVISIONING"}}}},
	}
	f.routes["/compute/v1/projects/222/aggregated/sslCertificates"] = map[string]any{"items": map[string]any{
		"global":               map[string]any{"sslCertificates": []any{map[string]any{"name": "lb-cert", "expireTime": ts(5 * 24 * time.Hour), "type": "SELF_MANAGED", "subjectAlternativeNames": []string{"api.example.com"}}}},
		"regions/europe-west1": map[string]any{"warning": map[string]any{"code": "NO_RESULTS_ON_PAGE"}},
	}}
	f.disabled["/compute/v1/projects/333/aggregated/sslCertificates"] = true // listed project without the APIs
	f.disabled["/v1/projects/333/locations/-/certificates"] = true
	c := f.checker(t, Config{Auth: "metadata", Organization: "123456", Projects: []string{"333"}}, "gcp")
	recs, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
		got[r.Source] = r.Name + "|" + r.Metadata["type"]
	}
	if got["gcp://certificatemanager/111/global/web"] != "www.example.com|managed" || got["gcp://compute/222/global/lb-cert"] != "api.example.com|self_managed" || len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if !f.tokens["Bearer meta-tok"] || len(f.tokens) != 1 {
		t.Fatalf("tokens %v", f.tokens)
	}
}

func writeExternal(t *testing.T, f *fake, tokenURL, impURL string) string {
	dir := t.TempDir()
	subj := filepath.Join(dir, "subject")
	os.WriteFile(subj, []byte("oidc-jwt\n"), 0o600)
	cfg := map[string]any{"type": "external_account", "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "token_url": tokenURL,
		"credential_source": map[string]any{"file": subj}}
	if impURL != "" {
		cfg["service_account_impersonation_url"] = impURL
	}
	b, _ := json.Marshal(cfg)
	p := filepath.Join(dir, "cred.json")
	os.WriteFile(p, b, 0o600)
	return p
}

func TestExternalAccount_ExchangeAndImpersonation(t *testing.T) {
	f := newFake(t)
	f.routes["/v1/projects/555/secrets"] = map[string]any{}
	file := writeExternal(t, f, f.srv.URL+"/v1/token", f.srv.URL+"/v1/projects/-/serviceAccounts/radar@p.iam.gserviceaccount.com:generateAccessToken")
	c := f.checker(t, Config{Auth: "external_account", CredentialFile: file, Projects: []string{"555"}, Services: []string{"secret_manager"}}, "gcp-secrets")
	if _, err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.stsForm.Get("subject_token") != "oidc-jwt" || f.stsForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" || !f.tokens["Bearer sa-tok"] {
		t.Fatalf("sts %v tokens %v", f.stsForm, f.tokens)
	}
}

// A crafted credential file must not send the subject token elsewhere.
func TestExternalAccount_TokenURLMustBeGoogle(t *testing.T) {
	f := newFake(t)
	file := writeExternal(t, f, "https://evil.example.com/v1/token", "")
	c := f.checker(t, Config{Auth: "external_account", CredentialFile: file, Projects: []string{"555"}}, "gcp")
	if _, err := c.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "sts.googleapis.com") {
		t.Fatalf("got %v", err)
	}
	if !defaultEndpoints().allowed(&url.URL{Scheme: "https", Host: "sts.googleapis.com"}, "sts.googleapis.com") ||
		defaultEndpoints().allowed(&url.URL{Scheme: "https", Host: "sts.googleapis.com.evil.com"}, "sts.googleapis.com") {
		t.Fatal("host check")
	}
}

func TestServiceAccountKeys(t *testing.T) {
	f := newFake(t)
	f.routes["/v1/projects/555/serviceAccounts"] = map[string]any{"accounts": []any{map[string]any{"email": "app@proj-one.iam.gserviceaccount.com"}}}
	f.routes["/v1/projects/555/serviceAccounts/app@proj-one.iam.gserviceaccount.com/keys"] = map[string]any{"keys": []any{
		map[string]any{"name": "projects/proj-one/serviceAccounts/app/keys/aaaaaaaa1111", "validAfterTime": ts(-100 * 24 * time.Hour), "validBeforeTime": "9999-12-31T23:59:59Z", "keyType": "USER_MANAGED"},
		map[string]any{"name": "projects/proj-one/serviceAccounts/app/keys/bbbbbbbb2222", "validAfterTime": ts(-10 * 24 * time.Hour), "validBeforeTime": ts(5 * 24 * time.Hour), "keyType": "USER_MANAGED"},
		map[string]any{"name": "projects/proj-one/serviceAccounts/app/keys/cccccccc3333", "validAfterTime": ts(-200 * 24 * time.Hour), "keyType": "USER_MANAGED", "disabled": true},
		map[string]any{"name": "projects/proj-one/serviceAccounts/app/keys/dddddddd4444", "validAfterTime": ts(-5 * 24 * time.Hour), "keyType": "SYSTEM_MANAGED"},
	}}
	c := f.checker(t, Config{Auth: "metadata", Projects: []string{"555"}, Services: []string{"service_account_keys"}}, "gcp-service-account-keys")
	recs, err := c.Check(context.Background())
	if err != nil || len(recs) != 3 {
		t.Fatalf("got %+v, %v", recs, err)
	}
	by := map[string]time.Time{}
	for _, r := range recs {
		by[r.Metadata["key_id"]] = r.ExpiresAt
		if r.Metadata["key_id"] == "cccccccc3333" && (r.Metadata["alerts"] != "off" || r.Metadata["status"] != "disabled") {
			t.Fatalf("disabled key: %+v", r)
		}
	}
	if !by["aaaaaaaa1111"].Before(time.Now()) || by["bbbbbbbb2222"].Sub(time.Now().Add(5*24*time.Hour)).Abs() > time.Minute {
		t.Fatalf("dates %v", by)
	}
}

func TestSecretManager(t *testing.T) {
	f := newFake(t)
	f.routes["/v1/projects/555/secrets"] = map[string]any{"secrets": []any{
		map[string]any{"name": "projects/555/secrets/db", "rotation": map[string]any{"rotationPeriod": "2592000s", "nextRotationTime": ts(10 * 24 * time.Hour)}},
		map[string]any{"name": "projects/555/secrets/temp", "expireTime": ts(3 * 24 * time.Hour)},
		map[string]any{"name": "projects/555/secrets/plain"},
	}}
	// last enabled version 60 days old with a 30-day period: overdue,
	// although nextRotationTime (a notification schedule) is in the future
	f.routes["/v1/projects/555/secrets/db/versions"] = map[string]any{"versions": []any{map[string]any{"createTime": ts(-60 * 24 * time.Hour)}, map[string]any{"createTime": ts(-90 * 24 * time.Hour)}}}
	c := f.checker(t, Config{Auth: "metadata", Projects: []string{"555"}, Services: []string{"secret_manager"}}, "gcp-secrets")
	recs, err := c.Check(context.Background())
	if err != nil || len(recs) != 2 {
		t.Fatalf("got %+v, %v", recs, err)
	}
	for _, r := range recs {
		switch r.Name {
		case "db":
			if !r.ExpiresAt.Before(time.Now()) || r.Metadata["reason"] != "rotation" {
				t.Fatalf("db: %+v", r)
			}
		case "temp":
			if r.Metadata["reason"] != "expire_time" {
				t.Fatalf("temp: %+v", r)
			}
		}
	}
}

func TestConfig(t *testing.T) {
	for name, c := range map[string]Config{
		"key file":      {Auth: "service_account_key", Projects: []string{"proj-one"}},
		"no scope":      {Auth: "metadata"},
		"bad org":       {Auth: "metadata", Organization: "org-1"},
		"bad project":   {Auth: "metadata", Projects: []string{"P_1"}},
		"short project": {Auth: "metadata", Projects: []string{"p-one"}},
		"bad service":   {Auth: "metadata", Projects: []string{"555"}, Services: []string{"bigquery"}},
	} {
		if c.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestMain(m *testing.M) {
	retryWait = time.Millisecond
	os.Exit(m.Run())
}

func TestCertificateManagerUnreachable(t *testing.T) {
	f := newFake(t)
	f.routes["/v1/projects/111/locations/-/certificates"] = map[string]any{"unreachable": []string{"europe-west1"}}
	c := f.checker(t, Config{Auth: "metadata", Projects: []string{"111"}, Services: []string{"certificate_manager"}}, "gcp")
	if _, err := c.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "europe-west1") {
		t.Fatalf("partial list accepted: %v", err)
	}
}

// A project given by ID and discovered by number is one project.
func TestProjectIDResolvedToNumber(t *testing.T) {
	f := newFake(t)
	f.routes["/v3/projects/proj-one"] = map[string]any{"name": "projects/111", "projectId": "proj-one"}
	f.assets["compute.googleapis.com/SslCertificate"] = []string{"111"}
	f.routes["/compute/v1/projects/111/aggregated/sslCertificates"] = map[string]any{"items": map[string]any{
		"global": map[string]any{"sslCertificates": []any{map[string]any{"name": "c", "expireTime": ts(9 * 24 * time.Hour)}}}}}
	c := f.checker(t, Config{Auth: "metadata", Organization: "9", Projects: []string{"proj-one"}, Services: []string{"compute_ssl"}}, "gcp")
	recs, err := c.Check(context.Background())
	if err != nil || len(recs) != 1 || recs[0].Source != "gcp://compute/111/global/c" {
		t.Fatalf("got %+v, %v", recs, err)
	}
}

func TestSecretRotationFromNextRotationTime(t *testing.T) {
	f := newFake(t)
	f.routes["/v1/projects/proj-one/secrets"] = map[string]any{"secrets": []any{
		map[string]any{"name": "projects/proj-one/secrets/api", "rotation": map[string]any{"nextRotationTime": ts(-5 * 24 * time.Hour)}}}}
	f.routes["/v3/projects/proj-one"] = map[string]any{"name": "projects/proj-one"}
	c := f.checker(t, Config{Auth: "metadata", Projects: []string{"222"}, Services: []string{"secret_manager"}}, "gcp-secrets")
	f.routes["/v1/projects/222/secrets"] = f.routes["/v1/projects/proj-one/secrets"]
	recs, err := c.Check(context.Background())
	if err != nil || len(recs) != 1 || !recs[0].ExpiresAt.Before(time.Now()) || recs[0].Metadata["reason"] != "rotation" {
		t.Fatalf("got %+v, %v", recs, err)
	}
}
