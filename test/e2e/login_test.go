package e2e

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/admin"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/rules"
	collector "github.com/Joao-Paulino/expiry-radar/internal/collector/server"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/testhelpers"
)

var csrfRe = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func TestEndToEnd_AdminLoginMuteLogout(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "radar.db")

	// Configure the Administrator the same way the CLI does.
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	as := &admin.Store{DB: database}
	const password = "correct horse battery staple"
	h, _ := admin.HashPassword(password)
	as.SetPassword(ctx, h)
	secret, _ := admin.NewTOTPSecret()
	_, hashes, _ := admin.NewRecoveryCodes()
	as.SetTOTP(ctx, secret, hashes)

	certFile, keyFile := testhelpers.WriteSelfSignedCertForTest(t, dir)
	addr, stop, err := testhelpers.StartForTest(collector.Config{
		DBPath:      dbPath,
		ListenAddr:  "127.0.0.1:0",
		AuthTokens:  []string{"e2e-agent-token-0123456789abcdef0123"},
		AdminTokens: []string{"e2e-admin-token-0123456789abcdef0123"},
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	base := "https://" + addr

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	get := func(path string) string {
		req, _ := http.NewRequest("GET", base+path, nil)
		req.Header.Set("Accept", "text/html")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	post := func(path string, form url.Values) *http.Response {
		resp, err := client.PostForm(base+path, form)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	if body := get("/"); !strings.Contains(body, `action="/login"`) {
		t.Fatalf("unauthenticated browser did not land on the login page: %s", body)
	}

	code, _ := admin.TOTPCode(secret, time.Now().Unix()/30)
	post("/login", url.Values{"password": {password}, "code": {code}})

	list := get("/")
	m := csrfRe.FindStringSubmatch(list)
	if m == nil {
		t.Fatalf("not logged in, or no CSRF field on the list page: %s", list)
	}

	if resp := post("/rules", url.Values{"source": {"a:443"}, "name": {"a"}, "kind": {"certificate"}, "muted": {"on"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mute without CSRF: got %d, want 403", resp.StatusCode)
	}
	post("/rules", url.Values{"csrf_token": {m[1]}, "source": {"a:443"}, "name": {"a"}, "kind": {"certificate"}, "muted": {"on"}})
	rule, found, err := rules.NewSQLite(database).Get(ctx, "a:443", "a", "certificate")
	if err != nil || !found || !rule.Muted {
		t.Fatalf("record not muted: %+v found=%v err=%v", rule, found, err)
	}

	post("/logout", url.Values{"csrf_token": {m[1]}})
	if body := get("/"); !strings.Contains(body, `action="/login"`) {
		t.Fatalf("still logged in after logout: %s", body)
	}
}
