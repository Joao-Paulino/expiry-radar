package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/admin"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
)

func writeTestConfig(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "radar.db")
	cfgPath = filepath.Join(dir, "collector.json")
	data, _ := json.Marshal(map[string]any{"db_path": dbPath})
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dbPath
}

func openStores(t *testing.T, dbPath string) (*admin.Store, *session.Store) {
	t.Helper()
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return &admin.Store{DB: database}, &session.Store{DB: database, Now: time.Now}
}

func TestSetAdminPassword_StoresHashAndRevokesSessions(t *testing.T) {
	cfgPath, dbPath := writeTestConfig(t)
	as, ss := openStores(t, dbPath)
	id, _, _ := ss.Create(context.Background())

	var out bytes.Buffer
	in := strings.NewReader("correct horse battery staple\ncorrect horse battery staple\n")
	if err := runSetAdminPassword(cfgPath, in, &out); err != nil {
		t.Fatalf("unexpected error: %v (output %s)", err, out.String())
	}
	acc, found, _ := as.Get(context.Background())
	if !found {
		t.Fatal("no account stored")
	}
	if ok, _ := admin.VerifyPassword(acc.PasswordHash, "correct horse battery staple"); !ok {
		t.Fatal("stored hash does not verify")
	}
	if strings.Contains(out.String(), "correct horse") {
		t.Fatal("password echoed in output")
	}
	if _, ok, _ := ss.Lookup(context.Background(), id); ok {
		t.Fatal("existing session not revoked")
	}
}

func TestSetAdminPassword_MismatchAndShort(t *testing.T) {
	for name, input := range map[string]string{
		"mismatch": "correct horse battery staple\ndifferent horse battery\n",
		"short":    "short\nshort\n",
	} {
		cfgPath, dbPath := writeTestConfig(t)
		as, _ := openStores(t, dbPath)
		if err := runSetAdminPassword(cfgPath, strings.NewReader(input), &bytes.Buffer{}); err == nil {
			t.Errorf("%s: expected error", name)
		}
		if _, found, _ := as.Get(context.Background()); found {
			t.Errorf("%s: account stored despite error", name)
		}
	}
}

var secretRe = regexp.MustCompile(`secret=([A-Z2-7]+)`)

func TestSetAdminTOTP_ConfirmsCodeAndPrintsRecoveryCodes(t *testing.T) {
	cfgPath, dbPath := writeTestConfig(t)
	as, ss := openStores(t, dbPath)
	id, _, _ := ss.Create(context.Background())
	now := time.Unix(1_700_000_000, 0)

	// The secret is printed before the code is read, so feed the code
	// through a pipe once the secret has been written.
	pr, pw, _ := os.Pipe()
	var out syncBuffer
	done := make(chan error, 1)
	go func() { done <- runSetAdminTOTP(cfgPath, pr, &out, func() time.Time { return now }) }()

	var secret string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if m := secretRe.FindStringSubmatch(out.String()); m != nil {
			secret = m[1]
			break
		}
	}
	if secret == "" {
		t.Fatalf("no otpauth URI printed: %s", out.String())
	}
	code, _ := admin.TOTPCode(secret, now.Unix()/30)
	pw.WriteString(code + "\n")
	pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	acc, _, _ := as.Get(context.Background())
	if acc.TOTPSecret != secret {
		t.Fatalf("stored secret %q, printed %q", acc.TOTPSecret, secret)
	}
	if acc.TOTPLastStep != now.Unix()/30 {
		t.Fatal("confirmation code could be replayed for login")
	}
	codes := regexp.MustCompile(`(?m)^\s+([a-z2-9]{10})$`).FindAllString(out.String(), -1)
	if len(codes) != 8 {
		t.Fatalf("want 8 recovery codes printed, got %d: %s", len(codes), out.String())
	}
	if _, ok, _ := ss.Lookup(context.Background(), id); ok {
		t.Fatal("existing session not revoked")
	}
}

func TestSetAdminTOTP_WrongCodeStoresNothing(t *testing.T) {
	cfgPath, dbPath := writeTestConfig(t)
	as, _ := openStores(t, dbPath)
	err := runSetAdminTOTP(cfgPath, strings.NewReader("000000\n"), &bytes.Buffer{}, func() time.Time { return time.Unix(1_700_000_000, 0) })
	if err == nil {
		t.Fatal("expected an error for a wrong code")
	}
	if acc, _, _ := as.Get(context.Background()); acc.TOTPSecret != "" {
		t.Fatal("secret stored despite wrong code")
	}
}
