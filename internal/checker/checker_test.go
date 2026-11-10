package checker

import (
	"testing"
	"time"
)

func TestExpiryRecord_Validate(t *testing.T) {
	valid := ExpiryRecord{Source: "host:443", Name: "example.com", Kind: "certificate", ExpiresAt: time.Now().Add(24 * time.Hour)}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid record to pass, got %v", err)
	}
	missingSource := valid
	missingSource.Source = ""
	if err := missingSource.Validate(); err == nil {
		t.Fatal("expected error for missing Source")
	}
	zeroExpiry := valid
	zeroExpiry.ExpiresAt = time.Time{}
	if err := zeroExpiry.Validate(); err == nil {
		t.Fatal("expected error for zero ExpiresAt")
	}
}
