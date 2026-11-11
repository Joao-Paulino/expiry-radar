package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHandleVersion(t *testing.T) {
	orig := version
	version = "v1.2.3"
	defer func() { version = orig }()
	var out bytes.Buffer
	if !handleVersion([]string{"prog", "version"}, &out) || !strings.Contains(out.String(), "v1.2.3") {
		t.Fatalf("version not printed: %q", out.String())
	}
	if handleVersion([]string{"prog", "config.json"}, &out) {
		t.Fatal("non-version argument handled as version")
	}
}
