package opcua

import (
	"context"
	"os"
	"testing"
)

// Interop check against a real OPC UA server, run by hand:
// OPCUA_INTEROP_URL=opc.tcp://127.0.0.1:48400/test go test -run Interop ./internal/checker/opcua
func TestInterop_RealServer(t *testing.T) {
	url := os.Getenv("OPCUA_INTEROP_URL")
	if url == "" {
		t.Skip("set OPCUA_INTEROP_URL to run against a real OPC UA server")
	}
	recs, err := New(Config{Targets: []Target{{Endpoint: url}}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		t.Logf("%s | %s | %s | %v", r.Source, r.Name, r.ExpiresAt, r.Metadata)
	}
	if len(recs) == 0 {
		t.Fatal("no certificate reported")
	}
}
