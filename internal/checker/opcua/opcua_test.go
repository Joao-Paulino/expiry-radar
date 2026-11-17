package opcua

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// fakeServer answers Hello, OpenSecureChannel and GetEndpoints like an
// OPC UA server's discovery endpoint, and records the message types it
// saw. It refuses anything else (in particular CreateSession).
type fakeServer struct {
	ln       net.Listener
	eps      []Endpoint
	chunked  bool // split the GetEndpoints response into two chunks
	seen     chan string
	errReply string // if set, answer Hello with ERR
}

func startFake(t *testing.T, fs *fakeServer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fs.ln = ln
	fs.seen = make(chan string, 16)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go fs.serve(conn)
		}
	}()
	return "opc.tcp://" + ln.Addr().String()
}

func (fs *fakeServer) serve(conn net.Conn) {
	defer conn.Close()
	for {
		typ, _, body, err := readChunk(conn)
		if err != nil {
			return
		}
		fs.seen <- typ
		switch typ {
		case "HEL":
			if fs.errReply != "" {
				var e encoder
				e.u32(0x80010000)
				e.str(fs.errReply)
				_ = writeMsg(conn, "ERR", e.b)
				return
			}
			var e encoder
			for i := 0; i < 5; i++ {
				e.u32(bufferSize)
			}
			_ = writeMsg(conn, "ACK", e.b)
		case "OPN":
			var e encoder
			e.u32(7)
			e.str(securityPolicyNone)
			e.bytes(nil)
			e.bytes(nil)
			e.u32(1)
			e.u32(1)
			e.nodeID(idOpenSecureChannelResponse)
			responseHeader(&e, 0)
			e.u32(0) // ServerProtocolVersion
			e.u32(7) // ChannelId
			e.u32(9) // TokenId
			e.i64(0)
			e.u32(60000)
			e.bytes([]byte{})
			_ = writeMsg(conn, "OPN", e.b)
		case "MSG":
			d := &decoder{b: body}
			d.take(16)
			if id := d.nodeID(); id != idGetEndpointsRequest {
				return // only discovery is allowed
			}
			var svc encoder
			svc.nodeID(idGetEndpointsResponse)
			responseHeader(&svc, 0)
			svc.i32(int32(len(fs.eps)))
			for _, ep := range fs.eps {
				encodeEndpoint(&svc, ep)
			}
			hdr := func() []byte {
				var h encoder
				h.u32(7)
				h.u32(9)
				h.u32(2)
				h.u32(2)
				return h.b
			}
			if fs.chunked {
				half := len(svc.b) / 2
				c1 := append(hdr(), svc.b[:half]...)
				msg := make([]byte, 8)
				copy(msg, "MSGC")
				putSize(msg, len(c1)+8)
				_, _ = conn.Write(append(msg, c1...))
				_ = writeMsg(conn, "MSG", append(hdr(), svc.b[half:]...))
			} else {
				_ = writeMsg(conn, "MSG", append(hdr(), svc.b...))
			}
		case "CLO":
			return
		}
	}
}

func putSize(hdr []byte, n int) {
	hdr[4], hdr[5], hdr[6], hdr[7] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
}

func responseHeader(e *encoder, status uint32) {
	e.i64(0)
	e.u32(1)
	e.u32(status)
	e.u8(0)   // DiagnosticInfo: empty
	e.i32(-1) // StringTable
	e.nodeID(0)
	e.u8(0)
}

func encodeEndpoint(e *encoder, ep Endpoint) {
	e.str(ep.URL)
	e.str(ep.ApplicationURI)
	e.str("urn:product")
	e.u8(0x02)
	e.str(ep.ApplicationName)
	e.u32(0)
	e.str("")
	e.str("")
	e.i32(1)
	e.str(ep.URL)
	e.bytes(ep.ServerCertificate)
	e.u32(ep.SecurityMode)
	e.str(ep.SecurityPolicyURI)
	e.i32(1) // one UserTokenPolicy
	e.str("anonymous")
	e.u32(0)
	e.str("")
	e.str("")
	e.str("")
	e.str("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary")
	e.u8(0)
}

func TestCheck_ReportsServerCertificateOncePerCertificate(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second).UTC()
	cert := testCert(t, "plc-01 OPC UA", notAfter)
	const pol = "http://opcfoundation.org/UA/SecurityPolicy#"
	fs := &fakeServer{eps: []Endpoint{
		{URL: "opc.tcp://plc-01:4840", ApplicationURI: "urn:plc-01", ApplicationName: "PLC 01", SecurityMode: 1, SecurityPolicyURI: pol + "None"},
		{URL: "opc.tcp://plc-01:4840", ApplicationURI: "urn:plc-01", ApplicationName: "PLC 01", ServerCertificate: cert, SecurityMode: 2, SecurityPolicyURI: pol + "Basic256Sha256"},
		{URL: "opc.tcp://plc-01:4840", ApplicationURI: "urn:plc-01", ApplicationName: "PLC 01", ServerCertificate: cert, SecurityMode: 3, SecurityPolicyURI: pol + "Aes128_Sha256_RsaOaep"},
	}}
	url := startFake(t, fs)

	recs, err := New(Config{Targets: []Target{{Endpoint: url}}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 record (same certificate on two endpoints), got %d: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.Source != url || r.Name != "plc-01 OPC UA" || r.Kind != "certificate" || !r.ExpiresAt.Equal(notAfter) {
		t.Errorf("record = %+v", r)
	}
	if got := r.Metadata["security_policies"]; got != "Aes128_Sha256_RsaOaep,Basic256Sha256" {
		t.Errorf("security_policies = %q", got)
	}
	if r.Metadata["application_uri"] != "urn:plc-01" || r.Metadata["self_signed"] != "true" {
		t.Errorf("metadata = %v", r.Metadata)
	}
}

// The checker must stay on the discovery path: Hello, OpenSecureChannel,
// one GetEndpoints and CloseSecureChannel. Never a session.
func TestCheck_OnlyUsesDiscoveryMessages(t *testing.T) {
	fs := &fakeServer{eps: []Endpoint{{URL: "x", ServerCertificate: testCert(t, "a", time.Now().Add(time.Hour)), SecurityPolicyURI: "#Basic256Sha256"}}}
	url := startFake(t, fs)
	if _, err := New(Config{Targets: []Target{{Endpoint: url}}}).Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got []string
	timeout := time.After(2 * time.Second)
	for len(got) < 4 {
		select {
		case s := <-fs.seen:
			got = append(got, s)
		case <-timeout:
			t.Fatalf("messages seen: %v", got)
		}
	}
	if strings.Join(got, ",") != "HEL,OPN,MSG,CLO" {
		t.Errorf("messages = %v, want HEL,OPN,MSG,CLO", got)
	}
}

func TestCheck_ReassemblesChunkedResponse(t *testing.T) {
	cert := testCert(t, "chunked", time.Now().Add(time.Hour))
	fs := &fakeServer{chunked: true, eps: []Endpoint{{URL: "x", ServerCertificate: cert, SecurityPolicyURI: "#Basic256Sha256"}}}
	url := startFake(t, fs)
	recs, err := New(Config{Targets: []Target{{Endpoint: url}}}).Check(context.Background())
	if err != nil || len(recs) != 1 || recs[0].Name != "chunked" {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
}

func TestCheck_ServerErrorAndBadTargetDoNotStopOthers(t *testing.T) {
	bad := startFake(t, &fakeServer{errReply: "BadTcpEndpointUrlInvalid"})
	good := startFake(t, &fakeServer{eps: []Endpoint{{URL: "x", ServerCertificate: testCert(t, "good", time.Now().Add(time.Hour)), SecurityPolicyURI: "#Basic256Sha256"}}})
	recs, err := New(Config{Targets: []Target{{Endpoint: bad}, {Endpoint: "http://not-opc"}, {Endpoint: good}}}).Check(context.Background())
	if len(recs) != 1 || recs[0].Name != "good" {
		t.Fatalf("recs = %+v", recs)
	}
	if err == nil || !strings.Contains(err.Error(), "BadTcpEndpointUrlInvalid") || !strings.Contains(err.Error(), "invalid endpoint") {
		t.Fatalf("err = %v", err)
	}
}

func TestGetEndpoints_TimesOutOnSilentServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(3 * time.Second)
		}
	}()
	start := time.Now()
	_, err = GetEndpoints(context.Background(), "opc.tcp://"+ln.Addr().String(), 300*time.Millisecond)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
}

// Older PLC/HMI tooling issues certificates with a negative serial,
// which Go's x509 parser rejects. The device must still be reported.
func TestCheck_NegativeSerialCertificateIsStillReported(t *testing.T) {
	notAfter := time.Now().Add(10 * 24 * time.Hour).Truncate(time.Second).UTC()
	der := testCert(t, "old-hmi", notAfter)
	neg := bytes.Replace(der, []byte{0x02, 0x01, 0x2a}, []byte{0x02, 0x01, 0xd6}, 1) // serial 42 -> -42
	if _, err := x509.ParseCertificate(neg); err == nil {
		t.Skip("this Go accepts negative serials")
	}
	url := startFake(t, &fakeServer{eps: []Endpoint{{URL: "x", ServerCertificate: neg, SecurityPolicyURI: "#Basic256Sha256"}}})
	recs, err := New(Config{Targets: []Target{{Endpoint: url}}}).Check(context.Background())
	if err != nil || len(recs) != 1 || recs[0].Name != "old-hmi" || !recs[0].ExpiresAt.Equal(notAfter) {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
}

// A chain whose second certificate is broken must not lose the leaf.
func TestCheck_BrokenChainKeepsLeaf(t *testing.T) {
	leaf := testCert(t, "leaf", time.Now().Add(time.Hour))
	chain := append(append([]byte{}, leaf...), 0x30, 0x03, 0x02, 0x01, 0x00)
	url := startFake(t, &fakeServer{eps: []Endpoint{{URL: "x", ServerCertificate: chain, SecurityPolicyURI: "#Basic256Sha256"}}})
	recs, err := New(Config{Targets: []Target{{Endpoint: url}}}).Check(context.Background())
	if err != nil || len(recs) != 1 || recs[0].Name != "leaf" {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
}

// A server that advertises no certificate at all must not look healthy.
func TestCheck_NoCertificateAdvertisedIsAnError(t *testing.T) {
	url := startFake(t, &fakeServer{eps: []Endpoint{{URL: "x", SecurityPolicyURI: securityPolicyNone, SecurityMode: 1}}})
	recs, err := New(Config{Targets: []Target{{Endpoint: url}}}).Check(context.Background())
	if len(recs) != 0 || err == nil || !strings.Contains(err.Error(), "no server certificate") {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
}

// Server-supplied strings are bounded before they reach records.
func TestCheck_LongServerStringsAreTruncated(t *testing.T) {
	long := strings.Repeat("u", 5000)
	url := startFake(t, &fakeServer{eps: []Endpoint{{URL: "x", ApplicationURI: long, ServerCertificate: testCert(t, "", time.Now().Add(time.Hour)), SecurityPolicyURI: "#" + long}}})
	recs, err := New(Config{Targets: []Target{{Endpoint: url}}}).Check(context.Background())
	if err != nil || len(recs) != 1 {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
	r := recs[0]
	if len(r.Name) > 256 || len(r.Metadata["application_uri"]) > 256 || len(r.Metadata["security_policies"]) > 256 {
		t.Fatalf("not truncated: name %d, uri %d, policies %d", len(r.Name), len(r.Metadata["application_uri"]), len(r.Metadata["security_policies"]))
	}
}

func TestConfig_RejectsDuplicateEndpoints(t *testing.T) {
	cfg := Config{Targets: []Target{{Endpoint: "opc.tcp://plc:4840"}, {Endpoint: "opc.tcp://plc:4840"}}}
	if cfg.Validate() == nil {
		t.Fatal("duplicate endpoint accepted")
	}
}

// OWASP IoT I2: a hostile server announcing a huge chunk must be refused
// before anything is allocated for it.
func TestGetEndpoints_RejectsOversizedChunk(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _, _, _ = readChunk(c)                                          // HEL
		_, _ = c.Write([]byte{'A', 'C', 'K', 'F', 0xff, 0xff, 0xff, 0x7f}) // 2 GiB
		time.Sleep(time.Second)
	}()
	_, err = GetEndpoints(context.Background(), "opc.tcp://"+ln.Addr().String(), 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("err = %v", err)
	}
}
