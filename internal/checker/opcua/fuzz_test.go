package opcua

import "testing"

// The response parser sees bytes from any server the agent is pointed
// at: it must never panic or allocate without bound.
func FuzzParseGetEndpointsResponse(f *testing.F) {
	var e encoder
	e.nodeID(idGetEndpointsResponse)
	responseHeader(&e, 0)
	e.i32(1)
	encodeEndpoint(&e, Endpoint{URL: "opc.tcp://x:4840", ApplicationURI: "urn:x", ServerCertificate: []byte{1, 2, 3}, SecurityPolicyURI: securityPolicyNone})
	f.Add(e.b)
	f.Add([]byte{0x01, 0x00, 0x8d, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		eps, err := parseGetEndpointsResponse(b)
		if err == nil {
			_, _ = recordsFor("opc.tcp://fuzz", eps)
		}
	})
}
