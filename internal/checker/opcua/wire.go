package opcua

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// OPC UA binary encoding (Part 6 §5.2): little-endian, strings and byte
// strings prefixed by an int32 length where -1 means null.

// Limits applied while decoding untrusted server responses.
const (
	maxArrayLen  = 1024     // endpoints, user token policies, strings in arrays
	maxFieldLen  = 1 << 20  // one string or byte string (certificates are a few KiB)
	maxDiagDepth = 4        // nested DiagnosticInfo
	maxMessage   = 16 << 20 // reassembled message
	maxChunks    = 256
)

// Numeric NodeIds (namespace 0) of the binary encodings used here.
const (
	idOpenSecureChannelRequest  = 446
	idOpenSecureChannelResponse = 449
	idCloseSecureChannelRequest = 452
	idGetEndpointsRequest       = 428
	idGetEndpointsResponse      = 431
	idServiceFault              = 397
)

const securityPolicyNone = "http://opcfoundation.org/UA/SecurityPolicy#None"

var errTruncated = errors.New("opcua: message truncated")

type encoder struct{ b []byte }

func (e *encoder) u8(v byte)    { e.b = append(e.b, v) }
func (e *encoder) u16(v uint16) { e.b = binary.LittleEndian.AppendUint16(e.b, v) }
func (e *encoder) u32(v uint32) { e.b = binary.LittleEndian.AppendUint32(e.b, v) }
func (e *encoder) i32(v int32)  { e.u32(uint32(v)) }                                       // #nosec G115 -- two's complement wire encoding
func (e *encoder) i64(v int64)  { e.b = binary.LittleEndian.AppendUint64(e.b, uint64(v)) } // #nosec G115 -- two's complement wire encoding

// str encodes s; the empty string is encoded as null.
func (e *encoder) str(s string) {
	if s == "" {
		e.i32(-1)
		return
	}
	e.length(len(s))
	e.b = append(e.b, s...)
}

// length encodes a string or byte string length. Requests only carry
// short URLs and policy names; anything longer than maxFieldLen is a bug.
func (e *encoder) length(n int) {
	if n > maxFieldLen {
		panic("opcua: field too long to encode")
	}
	e.i32(int32(n)) // #nosec G115 -- bounded by maxFieldLen above
}

// bytes encodes b; nil is encoded as null.
func (e *encoder) bytes(b []byte) {
	if b == nil {
		e.i32(-1)
		return
	}
	e.length(len(b))
	e.b = append(e.b, b...)
}

// nodeID encodes a numeric NodeId in namespace 0 in its shortest form.
func (e *encoder) nodeID(id uint32) {
	switch {
	case id <= math.MaxUint8:
		e.u8(0x00)
		e.u8(byte(id))
	case id <= math.MaxUint16:
		e.u8(0x01)
		e.u8(0)
		e.u16(uint16(id))
	default:
		e.u8(0x02)
		e.u16(0)
		e.u32(id)
	}
}

// requestHeader encodes a RequestHeader with no authentication token.
func (e *encoder) requestHeader(handle, timeoutMs uint32) {
	e.nodeID(0)      // AuthenticationToken
	e.i64(0)         // Timestamp
	e.u32(handle)    // RequestHandle
	e.u32(0)         // ReturnDiagnostics
	e.str("")        // AuditEntryId
	e.u32(timeoutMs) // TimeoutHint
	e.nodeID(0)      // AdditionalHeader: ExtensionObject with null type
	e.u8(0)          //   and no body
}

// decoder reads from b; the first error sticks and later reads return
// zero values, so callers check d.err once at the end.
type decoder struct {
	b   []byte
	err error
}

func (d *decoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b) {
		d.err = errTruncated
		return nil
	}
	v := d.b[:n]
	d.b = d.b[n:]
	return v
}

func (d *decoder) u8() byte {
	if v := d.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (d *decoder) u16() uint16 {
	if v := d.take(2); v != nil {
		return binary.LittleEndian.Uint16(v)
	}
	return 0
}

func (d *decoder) u32() uint32 {
	if v := d.take(4); v != nil {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

func (d *decoder) i32() int32 { return int32(d.u32()) } // #nosec G115 -- two's complement wire decoding

func (d *decoder) i64() int64 {
	if v := d.take(8); v != nil {
		return int64(binary.LittleEndian.Uint64(v)) // #nosec G115 -- two's complement wire decoding
	}
	return 0
}

// bytes returns a copy of a byte string (nil for null).
func (d *decoder) bytes() []byte {
	n := d.i32()
	if d.err != nil || n == -1 {
		return nil
	}
	if n < -1 || n > maxFieldLen {
		d.err = fmt.Errorf("opcua: field length %d out of range", n)
		return nil
	}
	v := d.take(int(n))
	if v == nil {
		return nil
	}
	return append([]byte{}, v...)
}

func (d *decoder) str() string { return string(d.bytes()) }

// arrayLen reads an array length; null (-1) is returned as 0.
func (d *decoder) arrayLen() int {
	n := d.i32()
	if d.err != nil || n == -1 {
		return 0
	}
	if n < -1 || n > maxArrayLen {
		d.err = fmt.Errorf("opcua: array length %d out of range", n)
		return 0
	}
	return int(n)
}

func (d *decoder) strings() {
	for i, n := 0, d.arrayLen(); i < n && d.err == nil; i++ {
		d.str()
	}
}

// nodeID decodes any NodeId or ExpandedNodeId and returns the numeric
// identifier (0 for non-numeric forms).
func (d *decoder) nodeID() uint32 {
	enc := d.u8()
	var id uint32
	switch enc & 0x3f {
	case 0x00:
		id = uint32(d.u8())
	case 0x01:
		d.u8()
		id = uint32(d.u16())
	case 0x02:
		d.u16()
		id = d.u32()
	case 0x03:
		d.u16()
		d.str()
	case 0x04:
		d.u16()
		d.take(16)
	case 0x05:
		d.u16()
		d.bytes()
	default:
		if d.err == nil {
			d.err = fmt.Errorf("opcua: unknown NodeId encoding 0x%02x", enc)
		}
	}
	if enc&0x80 != 0 {
		d.str() // NamespaceUri
	}
	if enc&0x40 != 0 {
		d.u32() // ServerIndex
	}
	return id
}

func (d *decoder) extensionObject() {
	d.nodeID()
	switch enc := d.u8(); enc {
	case 0x00:
	case 0x01, 0x02:
		d.bytes()
	default:
		if d.err == nil {
			d.err = fmt.Errorf("opcua: unknown ExtensionObject encoding 0x%02x", enc)
		}
	}
}

func (d *decoder) diagnosticInfo(depth int) {
	if depth > maxDiagDepth {
		if d.err == nil {
			d.err = errors.New("opcua: DiagnosticInfo nested too deeply")
		}
		return
	}
	mask := d.u8()
	for _, bit := range []byte{0x01, 0x02, 0x04, 0x08} {
		if mask&bit != 0 {
			d.i32()
		}
	}
	if mask&0x10 != 0 {
		d.str()
	}
	if mask&0x20 != 0 {
		d.u32()
	}
	if mask&0x40 != 0 {
		d.diagnosticInfo(depth + 1)
	}
}

func (d *decoder) localizedText() string {
	mask := d.u8()
	if mask&0x01 != 0 {
		d.str() // Locale
	}
	if mask&0x02 != 0 {
		return d.str()
	}
	return ""
}

// responseHeader decodes a ResponseHeader and returns its ServiceResult.
func (d *decoder) responseHeader() uint32 {
	d.i64() // Timestamp
	d.u32() // RequestHandle
	result := d.u32()
	d.diagnosticInfo(0)
	d.strings() // StringTable
	d.extensionObject()
	return result
}

// Endpoint is the part of an EndpointDescription the checker uses.
type Endpoint struct {
	URL               string
	ApplicationURI    string
	ApplicationName   string
	ServerCertificate []byte
	SecurityMode      uint32
	SecurityPolicyURI string
}

func (d *decoder) endpoint() Endpoint {
	var ep Endpoint
	ep.URL = d.str()
	// ApplicationDescription
	ep.ApplicationURI = d.str()
	d.str() // ProductUri
	ep.ApplicationName = d.localizedText()
	d.u32() // ApplicationType
	d.str() // GatewayServerUri
	d.str() // DiscoveryProfileUri
	d.strings()
	ep.ServerCertificate = d.bytes()
	ep.SecurityMode = d.u32()
	ep.SecurityPolicyURI = d.str()
	for i, n := 0, d.arrayLen(); i < n && d.err == nil; i++ { // UserTokenPolicy
		d.str()
		d.u32()
		d.str()
		d.str()
		d.str()
	}
	d.str() // TransportProfileUri
	d.u8()  // SecurityLevel
	return ep
}

// parseGetEndpointsResponse decodes the service body of a MSG that
// answers GetEndpoints (starting at the type NodeId).
func parseGetEndpointsResponse(body []byte) ([]Endpoint, error) {
	d := &decoder{b: body}
	switch id := d.nodeID(); {
	case d.err != nil:
		return nil, d.err
	case id == idServiceFault:
		res := d.responseHeader()
		if d.err != nil {
			return nil, d.err
		}
		return nil, fmt.Errorf("opcua: server returned ServiceFault 0x%08X", res)
	case id != idGetEndpointsResponse:
		return nil, fmt.Errorf("opcua: unexpected response type %d", id)
	}
	if res := d.responseHeader(); d.err == nil && res&0x80000000 != 0 {
		return nil, fmt.Errorf("opcua: GetEndpoints failed with status 0x%08X", res)
	}
	n := d.arrayLen()
	eps := make([]Endpoint, 0, n)
	for i := 0; i < n && d.err == nil; i++ {
		eps = append(eps, d.endpoint())
	}
	if d.err != nil {
		return nil, d.err
	}
	return eps, nil
}
