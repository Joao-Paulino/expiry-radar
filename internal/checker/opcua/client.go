package opcua

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

// Transport limits we announce in Hello.
const (
	bufferSize = 1 << 16
)

// GetEndpoints asks the server at endpointURL (opc.tcp://host:port[/path])
// for its endpoints over an unsecured secure channel, the discovery path
// every OPC UA server must offer (Part 4 §5.4.4). It never creates a
// session and never reads or writes node values.
func GetEndpoints(ctx context.Context, endpointURL string, timeout time.Duration) ([]Endpoint, error) {
	u, err := url.Parse(endpointURL)
	if err != nil || u.Scheme != "opc.tcp" || u.Hostname() == "" {
		return nil, fmt.Errorf("opcua: invalid endpoint %q (want opc.tcp://host:port)", endpointURL)
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "4840")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if err := hello(conn, endpointURL); err != nil {
		return nil, err
	}
	timeoutMs := uint32(min(timeout, time.Hour) / time.Millisecond) // #nosec G115 -- clamped to one hour
	channelID, tokenID, err := openChannel(conn, timeoutMs)
	if err != nil {
		return nil, err
	}
	eps, err := getEndpoints(conn, channelID, tokenID, endpointURL, timeoutMs)
	closeChannel(conn, channelID, tokenID)
	return eps, err
}

// writeMsg frames body as one final chunk of message type typ.
func writeMsg(w io.Writer, typ string, body []byte) error {
	hdr := make([]byte, 8, 8+len(body))
	copy(hdr, typ)
	hdr[3] = 'F'
	if len(body) > maxFieldLen {
		return errors.New("opcua: request too large")
	}
	binary.LittleEndian.PutUint32(hdr[4:], uint32(8+len(body))) // #nosec G115 -- bounded above
	_, err := w.Write(append(hdr, body...))
	return err
}

// readChunk reads one chunk: its 3-letter type, chunk flag and body.
func readChunk(r io.Reader) (string, byte, []byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", 0, nil, err
	}
	size := binary.LittleEndian.Uint32(hdr[4:])
	if size < 8 || size > maxFieldLen {
		return "", 0, nil, fmt.Errorf("opcua: chunk size %d out of range", size)
	}
	body := make([]byte, size-8)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", 0, nil, err
	}
	return string(hdr[:3]), hdr[3], body, nil
}

// serverError turns an ERR message body into an error.
func serverError(body []byte) error {
	d := &decoder{b: body}
	code := d.u32()
	reason := d.str()
	if d.err != nil {
		return errors.New("opcua: server sent an error")
	}
	return fmt.Errorf("opcua: server error 0x%08X %s", code, clip(reason))
}

func hello(conn net.Conn, endpointURL string) error {
	var e encoder
	e.u32(0)          // ProtocolVersion
	e.u32(bufferSize) // ReceiveBufferSize
	e.u32(bufferSize) // SendBufferSize
	e.u32(maxMessage) // MaxMessageSize
	e.u32(maxChunks)  // MaxChunkCount
	e.str(endpointURL)
	if err := writeMsg(conn, "HEL", e.b); err != nil {
		return err
	}
	typ, _, body, err := readChunk(conn)
	switch {
	case err != nil:
		return err
	case typ == "ERR":
		return serverError(body)
	case typ != "ACK":
		return fmt.Errorf("opcua: expected ACK, got %q", typ)
	}
	return nil
}

func openChannel(conn net.Conn, timeoutMs uint32) (channelID, tokenID uint32, err error) {
	var e encoder
	e.u32(0) // SecureChannelId
	e.str(securityPolicyNone)
	e.bytes(nil) // SenderCertificate
	e.bytes(nil) // ReceiverCertificateThumbprint
	e.u32(1)     // SequenceNumber
	e.u32(1)     // RequestId
	e.nodeID(idOpenSecureChannelRequest)
	e.requestHeader(1, timeoutMs)
	e.u32(0)          // ClientProtocolVersion
	e.u32(0)          // RequestType: Issue
	e.u32(1)          // SecurityMode: None
	e.bytes([]byte{}) // ClientNonce
	e.u32(60000)      // RequestedLifetime
	if err := writeMsg(conn, "OPN", e.b); err != nil {
		return 0, 0, err
	}
	typ, _, body, err := readChunk(conn)
	switch {
	case err != nil:
		return 0, 0, err
	case typ == "ERR":
		return 0, 0, serverError(body)
	case typ != "OPN":
		return 0, 0, fmt.Errorf("opcua: expected OPN, got %q", typ)
	}
	d := &decoder{b: body}
	d.u32()   // SecureChannelId (header)
	d.str()   // SecurityPolicyUri
	d.bytes() // SenderCertificate
	d.bytes() // ReceiverCertificateThumbprint
	d.u32()   // SequenceNumber
	d.u32()   // RequestId
	id := d.nodeID()
	if d.err == nil && id != idOpenSecureChannelResponse {
		return 0, 0, fmt.Errorf("opcua: unexpected OpenSecureChannel response type %d", id)
	}
	res := d.responseHeader()
	d.u32() // ServerProtocolVersion
	channelID = d.u32()
	tokenID = d.u32()
	if d.err != nil {
		return 0, 0, d.err
	}
	if res&0x80000000 != 0 {
		return 0, 0, fmt.Errorf("opcua: OpenSecureChannel failed with status 0x%08X", res)
	}
	return channelID, tokenID, nil
}

func getEndpoints(conn net.Conn, channelID, tokenID uint32, endpointURL string, timeoutMs uint32) ([]Endpoint, error) {
	var e encoder
	e.u32(channelID)
	e.u32(tokenID)
	e.u32(2) // SequenceNumber
	e.u32(2) // RequestId
	e.nodeID(idGetEndpointsRequest)
	e.requestHeader(2, timeoutMs)
	e.str(endpointURL)
	e.i32(-1) // LocaleIds
	e.i32(-1) // ProfileUris
	if err := writeMsg(conn, "MSG", e.b); err != nil {
		return nil, err
	}
	// Reassemble the response: every chunk repeats the channel, token
	// and sequence headers (16 bytes) before its part of the body.
	var msg []byte
	for i := 0; ; i++ {
		if i >= maxChunks {
			return nil, errors.New("opcua: too many chunks")
		}
		typ, flag, body, err := readChunk(conn)
		switch {
		case err != nil:
			return nil, err
		case typ == "ERR":
			return nil, serverError(body)
		case typ != "MSG":
			return nil, fmt.Errorf("opcua: expected MSG, got %q", typ)
		case len(body) < 16:
			return nil, errTruncated
		}
		if flag == 'A' {
			return nil, errors.New("opcua: server aborted the response")
		}
		msg = append(msg, body[16:]...)
		if len(msg) > maxMessage {
			return nil, errors.New("opcua: response too large")
		}
		if flag == 'F' {
			break
		}
		if flag != 'C' {
			return nil, fmt.Errorf("opcua: unknown chunk flag %q", flag)
		}
	}
	return parseGetEndpointsResponse(msg)
}

// closeChannel politely closes the secure channel; errors are ignored
// because the connection is closed right after.
func closeChannel(conn net.Conn, channelID, tokenID uint32) {
	var e encoder
	e.u32(channelID)
	e.u32(tokenID)
	e.u32(3)
	e.u32(3)
	e.nodeID(idCloseSecureChannelRequest)
	e.requestHeader(3, 0)
	_ = writeMsg(conn, "CLO", e.b)
}
