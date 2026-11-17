package opcua

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// leafInfo is what the checker reports about a server certificate.
type leafInfo struct {
	raw        []byte
	commonName string
	issuerCN   string
	selfSigned bool
	serial     string
	notAfter   time.Time
}

// parseLeaf reads the first certificate of a ServerCertificate field
// (which may hold a DER chain). It parses only that element, so a broken
// later certificate cannot hide the leaf, and it falls back to a minimal
// ASN.1 read for certificates Go's x509 parser rejects (for example the
// negative serial numbers some older PLC and HMI tooling issues).
func parseLeaf(b []byte) (leafInfo, error) {
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(b, &first); err != nil {
		return leafInfo{}, err
	}
	raw := first.FullBytes
	if c, err := x509.ParseCertificate(raw); err == nil {
		return leafInfo{
			raw:        raw,
			commonName: c.Subject.CommonName,
			issuerCN:   c.Issuer.CommonName,
			selfSigned: c.Issuer.String() == c.Subject.String(),
			serial:     c.SerialNumber.String(),
			notAfter:   c.NotAfter,
		}, nil
	}
	// Minimal read: Certificate ::= SEQUENCE { tbsCertificate, ... }.
	var cert struct {
		TBS struct {
			Version  int `asn1:"optional,explicit,default:0,tag:0"`
			Serial   *big.Int
			SigAlg   asn1.RawValue
			Issuer   asn1.RawValue
			Validity struct{ NotBefore, NotAfter time.Time }
			Subject  asn1.RawValue
		}
	}
	if _, err := asn1.Unmarshal(raw, &cert); err != nil {
		return leafInfo{}, errors.New("unreadable certificate")
	}
	var subject, issuer pkix.RDNSequence
	_, _ = asn1.Unmarshal(cert.TBS.Subject.FullBytes, &subject)
	_, _ = asn1.Unmarshal(cert.TBS.Issuer.FullBytes, &issuer)
	var sn, in pkix.Name
	sn.FillFromRDNSequence(&subject)
	in.FillFromRDNSequence(&issuer)
	serial := ""
	if cert.TBS.Serial != nil {
		serial = cert.TBS.Serial.String()
	}
	return leafInfo{
		raw:        raw,
		commonName: sn.CommonName,
		issuerCN:   in.CommonName,
		selfSigned: sn.String() == in.String(),
		serial:     serial,
		notAfter:   cert.TBS.Validity.NotAfter,
	}, nil
}

// maxReported bounds every server-supplied string put in a record.
const maxReported = 256

func clip(s string) string {
	if len(s) <= maxReported {
		return s
	}
	return s[:maxReported]
}
