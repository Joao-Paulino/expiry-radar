package azure

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

const (
	webAPIVersion = "2023-12-01" // also CertificateRegistration
	cdnAPIVersion = "2024-02-01"
	netAPIVersion = "2024-05-01"
)

// parseARMTime accepts the date formats ARM services return: RFC 3339
// (also with a "-00:00" offset) and a date-time without offset (UTC).
func parseARMTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "-00:00") {
		s = strings.TrimSuffix(s, "-00:00") + "Z"
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	return time.Parse("2006-01-02T15:04:05", s)
}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

// leafFromPublicCertData decodes an Application Gateway publicCertData
// (base64 PKCS#7 with the chain; plain DER or PEM accepted too) and
// returns the leaf: the first certificate that is not a CA.
func leafFromPublicCertData(b64 string) (*x509.Certificate, error) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(data) == 0 {
		return nil, errors.New("publicCertData is not base64")
	}
	var certs []*x509.Certificate
	if b, _ := pem.Decode(data); b != nil {
		data = b.Bytes
	}
	if c, err := x509.ParseCertificate(data); err == nil {
		certs = []*x509.Certificate{c}
	} else {
		var ci pkcs7ContentInfo
		var sd pkcs7SignedData
		if _, err := asn1.Unmarshal(data, &ci); err != nil {
			return nil, fmt.Errorf("publicCertData: %w", err)
		}
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
			return nil, fmt.Errorf("publicCertData PKCS#7: %w", err)
		}
		if certs, err = x509.ParseCertificates(sd.Certificates.Bytes); err != nil {
			return nil, fmt.Errorf("publicCertData certificates: %w", err)
		}
	}
	for _, c := range certs {
		if !c.IsCA {
			return c, nil
		}
	}
	// All marked CA (e.g. a self-signed certificate): the leaf is the one
	// that issued none of the others.
	for _, c := range certs {
		issuer := false
		for _, o := range certs {
			if o != c && string(o.RawIssuer) == string(c.RawSubject) {
				issuer = true
			}
		}
		if !issuer {
			return c, nil
		}
	}
	if len(certs) > 0 {
		return certs[0], nil
	}
	return nil, errors.New("publicCertData holds no certificate")
}

// safeResourceID accepts only an ARM resource ID inside subscription
// sub, so a URL built from it cannot leave the ARM host or path.
func safeResourceID(id, sub string) bool {
	prefix := "/subscriptions/" + strings.ToLower(sub) + "/resourcegroups/"
	return strings.HasPrefix(strings.ToLower(id), prefix) && !strings.ContainsAny(id, "?#%@\\ ") && !strings.Contains(id, "..") && !strings.Contains(id, "//")
}

type armResource struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Location   string                `json:"location"`
	SKU        struct{ Name string } `json:"sku"`
	Properties json.RawMessage       `json:"properties"`
}

// checkManagedCerts reports certificates managed by Azure services in
// each subscription: App Service certificates and certificate orders,
// Front Door Standard/Premium secrets and Application Gateway listener
// certificates. Reader on the subscription is enough. Each service
// fails on its own.
func (c *Checker) checkManagedCerts(ctx context.Context, src tokenSource) ([]checker.ExpiryRecord, error) {
	tok, err := src.token(ctx, resARM)
	if err != nil {
		return nil, fmt.Errorf("managed certificates: %w", err)
	}
	arm := strings.TrimRight(c.ep.arm, "/")
	var records []checker.ExpiryRecord
	var errs []error
	// No 30-day horizon here: an expired certificate may still be served
	// (a listener, a binding), so it keeps alerting instead of being
	// taken for gone.
	add := func(sub, id, name, service, rawExp string, extra map[string]string) {
		if strings.TrimSpace(rawExp) == "" {
			return // not issued / not synced yet: nothing to expire
		}
		exp, err := parseARMTime(rawExp)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %s: unreadable expiry %q", service, name, rawExp))
			return
		}
		meta := map[string]string{"service": service, "subscription": sub, "resource_group": resourceGroup(id)}
		for k, v := range extra {
			meta[k] = v
		}
		// Lower case: ARM returns the same ID with varying case
		// (resourceGroups / resourcegroups); the source is an identity.
		records = append(records, checker.ExpiryRecord{Source: "azure://arm" + strings.ToLower(id), Name: name, Kind: "certificate", ExpiresAt: exp, Metadata: meta})
	}
	list := func(path, apiVersion string) []armResource {
		items, err := c.getPages(ctx, arm+path+"?api-version="+apiVersion, tok)
		if err != nil && (strings.Contains(err.Error(), "MissingSubscriptionRegistration") || strings.Contains(err.Error(), "NoRegisteredProviderFound")) {
			return nil // provider never registered here: nothing of that kind exists
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
		}
		var out []armResource
		for _, raw := range items {
			var r armResource
			if json.Unmarshal(raw, &r) == nil && r.ID != "" {
				out = append(out, r)
			}
		}
		return out
	}

	for _, sub := range c.cfg.Subscriptions {
		base := "/subscriptions/" + sub
		for _, r := range list(base+"/providers/Microsoft.Web/certificates", webAPIVersion) {
			var p struct {
				SubjectName, ExpirationDate, CanonicalName, Thumbprint, KeyVaultID string
			}
			json.Unmarshal(r.Properties, &p)
			name := p.SubjectName
			if name == "" {
				name = r.Name
			}
			add(sub, r.ID, name, "app_service", p.ExpirationDate, map[string]string{"managed": fmt.Sprint(p.CanonicalName != ""), "thumbprint": p.Thumbprint, "key_vault": p.KeyVaultID})
		}
		for _, r := range list(base+"/providers/Microsoft.CertificateRegistration/certificateOrders", webAPIVersion) {
			var p struct {
				DistinguishedName, ExpirationTime, Status string
				AutoRenew                                 bool
			}
			json.Unmarshal(r.Properties, &p)
			name := r.Name
			for _, part := range strings.Split(p.DistinguishedName, ",") {
				if cn, ok := strings.CutPrefix(strings.TrimSpace(part), "CN="); ok {
					name = cn
				}
			}
			switch p.Status {
			case "Canceled", "Revoked", "Denied":
				continue // not in use
			}
			add(sub, r.ID, name, "app_service_certificate_order", p.ExpirationTime, map[string]string{"auto_renew": fmt.Sprint(p.AutoRenew), "status": p.Status})
		}
		for _, prof := range list(base+"/providers/Microsoft.Cdn/profiles", cdnAPIVersion) {
			if !strings.HasSuffix(prof.SKU.Name, "_AzureFrontDoor") {
				continue // classic CDN / Front Door classic are retiring
			}
			if !safeResourceID(prof.ID, sub) {
				errs = append(errs, fmt.Errorf("front door profile %s: unexpected resource id", prof.Name))
				continue
			}
			for _, r := range list(prof.ID+"/secrets", cdnAPIVersion) {
				var p struct {
					Parameters struct {
						Type, Subject, ExpirationDate string
					} `json:"parameters"`
				}
				json.Unmarshal(r.Properties, &p)
				if !strings.HasSuffix(p.Parameters.Type, "Certificate") || p.Parameters.ExpirationDate == "" {
					continue // URL signing keys, certificates not provisioned yet
				}
				name := p.Parameters.Subject
				if name == "" {
					name = r.Name
				}
				add(sub, r.ID, name, "front_door", p.Parameters.ExpirationDate, map[string]string{"certificate_type": p.Parameters.Type, "profile": prof.Name})
			}
		}
		for _, gw := range list(base+"/providers/Microsoft.Network/applicationGateways", netAPIVersion) {
			var p struct {
				SSLCertificates []struct {
					Name       string `json:"name"`
					Properties struct {
						PublicCertData   string `json:"publicCertData"`
						KeyVaultSecretID string `json:"keyVaultSecretId"`
					} `json:"properties"`
				} `json:"sslCertificates"`
			}
			json.Unmarshal(gw.Properties, &p)
			for _, sc := range p.SSLCertificates {
				if sc.Properties.PublicCertData == "" {
					continue
				}
				leaf, err := leafFromPublicCertData(sc.Properties.PublicCertData)
				if err != nil {
					errs = append(errs, fmt.Errorf("application gateway %s certificate %s: %w", gw.Name, sc.Name, err))
					continue
				}
				add(sub, gw.ID+"/sslCertificates/"+sc.Name, gw.Name+"/"+sc.Name, "application_gateway", leaf.NotAfter.UTC().Format(time.RFC3339),
					map[string]string{"common_name": leaf.Subject.CommonName, "key_vault_secret": sc.Properties.KeyVaultSecretID, "location": gw.Location})
			}
		}
	}
	return records, errors.Join(errs...)
}
