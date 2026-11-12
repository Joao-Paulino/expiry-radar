// Package vmware checks VMware vSphere for things that expire: the
// vCenter TLS certificate, the vCenter STS (SSO) signing certificate,
// trusted root CAs, every ESXi host's TLS certificate and licences.
// Go standard library only; read-only.
package vmware

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// Config is the agent's "vmware" section. vSphere has no password-less
// API login: use a read-only account, password in a file (chmod 600).
type Config struct {
	URL          string `json:"url"` // https://vcenter.example.com
	Username     string `json:"username"`
	PasswordFile string `json:"password_file"`
	CAFile       string `json:"ca_file"` // VMCA root (PEM); system roots when empty
	ESXiHosts    *bool  `json:"esxi_hosts"`
	Licenses     *bool  `json:"licenses"`
	esxiPort     string // tests
}

func (c *Config) on(b *bool) bool { return b == nil || *b }

func (c *Config) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
		return errors.New("vmware: url must be https://<vcenter host>")
	}
	if c.Username == "" || c.PasswordFile == "" {
		return errors.New("vmware: username and password_file are required")
	}
	return nil
}

type Checker struct {
	cfg  Config
	http *http.Client
	tls  *tls.Config
}

func New(cfg Config) (*Checker, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pemData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("vmware: ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, errors.New("vmware: ca_file has no certificate")
		}
		tc.RootCAs = pool
	}
	jar, _ := cookiejar.New(nil)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	return &Checker{cfg: cfg, tls: tc, http: &http.Client{Timeout: 30 * time.Second, Transport: tr, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Checker) Name() string { return "vmware" }
func (c *Checker) Kind() string { return "certificate" }

func (c *Checker) host() string { u, _ := url.Parse(c.cfg.URL); return u.Host }

func (c *Checker) call(ctx context.Context, method, path string, hdr map[string]string, body []byte) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.cfg.URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode/100 != 2 {
		msg := []rune(strings.TrimSpace(string(data)))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, nil, fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, logging.Sanitize(string(msg)))
	}
	return data, resp.Header, nil
}

func leafOf(chain []string) (*x509.Certificate, error) {
	for _, p := range chain {
		b, _ := pem.Decode([]byte(p))
		if b == nil {
			continue
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			return c, nil
		}
	}
	return nil, errors.New("no certificate in chain")
}

func (c *Checker) rec(name, kind, path string, cert *x509.Certificate, meta map[string]string) checker.ExpiryRecord {
	if meta == nil {
		meta = map[string]string{}
	}
	meta["subject"] = cert.Subject.CommonName
	return checker.ExpiryRecord{Source: "vmware://" + c.host() + "/" + path, Name: name, Kind: kind, ExpiresAt: cert.NotAfter.UTC(), Metadata: meta}
}

// Check logs in to the REST API, then reads the vCenter certificates,
// the ESXi hosts and the licences. Each part fails on its own.
func (c *Checker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	pw, err := os.ReadFile(c.cfg.PasswordFile)
	if err != nil {
		return nil, fmt.Errorf("vmware: password_file: %w", err)
	}
	password := strings.TrimRight(string(pw), "\r\n")
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.URL, "/")+"/api/session", nil)
	req.SetBasicAuth(c.cfg.Username, password)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vmware: login: %w", err)
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	var session string
	if resp.StatusCode != 201 && resp.StatusCode != 200 || json.Unmarshal(data, &session) != nil || session == "" {
		return nil, fmt.Errorf("vmware: login: HTTP %d", resp.StatusCode)
	}
	auth := map[string]string{"vmware-api-session-id": session}
	defer c.call(context.Background(), http.MethodDelete, "/api/session", auth, nil)

	var records []checker.ExpiryRecord
	var errs []error
	// vCenter TLS certificate, as served (no privilege needed).
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		records = append(records, c.rec("vCenter TLS", "certificate", "vcenter/tls", resp.TLS.PeerCertificates[0], nil))
	}
	// STS signing certificate: its expiry stops every vSphere login.
	if data, _, err := c.call(ctx, http.MethodGet, "/api/vcenter/certificate-management/vcenter/signing-certificate", auth, nil); err != nil {
		errs = append(errs, fmt.Errorf("STS signing certificate: %w", err))
	} else {
		var r struct {
			Active struct {
				Chain []string `json:"cert_chain"`
			} `json:"active_cert_chain"`
		}
		if err := json.Unmarshal(data, &r); err == nil {
			if cert, err := leafOf(r.Active.Chain); err == nil {
				records = append(records, c.rec("vCenter STS signing", "certificate", "vcenter/sts-signing", cert, nil))
			} else {
				errs = append(errs, fmt.Errorf("STS signing certificate: %w", err))
			}
		}
	}
	// Trusted root CAs.
	if data, _, err := c.call(ctx, http.MethodGet, "/api/vcenter/certificate-management/vcenter/trusted-root-chains", auth, nil); err != nil {
		errs = append(errs, fmt.Errorf("trusted roots: %w", err))
	} else {
		var ids []struct {
			Chain string `json:"chain"`
		}
		json.Unmarshal(data, &ids)
		for _, id := range ids {
			d, _, err := c.call(ctx, http.MethodGet, "/api/vcenter/certificate-management/vcenter/trusted-root-chains/"+url.PathEscape(id.Chain), auth, nil)
			if err != nil {
				errs = append(errs, fmt.Errorf("trusted root %s: %w", id.Chain, err))
				continue
			}
			var r struct {
				CertChain struct {
					Chain []string `json:"cert_chain"`
				} `json:"cert_chain"`
			}
			json.Unmarshal(d, &r)
			if cert, err := leafOf(r.CertChain.Chain); err == nil {
				records = append(records, c.rec(cert.Subject.CommonName, "ca_certificate", "trusted-root/"+id.Chain, cert, nil))
			}
		}
	}
	if c.cfg.on(c.cfg.ESXiHosts) {
		recs, err := c.esxi(ctx, auth)
		records = append(records, recs...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if c.cfg.on(c.cfg.Licenses) {
		recs, err := c.licenses(ctx, password)
		records = append(records, recs...)
		if err != nil {
			errs = append(errs, fmt.Errorf("licences: %w", err))
		}
	}
	return records, errors.Join(errs...)
}

// esxi lists the hosts known to vCenter and reads each one's TLS
// certificate (disconnected hosts are skipped).
func (c *Checker) esxi(ctx context.Context, auth map[string]string) ([]checker.ExpiryRecord, error) {
	data, _, err := c.call(ctx, http.MethodGet, "/api/vcenter/host", auth, nil)
	if err != nil {
		return nil, fmt.Errorf("ESXi hosts: %w", err)
	}
	var hosts []struct {
		Name            string `json:"name"`
		ConnectionState string `json:"connection_state"`
	}
	if err := json.Unmarshal(data, &hosts); err != nil {
		return nil, fmt.Errorf("ESXi hosts: %w", err)
	}
	port := c.cfg.esxiPort
	if port == "" {
		port = "443"
	}
	var out []checker.ExpiryRecord
	var errs []error
	for _, h := range hosts {
		if h.ConnectionState != "" && h.ConnectionState != "CONNECTED" {
			continue
		}
		tc := c.tls.Clone()
		tc.ServerName = h.Name
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: tc}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(h.Name, port))
		if err != nil {
			errs = append(errs, fmt.Errorf("ESXi %s: %w", h.Name, err))
			continue
		}
		cs := conn.(*tls.Conn).ConnectionState()
		conn.Close()
		if len(cs.PeerCertificates) > 0 {
			out = append(out, c.rec(h.Name, "certificate", "esxi/"+h.Name, cs.PeerCertificates[0], map[string]string{"host": h.Name}))
		}
	}
	return out, errors.Join(errs...)
}

// licenses reads LicenseManager.licenses over the vSphere SOAP API (the
// REST API has no licences). Only the last 5 characters of a key are
// kept. Licences without an expirationDate (perpetual) are skipped.
func (c *Checker) licenses(ctx context.Context, password string) ([]checker.ExpiryRecord, error) {
	soap := func(body string) ([]byte, error) {
		env := `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body>` + body + `</soapenv:Body></soapenv:Envelope>`
		data, _, err := c.call(ctx, http.MethodPost, "/sdk", map[string]string{"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "urn:vim25/7.0"}, []byte(env))
		return data, err
	}
	data, err := soap(`<RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent>`)
	if err != nil {
		return nil, err
	}
	var sc struct {
		SessionManager    string `xml:"Body>RetrieveServiceContentResponse>returnval>sessionManager"`
		PropertyCollector string `xml:"Body>RetrieveServiceContentResponse>returnval>propertyCollector"`
		LicenseManager    string `xml:"Body>RetrieveServiceContentResponse>returnval>licenseManager"`
	}
	if err := xml.Unmarshal(data, &sc); err != nil || sc.LicenseManager == "" {
		return nil, errors.New("no licenseManager in the service content")
	}
	esc := html.EscapeString
	if _, err := soap(`<Login xmlns="urn:vim25"><_this type="SessionManager">` + esc(sc.SessionManager) + `</_this><userName>` + esc(c.cfg.Username) + `</userName><password>` + esc(password) + `</password></Login>`); err != nil {
		return nil, errors.New("SOAP login failed")
	}
	defer soap(`<Logout xmlns="urn:vim25"><_this type="SessionManager">` + esc(sc.SessionManager) + `</_this></Logout>`)
	data, err = soap(`<RetrievePropertiesEx xmlns="urn:vim25"><_this type="PropertyCollector">` + esc(sc.PropertyCollector) +
		`</_this><specSet><propSet><type>LicenseManager</type><pathSet>licenses</pathSet></propSet><objectSet><obj type="LicenseManager">` +
		esc(sc.LicenseManager) + `</obj></objectSet></specSet><options></options></RetrievePropertiesEx>`)
	if err != nil {
		return nil, err
	}
	var r struct {
		Infos []struct {
			Key        string `xml:"licenseKey"`
			Name       string `xml:"name"`
			EditionKey string `xml:"editionKey"`
			Props      []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"properties"`
		} `xml:"Body>RetrievePropertiesExResponse>returnval>objects>propSet>val>LicenseManagerLicenseInfo"`
	}
	if err := xml.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	var out []checker.ExpiryRecord
	for _, l := range r.Infos {
		var exp string
		for _, p := range l.Props {
			if p.Key == "expirationDate" {
				exp = strings.TrimSpace(p.Value)
			}
		}
		if exp == "" {
			continue // perpetual
		}
		t, err := time.Parse(time.RFC3339Nano, exp)
		if err != nil {
			return out, fmt.Errorf("licence ...%s: unreadable expirationDate", lastN(l.Key, 5))
		}
		out = append(out, checker.ExpiryRecord{Source: "vmware://" + c.host() + "/license/" + lastN(l.Key, 5), Name: l.Name + " (…" + lastN(l.Key, 5) + ")",
			Kind: "license", ExpiresAt: t.UTC(), Metadata: map[string]string{"edition": l.EditionKey}})
	}
	return out, nil
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
