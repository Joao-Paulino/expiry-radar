package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// listIoTCore reports AWS IoT Core device certificates (ListCertificates
// + DescribeCertificate per certificate) that expire. Revoked
// certificates are not in use and are skipped before DescribeCertificate
// is even called.
func (c *Checker) listIoTCore(ctx context.Context, cr credentials, account, region string) ([]checker.ExpiryRecord, error) {
	var records []checker.ExpiryRecord
	var errs []error
	marker := ""
	for page := 0; page < 1000; page++ {
		q := url.Values{"pageSize": {"250"}}
		if marker != "" {
			q.Set("marker", marker)
		}
		data, err := send(ctx, c.http, "ListCertificates", func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ep.iot(region)+"/certificates?"+q.Encode(), nil)
			if err != nil {
				return nil, err
			}
			signV4(req, nil, cr, region, "iot", time.Now())
			return req, nil
		})
		if err != nil {
			return records, errors.Join(append(errs, err)...)
		}
		var out struct {
			NextMarker   string
			Certificates []struct {
				CertificateID, Status, CertificateMode string
			} `json:"certificates"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return records, fmt.Errorf("ListCertificates: %w", err)
		}
		for _, s := range out.Certificates {
			if s.Status == "REVOKED" {
				continue
			}
			rec, err := c.describeIoTCertificate(ctx, cr, account, region, s.CertificateID, s.CertificateMode)
			if err != nil {
				errs = append(errs, fmt.Errorf("DescribeCertificate %s: %w", s.CertificateID, err))
				continue
			}
			if rec != nil {
				records = append(records, *rec)
			}
		}
		if out.NextMarker == "" {
			return records, errors.Join(errs...)
		}
		marker = out.NextMarker
	}
	return records, errors.Join(append(errs, errors.New("ListCertificates: more than 1000 pages"))...)
}

// describeIoTCertificate fetches validity.notAfter for one certificate.
// A certificate without a validity date (not yet issued) is skipped.
func (c *Checker) describeIoTCertificate(ctx context.Context, cr credentials, account, region, id, mode string) (*checker.ExpiryRecord, error) {
	data, err := send(ctx, c.http, "DescribeCertificate", func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ep.iot(region)+"/certificates/"+url.PathEscape(id), nil)
		if err != nil {
			return nil, err
		}
		signV4(req, nil, cr, region, "iot", time.Now())
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	var out struct {
		CertificateDescription struct {
			Status   string
			Validity struct {
				NotAfter *float64
			}
		}
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("unreadable response: %w", err)
	}
	na := out.CertificateDescription.Validity.NotAfter
	if na == nil {
		return nil, nil
	}
	return &checker.ExpiryRecord{
		Source: "aws://iot/" + account + "/" + region + "/" + id, Name: id, Kind: "certificate",
		ExpiresAt: time.Unix(int64(*na), 0).UTC(),
		Metadata: map[string]string{"account": account, "region": region, "status": out.CertificateDescription.Status, "certificate_mode": mode},
	}, nil
}
