package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// expiredHorizon: credentials expired longer ago than this are old
// leftovers, not alerts.
const expiredHorizon = 30 * 24 * time.Hour

type graphCredential struct {
	KeyID               string `json:"keyId"`
	DisplayName         string `json:"displayName"`
	EndDateTime         string `json:"endDateTime"`
	CustomKeyIdentifier string `json:"customKeyIdentifier"`
	// hint (first characters of a secret) is deliberately not decoded.
}

type graphObject struct {
	AppID               string            `json:"appId"`
	DisplayName         string            `json:"displayName"`
	PasswordCredentials []graphCredential `json:"passwordCredentials"`
	KeyCredentials      []graphCredential `json:"keyCredentials"`
}

// checkGraph reports client secrets and certificates of app
// registrations and/or enterprise apps (service principals, e.g. SAML
// signing certificates). Graph never returns secret values; only
// metadata is selected.
func (c *Checker) checkGraph(ctx context.Context, src tokenSource) ([]checker.ExpiryRecord, error) {
	tok, err := src.token(ctx, resGraph)
	if err != nil {
		return nil, fmt.Errorf("graph: %w", err)
	}
	var colls []string
	if c.cfg.AppRegistrations {
		colls = append(colls, "applications")
	}
	if c.cfg.ServicePrincipals {
		colls = append(colls, "servicePrincipals")
	}
	now := time.Now()
	var records []checker.ExpiryRecord
	var errs []error
	for _, coll := range colls {
		q := url.Values{"$select": {"appId,displayName,passwordCredentials,keyCredentials"}, "$top": {"999"}}
		items, err := c.getPages(ctx, strings.TrimRight(c.ep.graph, "/")+"/v1.0/"+coll+"?"+q.Encode(), tok)
		if err != nil {
			errs = append(errs, fmt.Errorf("graph %s: %w", coll, err))
		}
		for _, raw := range items {
			var o graphObject
			if json.Unmarshal(raw, &o) != nil || o.AppID == "" {
				continue
			}
			source := "azure://graph.microsoft.com/" + coll + "/" + o.AppID
			add := func(cr graphCredential, kind string) {
				end, err := time.Parse(time.RFC3339, cr.EndDateTime)
				if err != nil || now.Sub(end) > expiredHorizon {
					return
				}
				label := cr.DisplayName
				if label == "" {
					label = cr.KeyID
					if len(label) > 8 {
						label = label[:8]
					}
				}
				name := o.DisplayName
				if name == "" {
					name = o.AppID
				}
				records = append(records, checker.ExpiryRecord{Source: source, Name: name + " · " + label, Kind: kind, ExpiresAt: end.UTC(),
					Metadata: map[string]string{"app_id": o.AppID, "key_id": cr.KeyID, "object_type": coll}})
			}
			for _, cr := range o.PasswordCredentials {
				add(cr, "secret")
			}
			// A certificate can be listed twice (Sign and Verify) with the
			// same thumbprint: report it once.
			seen := map[string]bool{}
			for _, cr := range o.KeyCredentials {
				id := cr.CustomKeyIdentifier + "|" + cr.EndDateTime
				if cr.CustomKeyIdentifier == "" {
					id = cr.KeyID
				}
				if seen[id] {
					continue
				}
				seen[id] = true
				add(cr, "certificate")
			}
		}
	}
	return records, errors.Join(errs...)
}
