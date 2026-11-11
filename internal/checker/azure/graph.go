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

// Tenants that own Microsoft's first-party service principals: their
// credentials are Microsoft's to rotate, not alerts for this tenant.
var microsoftTenants = map[string]bool{"f8cdef31-a31e-4b4a-93e4-5f571e91255a": true, "72f988bf-86f1-41af-91ab-2d7cd011db47": true}

type graphObject struct {
	AppID                  string            `json:"appId"`
	ServicePrincipalType   string            `json:"servicePrincipalType"`
	AppOwnerOrganizationID string            `json:"appOwnerOrganizationId"`
	DisplayName            string            `json:"displayName"`
	PasswordCredentials    []graphCredential `json:"passwordCredentials"`
	KeyCredentials         []graphCredential `json:"keyCredentials"`
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
	badDates := 0
	for _, coll := range colls {
		// No $select: selecting keyCredentials makes Graph return every
		// certificate in full; the default listing has them with key=null.
		q := url.Values{"$top": {"100"}}
		items, err := c.getPages(ctx, strings.TrimRight(c.ep.graph, "/")+"/v1.0/"+coll+"?"+q.Encode(), tok)
		if err != nil {
			errs = append(errs, fmt.Errorf("graph %s: %w", coll, err))
		}
		for _, raw := range items {
			var o graphObject
			if json.Unmarshal(raw, &o) != nil || o.AppID == "" {
				continue
			}
			// Managed identities rotate their own certificates; Microsoft's
			// service principals are not this tenant's to renew.
			if o.ServicePrincipalType == "ManagedIdentity" || microsoftTenants[strings.ToLower(o.AppOwnerOrganizationID)] {
				continue
			}
			source := "azure://graph.microsoft.com/" + coll + "/" + o.AppID
			add := func(cr graphCredential, kind string) {
				end, err := time.Parse(time.RFC3339, cr.EndDateTime)
				if err != nil {
					badDates++
					return
				}
				if now.Sub(end) > expiredHorizon {
					return
				}
				// The key id keeps two credentials with the same description
				// (a rotation pair) apart.
				short := cr.KeyID
				if len(short) > 8 {
					short = short[:8]
				}
				label := short
				if cr.DisplayName != "" {
					label = cr.DisplayName + " · " + short
				}
				name := o.DisplayName
				if name == "" {
					name = o.AppID
				}
				records = append(records, checker.ExpiryRecord{Source: source, Name: name + " · " + label, Kind: kind, ExpiresAt: end.UTC(),
					Metadata: map[string]string{"app_id": o.AppID, "key_id": cr.KeyID, "object_type": coll}})
			}
			// A SAML signing certificate comes with a password credential
			// (the PFX password) sharing its keyId / thumbprint: not a secret
			// of its own.
			certIDs := map[string]bool{}
			for _, cr := range o.KeyCredentials {
				certIDs[cr.KeyID] = true
				if cr.CustomKeyIdentifier != "" {
					certIDs[cr.CustomKeyIdentifier] = true
				}
			}
			for _, cr := range o.PasswordCredentials {
				if coll == "servicePrincipals" && (certIDs[cr.KeyID] || (cr.CustomKeyIdentifier != "" && certIDs[cr.CustomKeyIdentifier])) {
					continue
				}
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
	if badDates > 0 {
		errs = append(errs, fmt.Errorf("graph: %d credentials with an unreadable endDateTime skipped", badDates))
	}
	return records, errors.Join(errs...)
}
