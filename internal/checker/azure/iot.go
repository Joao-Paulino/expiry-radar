package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

const (
	iotHubAPIVersion = "2023-06-30"
	dpsAPIVersion    = "2022-12-12"
)

// checkIoT reports IoT Hub and Device Provisioning Service (DPS) CA
// certificates (used to authenticate devices) that expire, in every
// configured subscription. Reader on the subscription is enough.
func (c *Checker) checkIoT(ctx context.Context, src tokenSource) ([]checker.ExpiryRecord, error) {
	tok, err := src.token(ctx, resARM)
	if err != nil {
		return nil, fmt.Errorf("iot certificates: %w", err)
	}
	arm := strings.TrimRight(c.ep.arm, "/")
	var records []checker.ExpiryRecord
	var errs []error

	list := func(path, apiVersion string) []armResource {
		items, err := c.getPages(ctx, arm+path+"?api-version="+apiVersion, tok)
		if err != nil && (strings.Contains(err.Error(), "MissingSubscriptionRegistration") || strings.Contains(err.Error(), "NoRegisteredProviderFound")) {
			return nil // provider never registered here: no IoT Hub or DPS in this subscription
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
		}
		var out []armResource
		for _, raw := range items {
			var r armResource
			if err := json.Unmarshal(raw, &r); err != nil {
				errs = append(errs, fmt.Errorf("%s: unreadable item: %v", path, err))
				continue
			}
			if r.ID == "" {
				errs = append(errs, fmt.Errorf("%s: item without an id", path))
				continue
			}
			out = append(out, r)
		}
		return out
	}

	add := func(sub, id, name, service, parentName, rawExpiry, thumbprint string, verified bool) {
		if strings.TrimSpace(rawExpiry) == "" {
			return // not issued yet: nothing to expire
		}
		exp, err := parseARMTime(rawExpiry)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %s: unreadable expiry %q", service, name, rawExpiry))
			return
		}
		meta := map[string]string{"service": service, "subscription": sub, "resource_group": resourceGroup(id),
			"thumbprint": thumbprint, "verified": fmt.Sprint(verified)}
		if service == "iot_hub" {
			meta["hub"] = parentName
		} else {
			meta["dps"] = parentName
		}
		records = append(records, checker.ExpiryRecord{Source: "azure://arm" + strings.ToLower(id), Name: name, Kind: "certificate", ExpiresAt: exp, Metadata: meta})
	}

	certProps := func(r armResource) (subject, expiry, thumbprint string, verified bool) {
		var p struct {
			Subject, Expiry, Thumbprint string
			IsVerified                  bool
		}
		if len(r.Properties) > 0 {
			if err := json.Unmarshal(r.Properties, &p); err != nil {
				errs = append(errs, fmt.Errorf("%s: unreadable properties: %v", r.Name, err))
			}
		}
		return p.Subject, p.Expiry, p.Thumbprint, p.IsVerified
	}

	for _, sub := range c.cfg.Subscriptions {
		base := "/subscriptions/" + sub
		for _, hub := range list(base+"/providers/Microsoft.Devices/IotHubs", iotHubAPIVersion) {
			if !safeResourceID(hub.ID, sub) {
				errs = append(errs, fmt.Errorf("iot hub %s: unexpected resource id", hub.Name))
				continue
			}
			for _, r := range list(hub.ID+"/certificates", iotHubAPIVersion) {
				_, expiry, thumbprint, verified := certProps(r)
				add(sub, r.ID, r.Name, "iot_hub", hub.Name, expiry, thumbprint, verified)
			}
		}
		for _, dps := range list(base+"/providers/Microsoft.Devices/provisioningServices", dpsAPIVersion) {
			if !safeResourceID(dps.ID, sub) {
				errs = append(errs, fmt.Errorf("dps %s: unexpected resource id", dps.Name))
				continue
			}
			for _, r := range list(dps.ID+"/certificates", dpsAPIVersion) {
				_, expiry, thumbprint, verified := certProps(r)
				add(sub, r.ID, r.Name, "dps", dps.Name, expiry, thumbprint, verified)
			}
		}
	}
	return records, errors.Join(errs...)
}
