package aws

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

const rootUser = "<root_account>"

// reportWait is the pause between credential report polls (tests
// shorten it).
var reportWait = 2 * time.Second

// credentialReport returns the account's IAM credential report (CSV).
// GenerateCredentialReport reuses a report younger than 4 hours, so
// this is one or two calls per account per run.
func (c *Checker) credentialReport(ctx context.Context, cr credentials) ([]byte, error) {
	data, err := c.fetchReport(ctx, cr)
	var ae *apiError
	if err != nil && errors.As(err, &ae) && (ae.status == 404 || ae.status == 410) {
		// ReportNotPresent / ReportExpired / ReportInProgress: generate
		// and wait again, once.
		data, err = c.fetchReport(ctx, cr)
	}
	return data, err
}

func (c *Checker) fetchReport(ctx context.Context, cr credentials) ([]byte, error) {
	for i := 0; ; i++ {
		data, err := c.iamQuery(ctx, cr, url.Values{"Action": {"GenerateCredentialReport"}})
		if err != nil {
			return nil, err
		}
		var g struct {
			State string `xml:"GenerateCredentialReportResult>State"`
		}
		if err := xml.Unmarshal(data, &g); err != nil {
			return nil, fmt.Errorf("GenerateCredentialReport: %w", err)
		}
		if g.State == "COMPLETE" {
			break
		}
		if i == 15 {
			return nil, errors.New("credential report still being generated")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(reportWait):
		}
	}
	data, err := c.iamQuery(ctx, cr, url.Values{"Action": {"GetCredentialReport"}})
	if err != nil {
		return nil, err
	}
	var r struct {
		Content string `xml:"GetCredentialReportResult>Content"`
	}
	if err := xml.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(r.Content)
}

// listAccessKeys reports every IAM user's access keys from the
// credential report (the keys themselves are never seen). Access keys
// do not expire: an active key is due access_key_max_age_days after its
// last rotation. An active root key is due at once (the root user
// should have none). Inactive keys are listed with alerts=off: they
// cannot sign requests, but should be deleted.
func (c *Checker) listAccessKeys(ctx context.Context, cr credentials, account string) ([]checker.ExpiryRecord, error) {
	data, err := c.credentialReport(ctx, cr)
	if err != nil {
		return nil, err
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil || len(rows) == 0 {
		return nil, fmt.Errorf("credential report: %v", err)
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	for _, need := range []string{"user", "access_key_1_active", "access_key_1_last_rotated", "access_key_2_active", "access_key_2_last_rotated"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("credential report without column %q", need)
		}
	}
	maxAge := c.cfg.AccessKeyMaxAgeDays
	if maxAge == 0 {
		maxAge = 90
	}
	var records []checker.ExpiryRecord
	var bad int
	for _, row := range rows[1:] {
		user := row[col["user"]]
		for slot := 1; slot <= 2; slot++ {
			p := "access_key_" + strconv.Itoa(slot)
			rotated := strings.TrimSpace(row[col[p+"_last_rotated"]])
			switch strings.ToLower(rotated) {
			case "", "n/a", "not_supported", "no_information":
				continue // no key in this slot
			}
			rot, err := time.Parse(time.RFC3339, rotated)
			if err != nil {
				bad++ // an unknown value: an error, never a silent skip
				continue
			}
			// Fail safe: only an explicit false is inactive; anything else
			// (TRUE, an unknown value) counts as active and alerts.
			active := !strings.EqualFold(strings.TrimSpace(row[col[p+"_active"]]), "false")
			meta := map[string]string{"account": account, "user": user, "slot": strconv.Itoa(slot),
				"last_rotated": rot.UTC().Format(time.RFC3339), "max_age_days": strconv.Itoa(maxAge), "status": "active"}
			if i, ok := col[p+"_last_used_date"]; ok {
				meta["last_used"] = row[i]
			}
			exp := rot.Add(time.Duration(maxAge) * 24 * time.Hour)
			if user == rootUser {
				meta["root"] = "true"
				exp = rot // the root user should have no access keys at all
			}
			if !active {
				meta["status"] = "inactive"
				if user != rootUser { // CIS: root should have no keys, even inactive ones
					meta["alerts"] = "off"
				}
			}
			// The creation/rotation time is part of the identity: a mute or
			// owner set on one key never covers a new key in the same slot.
			records = append(records, checker.ExpiryRecord{
				Source: "aws://iam/" + account + "/user/" + user + "/" + p + "@" + rot.UTC().Format(time.RFC3339), Name: user + " · key " + strconv.Itoa(slot),
				Kind: "access_key", ExpiresAt: exp.UTC(), Metadata: meta,
			})
		}
	}
	if bad > 0 {
		return records, fmt.Errorf("credential report: %d unreadable rows or dates", bad)
	}
	return records, nil
}
