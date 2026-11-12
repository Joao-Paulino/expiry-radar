package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// rotationGrace: a rotation counts as overdue this long after its
// interval has passed since the last successful rotation.
const rotationGrace = 2 * 24 * time.Hour

var rateRe = regexp.MustCompile(`^rate\((\d+) (day|days|hour|hours)\)$`)

// smCall sends a signed Secrets Manager JSON 1.1 request.
func (c *Checker) smCall(ctx context.Context, cr credentials, region, target string, in any) ([]byte, error) {
	body, _ := json.Marshal(in)
	return send(ctx, c.http, target, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ep.secrets(region)+"/", strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "secretsmanager."+target)
		signV4(req, body, cr, region, "secretsmanager", time.Now())
		return req, nil
	})
}

func unix(f *float64) time.Time {
	if f == nil {
		return time.Time{}
	}
	return time.Unix(int64(*f), 0).UTC()
}

// rotationInterval from AutomaticallyAfterDays or rate(N days|hours);
// zero for cron() or when unknown.
func rotationInterval(days *int, schedule string) time.Duration {
	if days != nil && *days > 0 {
		return time.Duration(*days) * 24 * time.Hour
	}
	if m := rateRe.FindStringSubmatch(strings.TrimSpace(schedule)); m != nil {
		n, _ := strconv.Atoi(m[1])
		if strings.HasPrefix(m[2], "day") {
			return time.Duration(n) * 24 * time.Hour
		}
		return time.Duration(n) * time.Hour
	}
	return 0
}

// currentVersionCreated returns when the AWSCURRENT value was created
// (LastChangedDate also moves on tag or description edits).
func (c *Checker) currentVersionCreated(ctx context.Context, cr credentials, region, arn string) (time.Time, error) {
	next := ""
	for page := 0; page < 100; page++ {
		in := map[string]any{"SecretId": arn, "MaxResults": 100}
		if next != "" {
			in["NextToken"] = next
		}
		data, err := c.smCall(ctx, cr, region, "ListSecretVersionIds", in)
		if err != nil {
			return time.Time{}, err
		}
		var out struct {
			NextToken string
			Versions  []struct {
				VersionStages []string
				CreatedDate   *float64
			}
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return time.Time{}, err
		}
		for _, v := range out.Versions {
			for _, st := range v.VersionStages {
				if st == "AWSCURRENT" && v.CreatedDate != nil {
					return unix(v.CreatedDate), nil
				}
			}
		}
		if out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	return time.Time{}, nil
}

// listSecrets pages through Secrets Manager ListSecrets (metadata only;
// GetSecretValue is never called).
//
// Rotation on: due at the earlier of NextRotationDate and the last
// successful rotation (or creation) + interval + grace — with a schedule
// a failing rotation may move NextRotationDate forward, so the date
// alone could hide it. Rotation on without a date is due now.
// Rotation off: due secret_max_age_days after the current value was
// created (not reported when 0, nor for service-owned secrets).
// A replica is reported only from its primary region when both are
// configured.
func (c *Checker) listSecrets(ctx context.Context, cr credentials, account, region string) ([]checker.ExpiryRecord, error) {
	inRegions := map[string]bool{}
	for _, r := range c.cfg.Regions {
		inRegions[r] = true
	}
	var records []checker.ExpiryRecord
	var errs []error
	next := ""
	for page := 0; page < 1000; page++ {
		in := map[string]any{"MaxResults": 100}
		if next != "" {
			in["NextToken"] = next
		}
		data, err := c.smCall(ctx, cr, region, "ListSecrets", in)
		if err != nil {
			return records, errors.Join(append(errs, err)...)
		}
		var out struct {
			NextToken  string
			SecretList []struct {
				ARN, Name, OwningService, PrimaryRegion, Type                   string
				RotationEnabled                                                 bool
				NextRotationDate, LastRotatedDate, CreatedDate, LastChangedDate *float64
				RotationRules                                                   struct {
					AutomaticallyAfterDays *int
					ScheduleExpression     string
				}
			}
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return records, fmt.Errorf("ListSecrets: %w", err)
		}
		for _, s := range out.SecretList {
			if s.PrimaryRegion != "" && s.PrimaryRegion != region && inRegions[s.PrimaryRegion] {
				continue // replica: reported from its primary region
			}
			meta := map[string]string{"account": account, "region": region, "rotation": "disabled"}
			for k, v := range map[string]string{"owning_service": s.OwningService, "primary_region": s.PrimaryRegion, "type": s.Type} {
				if v != "" {
					meta[k] = v
				}
			}
			var exp time.Time
			if s.RotationEnabled {
				meta["rotation"] = "enabled"
				base := unix(s.LastRotatedDate)
				if base.IsZero() {
					base = unix(s.CreatedDate)
				}
				interval := rotationInterval(s.RotationRules.AutomaticallyAfterDays, s.RotationRules.ScheduleExpression)
				if interval > 0 {
					meta["rotation_interval_days"] = strconv.Itoa(int(interval.Hours() / 24))
				}
				if !base.IsZero() {
					meta["last_rotated"] = base.Format(time.RFC3339)
				}
				exp = unix(s.NextRotationDate)
				if interval > 0 && !base.IsZero() {
					if overdue := base.Add(interval + rotationGrace); exp.IsZero() || overdue.Before(exp) {
						exp = overdue
					}
				}
				if exp.IsZero() { // rotation on but never scheduled: an anomaly, due now
					meta["rotation"] = "enabled-unscheduled"
					exp = base
					if exp.IsZero() {
						exp = time.Now().UTC()
					}
				}
			} else {
				if c.cfg.SecretMaxAgeDays == 0 || s.OwningService != "" {
					continue // nothing expires (service-owned secrets are the service's)
				}
				created, err := c.currentVersionCreated(ctx, cr, region, s.ARN)
				if err != nil {
					errs = append(errs, fmt.Errorf("secret %s: %w", s.Name, err))
					continue
				}
				if created.IsZero() {
					created = unix(s.CreatedDate)
				}
				if created.IsZero() {
					errs = append(errs, fmt.Errorf("secret %s: no creation date", s.Name))
					continue
				}
				meta["max_age_days"] = strconv.Itoa(c.cfg.SecretMaxAgeDays)
				meta["value_created"] = created.Format(time.RFC3339)
				exp = created.Add(time.Duration(c.cfg.SecretMaxAgeDays) * 24 * time.Hour)
			}
			records = append(records, checker.ExpiryRecord{
				Source: "aws://secretsmanager/" + account + "/" + region + "/" + s.Name, Name: s.Name, Kind: "secret",
				ExpiresAt: exp.UTC(), Metadata: meta,
			})
		}
		if out.NextToken == "" {
			return records, errors.Join(errs...)
		}
		next = out.NextToken
	}
	return records, errors.Join(append(errs, errors.New("ListSecrets: more than 1000 pages"))...)
}
