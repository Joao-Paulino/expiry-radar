package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// listSecrets pages through Secrets Manager ListSecrets (metadata only;
// GetSecretValue is never called). Rotation on: due at
// NextRotationDate (a failing rotation leaves it in the past, so it
// alerts). Rotation off: due secret_max_age_days after the last change
// (or creation), or not reported when that is 0.
func (c *Checker) listSecrets(ctx context.Context, cr credentials, account, region string) ([]checker.ExpiryRecord, error) {
	var records []checker.ExpiryRecord
	next := ""
	for page := 0; page < 1000; page++ {
		in := map[string]any{"MaxResults": 100}
		if next != "" {
			in["NextToken"] = next
		}
		body, _ := json.Marshal(in)
		data, err := send(ctx, c.http, "ListSecrets", func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ep.secrets(region)+"/", strings.NewReader(string(body)))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/x-amz-json-1.1")
			req.Header.Set("X-Amz-Target", "secretsmanager.ListSecrets")
			signV4(req, body, cr, region, "secretsmanager", time.Now())
			return req, nil
		})
		if err != nil {
			return records, err
		}
		var out struct {
			NextToken  string
			SecretList []struct {
				Name, OwningService                                             string
				RotationEnabled                                                 bool
				NextRotationDate, LastRotatedDate, LastChangedDate, CreatedDate *float64
			}
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return records, fmt.Errorf("ListSecrets: %w", err)
		}
		for _, s := range out.SecretList {
			meta := map[string]string{"account": account, "region": region, "rotation": "disabled"}
			if s.OwningService != "" {
				meta["owning_service"] = s.OwningService
			}
			var exp time.Time
			switch {
			case s.RotationEnabled && s.NextRotationDate != nil:
				meta["rotation"] = "enabled"
				exp = time.Unix(int64(*s.NextRotationDate), 0)
			case s.RotationEnabled:
				continue // rotation on but not scheduled yet
			case c.cfg.SecretMaxAgeDays > 0:
				changed := s.LastChangedDate
				if changed == nil {
					changed = s.CreatedDate
				}
				if changed == nil {
					continue
				}
				meta["max_age_days"] = strconv.Itoa(c.cfg.SecretMaxAgeDays)
				exp = time.Unix(int64(*changed), 0).Add(time.Duration(c.cfg.SecretMaxAgeDays) * 24 * time.Hour)
			default:
				continue // no rotation and no max age: nothing expires
			}
			records = append(records, checker.ExpiryRecord{
				Source: "aws://secretsmanager/" + account + "/" + region + "/" + s.Name, Name: s.Name, Kind: "secret",
				ExpiresAt: exp.UTC(), Metadata: meta,
			})
		}
		if out.NextToken == "" {
			return records, nil
		}
		next = out.NextToken
	}
	return records, errors.New("ListSecrets: more than 1000 pages")
}
