package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// checkLeases walks the lease IDs under prefix and reports dynamic
// secret leases that expire. Leases granted for less than
// lease_min_ttl_hours (from issue or last renewal to expiry) are short
// credentials meant to be re-issued, not alerts, and are skipped.
func (c *Checker) checkLeases(ctx context.Context, s *session, source, prefix string) ([]checker.ExpiryRecord, error) {
	var ids []string
	dirs := []string{prefix}
	for len(dirs) > 0 {
		dir := dirs[0]
		dirs = dirs[1:]
		keys, err := s.list(ctx, "sys/leases/lookup/"+escapePath(dir))
		if err != nil {
			if isEmptyList(err) {
				continue
			}
			return nil, err
		}
		for _, k := range keys {
			if strings.HasSuffix(k, "/") {
				dirs = append(dirs, dir+k)
			} else {
				ids = append(ids, dir+k)
			}
		}
	}

	minTTL := time.Duration(c.cfg.LeaseMinTTLHours) * time.Hour
	if minTTL == 0 {
		minTTL = 24 * time.Hour
	}
	var (
		mu      sync.Mutex
		records []checker.ExpiryRecord
	)
	err := forEach(ids, func(id string) error {
		role, last, _ := cutLast(id)
		var r struct {
			Data struct {
				IssueTime       string  `json:"issue_time"`
				LastRenewalTime *string `json:"last_renewal_time"`
				ExpireTime      *string `json:"expire_time"`
				Renewable       bool    `json:"renewable"`
			} `json:"data"`
		}
		if err := s.call(ctx, http.MethodPost, "sys/leases/lookup", map[string]string{"lease_id": id}, &r); err != nil {
			var e *apiError
			if errors.As(err, &e) && e.status == http.StatusBadRequest {
				return nil // expired or revoked since the list
			}
			return fmt.Errorf("lease %s · %s: %w", role, shortAccessor(last), err)
		}
		d := r.Data
		if d.ExpireTime == nil || *d.ExpireTime == "" {
			return nil
		}
		exp, err := time.Parse(time.RFC3339, *d.ExpireTime)
		if err != nil {
			return fmt.Errorf("lease %s · %s: expire_time: %w", role, shortAccessor(last), err)
		}
		start := d.IssueTime
		if d.LastRenewalTime != nil && *d.LastRenewalTime != "" {
			start = *d.LastRenewalTime
		}
		if from, err := time.Parse(time.RFC3339, start); err == nil && exp.Sub(from) < minTTL {
			return nil
		}
		mu.Lock()
		records = append(records, checker.ExpiryRecord{Source: source, Name: role + " · " + shortAccessor(last), Kind: "secret", ExpiresAt: exp,
			Metadata: map[string]string{"role": role, "renewable": fmt.Sprint(d.Renewable)}})
		mu.Unlock()
		return nil
	})
	return records, err
}

// cutLast splits "a/b/c" into "a/b" and "c".
func cutLast(id string) (string, string, bool) {
	i := strings.LastIndex(id, "/")
	if i < 0 {
		return "", id, false
	}
	return id[:i], id[i+1:], true
}
